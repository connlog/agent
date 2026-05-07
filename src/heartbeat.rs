use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct HeartbeatPayload {
    pub agent_version: String,
    pub protocol_version: u32,
    pub config_version: u32,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub uptime_seconds: u64,
    pub metrics: Metrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_mode: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Metrics {
    pub cpu_percent: f64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_mb: u64,
    pub disk_total_mb: u64,
    pub load_1m: f64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization, not yet read by agent
pub struct HeartbeatResponse {
    pub ok: bool,
    pub server_time: String,
    pub expected_interval_seconds: u64,
    pub config_outdated: Option<bool>,
    pub latest_config_version: Option<u32>,
    pub update: Option<UpdateInfo>,
    /// If true, the agent should uninstall itself
    #[serde(default)]
    pub uninstall: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpdateInfo {
    pub available: bool,
    pub latest_version: String,
    pub download_url: Option<String>,
    /// URL to the Ed25519 signature file (.sig)
    #[serde(default)]
    pub signature_url: Option<String>,
    /// Expected SHA-256 hex digest of the binary
    #[serde(default)]
    pub sha256: Option<String>,
    /// When true, bypass the compiled-in signing-key check for this update.
    /// Set by the platform when a workspace owner explicitly requests a force update.
    #[serde(default)]
    pub force_update: bool,
}

/// Server-authoritative agent configuration.
/// All values are clamped by the server based on workspace plan.
/// The agent MUST obey these values.
#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    /// Monotonic config version for change detection
    #[serde(rename = "configVersion")]
    pub version: u32,

    /// Server-enforced heartbeat interval (seconds)
    #[serde(rename = "heartbeatIntervalSeconds")]
    pub heartbeat_interval_secs: u64,

    /// Number of missed heartbeats before agent is marked offline
    #[serde(rename = "missedThreshold")]
    pub missed_threshold: u32,

    /// Which metrics to collect
    pub metrics: MetricsConfig,

    /// Maximum payload size for heartbeats (KB)
    #[serde(rename = "maxPayloadSizeKb")]
    pub max_payload_size_kb: u64,

    /// Extended Linux resource metrics (opt-in per agent)
    #[serde(rename = "extendedMetrics", default)]
    pub extended_metrics: ExtendedMetricsConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ExtendedMetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "discoverResources", default)]
    pub discover_resources: bool,
    #[serde(rename = "collectDisks", default)]
    pub collect_disks: bool,
    #[serde(rename = "collectNetwork", default)]
    pub collect_network: bool,
    #[serde(rename = "monitoredDiskKeys", default)]
    pub monitored_disk_keys: Vec<String>,
    #[serde(rename = "monitoredNetworkKeys", default)]
    pub monitored_network_keys: Vec<String>,
}

/// Configuration for which metrics to collect
#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    pub cpu: bool,
    pub memory: bool,
    pub disk: bool,
    pub load: bool,
}

impl AgentConfig {
    /// Create safe fallback config when server is unreachable.
    /// These are conservative defaults that won't violate any plan.
    pub fn safe_fallback() -> Self {
        Self {
            version: 0,
            heartbeat_interval_secs: 60, // Conservative default
            missed_threshold: 3,
            metrics: MetricsConfig {
                cpu: true,
                memory: true,
                disk: true,
                load: true,
            },
            max_payload_size_kb: 32,
            extended_metrics: ExtendedMetricsConfig::default(),
        }
    }

    /// Clamp server config values to safe client-side bounds.
    /// Prevents resource abuse from a malicious or buggy server response.
    pub fn clamp(&mut self) {
        // Minimum 10s heartbeat to prevent CPU/network spin
        // Maximum 86400s (24h) to ensure eventual check-in
        self.heartbeat_interval_secs = self.heartbeat_interval_secs.clamp(10, 86400);

        // Missed threshold: at least 1, at most 100
        self.missed_threshold = self.missed_threshold.clamp(1, 100);

        // Payload size: 1KB–1MB (0 means no limit, keep as-is)
        if self.max_payload_size_kb > 0 {
            self.max_payload_size_kb = self.max_payload_size_kb.clamp(1, 1024);
        }
    }

    /// Check if any metrics collection is enabled
    pub fn any_metrics_enabled(&self) -> bool {
        self.metrics.cpu || self.metrics.memory || self.metrics.disk || self.metrics.load
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
//
// These tests pin the wire contract between agent and platform. If they fail,
// you've changed the heartbeat protocol — update
// `../connlog-platform/src/app/api/agents/heartbeat/route.ts` in the same PR
// (and bump `protocol_version` if the change is breaking).
// ────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── AgentConfig::clamp ──────────────────────────────────────
    //
    // CLAUDE.md §10.4 calls this out as security-critical: a malicious or buggy
    // server could push interval to 0 and spin the CPU. Tests here pin every
    // boundary that matters.

    fn cfg(interval: u64, missed: u32, payload: u64) -> AgentConfig {
        AgentConfig {
            version: 1,
            heartbeat_interval_secs: interval,
            missed_threshold: missed,
            metrics: MetricsConfig {
                cpu: true,
                memory: true,
                disk: true,
                load: true,
            },
            max_payload_size_kb: payload,
            extended_metrics: ExtendedMetricsConfig::default(),
        }
    }

    #[test]
    fn clamp_interval_floor_blocks_zero_spin() {
        let mut c = cfg(0, 3, 32);
        c.clamp();
        assert_eq!(
            c.heartbeat_interval_secs, 10,
            "0s interval must be raised to floor (10s)"
        );
    }

    #[test]
    fn clamp_interval_ceiling_blocks_24h_plus() {
        let mut c = cfg(u64::MAX, 3, 32);
        c.clamp();
        assert_eq!(
            c.heartbeat_interval_secs, 86400,
            "absurd intervals must be capped at 24h"
        );
    }

    #[test]
    fn clamp_interval_passthrough_in_range() {
        let mut c = cfg(60, 3, 32);
        c.clamp();
        assert_eq!(c.heartbeat_interval_secs, 60);
    }

    #[test]
    fn clamp_missed_threshold_floor_one() {
        let mut c = cfg(60, 0, 32);
        c.clamp();
        assert_eq!(
            c.missed_threshold, 1,
            "missed_threshold=0 would mark agent offline immediately"
        );
    }

    #[test]
    fn clamp_missed_threshold_ceiling_hundred() {
        let mut c = cfg(60, u32::MAX, 32);
        c.clamp();
        assert_eq!(c.missed_threshold, 100);
    }

    #[test]
    fn clamp_payload_size_zero_means_unlimited() {
        let mut c = cfg(60, 3, 0);
        c.clamp();
        assert_eq!(
            c.max_payload_size_kb, 0,
            "0 must remain 0 (unlimited sentinel)"
        );
    }

    #[test]
    fn clamp_payload_size_clamps_to_one_mb() {
        let mut c = cfg(60, 3, u64::MAX);
        c.clamp();
        assert_eq!(c.max_payload_size_kb, 1024);
    }

    #[test]
    fn clamp_payload_size_floor_one_kb() {
        // Non-zero values must clamp to at least 1 KB; 0 is the unlimited sentinel.
        let mut c = cfg(60, 3, 1);
        c.clamp();
        assert_eq!(c.max_payload_size_kb, 1);
    }

    #[test]
    fn clamp_does_not_touch_metrics_or_version() {
        let mut c = cfg(60, 3, 32);
        c.metrics.cpu = false;
        c.version = 42;
        c.clamp();
        assert!(!c.metrics.cpu);
        assert_eq!(c.version, 42, "clamp must not mutate version");
    }

    // ── safe_fallback ───────────────────────────────────────────

    #[test]
    fn safe_fallback_is_clamp_idempotent() {
        // The fallback must already satisfy clamp() — i.e. clamp on it must be
        // a no-op. Otherwise we'd flap on every cold start.
        let mut a = AgentConfig::safe_fallback();
        let mut b = AgentConfig::safe_fallback();
        b.clamp();
        a.clamp();
        a.clamp(); // double-clamp must also be a no-op
        assert_eq!(a.version, b.version);
        assert_eq!(a.heartbeat_interval_secs, b.heartbeat_interval_secs);
        assert_eq!(a.missed_threshold, b.missed_threshold);
        assert_eq!(a.max_payload_size_kb, b.max_payload_size_kb);
    }

    #[test]
    fn safe_fallback_is_marked_v0() {
        // The agent uses version=0 as the "this is fallback, please refetch" signal.
        assert_eq!(AgentConfig::safe_fallback().version, 0);
    }

    // ── any_metrics_enabled ─────────────────────────────────────

    #[test]
    fn any_metrics_enabled_true_when_at_least_one_set() {
        let mut c = cfg(60, 3, 32);
        c.metrics = MetricsConfig {
            cpu: false,
            memory: false,
            disk: false,
            load: true,
        };
        assert!(c.any_metrics_enabled());
        c.metrics = MetricsConfig {
            cpu: true,
            memory: false,
            disk: false,
            load: false,
        };
        assert!(c.any_metrics_enabled());
    }

    #[test]
    fn any_metrics_enabled_false_when_all_off() {
        let mut c = cfg(60, 3, 32);
        c.metrics = MetricsConfig {
            cpu: false,
            memory: false,
            disk: false,
            load: false,
        };
        assert!(!c.any_metrics_enabled());
    }

    // ── AgentConfig deserialisation contract ─────────────────────
    //
    // Field renames (camelCase on the wire ↔ snake_case in Rust) are part of
    // the protocol contract. These tests fail loudly if anyone changes a
    // serde rename without coordinating with the platform.

    #[test]
    fn agent_config_deserialises_camel_case_wire_format() {
        let json = r#"{
            "configVersion": 7,
            "heartbeatIntervalSeconds": 45,
            "missedThreshold": 5,
            "metrics": {"cpu": true, "memory": false, "disk": true, "load": false},
            "maxPayloadSizeKb": 64
        }"#;
        let cfg: AgentConfig =
            serde_json::from_str(json).expect("must accept platform's camelCase");
        assert_eq!(cfg.version, 7);
        assert_eq!(cfg.heartbeat_interval_secs, 45);
        assert_eq!(cfg.missed_threshold, 5);
        assert!(cfg.metrics.cpu);
        assert!(!cfg.metrics.memory);
        assert!(cfg.metrics.disk);
        assert!(!cfg.metrics.load);
        assert_eq!(cfg.max_payload_size_kb, 64);
    }

    #[test]
    fn agent_config_rejects_snake_case_wire_format() {
        // Symmetric guard — if someone removes the rename, this test fails so
        // they can't accidentally break the platform contract.
        let json = r#"{
            "version": 7,
            "heartbeat_interval_secs": 45,
            "missed_threshold": 5,
            "metrics": {"cpu": true, "memory": false, "disk": true, "load": false},
            "max_payload_size_kb": 64
        }"#;
        let result: Result<AgentConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "snake_case keys must be rejected (platform sends camelCase)"
        );
    }

    // ── HeartbeatResponse deserialisation contract ───────────────

    #[test]
    fn heartbeat_response_minimal_form() {
        // The platform may omit every optional field. The agent must accept it.
        let json = r#"{
            "ok": true,
            "server_time": "2026-04-28T12:00:00Z",
            "expected_interval_seconds": 30
        }"#;
        let resp: HeartbeatResponse = serde_json::from_str(json).expect("minimal form must parse");
        assert!(resp.ok);
        assert_eq!(resp.expected_interval_seconds, 30);
        assert_eq!(resp.config_outdated, None);
        assert_eq!(resp.latest_config_version, None);
        assert!(resp.update.is_none());
        assert!(
            !resp.uninstall,
            "missing `uninstall` must default to false (#[serde(default)])"
        );
    }

    #[test]
    fn heartbeat_response_full_form_with_update() {
        let json = r#"{
            "ok": true,
            "server_time": "2026-04-28T12:00:00Z",
            "expected_interval_seconds": 60,
            "config_outdated": true,
            "latest_config_version": 9,
            "uninstall": false,
            "update": {
                "available": true,
                "latest_version": "1.0.0",
                "download_url": "https://platform.example/api/agents/updates/x86_64/binary",
                "signature_url": "https://platform.example/api/agents/updates/x86_64/signature",
                "sha256": "deadbeef"
            }
        }"#;
        let resp: HeartbeatResponse = serde_json::from_str(json).unwrap();
        let upd = resp.update.expect("update field must be parsed");
        assert!(upd.available);
        assert_eq!(upd.latest_version, "1.0.0");
        assert_eq!(
            upd.download_url.as_deref(),
            Some("https://platform.example/api/agents/updates/x86_64/binary")
        );
        assert_eq!(upd.sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn update_info_defaults_when_signature_and_sha_missing() {
        // Platform may legitimately return `available: false` with only a version.
        let json = r#"{"available": false, "latest_version": "0.3.6"}"#;
        let upd: UpdateInfo = serde_json::from_str(json).unwrap();
        assert!(!upd.available);
        assert!(upd.signature_url.is_none());
        assert!(upd.sha256.is_none());
    }

    // ── Metrics wire format — aggregate CPU only, no per-core ────
    //
    // The agent collects only global_cpu_usage() from sysinfo. Per-core CPU
    // data is not in scope for V1. These tests pin the JSON shape so that a
    // change to the Metrics struct forces an explicit contract review.

    #[test]
    fn metrics_wire_format_has_aggregate_cpu_only() {
        let m = Metrics {
            cpu_percent: 42.5,
            memory_used_mb: 1024,
            memory_total_mb: 8192,
            disk_used_mb: 20480,
            disk_total_mb: 100000,
            load_1m: 0.5,
        };
        let json = serde_json::to_string(&m).unwrap();
        let obj: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = obj
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();

        // Per-core fields must be absent from the wire format
        assert!(
            !keys.contains(&"cpu_per_core"),
            "per-core CPU array must not appear on the wire"
        );
        assert!(
            !keys.contains(&"cpu_cores"),
            "CPU core count must not appear on the wire"
        );

        // Aggregate CPU must be present
        assert!(
            keys.contains(&"cpu_percent"),
            "aggregate cpu_percent must be on the wire"
        );

        // load_1m only — no 5m or 15m
        assert!(
            !keys.contains(&"load_5m"),
            "5-minute load average is not in the wire format"
        );
        assert!(
            !keys.contains(&"load_15m"),
            "15-minute load average is not in the wire format"
        );
        assert!(
            keys.contains(&"load_1m"),
            "1-minute load average must be on the wire"
        );
    }

    #[test]
    fn metrics_exact_field_set() {
        // Pin the complete set of fields so additions require deliberate review.
        let m = Metrics {
            cpu_percent: 0.0,
            memory_used_mb: 0,
            memory_total_mb: 0,
            disk_used_mb: 0,
            disk_total_mb: 0,
            load_1m: 0.0,
        };
        let json = serde_json::to_string(&m).unwrap();
        let obj: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut keys: Vec<&str> = obj
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            &[
                "cpu_percent",
                "disk_total_mb",
                "disk_used_mb",
                "load_1m",
                "memory_total_mb",
                "memory_used_mb",
            ],
            "wire format field set changed — update both this test and \
             ../connlog-platform/src/app/api/agents/heartbeat/route.ts"
        );
    }

    // ── HeartbeatPayload serialisation contract ──────────────────

    #[test]
    fn heartbeat_payload_omits_dev_mode_when_none() {
        let payload = HeartbeatPayload {
            agent_version: "1.0.0".to_string(),
            protocol_version: 1,
            config_version: 1,
            hostname: "h".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            uptime_seconds: 0,
            metrics: Metrics {
                cpu_percent: 0.0,
                memory_used_mb: 0,
                memory_total_mb: 0,
                disk_used_mb: 0,
                disk_total_mb: 0,
                load_1m: 0.0,
            },
            dev_mode: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(
            !json.contains("dev_mode"),
            "None dev_mode must be skipped on the wire"
        );
    }
}
