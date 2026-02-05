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
#[allow(dead_code)]
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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UpdateInfo {
    pub available: bool,
    pub latest_version: String,
    pub download_url: Option<String>,
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
        }
    }

    /// Check if any metrics collection is enabled
    pub fn any_metrics_enabled(&self) -> bool {
        self.metrics.cpu || self.metrics.memory || self.metrics.disk || self.metrics.load
    }
}
