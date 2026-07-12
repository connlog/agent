//! BMC hardware-health poller (Dell iDRAC, HPE iLO — anything Redfish).
//!
//! Polls the machine's out-of-band management controller over its Redfish
//! REST API and reports storage hardware health (physical drives, RAID
//! volumes, storage controllers) to the platform, which alerts on
//! transitions (e.g. a drive going CRITICAL or predicting failure).
//!
//! Opt-in and fully isolated from the heartbeat loop:
//!   - Enabled only when `CONNLOG_BMC_ENDPOINT`, `CONNLOG_BMC_USERNAME`, and
//!     `CONNLOG_BMC_PASSWORD` are all set (normally via
//!     `/etc/connlog/agent.conf`, the systemd EnvironmentFile).
//!   - Runs on its own thread with its own HTTP clients; a slow or dead BMC
//!     can never delay a heartbeat.
//!   - BMC credentials are sent only to the BMC itself (HTTP basic auth) and
//!     are never logged and never forwarded to the platform.
//!
//! Supported env vars:
//!   CONNLOG_BMC_ENDPOINT            e.g. https://10.0.0.120 (the BMC, not the OS)
//!   CONNLOG_BMC_USERNAME            read-only BMC account recommended
//!   CONNLOG_BMC_PASSWORD
//!   CONNLOG_BMC_POLL_INTERVAL_SECS  default 300, clamped to 60..=3600
//!   CONNLOG_BMC_INSECURE_TLS        "true" to accept the BMC's self-signed
//!                                   certificate (common on iDRAC/iLO).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use log::{info, warn};
use serde::Serialize;
use serde_json::Value;

/// Per-request timeout against the BMC. BMCs are slow embedded systems —
/// this is deliberately looser than the platform heartbeat timeout, and it
/// only ever blocks the dedicated poller thread.
const BMC_REQUEST_TIMEOUT_SECS: u64 = 20;
const BMC_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Timeout for the report POST to the platform.
const REPORT_TIMEOUT_SECS: u64 = 15;

/// Upper bounds so a huge (or lying) Redfish tree cannot run away.
const MAX_COMPONENTS: usize = 256;
const MAX_BMC_REQUESTS: usize = 200;

/// Delay before the first poll so the initial heartbeat registers the agent
/// before any hardware report arrives.
const INITIAL_POLL_DELAY_SECS: u64 = 15;

const DEFAULT_POLL_INTERVAL_SECS: u64 = 300;
const MIN_POLL_INTERVAL_SECS: u64 = 60;
const MAX_POLL_INTERVAL_SECS: u64 = 3600;

// ── Configuration ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BmcConfig {
    pub endpoint: String,
    pub username: String,
    pub password: String,
    pub poll_interval_secs: u64,
    pub insecure_tls: bool,
}

impl BmcConfig {
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Testable core of `from_env`: all three of endpoint/username/password
    /// must be present and non-empty, everything else has defaults.
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let non_empty = |key: &str| {
            get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let endpoint = non_empty("CONNLOG_BMC_ENDPOINT")?;
        let username = non_empty("CONNLOG_BMC_USERNAME")?;
        let password = non_empty("CONNLOG_BMC_PASSWORD")?;

        let poll_interval_secs = non_empty("CONNLOG_BMC_POLL_INTERVAL_SECS")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECS)
            .clamp(MIN_POLL_INTERVAL_SECS, MAX_POLL_INTERVAL_SECS);

        let insecure_tls = non_empty("CONNLOG_BMC_INSECURE_TLS")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        Some(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            username,
            password,
            poll_interval_secs,
            insecure_tls,
        })
    }
}

// ── Component model + platform wire format ──────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Health {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "WARNING")]
    Warning,
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl Health {
    fn from_redfish(value: Option<&str>) -> Self {
        match value {
            Some(v) if v.eq_ignore_ascii_case("ok") => Health::Ok,
            Some(v) if v.eq_ignore_ascii_case("warning") => Health::Warning,
            Some(v) if v.eq_ignore_ascii_case("critical") => Health::Critical,
            _ => Health::Unknown,
        }
    }
}

/// One hardware component in the platform wire format
/// (`POST /api/agents/hardware-health`, snake_case).
#[derive(Debug, Clone, Serialize)]
pub struct HardwareComponent {
    pub component_type: &'static str,
    pub component_key: String,
    pub name: String,
    pub health: Health,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub failure_predicted: bool,
    pub attributes: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize)]
pub struct HardwareHealthReport {
    pub source: &'static str,
    pub collected_at_unix_ms: u64,
    pub components: Vec<HardwareComponent>,
}

// ── Redfish document extraction (pure, unit-tested) ─────────────

fn str_field(doc: &Value, key: &str) -> Option<String> {
    doc.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn status_health(doc: &Value) -> Health {
    Health::from_redfish(doc.pointer("/Status/Health").and_then(|v| v.as_str()))
}

fn status_state(doc: &Value) -> Option<String> {
    doc.pointer("/Status/State")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn is_absent(doc: &Value) -> bool {
    status_state(doc).is_some_and(|s| s.eq_ignore_ascii_case("absent"))
}

fn odata_ref(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|v| v.get("@odata.id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn member_refs(collection: &Value) -> Vec<String> {
    collection
        .get("Members")
        .and_then(|m| m.as_array())
        .map(|members| members.iter().filter_map(|m| odata_ref(Some(m))).collect())
        .unwrap_or_default()
}

/// Stable component key: Redfish `Id`, falling back to the resource path.
fn component_key(doc: &Value) -> Option<String> {
    str_field(doc, "Id").or_else(|| str_field(doc, "@odata.id"))
}

fn insert_attr(attrs: &mut serde_json::Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(v) = value {
        if !v.is_null() {
            attrs.insert(key.to_string(), v);
        }
    }
}

/// Physical drive → component. `None` for absent bays or undecodable docs.
pub(crate) fn drive_component(doc: &Value) -> Option<HardwareComponent> {
    if is_absent(doc) {
        return None;
    }
    let key = component_key(doc)?;
    let name = str_field(doc, "Name").unwrap_or_else(|| key.clone());
    let failure_predicted = doc
        .get("FailurePredicted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut attributes = serde_json::Map::new();
    insert_attr(&mut attributes, "model", doc.get("Model").cloned());
    insert_attr(
        &mut attributes,
        "serial_number",
        doc.get("SerialNumber").cloned(),
    );
    insert_attr(&mut attributes, "media_type", doc.get("MediaType").cloned());
    insert_attr(
        &mut attributes,
        "capacity_bytes",
        doc.get("CapacityBytes").cloned(),
    );
    insert_attr(
        &mut attributes,
        "media_life_left_percent",
        doc.get("PredictedMediaLifeLeftPercent").cloned(),
    );

    Some(HardwareComponent {
        component_type: "drive",
        component_key: key,
        name,
        health: status_health(doc),
        state: status_state(doc),
        failure_predicted,
        attributes,
    })
}

/// RAID / logical volume → component.
pub(crate) fn volume_component(doc: &Value) -> Option<HardwareComponent> {
    if is_absent(doc) {
        return None;
    }
    let key = component_key(doc)?;
    let name = str_field(doc, "Name").unwrap_or_else(|| key.clone());

    let mut attributes = serde_json::Map::new();
    insert_attr(&mut attributes, "raid_type", doc.get("RAIDType").cloned());
    insert_attr(
        &mut attributes,
        "capacity_bytes",
        doc.get("CapacityBytes").cloned(),
    );

    Some(HardwareComponent {
        component_type: "volume",
        component_key: key,
        name,
        health: status_health(doc),
        state: status_state(doc),
        failure_predicted: false,
        attributes,
    })
}

/// Storage controllers are embedded in the storage subsystem document
/// (`StorageControllers` array) rather than linked resources.
pub(crate) fn controller_components(storage_doc: &Value) -> Vec<HardwareComponent> {
    let Some(controllers) = storage_doc
        .get("StorageControllers")
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    let storage_key = component_key(storage_doc).unwrap_or_else(|| "storage".to_string());

    controllers
        .iter()
        .filter(|doc| !is_absent(doc))
        .map(|doc| {
            let member = str_field(doc, "MemberId")
                .or_else(|| str_field(doc, "@odata.id"))
                .unwrap_or_else(|| "0".to_string());
            let name = str_field(doc, "Name")
                .or_else(|| str_field(doc, "Model"))
                .unwrap_or_else(|| format!("Controller {member}"));

            let mut attributes = serde_json::Map::new();
            insert_attr(&mut attributes, "model", doc.get("Model").cloned());
            insert_attr(
                &mut attributes,
                "firmware_version",
                doc.get("FirmwareVersion").cloned(),
            );

            HardwareComponent {
                component_type: "controller",
                component_key: format!("{storage_key}/{member}"),
                name,
                health: status_health(doc),
                state: status_state(doc),
                failure_predicted: false,
                attributes,
            }
        })
        .collect()
}

// ── Redfish HTTP client + tree walk ─────────────────────────────

struct RedfishClient {
    http: reqwest::blocking::Client,
    config: BmcConfig,
}

struct RequestBudget(usize);

impl RequestBudget {
    fn take(&mut self) -> Result<()> {
        if self.0 == 0 {
            return Err(anyhow!("BMC request budget exhausted"));
        }
        self.0 -= 1;
        Ok(())
    }
}

impl RedfishClient {
    fn new(config: BmcConfig) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(BMC_REQUEST_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(BMC_CONNECT_TIMEOUT_SECS))
            // iDRAC/iLO ship self-signed certs; opt-in only, and the BMC
            // endpoint is operator-configured, so the blast radius is the
            // BMC credentials the operator already chose to use here.
            .danger_accept_invalid_certs(config.insecure_tls)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("connlog-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to create BMC HTTP client")?;
        Ok(Self { http, config })
    }

    fn get_json(&self, path: &str, budget: &mut RequestBudget) -> Result<Value> {
        budget.take()?;
        let url = format!("{}{}", self.config.endpoint, path);
        let response = self
            .http
            .get(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .header("Accept", "application/json")
            .send()
            .with_context(|| format!("BMC request failed: {path}"))?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "BMC returned HTTP {} for {path}",
                response.status()
            ));
        }
        response
            .json()
            .with_context(|| format!("BMC returned non-JSON for {path}"))
    }

    /// Walk Systems → Storage → {controllers, drives, volumes}.
    fn collect_components(&self) -> Result<Vec<HardwareComponent>> {
        let mut budget = RequestBudget(MAX_BMC_REQUESTS);
        let mut components: Vec<HardwareComponent> = Vec::new();

        let systems = self.get_json("/redfish/v1/Systems", &mut budget)?;
        for system_ref in member_refs(&systems) {
            let Ok(system) = self.get_json(&system_ref, &mut budget) else {
                continue;
            };
            let Some(storage_col_ref) = odata_ref(system.get("Storage")) else {
                continue;
            };
            let Ok(storage_col) = self.get_json(&storage_col_ref, &mut budget) else {
                continue;
            };

            for storage_ref in member_refs(&storage_col) {
                let Ok(storage) = self.get_json(&storage_ref, &mut budget) else {
                    continue;
                };

                components.extend(controller_components(&storage));

                let drive_refs: Vec<String> = storage
                    .get("Drives")
                    .and_then(|v| v.as_array())
                    .map(|drives| drives.iter().filter_map(|d| odata_ref(Some(d))).collect())
                    .unwrap_or_default();
                for drive_ref in drive_refs {
                    if components.len() >= MAX_COMPONENTS {
                        break;
                    }
                    if let Ok(doc) = self.get_json(&drive_ref, &mut budget) {
                        components.extend(drive_component(&doc));
                    }
                }

                if let Some(volumes_ref) = odata_ref(storage.get("Volumes")) {
                    if let Ok(volumes) = self.get_json(&volumes_ref, &mut budget) {
                        for volume_ref in member_refs(&volumes) {
                            if components.len() >= MAX_COMPONENTS {
                                break;
                            }
                            if let Ok(doc) = self.get_json(&volume_ref, &mut budget) {
                                components.extend(volume_component(&doc));
                            }
                        }
                    }
                }
            }
        }

        components.truncate(MAX_COMPONENTS);
        Ok(components)
    }
}

// ── Platform reporter ───────────────────────────────────────────

pub(crate) struct PlatformReporter {
    http: reqwest::blocking::Client,
    url: String,
    token: String,
}

impl PlatformReporter {
    pub(crate) fn new(platform_endpoint: &str, token: String) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(REPORT_TIMEOUT_SECS))
            // SECURITY: same rationale as the heartbeat client — never follow
            // a redirect that could leak the bearer token to another host.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("connlog-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to create hardware report HTTP client")?;
        Ok(Self {
            http,
            url: format!(
                "{}/api/agents/hardware-health",
                platform_endpoint.trim_end_matches('/')
            ),
            token,
        })
    }

    pub(crate) fn send(&self, report: &HardwareHealthReport) -> Result<()> {
        let response = self
            .http
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(report)
            .send()
            .context("Hardware report request failed")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("Platform rejected hardware report: HTTP {status}"));
        }
        Ok(())
    }
}

// ── Poller thread ───────────────────────────────────────────────

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Stop-aware sleep in 500ms ticks; Err(()) when shutdown was requested.
fn interruptible_sleep(stop: &AtomicBool, total: Duration) -> Result<(), ()> {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if stop.load(Ordering::SeqCst) {
            return Err(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

/// Spawn the BMC poller thread when `CONNLOG_BMC_*` is configured.
/// Returns `None` (and stays completely inert) otherwise.
pub fn spawn_if_configured(
    stop: Arc<AtomicBool>,
    platform_endpoint: String,
    token: String,
) -> Option<thread::JoinHandle<()>> {
    let config = BmcConfig::from_env()?;
    info!(
        "✓ BMC hardware health poller enabled (endpoint={}, interval={}s)",
        config.endpoint, config.poll_interval_secs
    );

    let handle = thread::Builder::new()
        .name("bmc-poller".to_string())
        .spawn(move || run_poller(&stop, config, &platform_endpoint, token))
        .ok()?;
    Some(handle)
}

fn run_poller(stop: &AtomicBool, config: BmcConfig, platform_endpoint: &str, token: String) {
    let interval = Duration::from_secs(config.poll_interval_secs);
    let redfish = match RedfishClient::new(config) {
        Ok(client) => client,
        Err(e) => {
            warn!("BMC poller disabled: {e}");
            return;
        }
    };
    let reporter = match PlatformReporter::new(platform_endpoint, token) {
        Ok(reporter) => reporter,
        Err(e) => {
            warn!("BMC poller disabled: {e}");
            return;
        }
    };

    if interruptible_sleep(stop, Duration::from_secs(INITIAL_POLL_DELAY_SECS)).is_err() {
        return;
    }

    loop {
        match redfish.collect_components() {
            Ok(components) => {
                let degraded = components
                    .iter()
                    .filter(|c| c.health != Health::Ok || c.failure_predicted)
                    .count();
                info!(
                    "BMC poll: {} hardware component(s), {} not healthy",
                    components.len(),
                    degraded
                );
                let report = HardwareHealthReport {
                    source: "redfish",
                    collected_at_unix_ms: unix_ms_now(),
                    components,
                };
                if let Err(e) = reporter.send(&report) {
                    warn!("Hardware report failed (will retry next poll): {e}");
                }
            }
            Err(e) => {
                warn!("BMC poll failed (will retry next poll): {e}");
            }
        }

        if interruptible_sleep(stop, interval).is_err() {
            return;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    // ── config gating ───────────────────────────────────────────

    #[test]
    fn config_requires_endpoint_username_and_password() {
        assert!(BmcConfig::from_lookup(lookup(&[])).is_none());
        assert!(BmcConfig::from_lookup(lookup(&[
            ("CONNLOG_BMC_ENDPOINT", "https://10.0.0.5"),
            ("CONNLOG_BMC_USERNAME", "monitor"),
        ]))
        .is_none());
        assert!(BmcConfig::from_lookup(lookup(&[
            ("CONNLOG_BMC_ENDPOINT", "https://10.0.0.5"),
            ("CONNLOG_BMC_USERNAME", "monitor"),
            ("CONNLOG_BMC_PASSWORD", "  "),
        ]))
        .is_none());

        let config = BmcConfig::from_lookup(lookup(&[
            ("CONNLOG_BMC_ENDPOINT", "https://10.0.0.5/"),
            ("CONNLOG_BMC_USERNAME", "monitor"),
            ("CONNLOG_BMC_PASSWORD", "secret"),
        ]))
        .expect("complete config must parse");
        assert_eq!(
            config.endpoint, "https://10.0.0.5",
            "trailing slash stripped"
        );
        assert_eq!(config.poll_interval_secs, DEFAULT_POLL_INTERVAL_SECS);
        assert!(!config.insecure_tls);
    }

    #[test]
    fn config_clamps_poll_interval() {
        let base = [
            ("CONNLOG_BMC_ENDPOINT", "https://bmc"),
            ("CONNLOG_BMC_USERNAME", "u"),
            ("CONNLOG_BMC_PASSWORD", "p"),
        ];

        let mut fast = base.to_vec();
        fast.push(("CONNLOG_BMC_POLL_INTERVAL_SECS", "5"));
        assert_eq!(
            BmcConfig::from_lookup(lookup(&fast))
                .unwrap()
                .poll_interval_secs,
            MIN_POLL_INTERVAL_SECS,
            "sub-minute polling would hammer the BMC"
        );

        let mut slow = base.to_vec();
        slow.push(("CONNLOG_BMC_POLL_INTERVAL_SECS", "999999"));
        assert_eq!(
            BmcConfig::from_lookup(lookup(&slow))
                .unwrap()
                .poll_interval_secs,
            MAX_POLL_INTERVAL_SECS
        );
    }

    #[test]
    fn config_parses_insecure_tls_opt_in() {
        let base = [
            ("CONNLOG_BMC_ENDPOINT", "https://bmc"),
            ("CONNLOG_BMC_USERNAME", "u"),
            ("CONNLOG_BMC_PASSWORD", "p"),
            ("CONNLOG_BMC_INSECURE_TLS", "TRUE"),
        ];
        assert!(BmcConfig::from_lookup(lookup(&base)).unwrap().insecure_tls);
    }

    // ── Redfish extraction ──────────────────────────────────────

    fn idrac_drive(health: &str, predicted: bool) -> Value {
        json!({
            "@odata.id": "/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Integrated.1-1/Drives/Disk.Bay.0",
            "Id": "Disk.Bay.0:Enclosure.Internal.0-1:RAID.Integrated.1-1",
            "Name": "Physical Disk 0:1:0",
            "Model": "ST4000NM0023",
            "SerialNumber": "Z1Z8Ls9K",
            "MediaType": "HDD",
            "CapacityBytes": 4000787030016u64,
            "FailurePredicted": predicted,
            "PredictedMediaLifeLeftPercent": null,
            "Status": { "Health": health, "State": "Enabled" }
        })
    }

    #[test]
    fn drive_component_maps_idrac_fields() {
        let component = drive_component(&idrac_drive("OK", false)).expect("drive must map");
        assert_eq!(component.component_type, "drive");
        assert_eq!(
            component.component_key,
            "Disk.Bay.0:Enclosure.Internal.0-1:RAID.Integrated.1-1"
        );
        assert_eq!(component.name, "Physical Disk 0:1:0");
        assert_eq!(component.health, Health::Ok);
        assert_eq!(component.state.as_deref(), Some("Enabled"));
        assert!(!component.failure_predicted);
        assert_eq!(
            component.attributes.get("model").and_then(|v| v.as_str()),
            Some("ST4000NM0023")
        );
        assert_eq!(
            component
                .attributes
                .get("serial_number")
                .and_then(|v| v.as_str()),
            Some("Z1Z8Ls9K")
        );
        assert!(
            !component.attributes.contains_key("media_life_left_percent"),
            "null attributes must be omitted"
        );
    }

    #[test]
    fn drive_component_flags_critical_and_predicted_failure() {
        let critical = drive_component(&idrac_drive("Critical", true)).unwrap();
        assert_eq!(critical.health, Health::Critical);
        assert!(critical.failure_predicted);

        let warning = drive_component(&idrac_drive("Warning", false)).unwrap();
        assert_eq!(warning.health, Health::Warning);
    }

    #[test]
    fn drive_component_skips_absent_bays() {
        let absent = json!({
            "Id": "Disk.Bay.3",
            "Name": "Empty Bay",
            "Status": { "Health": null, "State": "Absent" }
        });
        assert!(
            drive_component(&absent).is_none(),
            "empty bays are not components"
        );
    }

    #[test]
    fn unknown_health_maps_to_unknown() {
        let doc = json!({
            "Id": "Disk.Bay.1",
            "Name": "Disk 1",
            "Status": { "Health": null, "State": "Enabled" }
        });
        assert_eq!(drive_component(&doc).unwrap().health, Health::Unknown);
    }

    #[test]
    fn volume_component_maps_raid_state() {
        let doc = json!({
            "@odata.id": "/redfish/v1/Systems/1/Storage/0/Volumes/1",
            "Id": "1",
            "Name": "System RAID1",
            "RAIDType": "RAID1",
            "CapacityBytes": 500000000000u64,
            "Status": { "Health": "Critical", "State": "Enabled" }
        });
        let component = volume_component(&doc).expect("volume must map");
        assert_eq!(component.component_type, "volume");
        assert_eq!(component.health, Health::Critical);
        assert_eq!(
            component
                .attributes
                .get("raid_type")
                .and_then(|v| v.as_str()),
            Some("RAID1")
        );
    }

    #[test]
    fn controller_components_read_embedded_array() {
        // iLO-style storage document with an embedded controller.
        let storage = json!({
            "Id": "DE00A000",
            "StorageControllers": [{
                "MemberId": "0",
                "Name": "HPE Smart Array P408i-a SR Gen10",
                "Model": "P408i-a",
                "FirmwareVersion": "2.65",
                "Status": { "Health": "Warning", "State": "Enabled" }
            }]
        });
        let components = controller_components(&storage);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].component_type, "controller");
        assert_eq!(components[0].component_key, "DE00A000/0");
        assert_eq!(components[0].health, Health::Warning);
        assert_eq!(
            components[0]
                .attributes
                .get("firmware_version")
                .and_then(|v| v.as_str()),
            Some("2.65")
        );
    }

    #[test]
    fn member_refs_walks_collections() {
        let collection = json!({
            "Members": [
                { "@odata.id": "/redfish/v1/Systems/1" },
                { "@odata.id": "/redfish/v1/Systems/2" },
                { "unexpected": true }
            ]
        });
        assert_eq!(
            member_refs(&collection),
            vec!["/redfish/v1/Systems/1", "/redfish/v1/Systems/2"]
        );
        assert!(member_refs(&json!({})).is_empty());
    }

    // ── wire format contract ────────────────────────────────────
    //
    // Pins the JSON shape consumed by the platform's
    // `hardwareHealthReportSchema` in
    // `../connlog-platform/src/features/agents/server/services/hardware-health.service.ts`.
    // Change both sides in the same PR or ingestion breaks.

    #[test]
    fn report_wire_format_is_snake_case_with_upper_health() {
        let report = HardwareHealthReport {
            source: "redfish",
            collected_at_unix_ms: 1234,
            components: vec![drive_component(&idrac_drive("Critical", true)).unwrap()],
        };
        let value: Value = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();

        assert_eq!(value["source"], "redfish");
        assert_eq!(value["collected_at_unix_ms"], 1234);
        let component = &value["components"][0];
        assert_eq!(component["component_type"], "drive");
        assert_eq!(
            component["health"], "CRITICAL",
            "health must serialize UPPERCASE"
        );
        assert_eq!(component["failure_predicted"], true);
        assert!(component.get("component_key").is_some());
        assert!(component.get("name").is_some());
        assert!(component.get("state").is_some());
        assert!(component["attributes"].is_object());
    }
}
