//! BMC hardware-health poller (Dell iDRAC, HPE iLO, OpenBMC — anything Redfish).
//!
//! Polls the machine's out-of-band management controller over its Redfish
//! REST API and reports hardware health to the platform, which alerts on
//! transitions (e.g. a drive going CRITICAL or predicting failure):
//!   - Overall system health (rolls up CPU + RAM summaries)
//!   - Storage: physical drives, RAID volumes, storage controllers
//!   - Chassis Thermal: fans and health-tracked temperature sensors
//!   - Chassis Power: power supplies
//!
//! Storage is optional in Redfish: OpenBMC and no-RAID hosts expose little or
//! no storage but still report system health, fans and PSUs, so those are what
//! make the poller useful across every vendor rather than Dell/HPE RAID only.
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
//! Configuration (CLI flag > env var / agent.conf > default). The installer
//! (`connlog-agent install --bmc-endpoint … --bmc-username … --bmc-password …`)
//! persists these into `/etc/connlog/agent.conf` for the systemd service:
//!   --bmc-endpoint       CONNLOG_BMC_ENDPOINT            https://10.0.0.120 (the BMC IP, not the OS)
//!   --bmc-username       CONNLOG_BMC_USERNAME            read-only BMC account recommended
//!   --bmc-password       CONNLOG_BMC_PASSWORD            prefer env/agent.conf over the CLI flag
//!   --bmc-poll-interval  CONNLOG_BMC_POLL_INTERVAL_SECS  default 300, clamped to 60..=3600
//!   --bmc-insecure-tls   CONNLOG_BMC_INSECURE_TLS        accept the BMC's self-signed cert
//!                                                        (common on iDRAC/iLO)

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

/// Largest Redfish document the poller will read. Real ones are a few KB.
const MAX_BMC_BODY_BYTES: u64 = 4 * 1024 * 1024;

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
    /// Build from the resolved CLI/env `Config`. clap has already folded the
    /// `--bmc-*` flags over the `CONNLOG_BMC_*` env vars (which arrive from the
    /// systemd EnvironmentFile `/etc/connlog/agent.conf`), so reading the
    /// config fields here composes CLI > env > agent.conf with no extra merge
    /// logic. Delegates to `from_lookup` so the non-empty/clamp/trim rules
    /// stay in one tested place.
    pub fn from_config(cfg: &crate::config::Config) -> Option<Self> {
        Self::from_lookup(|key| match key {
            "CONNLOG_BMC_ENDPOINT" => cfg.bmc_endpoint.clone(),
            "CONNLOG_BMC_USERNAME" => cfg.bmc_username.clone(),
            "CONNLOG_BMC_PASSWORD" => cfg.bmc_password.clone(),
            "CONNLOG_BMC_POLL_INTERVAL_SECS" => cfg.bmc_poll_interval_secs.map(|v| v.to_string()),
            "CONNLOG_BMC_INSECURE_TLS" => Some(cfg.bmc_insecure_tls.to_string()),
            _ => None,
        })
    }

    /// Testable core: all three of endpoint/username/password must be present
    /// and non-empty, everything else has defaults.
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
pub(crate) fn drive_component(doc: &Value, include_identifiers: bool) -> Option<HardwareComponent> {
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
    // A drive serial number identifies a physical machine more precisely
    // than a hostname does, and the hostname is opt-in.
    if include_identifiers {
        insert_attr(
            &mut attributes,
            "serial_number",
            doc.get("SerialNumber").cloned(),
        );
    }
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

/// Stable id for an embedded array member (Thermal `Fans`/`Temperatures`,
/// Power `PowerSupplies`). Prefers `MemberId`, then `Name`, then the raw
/// `@odata.id` fragment.
fn embedded_key(doc: &Value) -> String {
    str_field(doc, "MemberId")
        .or_else(|| str_field(doc, "Name"))
        .or_else(|| str_field(doc, "@odata.id"))
        .unwrap_or_else(|| "0".to_string())
}

/// Overall `ComputerSystem` health (CPU + RAM summaries roll up here).
///
/// This is what makes OpenBMC and no-RAID hosts report something useful: they
/// often expose no Redfish `Storage`, but every Redfish system exposes an
/// overall `Status/Health`.
pub(crate) fn system_component(doc: &Value) -> Option<HardwareComponent> {
    let key = component_key(doc)?;
    let name = str_field(doc, "Name").unwrap_or_else(|| format!("System {key}"));

    let mut attributes = serde_json::Map::new();
    insert_attr(
        &mut attributes,
        "manufacturer",
        doc.get("Manufacturer").cloned(),
    );
    insert_attr(&mut attributes, "model", doc.get("Model").cloned());
    insert_attr(
        &mut attributes,
        "power_state",
        doc.get("PowerState").cloned(),
    );
    insert_attr(
        &mut attributes,
        "processor_summary_health",
        doc.pointer("/ProcessorSummary/Status/Health").cloned(),
    );
    insert_attr(
        &mut attributes,
        "memory_summary_health",
        doc.pointer("/MemorySummary/Status/Health").cloned(),
    );

    Some(HardwareComponent {
        component_type: "system",
        component_key: format!("system/{key}"),
        name,
        health: status_health(doc),
        state: status_state(doc),
        failure_predicted: false,
        attributes,
    })
}

/// Fans + Temperatures embedded in a Chassis `Thermal` document (arrays, like
/// storage controllers). `chassis_key` namespaces the component keys.
pub(crate) fn thermal_components(thermal_doc: &Value, chassis_key: &str) -> Vec<HardwareComponent> {
    let mut out = Vec::new();

    if let Some(fans) = thermal_doc.get("Fans").and_then(|v| v.as_array()) {
        for fan in fans.iter().filter(|d| !is_absent(d)) {
            let member = embedded_key(fan);
            let name = str_field(fan, "Name")
                .or_else(|| str_field(fan, "FanName"))
                .unwrap_or_else(|| format!("Fan {member}"));

            let mut attributes = serde_json::Map::new();
            insert_attr(
                &mut attributes,
                "reading",
                fan.get("Reading")
                    .or_else(|| fan.get("ReadingRPM"))
                    .cloned(),
            );
            insert_attr(
                &mut attributes,
                "reading_units",
                fan.get("ReadingUnits").cloned(),
            );

            out.push(HardwareComponent {
                component_type: "fan",
                component_key: format!("{chassis_key}/fan/{member}"),
                name,
                health: status_health(fan),
                state: status_state(fan),
                failure_predicted: false,
                attributes,
            });
        }
    }

    if let Some(temps) = thermal_doc.get("Temperatures").and_then(|v| v.as_array()) {
        for temp in temps.iter().filter(|d| !is_absent(d)) {
            // Only sensors the BMC actually health-tracks — skip bare readings
            // so we don't flood the report with dozens of Unknown temp sensors.
            if temp
                .pointer("/Status/Health")
                .and_then(|v| v.as_str())
                .is_none()
            {
                continue;
            }
            let member = embedded_key(temp);
            let name = str_field(temp, "Name").unwrap_or_else(|| format!("Temperature {member}"));

            let mut attributes = serde_json::Map::new();
            insert_attr(
                &mut attributes,
                "reading_celsius",
                temp.get("ReadingCelsius").cloned(),
            );
            insert_attr(
                &mut attributes,
                "upper_threshold_critical",
                temp.get("UpperThresholdCritical").cloned(),
            );

            out.push(HardwareComponent {
                component_type: "temperature",
                component_key: format!("{chassis_key}/temp/{member}"),
                name,
                health: status_health(temp),
                state: status_state(temp),
                failure_predicted: false,
                attributes,
            });
        }
    }

    out
}

/// Power supplies embedded in a Chassis `Power` document.
pub(crate) fn power_components(power_doc: &Value, chassis_key: &str) -> Vec<HardwareComponent> {
    let Some(supplies) = power_doc.get("PowerSupplies").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    supplies
        .iter()
        .filter(|d| !is_absent(d))
        .map(|psu| {
            let member = embedded_key(psu);
            let name = str_field(psu, "Name").unwrap_or_else(|| format!("PSU {member}"));

            let mut attributes = serde_json::Map::new();
            insert_attr(&mut attributes, "model", psu.get("Model").cloned());
            insert_attr(
                &mut attributes,
                "line_input_voltage",
                psu.get("LineInputVoltage").cloned(),
            );
            insert_attr(
                &mut attributes,
                "power_output_watts",
                psu.get("LastPowerOutputWatts")
                    .or_else(|| psu.get("PowerOutputWatts"))
                    .cloned(),
            );

            HardwareComponent {
                component_type: "psu",
                component_key: format!("{chassis_key}/psu/{member}"),
                name,
                health: status_health(psu),
                state: status_state(psu),
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
    /// The configured endpoint, parsed once; every resource path is resolved
    /// against it and must stay on the same origin.
    base: reqwest::Url,
    /// Whether identifying attributes (drive serial numbers) are reported.
    /// Follows the hostname opt-in: identity leaves the host only when asked.
    include_identifiers: bool,
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
    fn new(config: BmcConfig, include_identifiers: bool) -> Result<Self> {
        let base = reqwest::Url::parse(&config.endpoint)
            .with_context(|| format!("BMC endpoint is not a valid URL: {}", config.endpoint))?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            anyhow::bail!(
                "BMC endpoint must be an http(s) URL with a host: {}",
                config.endpoint
            );
        }
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
        Ok(Self {
            http,
            config,
            base,
            include_identifiers,
        })
    }

    /// Resolve a Redfish `@odata.id` against the configured endpoint.
    ///
    /// The paths come out of documents the BMC sent, so they are data, not
    /// configuration. A path that resolves anywhere but the configured
    /// origin is refused: the request would carry the BMC credentials.
    fn resource_url(&self, path: &str) -> Result<reqwest::Url> {
        if !path.starts_with('/') || path.starts_with("//") {
            anyhow::bail!("BMC resource path is not an absolute path on the BMC: {path}");
        }
        let url = self
            .base
            .join(path)
            .with_context(|| format!("BMC resource path does not resolve: {path}"))?;
        let same_origin = url.scheme() == self.base.scheme()
            && url.host_str() == self.base.host_str()
            && url.port_or_known_default() == self.base.port_or_known_default();
        if !same_origin {
            anyhow::bail!("BMC resource path left the configured endpoint: {path}");
        }
        Ok(url)
    }

    fn get_json(&self, path: &str, budget: &mut RequestBudget) -> Result<Value> {
        budget.take()?;
        let url = self.resource_url(path)?;
        let response = self
            .http
            .get(url)
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
        // Bounded read: a Redfish document is kilobytes, and the BMC is on
        // the same LAN as the host, so a body that keeps coming is a fault
        // to refuse rather than buffer.
        let mut body = Vec::new();
        let mut limited = std::io::Read::take(response, MAX_BMC_BODY_BYTES + 1);
        std::io::Read::read_to_end(&mut limited, &mut body)
            .with_context(|| format!("BMC response could not be read for {path}"))?;
        if body.len() as u64 > MAX_BMC_BODY_BYTES {
            anyhow::bail!("BMC response for {path} exceeded {MAX_BMC_BODY_BYTES} bytes");
        }
        serde_json::from_slice(&body).with_context(|| format!("BMC returned non-JSON for {path}"))
    }

    /// Walk Systems → Storage → {controllers, drives, volumes}.
    fn collect_components(&self) -> Result<Vec<HardwareComponent>> {
        let mut budget = RequestBudget(MAX_BMC_REQUESTS);
        let mut components: Vec<HardwareComponent> = Vec::new();

        // Systems → overall health (+ optional Storage). Capturing the system
        // health first means OpenBMC / no-RAID / iLO4 hosts (which expose no
        // Redfish Storage) still report a meaningful signal instead of nothing.
        if let Ok(systems) = self.get_json("/redfish/v1/Systems", &mut budget) {
            for system_ref in member_refs(&systems) {
                if components.len() >= MAX_COMPONENTS {
                    break;
                }
                let Ok(system) = self.get_json(&system_ref, &mut budget) else {
                    continue;
                };
                components.extend(system_component(&system));
                self.collect_storage(&system, &mut components, &mut budget);
            }
        }

        // Chassis → Thermal (fans + temperatures) and Power (PSUs). Present on
        // iDRAC, iLO and OpenBMC even when there is no Redfish Storage, and the
        // signals operators actually alert on (a dead fan, a failed PSU).
        if let Ok(chassis_col) = self.get_json("/redfish/v1/Chassis", &mut budget) {
            for chassis_ref in member_refs(&chassis_col) {
                if components.len() >= MAX_COMPONENTS {
                    break;
                }
                let Ok(chassis) = self.get_json(&chassis_ref, &mut budget) else {
                    continue;
                };
                let chassis_key = component_key(&chassis).unwrap_or_else(|| "chassis".to_string());

                if let Some(thermal_ref) = odata_ref(chassis.get("Thermal")) {
                    if let Ok(thermal) = self.get_json(&thermal_ref, &mut budget) {
                        components.extend(thermal_components(&thermal, &chassis_key));
                    }
                }
                if let Some(power_ref) = odata_ref(chassis.get("Power")) {
                    if let Ok(power) = self.get_json(&power_ref, &mut budget) {
                        components.extend(power_components(&power, &chassis_key));
                    }
                }
            }
        }

        components.truncate(MAX_COMPONENTS);
        Ok(components)
    }

    /// Walk a `ComputerSystem`'s Storage subsystem into drive/volume/controller
    /// components. Storage is optional in Redfish, so a missing or unreadable
    /// subsystem is not an error — the caller keeps the system health it already
    /// captured.
    fn collect_storage(
        &self,
        system: &Value,
        components: &mut Vec<HardwareComponent>,
        budget: &mut RequestBudget,
    ) {
        let Some(storage_col_ref) = odata_ref(system.get("Storage")) else {
            return;
        };
        let Ok(storage_col) = self.get_json(&storage_col_ref, budget) else {
            return;
        };

        for storage_ref in member_refs(&storage_col) {
            if components.len() >= MAX_COMPONENTS {
                break;
            }
            let Ok(storage) = self.get_json(&storage_ref, budget) else {
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
                if let Ok(doc) = self.get_json(&drive_ref, budget) {
                    components.extend(drive_component(&doc, self.include_identifiers));
                }
            }

            if let Some(volumes_ref) = odata_ref(storage.get("Volumes")) {
                if let Ok(volumes) = self.get_json(&volumes_ref, budget) {
                    for volume_ref in member_refs(&volumes) {
                        if components.len() >= MAX_COMPONENTS {
                            break;
                        }
                        if let Ok(doc) = self.get_json(&volume_ref, budget) {
                            components.extend(volume_component(&doc));
                        }
                    }
                }
            }
        }
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

/// Spawn the BMC poller thread when BMC is configured (endpoint + username +
/// password via `--bmc-*` flags or `CONNLOG_BMC_*` / agent.conf). Returns
/// `None` (and stays completely inert) otherwise.
pub fn spawn_if_configured(
    stop: Arc<AtomicBool>,
    bmc_config: Option<BmcConfig>,
    platform_endpoint: String,
    token: String,
    include_identifiers: bool,
) -> Option<thread::JoinHandle<()>> {
    let config = bmc_config?;
    info!(
        "✓ BMC hardware health poller enabled (endpoint={}, interval={}s)",
        config.endpoint, config.poll_interval_secs
    );

    let handle = thread::Builder::new()
        .name("bmc-poller".to_string())
        .spawn(move || {
            run_poller(
                &stop,
                config,
                &platform_endpoint,
                token,
                include_identifiers,
            )
        })
        .ok()?;
    Some(handle)
}

fn run_poller(
    stop: &AtomicBool,
    config: BmcConfig,
    platform_endpoint: &str,
    token: String,
    include_identifiers: bool,
) {
    let interval = Duration::from_secs(config.poll_interval_secs);
    let redfish = match RedfishClient::new(config, include_identifiers) {
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
        let component = drive_component(&idrac_drive("OK", false), true).expect("drive must map");
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
    fn drive_component_omits_serial_number_unless_identifiers_are_shared() {
        let component = drive_component(&idrac_drive("OK", false), false).expect("drive must map");
        assert!(
            !component.attributes.contains_key("serial_number"),
            "serial numbers leave the host only with the system-info opt-in"
        );
        assert_eq!(
            component.attributes.get("model").and_then(|v| v.as_str()),
            Some("ST4000NM0023"),
            "non-identifying attributes are still reported"
        );
    }

    fn client_for(endpoint: &str) -> RedfishClient {
        let config = BmcConfig {
            endpoint: endpoint.to_string(),
            username: "u".to_string(),
            password: "p".to_string(),
            poll_interval_secs: 60,
            insecure_tls: false,
        };
        RedfishClient::new(config, true).expect("client")
    }

    #[test]
    fn resource_url_stays_on_the_configured_bmc() {
        let client = client_for("https://10.0.0.120");
        let url = client
            .resource_url("/redfish/v1/Systems/System.Embedded.1")
            .expect("absolute path resolves");
        assert_eq!(
            url.as_str(),
            "https://10.0.0.120/redfish/v1/Systems/System.Embedded.1"
        );
        let with_port = client_for("https://bmc.example:8443");
        assert_eq!(
            with_port.resource_url("/redfish/v1").unwrap().as_str(),
            "https://bmc.example:8443/redfish/v1"
        );
    }

    #[test]
    fn resource_url_refuses_paths_that_would_leave_the_bmc() {
        let client = client_for("https://10.0.0.120");
        for path in [
            "@evil.example/x",
            "//evil.example/redfish/v1",
            "https://evil.example/redfish/v1",
            "redfish/v1",
            "",
        ] {
            assert!(
                client.resource_url(path).is_err(),
                "{path:?} must not be fetched with BMC credentials"
            );
        }
    }

    #[test]
    fn redfish_client_rejects_endpoints_without_a_host() {
        for endpoint in ["10.0.0.120", "file:///etc/passwd", "https://"] {
            let config = BmcConfig {
                endpoint: endpoint.to_string(),
                username: "u".to_string(),
                password: "p".to_string(),
                poll_interval_secs: 60,
                insecure_tls: false,
            };
            assert!(RedfishClient::new(config, true).is_err(), "{endpoint:?}");
        }
    }

    #[test]
    fn drive_component_flags_critical_and_predicted_failure() {
        let critical = drive_component(&idrac_drive("Critical", true), true).unwrap();
        assert_eq!(critical.health, Health::Critical);
        assert!(critical.failure_predicted);

        let warning = drive_component(&idrac_drive("Warning", false), true).unwrap();
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
            drive_component(&absent, true).is_none(),
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
        assert_eq!(drive_component(&doc, true).unwrap().health, Health::Unknown);
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

    // ── system / thermal / power extraction ─────────────────────

    #[test]
    fn system_component_rolls_up_health() {
        // OpenBMC-style system: no Storage subsystem, but an overall health
        // plus CPU/RAM summaries — the signal that makes OpenBMC report at all.
        let doc = json!({
            "@odata.id": "/redfish/v1/Systems/system",
            "Id": "system",
            "Name": "OpenBMC System",
            "Manufacturer": "OpenBMC",
            "PowerState": "On",
            "ProcessorSummary": { "Status": { "Health": "OK" } },
            "MemorySummary": { "Status": { "Health": "Warning" } },
            "Status": { "Health": "Warning", "State": "Enabled" }
        });
        let c = system_component(&doc).expect("system must map");
        assert_eq!(c.component_type, "system");
        assert_eq!(c.component_key, "system/system");
        assert_eq!(c.health, Health::Warning);
        assert_eq!(c.state.as_deref(), Some("Enabled"));
        assert!(!c.failure_predicted);
        assert_eq!(
            c.attributes
                .get("memory_summary_health")
                .and_then(|v| v.as_str()),
            Some("Warning")
        );
        assert_eq!(
            c.attributes
                .get("processor_summary_health")
                .and_then(|v| v.as_str()),
            Some("OK")
        );
    }

    #[test]
    fn thermal_components_map_fans_and_health_tracked_temps() {
        let thermal = json!({
            "Fans": [
                { "MemberId": "0", "Name": "Fan 1A", "Reading": 4680, "ReadingUnits": "RPM",
                  "Status": { "Health": "OK", "State": "Enabled" } },
                { "MemberId": "1", "Name": "Fan 2A",
                  "Status": { "Health": "Critical", "State": "Enabled" } },
                { "MemberId": "9", "Name": "Fan Empty", "Status": { "State": "Absent" } }
            ],
            "Temperatures": [
                { "MemberId": "0", "Name": "Inlet Temp", "ReadingCelsius": 22,
                  "UpperThresholdCritical": 47, "Status": { "Health": "OK", "State": "Enabled" } },
                // Bare reading with no Status/Health — must be skipped as noise.
                { "MemberId": "5", "Name": "DIMM Zone", "ReadingCelsius": 30 }
            ]
        });
        let components = thermal_components(&thermal, "System.Chassis.1");
        // 2 fans (absent skipped) + 1 temperature (bare reading skipped).
        assert_eq!(components.len(), 3);

        let fan = components.iter().find(|c| c.name == "Fan 1A").unwrap();
        assert_eq!(fan.component_type, "fan");
        assert_eq!(fan.component_key, "System.Chassis.1/fan/0");
        assert_eq!(fan.health, Health::Ok);
        assert_eq!(
            fan.attributes.get("reading").and_then(|v| v.as_u64()),
            Some(4680)
        );

        assert_eq!(
            components
                .iter()
                .find(|c| c.name == "Fan 2A")
                .unwrap()
                .health,
            Health::Critical
        );

        let temp = components
            .iter()
            .find(|c| c.component_type == "temperature")
            .unwrap();
        assert_eq!(temp.name, "Inlet Temp");
        assert_eq!(temp.component_key, "System.Chassis.1/temp/0");
        assert_eq!(
            temp.attributes
                .get("reading_celsius")
                .and_then(|v| v.as_i64()),
            Some(22)
        );
        assert!(
            !components.iter().any(|c| c.name == "DIMM Zone"),
            "temperature sensors without a health status are skipped"
        );
    }

    #[test]
    fn power_components_map_supplies_and_skip_absent() {
        let power = json!({
            "PowerSupplies": [
                { "MemberId": "0", "Name": "PSU 1", "Model": "PWR-1200W", "LineInputVoltage": 230,
                  "LastPowerOutputWatts": 210, "Status": { "Health": "OK", "State": "Enabled" } },
                { "MemberId": "1", "Name": "PSU 2",
                  "Status": { "Health": "Critical", "State": "Enabled" } },
                { "MemberId": "2", "Name": "PSU 3", "Status": { "State": "Absent" } }
            ]
        });
        let components = power_components(&power, "System.Chassis.1");
        assert_eq!(components.len(), 2, "absent PSU bay skipped");
        let psu = &components[0];
        assert_eq!(psu.component_type, "psu");
        assert_eq!(psu.component_key, "System.Chassis.1/psu/0");
        assert_eq!(psu.health, Health::Ok);
        assert_eq!(
            psu.attributes.get("model").and_then(|v| v.as_str()),
            Some("PWR-1200W")
        );
        assert_eq!(components[1].health, Health::Critical);
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
            components: vec![drive_component(&idrac_drive("Critical", true), true).unwrap()],
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
