//! The network map on this host (docs/topology/PLAN.md): its settings and
//! the thread that keeps the platform's copy of the inventory current.
//!
//! Everything here is off unless the root-only `/etc/connlog/agent.conf`
//! says `CONNLOG_NETWORK_MAP=true` (guarantee 1); the platform cannot turn it
//! on, and a host with it off sends no inventory, runs no probes and says so
//! in the `X-Network-Map` header. The site name and the extra ports are
//! checked here: `install` and `config` refuse a bad value, the daemon warns
//! once and carries on as if it were absent.
//!
//! The work runs on its own thread with its own HTTP client, and the
//! heartbeat loop only ever hands it a message that cannot block: nothing
//! the map does can delay or fail a heartbeat (guarantee 5).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use log::{info, warn};

use crate::config::Config;
use crate::features::network_inventory::{self, Inventory};
use crate::features::reachability::{self, ProbeRequest, Prober, SystemProber};
use crate::http::{ApiClient, ApiError};

/// `X-Network-Map` on every heartbeat the daemon sends.
pub const NETWORK_MAP_HEADER: &str = "X-Network-Map";
pub const NETWORK_MAP_ENABLED: &str = "enabled";
pub const NETWORK_MAP_DISABLED: &str = "disabled";

/// The agent.conf keys, as `install` and `config` write them.
pub const CONF_NETWORK_MAP: &str = "CONNLOG_NETWORK_MAP";
pub const CONF_NETWORK_SITE: &str = "CONNLOG_NETWORK_SITE";
pub const CONF_NETWORK_MAP_PORTS: &str = "CONNLOG_NETWORK_MAP_PORTS";
pub const CONF_PROBE_PUBLIC: &str = "CONNLOG_PROBE_PUBLIC";

/// `SITE_NAME_MAX` and `INVENTORY_MAX_EXTRA_PORTS` in
/// `packages/agent-protocol/src/network.ts`.
pub const SITE_NAME_MAX: usize = 64;
pub const MAX_EXTRA_PORTS: usize = 16;

/// What the daemon runs with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkMapSettings {
    /// CONNLOG_NETWORK_MAP: only an explicit true.
    pub enabled: bool,
    /// CONNLOG_NETWORK_SITE, when valid.
    pub site: Option<String>,
    /// CONNLOG_NETWORK_MAP_PORTS, when valid: sorted, no duplicates.
    pub extra_ports: Vec<u16>,
    /// CONNLOG_PROBE_PUBLIC: only an explicit true.
    pub probe_public: bool,
}

impl NetworkMapSettings {
    /// The daemon's reading of its configuration. A site or port list that
    /// does not parse is warned about here, once, and left out.
    pub fn from_config(config: &Config) -> Self {
        let site = match parse_site(config.network_site.as_deref()) {
            Ok(site) => site,
            Err(e) => {
                warn!("Ignoring {CONF_NETWORK_SITE}: {e}");
                None
            }
        };
        let extra_ports = match parse_ports(config.network_map_ports.as_deref()) {
            Ok(ports) => ports,
            Err(e) => {
                warn!("Ignoring {CONF_NETWORK_MAP_PORTS}: {e}");
                Vec::new()
            }
        };
        Self {
            enabled: config.network_map_enabled(),
            site,
            extra_ports,
            probe_public: config.probe_public == Some(true),
        }
    }
}

/// What `install` and `config enable-network-map` write. `None` leaves the
/// host's existing line as it is (a reinstall keeps the host's choice).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfChoice {
    pub enabled: Option<bool>,
    pub site: Option<String>,
    pub ports: Option<Vec<u16>>,
    pub probe_public: Option<bool>,
}

impl ConfChoice {
    /// The choice the command line (or the installing shell's environment)
    /// makes. A site or port list that does not parse is an error: nothing is
    /// written.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let site = parse_site(config.network_site.as_deref())
            .map_err(|e| anyhow::anyhow!("--network-site: {e}"))?;
        let ports = parse_ports(config.network_map_ports.as_deref())
            .map_err(|e| anyhow::anyhow!("--network-map-ports: {e}"))?;
        Ok(Self {
            enabled: config.requested_network_map(),
            site,
            ports: (!ports.is_empty()).then_some(ports),
            probe_public: config.probe_public,
        })
    }

    /// Fill what this choice leaves open from an existing agent.conf, so a
    /// reinstall does not quietly turn the map off or forget the site. A
    /// value in the file that does not parse is dropped.
    pub fn or_existing(self, conf: Option<&str>) -> Self {
        let Some(conf) = conf else {
            return self;
        };
        let value = |key: &str| crate::install::conf_value(conf, key);
        Self {
            enabled: self
                .enabled
                .or_else(|| crate::install::conf_bool(conf, CONF_NETWORK_MAP)),
            site: self.site.or_else(|| {
                parse_site(value(CONF_NETWORK_SITE).as_deref())
                    .ok()
                    .flatten()
            }),
            ports: self.ports.or_else(|| {
                parse_ports(value(CONF_NETWORK_MAP_PORTS).as_deref())
                    .ok()
                    .filter(|p| !p.is_empty())
            }),
            probe_public: self
                .probe_public
                .or_else(|| crate::install::conf_bool(conf, CONF_PROBE_PUBLIC)),
        }
    }

    /// The agent.conf lines this choice writes, keys in a fixed order.
    pub fn conf_lines(&self) -> Vec<(&'static str, String)> {
        let mut lines = Vec::new();
        if let Some(enabled) = self.enabled {
            lines.push((CONF_NETWORK_MAP, enabled.to_string()));
        }
        if let Some(site) = &self.site {
            lines.push((CONF_NETWORK_SITE, site.clone()));
        }
        if let Some(ports) = &self.ports {
            lines.push((CONF_NETWORK_MAP_PORTS, format_ports(ports)));
        }
        if let Some(public) = self.probe_public {
            lines.push((CONF_PROBE_PUBLIC, public.to_string()));
        }
        lines
    }
}

/// A site name: `^[a-z0-9][a-z0-9._-]*$`, at most 64. Unset or empty is no
/// site.
pub fn parse_site(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let mut chars = value.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if !(first_ok && rest_ok) {
        return Err(format!(
            "{value:?} is not a site name: lowercase letters, digits, dots, dashes and underscores, starting with a letter or digit"
        ));
    }
    if value.len() > SITE_NAME_MAX {
        return Err(format!(
            "a site name is at most {SITE_NAME_MAX} characters, this one has {}",
            value.len()
        ));
    }
    Ok(Some(value.to_string()))
}

/// A comma list of at most 16 TCP ports, 1..65535 (`443, 8443`). Unset or
/// empty is none. Returned sorted, without duplicates.
pub fn parse_ports(raw: Option<&str>) -> Result<Vec<u16>, String> {
    let Some(value) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(Vec::new());
    };
    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
    if parts.len() > MAX_EXTRA_PORTS {
        return Err(format!(
            "at most {MAX_EXTRA_PORTS} ports, {} given",
            parts.len()
        ));
    }
    let mut ports = Vec::with_capacity(parts.len());
    for part in parts {
        match part.parse::<u16>() {
            Ok(port) if port >= 1 => ports.push(port),
            _ => {
                return Err(format!(
                "{part:?} is not a TCP port (1..65535); write ports as a comma list, e.g. 443,8443"
            ))
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// The agent.conf form of a port list: `443,8443`.
pub fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

// ── The running map: an inventory thread, off the heartbeat path ──────────

/// How often the inventory is read; it is sent only when it changed.
pub const INVENTORY_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// An unchanged inventory is sent again after this long, so the platform
/// can tell a host that is quiet from one that stopped reporting.
pub const INVENTORY_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Never two inventory uploads closer than this, whatever the platform asks.
pub const INVENTORY_MIN_GAP: Duration = Duration::from_secs(60);

pub const INVENTORY_PATH: &str = "/api/agents/inventory";

/// What became of one upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    /// The platform has it.
    Accepted,
    /// The platform answered and does not want this one (`accepted: false`,
    /// or a 4xx about the body or a route it does not have): not sent again
    /// until it changes, a day passes or the platform asks.
    Refused,
    /// Not delivered (network, 5xx, 401, 423...): tried again next time.
    Failed,
}

impl UploadOutcome {
    pub fn of(result: &Result<bool, ApiError>) -> Self {
        match result {
            Ok(true) => Self::Accepted,
            Ok(false) => Self::Refused,
            Err(ApiError::HttpError {
                status: 400 | 404 | 413 | 415 | 422,
                ..
            }) => Self::Refused,
            Err(_) => Self::Failed,
        }
    }
}

/// What the inventory thread does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    Upload,
    /// Upload, but not before this much time has passed.
    Wait(Duration),
    Nothing,
}

/// When to send the inventory: when it differs from the last one the
/// platform accepted (the first one after a start is always sent), at least
/// once a day, and whenever the platform asks; never twice within a minute.
#[derive(Debug, Default)]
pub struct InventorySchedule {
    accepted: Option<([u8; 32], Instant)>,
    refused: Option<([u8; 32], Instant)>,
    last_attempt: Option<Instant>,
}

impl InventorySchedule {
    pub fn next(&self, hash: &[u8; 32], now: Instant, requested: bool) -> Next {
        let fresh = |seen: &Option<([u8; 32], Instant)>| {
            seen.is_some_and(|(h, at)| h == *hash && now.duration_since(at) < INVENTORY_MAX_AGE)
        };
        let wanted = requested || !(fresh(&self.accepted) || fresh(&self.refused));
        if !wanted {
            return Next::Nothing;
        }
        match self.last_attempt.map(|at| now.duration_since(at)) {
            Some(since) if since < INVENTORY_MIN_GAP => Next::Wait(INVENTORY_MIN_GAP - since),
            _ => Next::Upload,
        }
    }

    pub fn record(&mut self, hash: [u8; 32], now: Instant, outcome: UploadOutcome) {
        self.last_attempt = Some(now);
        match outcome {
            UploadOutcome::Accepted => {
                self.accepted = Some((hash, now));
                self.refused = None;
            }
            UploadOutcome::Refused => self.refused = Some((hash, now)),
            UploadOutcome::Failed => {}
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Where the inventory comes from: the host, or a fixed one in tests.
pub type InventorySource = Arc<dyn Fn() -> Inventory + Send + Sync>;

/// What the map reads and probes with: the host itself, or stand-ins.
#[derive(Clone)]
pub struct Sources {
    pub inventory: InventorySource,
    pub prober: Arc<dyn Prober>,
}

impl Sources {
    pub fn system(settings: &NetworkMapSettings) -> Self {
        let site = settings.site.clone();
        let ports = settings.extra_ports.clone();
        Self {
            inventory: Arc::new(move || network_inventory::collect(site.clone(), &ports)),
            prober: Arc::new(SystemProber),
        }
    }
}

/// A failed results upload is tried once more after this; never one the
/// platform answered.
const PROBE_UPLOAD_RETRY_DELAY: Duration = Duration::from_secs(5);

/// The daemon's handle on the network map. With the host's flag off it is
/// inert: no thread, no inventory, no probe, whatever a heartbeat says.
pub struct NetworkMap {
    running: Option<Running>,
}

struct Running {
    inventory: Option<mpsc::Sender<()>>,
    probes: Option<ProbeLane>,
    started: bool,
}

/// The probe thread's inbox, and whether it is busy with a request.
struct ProbeLane {
    requests: mpsc::Sender<ProbeRequest>,
    busy: Arc<AtomicBool>,
}

impl NetworkMap {
    /// Start the map's threads when this host takes part in it; uploads go
    /// to the control plane at `base_url`.
    pub fn start(
        settings: &NetworkMapSettings,
        base_url: String,
        token: String,
        stop: Arc<AtomicBool>,
    ) -> Self {
        let sources = Sources::system(settings);
        Self::start_with(settings, base_url, token, stop, sources)
    }

    pub fn start_with(
        settings: &NetworkMapSettings,
        base_url: String,
        token: String,
        stop: Arc<AtomicBool>,
        sources: Sources,
    ) -> Self {
        if !settings.enabled {
            return Self { running: None };
        }

        let (tx, rx) = mpsc::channel();
        let (url, key, halt, source) = (
            base_url.clone(),
            token.clone(),
            Arc::clone(&stop),
            sources.inventory,
        );
        let inventory = thread::Builder::new()
            .name("network-inventory".into())
            .spawn(move || {
                let client = match ApiClient::new(url, key) {
                    Ok(client) => client,
                    Err(e) => {
                        warn!("Network map inventory is off: no HTTP client ({e})");
                        return;
                    }
                };
                inventory_loop(&client, &rx, &halt, &source);
            })
            .map_err(|e| warn!("Network map inventory is off: could not start its thread ({e})"))
            .ok()
            .map(|_| tx);

        let (tx, rx) = mpsc::channel();
        let busy = Arc::new(AtomicBool::new(false));
        let (flag, prober, allow_public) =
            (Arc::clone(&busy), sources.prober, settings.probe_public);
        let probes = thread::Builder::new()
            .name("network-probes".into())
            .spawn(move || {
                let client = match ApiClient::new(base_url, token) {
                    Ok(client) => client,
                    Err(e) => {
                        warn!("Network map probes are off: no HTTP client ({e})");
                        return;
                    }
                };
                probe_loop(&client, &rx, &stop, &flag, prober.as_ref(), allow_public);
            })
            .map_err(|e| warn!("Network map probes are off: could not start their thread ({e})"))
            .ok()
            .map(|_| ProbeLane { requests: tx, busy });

        if allow_public {
            info!("Network map probes may reach public addresses (CONNLOG_PROBE_PUBLIC=true)");
        }
        Self {
            running: Some(Running {
                inventory,
                probes,
                started: false,
            }),
        }
    }

    #[cfg(test)]
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// What an accepted heartbeat means for the map: the first one starts
    /// the inventory (the agent is known to the platform by then),
    /// `inventory_request` asks for a fresh one, and a `probe_request` is
    /// handed to the probe thread unless one is still running, in which case
    /// it is dropped. Never blocks; does nothing with the flag off.
    pub fn on_heartbeat(&mut self, inventory_request: bool, probe_request: Option<ProbeRequest>) {
        let Some(running) = self.running.as_mut() else {
            return;
        };
        if let Some(inventory) = &running.inventory {
            if !running.started || inventory_request {
                let _ = inventory.send(());
            }
        }
        running.started = true;

        let (Some(request), Some(lane)) = (probe_request, &running.probes) else {
            return;
        };
        if lane
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            info!(
                "Dropping probe request {}: the previous one is still running",
                request.id
            );
            return;
        }
        if lane.requests.send(request).is_err() {
            // The thread is gone; nothing will clear the flag but this.
            lane.busy.store(false, Ordering::SeqCst);
        }
    }
}

/// The probe thread: one request at a time, run within the caps of
/// `reachability`, and its results sent once (a delivery failure is tried
/// once more; an answer from the platform, whatever it is, is final).
fn probe_loop(
    client: &ApiClient,
    requests: &mpsc::Receiver<ProbeRequest>,
    stop: &AtomicBool,
    busy: &AtomicBool,
    prober: &dyn Prober,
    allow_public: bool,
) {
    while let Ok(request) = requests.recv() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reachability::run(&request, allow_public, prober)
        }));
        match ran {
            Ok(results) => {
                let body = results.to_json();
                for attempt in 1..=2 {
                    let result = client.upload_network(
                        reachability::PROBES_PATH,
                        reachability::CONTENT_TYPE,
                        body.clone(),
                    );
                    let retry = attempt == 1 && UploadOutcome::of(&result) == UploadOutcome::Failed;
                    match result {
                        Ok(accepted) => {
                            info!(
                                "Sent probe results for {}: {} results, {}",
                                results.id,
                                results.results.len(),
                                if accepted { "accepted" } else { "not accepted" }
                            );
                            break;
                        }
                        Err(e) if retry => {
                            warn!(
                                "Probe results upload for {} failed, trying once more: {e}",
                                results.id
                            );
                            if stop.load(Ordering::SeqCst) {
                                return;
                            }
                            thread::sleep(PROBE_UPLOAD_RETRY_DELAY);
                        }
                        Err(e) => {
                            warn!("Probe results upload for {} failed: {e}", results.id);
                            break;
                        }
                    }
                }
            }
            Err(_) => warn!("Running probe request {} panicked; dropped", request.id),
        }
        busy.store(false, Ordering::SeqCst);
    }
}

/// The inventory thread: waits for the first accepted heartbeat, then reads
/// the inventory every 15 minutes and on request, and sends it when
/// `InventorySchedule` says so. A panic while reading costs that reading.
fn inventory_loop(
    client: &ApiClient,
    wake: &mpsc::Receiver<()>,
    stop: &AtomicBool,
    source: &InventorySource,
) {
    if wake.recv().is_err() {
        return;
    }
    let mut schedule = InventorySchedule::default();
    let mut requested = true;
    loop {
        while wake.try_recv().is_ok() {}
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let mut wait = INVENTORY_INTERVAL;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| source())) {
            Ok(inventory) => {
                let body = inventory.to_json();
                let hash = sha256(&body);
                match schedule.next(&hash, Instant::now(), requested) {
                    Next::Upload => {
                        requested = false;
                        let bytes = body.len();
                        let result = client.upload_network(
                            INVENTORY_PATH,
                            network_inventory::CONTENT_TYPE,
                            body,
                        );
                        let outcome = UploadOutcome::of(&result);
                        schedule.record(hash, Instant::now(), outcome);
                        match (outcome, result) {
                            (UploadOutcome::Accepted, _) => info!(
                                "Sent the network inventory: {} addresses, {} listening ports, {bytes} bytes",
                                inventory.addresses.len(),
                                inventory.tcp_listeners.len()
                            ),
                            (_, Ok(_)) => info!("The platform did not take the network inventory"),
                            (_, Err(e)) => warn!("Network inventory upload failed: {e}"),
                        }
                    }
                    Next::Wait(delay) => wait = delay,
                    Next::Nothing => requested = false,
                }
            }
            Err(_) => warn!("Reading the network inventory panicked; trying again later"),
        }
        match wake.recv_timeout(wait) {
            Ok(()) => requested = true,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn site_names_follow_the_protocol_rule() {
        for ok in ["hq", "dc-1", "eu.west_2", "0", &"a".repeat(64)] {
            assert_eq!(parse_site(Some(ok)), Ok(Some(ok.to_string())), "{ok}");
        }
        assert_eq!(parse_site(None), Ok(None));
        assert_eq!(parse_site(Some("")), Ok(None));
        assert_eq!(parse_site(Some("  ")), Ok(None));
        assert_eq!(parse_site(Some(" hq ")), Ok(Some("hq".to_string())));
        for bad in [
            "head office",
            "HQ",
            "-hq",
            ".hq",
            "_hq",
            "hq/1",
            "hé",
            &"a".repeat(65),
        ] {
            assert!(parse_site(Some(bad)).is_err(), "{bad}");
        }
    }

    /// The protocol's own refusal: `inventory-uploads.json` "Site name with a
    /// space." can never be produced by this agent.
    #[test]
    fn the_invalid_fixture_site_is_refused() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../packages/agent-protocol/fixtures/inventory-uploads.json"
        ))
        .unwrap();
        let mut sites = 0;
        for case in fixture["invalid"].as_array().unwrap() {
            if let Some(site) = case["upload"]["site"].as_str() {
                assert!(parse_site(Some(site)).is_err(), "{site}");
                sites += 1;
            }
        }
        assert!(sites > 0);
    }

    #[test]
    fn port_lists_are_bounded_and_normalised() {
        assert_eq!(parse_ports(None), Ok(vec![]));
        assert_eq!(parse_ports(Some("")), Ok(vec![]));
        assert_eq!(parse_ports(Some("8443")), Ok(vec![8443]));
        assert_eq!(
            parse_ports(Some(" 8443 , 443,443 ")),
            Ok(vec![443, 8443]),
            "sorted, deduplicated, spaces allowed"
        );
        let sixteen = (8000..8016).map(|p| p.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_ports(Some(&sixteen.join(","))).unwrap().len(), 16);
        let seventeen = (8000..8017).map(|p| p.to_string()).collect::<Vec<_>>();
        assert!(parse_ports(Some(&seventeen.join(","))).is_err());
        for bad in [
            "0",
            "65536",
            "-1",
            "http",
            "443,,8443",
            "443;8443",
            "443 8443",
        ] {
            assert!(parse_ports(Some(bad)).is_err(), "{bad}");
        }
        assert_eq!(format_ports(&[443, 8443]), "443,8443");
    }

    #[test]
    fn the_daemon_ignores_bad_values_instead_of_failing() {
        let cfg = Config::parse_from([
            "connlog-agent",
            "--network-map",
            "true",
            "--network-site",
            "Head Office",
            "--network-map-ports",
            "0,99999",
        ]);
        let settings = NetworkMapSettings::from_config(&cfg);
        assert!(settings.enabled);
        assert_eq!(settings.site, None);
        assert!(settings.extra_ports.is_empty());
        assert!(!settings.probe_public);
    }

    #[test]
    fn install_refuses_bad_values_and_writes_good_ones() {
        let parse = |args: &[&str]| {
            ConfChoice::from_config(&Config::parse_from(
                std::iter::once("connlog-agent").chain(args.iter().copied()),
            ))
        };
        assert_eq!(parse(&["install"]).unwrap(), ConfChoice::default());
        assert!(parse(&["install", "--network-site", "Head Office"]).is_err());
        assert!(parse(&["install", "--network-map-ports", "22,0"]).is_err());

        let choice = parse(&[
            "install",
            "--enable-network-map",
            "--network-site",
            "hq",
            "--network-map-ports",
            "8443,443",
        ])
        .unwrap();
        assert_eq!(
            choice.conf_lines(),
            vec![
                (CONF_NETWORK_MAP, "true".to_string()),
                (CONF_NETWORK_SITE, "hq".to_string()),
                (CONF_NETWORK_MAP_PORTS, "443,8443".to_string()),
            ]
        );
    }

    #[test]
    fn a_reinstall_keeps_the_hosts_choice_unless_it_makes_a_new_one() {
        let conf = "CONNLOG_TOKEN=\"agent_x\"\nCONNLOG_NETWORK_MAP=\"true\"\nCONNLOG_NETWORK_SITE=\"dc-1\"\nCONNLOG_NETWORK_MAP_PORTS=\"443\"\nCONNLOG_PROBE_PUBLIC=\"false\"\n";
        let kept = ConfChoice::default().or_existing(Some(conf));
        assert_eq!(
            kept,
            ConfChoice {
                enabled: Some(true),
                site: Some("dc-1".into()),
                ports: Some(vec![443]),
                probe_public: Some(false),
            }
        );
        let changed = ConfChoice {
            site: Some("hq".into()),
            ..ConfChoice::default()
        }
        .or_existing(Some(conf));
        assert_eq!(changed.site.as_deref(), Some("hq"));
        assert_eq!(changed.enabled, Some(true));

        let broken = ConfChoice::default().or_existing(Some(
            "CONNLOG_NETWORK_SITE=\"Head Office\"\nCONNLOG_NETWORK_MAP_PORTS=\"0\"\n",
        ));
        assert_eq!(broken, ConfChoice::default());
        assert_eq!(
            ConfChoice::default().or_existing(None),
            ConfChoice::default()
        );
    }

    fn hash(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn the_first_inventory_after_a_start_is_sent() {
        let schedule = InventorySchedule::default();
        assert_eq!(schedule.next(&hash(1), Instant::now(), false), Next::Upload);
    }

    #[test]
    fn an_accepted_inventory_is_sent_again_only_when_it_changes_or_a_day_passes() {
        let start = Instant::now();
        let mut schedule = InventorySchedule::default();
        schedule.record(hash(1), start, UploadOutcome::Accepted);
        let later = start + INVENTORY_INTERVAL;
        assert_eq!(schedule.next(&hash(1), later, false), Next::Nothing);
        assert_eq!(schedule.next(&hash(2), later, false), Next::Upload);
        assert_eq!(schedule.next(&hash(1), later, true), Next::Upload, "asked");
        assert_eq!(
            schedule.next(&hash(1), start + INVENTORY_MAX_AGE, false),
            Next::Upload,
            "daily"
        );
    }

    #[test]
    fn a_failed_upload_is_tried_again_and_a_refused_one_is_not() {
        let start = Instant::now();
        let later = start + INVENTORY_INTERVAL;

        let mut failed = InventorySchedule::default();
        failed.record(hash(1), start, UploadOutcome::Failed);
        assert_eq!(failed.next(&hash(1), later, false), Next::Upload);

        let mut refused = InventorySchedule::default();
        refused.record(hash(1), start, UploadOutcome::Refused);
        assert_eq!(refused.next(&hash(1), later, false), Next::Nothing);
        assert_eq!(refused.next(&hash(2), later, false), Next::Upload);
        assert_eq!(refused.next(&hash(1), later, true), Next::Upload);
        assert_eq!(
            refused.next(&hash(1), start + INVENTORY_MAX_AGE, false),
            Next::Upload
        );
    }

    #[test]
    fn never_two_uploads_within_a_minute() {
        let start = Instant::now();
        let mut schedule = InventorySchedule::default();
        schedule.record(hash(1), start, UploadOutcome::Accepted);
        let soon = start + Duration::from_secs(20);
        assert_eq!(
            schedule.next(&hash(1), soon, true),
            Next::Wait(Duration::from_secs(40))
        );
        assert_eq!(
            schedule.next(&hash(2), soon, false),
            Next::Wait(Duration::from_secs(40))
        );
        assert_eq!(schedule.next(&hash(1), soon, false), Next::Nothing);
    }

    #[test]
    fn upload_outcomes() {
        let http = |status| {
            UploadOutcome::of(&Err(ApiError::HttpError {
                status,
                message: String::new(),
            }))
        };
        assert_eq!(UploadOutcome::of(&Ok(true)), UploadOutcome::Accepted);
        assert_eq!(UploadOutcome::of(&Ok(false)), UploadOutcome::Refused);
        for status in [400, 404, 413, 415, 422] {
            assert_eq!(http(status), UploadOutcome::Refused, "{status}");
        }
        for status in [401, 408, 409, 410, 423, 429, 500, 503] {
            assert_eq!(http(status), UploadOutcome::Failed, "{status}");
        }
    }

    #[test]
    fn with_the_flag_off_nothing_runs() {
        let mut map = NetworkMap::start(
            &NetworkMapSettings::default(),
            "http://127.0.0.1:9".into(),
            "agent_x".into(),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(!map.is_running());
        map.on_heartbeat(true, None);
    }

    #[test]
    fn everything_is_off_unless_set_to_true() {
        let settings = NetworkMapSettings::from_config(&Config::parse_from(["connlog-agent"]));
        assert_eq!(settings, NetworkMapSettings::default());

        for (value, on) in [("true", true), ("1", true), ("false", false), ("0", false)] {
            let cfg = Config::parse_from([
                "connlog-agent",
                "--network-map",
                value,
                "--probe-public",
                value,
            ]);
            let settings = NetworkMapSettings::from_config(&cfg);
            assert_eq!(settings.enabled, on, "{value}");
            assert_eq!(settings.probe_public, on, "{value}");
        }
    }
}
