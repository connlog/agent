use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── Core plumbing (crate root) ──────────────────────────────────
// The minimum an agent needs to authenticate, resolve where to send
// heartbeats, speak the wire protocol, and transport them.
mod config;
mod defaults;
mod endpoint_assignment;
mod heartbeat;
mod http;
mod identity;

// ── OS integration (already grouped by directory) ───────────────
mod install;
mod platform;

// ── Optional bolt-on capabilities ────────────────────────────────
mod features;

// ── Self-update subsystem (isolated on purpose — see src/update/mod.rs) ──
mod update;

#[cfg(test)]
mod simulation;

use config::{AgentCommand, Config, DiagnosticCommand, LocalConfigCommand};
use defaults::{CONFIG_FETCH_RETRY_DELAY_SECS, DEFAULT_ENDPOINT, DISABLED_BACKOFF_SECS};
use endpoint_assignment::EndpointAssignmentState;
use features::action_cli::run_action_command;
use features::flight_recorder;
use features::heartbeat_telemetry::HeartbeatTelemetry;
use features::metrics::MetricsCollector;
use features::quick_actions::{QuickActionRequest, QuickActionsRegistry};
use features::remote_reboot::{self, RebootReport, RebootState};
use heartbeat::{
    AgentConfig, HeartbeatPayload, QuickActionsConfig, HEARTBEAT_EARLIEST_GAP_PERMILLE,
    HEARTBEAT_JITTER_PCT,
};
use http::{ApiClient, ApiError, QuickActionPollingReport};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Wire protocol version. v1 = 32-byte little-endian binary frame over
/// `application/octet-stream`; identity metadata travels in `X-*` headers.
/// There is intentionally no JSON fallback — both ends speak binary only.
const PROTOCOL_VERSION: u32 = 1;

/// After this many consecutive 401s the agent logs an error (and again every
/// multiple of it). It never uninstalls on 401: only a 410 or an explicit
/// uninstall request from the platform removes files.
const MAX_UNAUTHORIZED_ATTEMPTS: u32 = 50;

/// Consecutive uninstall commands required from server before acting
const UNINSTALL_CONFIRM_THRESHOLD: u32 = 3;

/// Consecutive reboot commands required from server before acting
const REBOOT_CONFIRM_THRESHOLD: u32 = 3;

/// Remote command execution is not a product capability.
const REMOTE_CONTROL_ENABLED: bool = false;

/// Maximum config fetch failures before using fallback
const MAX_CONFIG_FETCH_RETRIES: u32 = 3;

/// Quick-action poll jitter, ±10%. A 5s interval becomes roughly 4.5s..5.5s,
/// enough to spread fleet polling without making dashboard pickup feel slow.
const QUICK_ACTION_POLL_JITTER_PCT: u64 = 10;

/// Initialise the logger with a structured, grep-friendly line format:
///
///     <ISO-8601> level=info component=heartbeat <message>
///
/// `component=` is derived from the log target (`module_path!()`), trimmed to
/// the last segment so `connlog_agent::http` becomes `component=http`. This
/// keeps `journalctl -u connlog-agent | grep component=http` working without
/// adding any logging dependency.
fn init_logger() {
    use std::io::Write;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let ts = buf.timestamp();
            let target = record.target();
            let component = target.rsplit("::").next().unwrap_or(target);
            writeln!(
                buf,
                "{ts} level={level} component={component} {msg}",
                level = record.level().to_string().to_lowercase(),
                msg = record.args(),
            )
        })
        .init();
}

/// Apply +0..=`HEARTBEAT_JITTER_PCT`% jitter to the heartbeat interval.
/// Uniform over [secs, secs + 10%] — spreading the herd does not need
/// negative offsets, and never undershooting the interval keeps the agent
/// clear of the platform's minimum-interval limiter. Source of entropy is
/// `SystemTime` nanos — no `rand` dependency required, no cryptographic
/// strength needed (we only want to spread the herd).
fn jittered(secs: u64) -> u64 {
    if secs == 0 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let span = (secs * HEARTBEAT_JITTER_PCT) / 100;
    if span == 0 {
        return secs;
    }
    secs + (nanos % (span + 1))
}

/// Sleep needed after a completed heartbeat cycle so the *next* heartbeat
/// fires one jittered interval after the cycle STARTED (fixed cadence).
/// Sleeping a full interval measured from completion — the old behavior —
/// let request time and post-heartbeat work (config fetches, quick actions)
/// stretch every gap past the interval, eating into the platform's offline
/// threshold on every single beat.
///
/// The result is floored at 90% of the interval so a slow cycle can never
/// compress the wire gap below the platform's minimum-interval grace
/// (heartbeats arriving faster than 0.9 × the plan minimum draw a 429).
fn next_heartbeat_sleep(interval_secs: u64, cycle_elapsed: Duration) -> Duration {
    let target = Duration::from_secs(jittered(interval_secs));
    let floor =
        Duration::from_millis(interval_secs.saturating_mul(HEARTBEAT_EARLIEST_GAP_PERMILLE));
    target.saturating_sub(cycle_elapsed).max(floor)
}

fn jittered_duration(base: Duration, pct: u64) -> Duration {
    if base.is_zero() || pct == 0 {
        return base;
    }

    let base_ms = base.as_millis();
    let span = (base_ms * pct as u128) / 100;
    if span == 0 {
        return base;
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u128)
        .unwrap_or(0);
    let offset = (nanos % (2 * span + 1)) as i128 - span as i128;
    let jittered_ms = (base_ms as i128 + offset).max(1) as u64;
    Duration::from_millis(jittered_ms)
}

fn unix_ms(time: SystemTime) -> Option<u128> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis())
}

#[derive(Debug, Clone)]
struct QuickActionPollState {
    enabled: bool,
    interval_secs: u64,
    last_poll_at: Option<SystemTime>,
    next_poll_at: Option<SystemTime>,
    next_due: Option<Instant>,
}

impl QuickActionPollState {
    fn new(config: &QuickActionsConfig, registry: &QuickActionsRegistry) -> Self {
        let mut state = Self {
            enabled: false,
            interval_secs: config.poll_interval_seconds,
            last_poll_at: None,
            next_poll_at: None,
            next_due: None,
        };
        state.sync(config, registry);
        state
    }

    fn sync(&mut self, config: &QuickActionsConfig, registry: &QuickActionsRegistry) {
        let next_enabled = config.enabled && registry.has_enabled_actions();
        let next_interval_secs = config.poll_interval_seconds;
        let changed = self.enabled != next_enabled || self.interval_secs != next_interval_secs;
        let was_enabled = self.enabled;

        self.enabled = next_enabled;
        self.interval_secs = next_interval_secs;

        if !self.enabled {
            self.next_due = None;
            self.next_poll_at = None;
        } else if !was_enabled || changed || self.next_due.is_none() {
            self.schedule_next(Instant::now(), SystemTime::now());
        }

        if changed {
            if self.enabled {
                info!(
                    "Quick action polling enabled (interval={}s)",
                    self.interval_secs
                );
            } else if config.enabled {
                info!("Quick action polling disabled (no enabled local actions)");
            } else {
                info!("Quick action polling disabled by platform config");
            }
        }
    }

    fn due(&self, now: Instant) -> bool {
        self.enabled
            && self
                .next_due
                .map(|next_due| now >= next_due)
                .unwrap_or(false)
    }

    fn next_due(&self) -> Option<Instant> {
        self.next_due
    }

    fn mark_poll_started(&mut self) -> QuickActionPollingReport {
        let now_instant = Instant::now();
        let now_wall = SystemTime::now();
        self.last_poll_at = Some(now_wall);
        self.schedule_next(now_instant, now_wall);
        self.report()
    }

    fn report(&self) -> QuickActionPollingReport {
        QuickActionPollingReport {
            enabled: self.enabled,
            poll_interval_seconds: self.interval_secs,
            last_poll_at_unix_ms: self.last_poll_at.and_then(unix_ms),
            next_poll_at_unix_ms: self.next_poll_at.and_then(unix_ms),
        }
    }

    fn schedule_next(&mut self, from_instant: Instant, from_wall: SystemTime) {
        let wait = jittered_duration(
            Duration::from_secs(self.interval_secs),
            QUICK_ACTION_POLL_JITTER_PCT,
        );
        self.next_due = Some(from_instant + wait);
        self.next_poll_at = from_wall.checked_add(wait);
    }
}

/// Validate that a bearer token has the `agent_` prefix the platform requires.
///
/// Three call sites used to inline this check with three slightly-different
/// error messages. Centralising it removes the drift hazard and gives both
/// the daemon and the diagnostic CLI paths a single place to evolve the
/// prefix rules from.
fn validate_token_prefix(token: &str) -> Result<()> {
    if !token.starts_with("agent_") {
        anyhow::bail!("Invalid token format — must start with 'agent_'");
    }
    Ok(())
}

fn main() -> Result<()> {
    init_logger();

    // A person typing `connlog-agent` in a terminal gets the menu; systemd
    // (no terminal, INVOCATION_ID set) and every argument get what they
    // always did. The rule is `features::menu::opens_menu`.
    if features::menu::opens_menu(&features::menu::Launch::current()) {
        return features::menu::run();
    }

    let config = Config::parse();

    // Handle --emit-service (used by ExecStopPost during self-update on Linux)
    if config.emit_service {
        print!("{}", install::SYSTEMD_SERVICE);
        return Ok(());
    }

    if let Some(command) = config.command.clone() {
        match command {
            AgentCommand::Register => {}
            AgentCommand::Install => {
                let token = config.token.clone().context("Token required for install")?;
                let bmc = features::bmc::BmcConfig::from_config(&config);
                let network_map = features::network_map::ConfChoice::from_config(&config)?;
                return install::install(
                    &token,
                    bmc.as_ref(),
                    config.expose_system_info,
                    config.requested_remote_reboot(),
                    &network_map,
                );
            }
            AgentCommand::Uninstall => return install::uninstall(),
            AgentCommand::Status => return install::status(),
            AgentCommand::RefreshService { restart } => return install::refresh_service(restart),
            AgentCommand::Config { command } => match command {
                LocalConfigCommand::EnableHostname => return install::set_hostname_sharing(true),
                LocalConfigCommand::DisableHostname => return install::set_hostname_sharing(false),
                LocalConfigCommand::DisableRemoteReboot => {
                    return install::set_remote_reboot(false)
                }
                LocalConfigCommand::EnableRemoteReboot => return install::set_remote_reboot(true),
                LocalConfigCommand::EnablePostmortem => {
                    return install::set_postmortem_sharing(true)
                }
                LocalConfigCommand::DisablePostmortem => {
                    return install::set_postmortem_sharing(false);
                }
                LocalConfigCommand::EnableNetworkMap => {
                    let choice = features::network_map::ConfChoice {
                        enabled: Some(true),
                        ..features::network_map::ConfChoice::from_config(&config)?
                    };
                    return install::set_network_map(&choice);
                }
                LocalConfigCommand::DisableNetworkMap => {
                    return install::set_network_map(&features::network_map::ConfChoice {
                        enabled: Some(false),
                        ..Default::default()
                    });
                }
            },
            AgentCommand::Update => return update::run_manual_update(),
            AgentCommand::ApplyStagedUpdate => return update::apply_staged_update(),
            AgentCommand::CollectPostmortem => {
                return features::postmortem::run_collect(config.share_postmortem);
            }
            AgentCommand::CheckConfig => {
                let token = config
                    .token
                    .clone()
                    .context("Token required for check-config")?;
                let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);
                return run_check_config(token, endpoint);
            }
            AgentCommand::TestHeartbeat => {
                let token = config
                    .token
                    .clone()
                    .context("Token required for test-heartbeat")?;
                let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);
                return run_test_heartbeat(token, endpoint);
            }
            AgentCommand::Action { command } => return run_action_command(command),
            AgentCommand::Diagnostics { command } => match command {
                DiagnosticCommand::CheckConfig => {
                    let token = config
                        .token
                        .clone()
                        .context("Token required for diagnostics check-config")?;
                    let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);
                    return run_check_config(token, endpoint);
                }
                DiagnosticCommand::TestHeartbeat => {
                    let token = config
                        .token
                        .clone()
                        .context("Token required for diagnostics test-heartbeat")?;
                    let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);
                    return run_test_heartbeat(token, endpoint);
                }
                DiagnosticCommand::Service => return install::print_service_diagnostics(),
                DiagnosticCommand::Heartbeats {
                    since,
                    limit,
                    format,
                } => {
                    // Local-only diagnostics: no token, no network, no root, no
                    // service mutation. Reads the bounded telemetry store the
                    // running agent wrote.
                    return features::heartbeat_telemetry::run_diagnostics_cli(
                        &since, limit, format,
                    );
                }
                DiagnosticCommand::History {
                    since,
                    limit,
                    format,
                } => {
                    // Local-only, like `heartbeats`: reads the flight ring.
                    return flight_recorder::history::run_history_cli(&since, limit, format);
                }
            },
        }
    }

    // Handle status check
    if config.status {
        return install::status();
    }

    // Handle manual update
    if config.update {
        return update::run_manual_update();
    }

    // Diagnostic commands — both require a token but never start the heartbeat
    // loop. They make running `connlog-agent check-config` or
    // `test-heartbeat` from a shell a fast way to confirm an install before
    // declaring it healthy.
    if config.check_config {
        let token = config
            .token
            .clone()
            .context("Token required for --check-config")?;
        let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);
        return run_check_config(token, endpoint);
    }

    if config.test_heartbeat {
        let token = config
            .token
            .clone()
            .context("Token required for --test-heartbeat")?;
        let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);
        return run_test_heartbeat(token, endpoint);
    }

    // Handle uninstallation
    if config.uninstall {
        return install::uninstall();
    }

    // Handle installation
    if config.install {
        let token = config
            .token
            .clone()
            .context("Token required for installation")?;
        let bmc = features::bmc::BmcConfig::from_config(&config);
        let network_map = features::network_map::ConfChoice::from_config(&config)?;
        return install::install(
            &token,
            bmc.as_ref(),
            config.expose_system_info,
            config.requested_remote_reboot(),
            &network_map,
        );
    }

    // Run mode - require token
    let token = config.token.clone().context(
        "Token is required. Use `connlog-agent register --token <token>` or set CONNLOG_TOKEN.",
    )?;

    let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);
    let expose_system_info = config.expose_system_info;
    let allow_remote_reboot = config.remote_reboot_allowed();
    // Resolve BMC config here (where the parsed Config is in scope). None ->
    // the poller stays inert.
    let bmc_config = features::bmc::BmcConfig::from_config(&config);
    let host_settings = http::HostSettings {
        bmc: bmc_config.is_some(),
        hostname: expose_system_info,
        postmortem: config.share_postmortem,
    };
    // Bad site or port values are warned about here, once, and left out.
    let network_map = features::network_map::NetworkMapSettings::from_config(&config);

    // A service stop (or the host shutting down) sets `stop` instead of
    // killing the process, so the loop ends where it is and exits 0.
    let stop = Arc::new(AtomicBool::new(false));
    if !platform::signals::install_stop_handlers(&stop) {
        warn!("Could not install SIGTERM/SIGINT handlers; a stop will kill the agent");
    }

    run_agent_with_shutdown_inner(
        token,
        endpoint,
        expose_system_info,
        allow_remote_reboot,
        host_settings,
        network_map,
        bmc_config,
        stop,
    )
}

// One call site (`main`), each argument a setting it has already read.
#[allow(clippy::too_many_arguments)]
fn run_agent_with_shutdown_inner(
    token: String,
    endpoint: String,
    expose_system_info: bool,
    allow_remote_reboot: bool,
    host_settings: http::HostSettings,
    network_map: features::network_map::NetworkMapSettings,
    bmc_config: Option<features::bmc::BmcConfig>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    info!("ConnLog Agent v{} starting", AGENT_VERSION);
    install::warn_if_installed_service_stale_once();

    #[cfg(debug_assertions)]
    info!("Endpoint: {} (debug build)", endpoint);

    #[cfg(not(debug_assertions))]
    info!("Endpoint: {}", endpoint);

    // Validate token format
    if let Err(e) = validate_token_prefix(&token) {
        error!("{e}");
        std::process::exit(1);
    }

    let mut endpoint_assignment = EndpointAssignmentState::new(&endpoint);
    info!(
        "Heartbeat endpoint: {} (assignment refreshed at most every {}h, or sooner on repeated failures)",
        endpoint_assignment.resolve_heartbeat_endpoint(),
        endpoint_assignment::DEFAULT_REGION_CHECK_INTERVAL_SECS / 3600,
    );

    // Optional BMC hardware-health poller (iDRAC/iLO via Redfish). Inert
    // unless CONNLOG_BMC_* is configured; runs on its own thread with its own
    // HTTP clients so it can never delay a heartbeat. Reports go to the base
    // platform endpoint (not the regional heartbeat endpoint).
    let _bmc_poller = features::bmc::spawn_if_configured(
        Arc::clone(&stop),
        bmc_config,
        endpoint.clone(),
        token.clone(),
        expose_system_info,
    );

    // The network map: inert unless CONNLOG_NETWORK_MAP=true. Its own
    // thread and HTTP client, like the BMC poller, so an inventory or probe
    // problem can never delay a heartbeat.
    let mut network = features::network_map::NetworkMap::start(
        &network_map,
        endpoint.clone(),
        token.clone(),
        Arc::clone(&stop),
    );

    let mut client = ApiClient::new(endpoint, token).context("Failed to initialize HTTP client")?;

    // Attach the heartbeat delivery telemetry store. Best-effort and isolated:
    // a missing/unwritable state directory degrades into no-op recording and
    // never affects heartbeat delivery. The store powers
    // `connlog-agent diagnostics heartbeats`.
    let telemetry = HeartbeatTelemetry::open_default();
    info!(
        target: features::heartbeat_telemetry::HB_LOG_TARGET,
        "Heartbeat diagnostics telemetry at {}",
        telemetry.log_path().display()
    );
    client.set_telemetry(telemetry);
    client.set_remote_reboot_allowed(allow_remote_reboot);
    client.set_host_settings(host_settings);
    client.set_network_map_enabled(network_map.enabled);
    if !network_map.enabled {
        info!(
            "Network map is off on this host; `sudo connlog-agent config enable-network-map` joins it"
        );
    }
    if !allow_remote_reboot {
        info!(
            "Remote reboot is off on this host; `sudo connlog-agent config enable-remote-reboot` allows it"
        );
    }

    // A reboot this agent handed to systemd before it last exited: say what
    // became of it on the next heartbeats.
    let state_dir = features::heartbeat_telemetry::default_state_dir();
    let boot_id = identity::boot_id();
    if let Some(report) = remote_reboot::take_attempt_outcome(
        &state_dir,
        boot_id.as_deref(),
        remote_reboot::system_uptime_secs(),
    ) {
        info!(
            "REBOOT: previous remote reboot {}: {}",
            report.state.as_str(),
            report.message.as_deref().unwrap_or("")
        );
        client.set_reboot_report(Some(report));
    }

    // The flight recorder: one record a minute to a fixed ring on disk, on
    // its own thread, whether or not the platform answers. The guard records
    // the clean stop when the loop ends on SIGTERM.
    let heartbeat_failing = Arc::new(AtomicBool::new(false));
    let recorder = flight_recorder::Recorder::open(&state_dir, boot_id.as_deref());
    let _stop_record = StopRecordGuard {
        sampler: recorder.as_ref().and_then(|r| {
            flight_recorder::spawn_sampler(
                r.clone(),
                Arc::clone(&stop),
                Arc::clone(&heartbeat_failing),
            )
        }),
        recorder: recorder.clone(),
        stop: Arc::clone(&stop),
    };

    // Initialize reusable metrics collector (avoids re-creating sysinfo each heartbeat)
    let mut collector =
        MetricsCollector::new().context("Failed to initialize metrics collector")?;
    info!("✓ Metrics collector initialized");

    // Fetch runtime config from server with retry logic
    info!("Fetching runtime configuration...");
    let mut config = fetch_config_with_retry(&client);
    config.clamp();
    // One heartbeat cycle (attempts + retry delays) must fit inside the
    // interval, or in-cycle retries against a hung connection keep the
    // platform's lastHeartbeatAt stale past the offline threshold.
    client.set_heartbeat_cycle_budget(Duration::from_secs(config.heartbeat_interval_secs));

    info!(
        "✓ Loaded config v{} (interval={}s, missed_threshold={})",
        config.version, config.heartbeat_interval_secs, config.missed_threshold
    );

    if config.version == 0 {
        warn!("Using fallback config - will retry fetching real config on next heartbeat");
    }

    let mut quick_actions = QuickActionsRegistry::load();
    let mut quick_actions_fingerprint = quick_actions.fingerprint();
    // The manifest is what the dashboard would run; while remote control is
    // compiled out there is nothing for it to do, and no reason to send
    // operator-authored action names anywhere.
    if REMOTE_CONTROL_ENABLED {
        publish_quick_actions_manifest(&client, &quick_actions);
    }
    let mut quick_action_polling = QuickActionPollState::new(&config.quick_actions, &quick_actions);

    let mut first_heartbeat = true;
    let mut consecutive_unauthorized = 0u32;
    let mut consecutive_errors = 0u32;
    let mut consecutive_uninstall_commands = 0u32;
    let mut consecutive_reboot_commands = 0u32;
    let mut reboot_refusal_logged = false;
    let mut history_answers = HistoryAnswers::default();

    // ── Update strategy ──────────────────────────────────────────
    //
    // Updates are delivered exclusively via the platform heartbeat response
    // (`response.update`). The platform does its own cached check against the
    // upstream release source and proxies the binary/signature/sha256 from an
    // in-house URL, so:
    //   - the agent never talks to api.github.com
    //   - a fleet of N agents produces O(1) upstream traffic, not O(N)
    //   - all artifact fetches go to a single TLS-pinned platform domain
    //
    // Ed25519 + SHA-256 verification is unchanged: the agent still verifies
    // the signed hash against its compiled-in public key, so the platform
    // proxy is untrusted by design.

    // Main loop
    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Shutdown requested (service stop) — exiting agent loop");
            return Ok(());
        }

        // Cadence anchor: the next heartbeat is scheduled one jittered
        // interval from HERE, not from wherever this cycle's request and
        // post-heartbeat work happen to finish (see `next_heartbeat_sleep`).
        let cycle_started = Instant::now();

        // V1 endpoint assignment: cheap no-op unless a refresh is actually
        // due (first run, ~24h elapsed, or repeated heartbeat failures —
        // see `EndpointAssignmentState::needs_refresh`). Repoints
        // `client`'s heartbeat target in place via `set_heartbeat_endpoint`.
        endpoint_assignment.refresh_if_needed(&client, cfg!(debug_assertions));

        let outcome = send_heartbeat(
            &client,
            &config,
            &mut collector,
            Some(&quick_action_polling),
            expose_system_info,
        );
        heartbeat_failing.store(outcome.is_err(), Ordering::SeqCst);
        match outcome {
            Ok(response) => {
                // The platform has the reboot report this heartbeat carried.
                client.set_reboot_report(None);

                // Reset error counters on success
                consecutive_unauthorized = 0;
                consecutive_errors = 0;
                endpoint_assignment.note_heartbeat_outcome(true);

                if first_heartbeat {
                    info!("✓ Successfully registered with ConnLog");
                    first_heartbeat = false;
                }

                // Check for remote uninstall command (require consecutive confirmations)
                if response.uninstall {
                    consecutive_uninstall_commands += 1;
                    consecutive_reboot_commands = 0;
                    warn!(
                        "Received remote uninstall command ({}/{})",
                        consecutive_uninstall_commands, UNINSTALL_CONFIRM_THRESHOLD
                    );
                    if consecutive_uninstall_commands >= UNINSTALL_CONFIRM_THRESHOLD {
                        warn!(
                            "Uninstall confirmed after {} consecutive commands",
                            UNINSTALL_CONFIRM_THRESHOLD
                        );
                        trigger_self_uninstall("Remote uninstall confirmed by workspace owner");
                        return Ok(());
                    }
                } else {
                    // Reset if server stops requesting uninstall
                    consecutive_uninstall_commands = 0;
                }

                // Remote host reboot (require consecutive confirmations). Uninstall
                // takes precedence when both flags are present. A host that
                // refuses remote reboot never counts a request at all.
                if !response.uninstall && response.reboot && !allow_remote_reboot {
                    if !reboot_refusal_logged {
                        warn!(
                            "Refusing remote reboot request: remote reboot is off on this host (CONNLOG_ALLOW_REMOTE_REBOOT is not true)"
                        );
                        client.set_reboot_report(Some(RebootReport::new(
                            RebootState::RefusedDisabled,
                            "Remote reboot is off on this host (CONNLOG_ALLOW_REMOTE_REBOOT is not true)",
                        )));
                        reboot_refusal_logged = true;
                    }
                } else if !response.uninstall && response.reboot {
                    consecutive_reboot_commands += 1;
                    warn!(
                        "Received remote reboot command ({}/{})",
                        consecutive_reboot_commands, REBOOT_CONFIRM_THRESHOLD
                    );
                    if consecutive_reboot_commands >= REBOOT_CONFIRM_THRESHOLD {
                        warn!(
                            "Reboot confirmed after {} consecutive commands",
                            REBOOT_CONFIRM_THRESHOLD
                        );
                        // Returns only when the reboot could not be handed
                        // to systemd; the platform hears why and stops asking.
                        let report = trigger_host_reboot(
                            "Remote reboot confirmed by workspace owner",
                            &state_dir,
                            boot_id.as_deref(),
                            recorder.as_ref(),
                        );
                        client.set_reboot_report(Some(report));
                        consecutive_reboot_commands = 0;
                    }
                } else if !response.reboot {
                    consecutive_reboot_commands = 0;
                    reboot_refusal_logged = false;
                }

                // Check for available update
                if let Some(ref update_info) = response.update {
                    info!(
                        "UPDATE CHECK: current=v{} latest=v{} available={} has_download={} has_sig={} has_sha256={}",
                        AGENT_VERSION,
                        update_info.latest_version,
                        update_info.available,
                        update_info.download_url.is_some(),
                        update_info.signature_url.is_some(),
                        update_info.sha256.is_some(),
                    );
                    match update::try_apply_update(update_info) {
                        Ok(true) => {
                            info!(
                                "Update to v{} staged successfully. Restarting for update...",
                                update_info.latest_version
                            );
                            if let Some(recorder) = &recorder {
                                recorder.record_stop(flight_recorder::ring::FLAG_EXIT_UPDATE);
                            }
                            // Exit cleanly - ExecStopPost will swap the binary,
                            // refresh the service file, and restart us.
                            std::process::exit(0);
                        }
                        Ok(false) => {
                            info!(
                                "UPDATE SKIPPED: v{} (see preceding log for reason)",
                                update_info.latest_version
                            );
                        }
                        Err(e) => {
                            error!(
                                "Update to v{} failed: {}. Continuing with current version.",
                                update_info.latest_version, e
                            );
                        }
                    }
                } else {
                    info!("UPDATE CHECK: server returned no update info");
                }

                // Check if config is outdated
                if response.config_outdated {
                    info!(
                        "Config outdated (current: v{}, latest: v{}), fetching update...",
                        config.version,
                        response.latest_config_version.unwrap_or(0)
                    );
                    match client.fetch_config() {
                        Ok(new_config) => {
                            let mut new_config = new_config;
                            new_config.clamp();
                            log_config_change(&config, &new_config);
                            config = new_config;
                            client.set_heartbeat_cycle_budget(Duration::from_secs(
                                config.heartbeat_interval_secs,
                            ));
                            quick_action_polling.sync(&config.quick_actions, &quick_actions);
                        }
                        Err(e) => {
                            error!("Failed to fetch updated config: {}", e);
                            // Continue with old config - it still works
                        }
                    }
                }

                // After an outage the platform asks what the flight recorder
                // saw. Answered once per window, at most three tries each;
                // never allowed to cost more than this cycle's request.
                if let Some(request) = response.history_request {
                    answer_history_request(
                        &client,
                        &config,
                        &state_dir,
                        request,
                        &mut history_answers,
                    );
                }

                // The network map: never blocks, does nothing with the flag off.
                network.on_heartbeat(response.inventory_request, response.probe_request);

                // Monitoring-only: do not execute dashboard-triggered commands.
                if !response.quick_actions.is_empty() {
                    warn!(
                        "Ignoring {} remote action request(s) — ConnLog does not execute remote commands",
                        response.quick_actions.len()
                    );
                }

                info!(
                    "Heartbeat sent successfully, next in {}s",
                    config.heartbeat_interval_secs
                );
                if sleep_with_quick_action_polling(
                    &stop,
                    next_heartbeat_sleep(config.heartbeat_interval_secs, cycle_started.elapsed()),
                    &client,
                    &mut quick_actions,
                    &mut quick_actions_fingerprint,
                    &config.quick_actions,
                    &mut quick_action_polling,
                )
                .is_err()
                {
                    return Ok(());
                }
            }
            Err(ApiError::Unauthorized) => {
                consecutive_unauthorized += 1;
                warn!(
                    "Unauthorized (401) - attempt {}/{}",
                    consecutive_unauthorized, MAX_UNAUTHORIZED_ATTEMPTS
                );

                // A rejected token is never a reason to delete the install. A
                // platform-side auth regression that answered 401 for an hour
                // would otherwise have wiped every agent in the fleet; a token
                // the owner really revoked answers 410 and is handled below.
                // Keep the files, keep retrying at the capped backoff, and say
                // so loudly at intervals.
                if consecutive_unauthorized >= MAX_UNAUTHORIZED_ATTEMPTS
                    && consecutive_unauthorized.is_multiple_of(MAX_UNAUTHORIZED_ATTEMPTS)
                {
                    error!(
                        "Token rejected {} consecutive times. The install is kept; if the token \
                         was rotated, run: sudo CONNLOG_TOKEN=<new token> connlog-agent install",
                        consecutive_unauthorized
                    );
                }

                // Linear backoff for unauthorized — start at 30 s, ramp by 10 s per
                // attempt, cap at 120 s. A 401 is cheap on the server (the token
                // lookup is indexed, no work done), so there's no reason to back
                // off for hours; we just want enough spacing to absorb a brief
                // platform glitch.
                let backoff = std::cmp::min(30 + 10 * consecutive_unauthorized as u64, 120);
                if interruptible_sleep(&stop, backoff).is_err() {
                    return Ok(());
                }
            }
            Err(ApiError::Decommissioned) => {
                warn!("Agent has been decommissioned (410 Gone). Self-uninstalling...");
                trigger_self_uninstall("Agent was decommissioned by the server");
                return Ok(());
            }
            Err(ApiError::Disabled) => {
                // 423 Locked: the agent has been DISABLED in ConnLog.
                // This is reversible — the user (or downgrade flow) can re-enable
                // the agent at any time. We must NOT self-uninstall, must NOT
                // touch the install on disk, and must NOT spam the server.
                //
                // Strategy: long fixed backoff (5 min) regardless of the
                // configured heartbeat interval, until the server starts
                // accepting heartbeats again. We also reset the unauthorized
                // counter so re-enable doesn't immediately trip self-uninstall.
                consecutive_unauthorized = 0;
                consecutive_errors = 0;
                warn!(
                    "Agent is disabled in ConnLog (423 Locked). Backing off for {}s before checking again. Re-enable from the dashboard.",
                    DISABLED_BACKOFF_SECS
                );
                if interruptible_sleep(&stop, DISABLED_BACKOFF_SECS).is_err() {
                    return Ok(());
                }
            }
            Err(e) => {
                consecutive_errors += 1;
                // Transport-level failure (network/HTTP) — the heartbeat
                // *endpoint* may be unreachable, so this (unlike Unauthorized/
                // Decommissioned/Disabled, which are account-level) counts
                // toward forcing a fresh endpoint assignment.
                endpoint_assignment.note_heartbeat_outcome(false);
                let backoff = heartbeat_error_backoff_secs(
                    &e,
                    consecutive_errors,
                    config.heartbeat_interval_secs,
                );
                error!("Heartbeat failed: {} (retry in {}s)", e, backoff);
                if interruptible_sleep(&stop, backoff).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod heartbeat_backoff_tests {
    use super::{heartbeat_error_backoff_secs, ApiError};

    #[test]
    fn transient_errors_stay_near_heartbeat_interval() {
        let err = ApiError::HttpError {
            status: 502,
            message: "bad gateway".into(),
        };
        assert_eq!(heartbeat_error_backoff_secs(&err, 1, 10), 10);
        assert_eq!(heartbeat_error_backoff_secs(&err, 2, 10), 20);
    }

    #[test]
    fn server_errors_are_transient() {
        // A platform 500 (e.g. transient DB error) must not trigger the 30s
        // exponential backoff: on a 10s-interval agent that single response
        // would exceed the offline threshold and flap the agent.
        let err = ApiError::HttpError {
            status: 500,
            message: "server error".into(),
        };
        assert_eq!(heartbeat_error_backoff_secs(&err, 1, 10), 10);
        assert_eq!(heartbeat_error_backoff_secs(&err, 2, 10), 20);
    }

    #[test]
    fn non_transient_errors_use_exponential_backoff() {
        let err = ApiError::HttpError {
            status: 400,
            message: "bad request".into(),
        };
        assert_eq!(heartbeat_error_backoff_secs(&err, 1, 10), 30);
        assert_eq!(heartbeat_error_backoff_secs(&err, 2, 10), 60);
    }

    #[test]
    fn rate_limited_honors_retry_after() {
        let err = ApiError::RateLimited {
            retry_after_secs: Some(45),
        };
        assert_eq!(heartbeat_error_backoff_secs(&err, 1, 10), 45);

        // Floored at one interval: retrying sooner re-trips the limiter.
        let err = ApiError::RateLimited {
            retry_after_secs: Some(2),
        };
        assert_eq!(heartbeat_error_backoff_secs(&err, 1, 10), 10);

        // Capped at an hour so a bogus header can't silence the agent.
        let err = ApiError::RateLimited {
            retry_after_secs: Some(86_400),
        };
        assert_eq!(heartbeat_error_backoff_secs(&err, 1, 10), 3600);
    }

    #[test]
    fn rate_limited_without_retry_after_stays_near_interval() {
        let err = ApiError::RateLimited {
            retry_after_secs: None,
        };
        assert_eq!(heartbeat_error_backoff_secs(&err, 1, 10), 10);
        assert_eq!(heartbeat_error_backoff_secs(&err, 2, 10), 20);
    }
}

/// Backoff after a failed heartbeat. Transient failures (5xx, network, rate
/// limiting) stay close to the configured interval so a brief blip does not
/// blow past the platform's missed-heartbeat threshold — a fixed 30s+ backoff
/// on a 10s-interval agent would single-handedly flap it offline.
fn heartbeat_error_backoff_secs(
    error: &ApiError,
    consecutive_errors: u32,
    heartbeat_interval_secs: u64,
) -> u64 {
    // One skipped beat per consecutive failure, capped well under any
    // offline threshold a longer-interval agent would have.
    let near_interval = {
        let multiplier = u64::from(consecutive_errors.min(3));
        std::cmp::min(heartbeat_interval_secs.saturating_mul(multiplier), 120)
    };

    match error {
        // Honor Retry-After when the platform sent one, floored at one
        // interval (retrying sooner would just re-trip the limiter) and
        // capped at an hour so a bogus header can't silence the agent.
        ApiError::RateLimited { retry_after_secs } => match retry_after_secs {
            Some(secs) => {
                let floor = heartbeat_interval_secs;
                let ceiling = floor.max(3600);
                (*secs).clamp(floor, ceiling)
            }
            None => near_interval,
        },
        _ if error.is_transient() => near_interval,
        _ => std::cmp::min(
            30 * 2u64.pow(consecutive_errors.saturating_sub(1).min(7)),
            3600,
        ),
    }
}

/// Cooperative sleep helper: returns Err(()) if shutdown was requested
/// mid-sleep, otherwise Ok(()). Sleeps in 500 ms ticks for responsiveness.
fn interruptible_sleep(stop: &Arc<AtomicBool>, total_secs: u64) -> Result<(), ()> {
    let deadline = Instant::now() + Duration::from_secs(total_secs);
    while Instant::now() < deadline {
        if stop.load(Ordering::SeqCst) {
            return Err(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

fn sleep_with_quick_action_polling(
    stop: &Arc<AtomicBool>,
    total: Duration,
    client: &ApiClient,
    quick_actions: &mut QuickActionsRegistry,
    quick_actions_fingerprint: &mut String,
    quick_actions_config: &QuickActionsConfig,
    quick_action_polling: &mut QuickActionPollState,
) -> Result<(), ()> {
    let deadline = Instant::now() + total;

    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(());
        }

        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }

        if REMOTE_CONTROL_ENABLED && quick_action_polling.due(now) {
            poll_quick_actions_once(
                client,
                quick_actions,
                quick_actions_fingerprint,
                quick_actions_config,
                quick_action_polling,
            );
            continue;
        }

        let next_wake = if REMOTE_CONTROL_ENABLED {
            quick_action_polling
                .next_due()
                .map(|next_due| std::cmp::min(deadline, next_due))
                .unwrap_or(deadline)
        } else {
            deadline
        };
        let sleep_for = std::cmp::min(
            Duration::from_millis(500),
            next_wake.saturating_duration_since(now),
        );

        if sleep_for > Duration::from_millis(0) {
            thread::sleep(sleep_for);
        } else {
            thread::yield_now();
        }
    }
}

fn reload_quick_actions_if_changed(
    client: &ApiClient,
    quick_actions: &mut QuickActionsRegistry,
    quick_actions_fingerprint: &mut String,
) -> bool {
    let reloaded_quick_actions = QuickActionsRegistry::load();
    let reloaded_fingerprint = reloaded_quick_actions.fingerprint();
    if reloaded_fingerprint != *quick_actions_fingerprint {
        *quick_actions = reloaded_quick_actions;
        *quick_actions_fingerprint = reloaded_fingerprint;
        if REMOTE_CONTROL_ENABLED {
            publish_quick_actions_manifest(client, quick_actions);
        }
        return true;
    }
    false
}

fn poll_quick_actions_once(
    client: &ApiClient,
    quick_actions: &mut QuickActionsRegistry,
    quick_actions_fingerprint: &mut String,
    quick_actions_config: &QuickActionsConfig,
    quick_action_polling: &mut QuickActionPollState,
) {
    if reload_quick_actions_if_changed(client, quick_actions, quick_actions_fingerprint) {
        quick_action_polling.sync(quick_actions_config, quick_actions);
    }

    if !quick_action_polling.enabled {
        return;
    }

    let report = quick_action_polling.mark_poll_started();
    match client.poll_quick_actions(&report) {
        Ok(requests) => {
            if requests.is_empty() {
                debug!("Quick action poll completed with no pending requests");
            } else {
                info!("Quick action poll claimed {} request(s)", requests.len());
            }
            run_quick_action_requests(client, quick_actions, &requests);
        }
        Err(e) => warn!("Quick action poll failed: {}", e),
    }
}

fn run_quick_action_requests(
    client: &ApiClient,
    quick_actions: &QuickActionsRegistry,
    requests: &[QuickActionRequest],
) {
    for request in requests {
        info!("Running quick action request {}", request.action_id);
        let result = quick_actions.execute(request);
        if let Err(e) = client.send_quick_action_result(&result) {
            warn!("Quick action result send failed: {}", e);
        }
    }
}

/// Fetch config with retry logic, falling back to safe defaults if all attempts fail.
fn fetch_config_with_retry(client: &ApiClient) -> AgentConfig {
    for attempt in 1..=MAX_CONFIG_FETCH_RETRIES {
        match client.fetch_config() {
            Ok(cfg) => return cfg,
            Err(e) => {
                if attempt < MAX_CONFIG_FETCH_RETRIES {
                    warn!(
                        "Config fetch attempt {}/{} failed: {}. Retrying in {}s...",
                        attempt, MAX_CONFIG_FETCH_RETRIES, e, CONFIG_FETCH_RETRY_DELAY_SECS
                    );
                    thread::sleep(Duration::from_secs(CONFIG_FETCH_RETRY_DELAY_SECS));
                } else {
                    error!(
                        "All {} config fetch attempts failed. Using safe fallback config.",
                        MAX_CONFIG_FETCH_RETRIES
                    );
                }
            }
        }
    }

    // Return safe fallback - agent will try to fetch real config on next heartbeat
    AgentConfig::safe_fallback()
}

fn publish_quick_actions_manifest(client: &ApiClient, registry: &QuickActionsRegistry) {
    let manifest = registry.manifest();
    match client.send_quick_actions_manifest(&manifest) {
        Ok(_) => info!(
            "Quick actions manifest sent (enabled={}, actions={})",
            manifest.enabled,
            manifest.actions.len()
        ),
        Err(e) => warn!("Quick actions manifest send failed: {}", e),
    }
}

/// Diagnostic: fetch the agent config from the platform and print the parsed
/// fields. Token comes from CLI/env; endpoint from `resolve_endpoint`. Never
/// touches the heartbeat loop and never prints the token.
fn run_check_config(token: String, endpoint: String) -> Result<()> {
    validate_token_prefix(&token)?;
    let client = ApiClient::new(endpoint.clone(), token).context("ApiClient init failed")?;
    println!("Endpoint: {endpoint}");
    println!("Fetching /api/agents/config...");
    let mut cfg = client
        .fetch_config()
        .context("Config fetch failed — check token, network, and platform URL")?;
    cfg.clamp();
    println!("✓ Config fetched");
    println!("  version:                  {}", cfg.version);
    println!(
        "  heartbeat_interval_secs:  {}",
        cfg.heartbeat_interval_secs
    );
    println!(
        "  quick_action_poll_secs:   {} (enabled={})",
        cfg.quick_actions.poll_interval_seconds, cfg.quick_actions.enabled
    );
    println!("  missed_threshold:         {}", cfg.missed_threshold);
    println!(
        "  metrics:                  cpu={} memory={} disk={} load={}",
        cfg.metrics.cpu, cfg.metrics.memory, cfg.metrics.disk, cfg.metrics.load
    );
    Ok(())
}

/// Diagnostic: collect one metrics sample, send a single heartbeat, and print
/// the platform's response. Useful as a smoke test after install or after a
/// config change. Never enters the retry loop and never prints the token.
fn run_test_heartbeat(token: String, endpoint: String) -> Result<()> {
    validate_token_prefix(&token)?;
    let client = ApiClient::new(endpoint.clone(), token).context("ApiClient init failed")?;
    let mut collector = MetricsCollector::new().context("Metrics collector init failed")?;
    let mut cfg = match client.fetch_config() {
        Ok(c) => c,
        Err(e) => {
            warn!("Config fetch failed ({e}); using safe fallback for the test heartbeat");
            AgentConfig::safe_fallback()
        }
    };
    cfg.clamp();

    println!("Endpoint: {endpoint}");
    println!("Sending one heartbeat...");
    match send_heartbeat(&client, &cfg, &mut collector, None, false) {
        Ok(result) => {
            println!("✓ Heartbeat accepted");
            println!("  config_outdated:        {}", result.config_outdated);
            if let Some(v) = result.latest_config_version {
                println!("  latest_config_version:  {v}");
            }
            println!("  uninstall:              {}", result.uninstall);
            println!("  reboot:                 {}", result.reboot);
            println!("  quick_actions:          {}", result.quick_actions.len());
            match result.update {
                Some(u) if u.available => {
                    println!(
                        "  update_available:       yes → {} (force={})",
                        u.latest_version, u.force_update
                    );
                }
                _ => println!("  update_available:       no"),
            }
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("Heartbeat failed: {e}")),
    }
}

/// Log config changes without exposing sensitive data
fn log_config_change(old: &AgentConfig, new: &AgentConfig) {
    info!(
        "✓ Config updated: v{} → v{} (interval: {}s → {}s, missed: {} → {})",
        old.version,
        new.version,
        old.heartbeat_interval_secs,
        new.heartbeat_interval_secs,
        old.missed_threshold,
        new.missed_threshold
    );

    // Log metrics config changes
    if old.metrics.cpu != new.metrics.cpu
        || old.metrics.memory != new.metrics.memory
        || old.metrics.disk != new.metrics.disk
        || old.metrics.load != new.metrics.load
    {
        info!(
            "  Metrics: cpu={}, memory={}, disk={}, load={}",
            new.metrics.cpu, new.metrics.memory, new.metrics.disk, new.metrics.load
        );
    }
}

/// Trigger self-uninstallation of the agent.
///
/// Writes the uninstall marker to /run/connlog/.uninstall_requested and exits.
/// The systemd ExecStopPost script (runs as root via the `+` prefix) detects
/// the marker on service stop and performs the actual root-level cleanup:
///   1. Disables the service
///   2. Removes the service file + daemon-reload
///   3. Removes /etc/connlog (token + config)
///   4. Removes the binary
///
/// RuntimeDirectory=connlog in the service unit ensures /run/connlog/ is owned
/// by the connlog-agent user, so the marker write always succeeds when running
/// under the service. If the write fails (e.g. running outside the service),
/// we log actionable instructions and exit — the runtime process is never root
/// so in-process cleanup is not possible regardless.
fn trigger_self_uninstall(reason: &str) {
    error!("UNINSTALL: {}", reason);

    match std::fs::write(platform::UNINSTALL_MARKER, reason) {
        Ok(_) => {
            info!(
                "UNINSTALL: Marker written to {}. Exiting — ExecStopPost will complete cleanup.",
                platform::UNINSTALL_MARKER
            );
        }
        Err(e) => {
            error!(
                "UNINSTALL: Could not write uninstall marker: {}. \
                 Agent will stop reporting, but files were not removed. \
                 To clean up manually: sudo connlog-agent uninstall",
                e
            );
        }
    }

    // Exit with 0 so systemd Restart=on-failure does not restart the agent.
    std::process::exit(0);
}

/// Which `history_request` the agent last dealt with, and how often it tried.
#[derive(Default)]
struct HistoryAnswers {
    last: Option<heartbeat::HistoryRequest>,
    attempts: u32,
    done: bool,
}

const HISTORY_UPLOAD_ATTEMPTS: u32 = 3;

/// Send the flight recorder's records for the window the platform asked
/// about. Best-effort: a failure is logged and retried on the next heartbeat
/// that repeats the request, three times in all.
fn answer_history_request(
    client: &ApiClient,
    config: &AgentConfig,
    state_dir: &std::path::Path,
    request: heartbeat::HistoryRequest,
    answers: &mut HistoryAnswers,
) {
    if answers.last != Some(request) {
        *answers = HistoryAnswers {
            last: Some(request),
            ..HistoryAnswers::default()
        };
    }
    if answers.done || answers.attempts >= HISTORY_UPLOAD_ATTEMPTS {
        return;
    }
    answers.attempts += 1;

    use flight_recorder::upload;
    let all = flight_recorder::ring::read(&flight_recorder::ring_path(state_dir));
    let records = upload::records_for(
        &all,
        request.since,
        request.until,
        upload::MetricToggles {
            cpu: config.metrics.cpu,
            memory: config.metrics.memory,
            disk: config.metrics.disk,
            load: config.metrics.load,
        },
    );
    let count = records.len();
    let body = upload::encode(&records);
    let bytes = body.len();
    match client.upload_history(body) {
        Ok(()) => {
            answers.done = true;
            info!(
                "Sent flight-recorder history for {}..{}: {count} records, {bytes} bytes",
                request.since, request.until
            );
            send_postmortem(client, state_dir);
        }
        Err(e) => warn!(
            "Flight-recorder history upload failed (attempt {}/{}): {e}",
            answers.attempts, HISTORY_UPLOAD_ATTEMPTS
        ),
    }
}

/// Send the previous boot's last words, when the opt-in collector left
/// some, right after the history that explains the outage. Forgotten once
/// the platform has answered (accepted or not); kept for the next outage
/// only when the platform could not be reached.
fn send_postmortem(client: &ApiClient, state_dir: &std::path::Path) {
    let Some((_boot, text)) = features::postmortem::read_pending(state_dir) else {
        return;
    };
    match client.upload_postmortem(text) {
        Ok(()) | Err(ApiError::HttpError { .. }) => {
            features::postmortem::clear_pending(state_dir);
            info!("Sent the previous boot's last warnings with the outage report");
        }
        Err(e) => warn!("Post-mortem upload failed: {e}"),
    }
}

/// Records the clean stop when the daemon loop ends because of SIGTERM or
/// SIGINT: waits for the sampler to finish its current record so the stop is
/// the last one, then writes it.
struct StopRecordGuard {
    recorder: Option<flight_recorder::Recorder>,
    sampler: Option<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl Drop for StopRecordGuard {
    fn drop(&mut self) {
        if !self.stop.load(Ordering::SeqCst) {
            return;
        }
        if let Some(sampler) = self.sampler.take() {
            let _ = sampler.join();
        }
        if let Some(recorder) = &self.recorder {
            recorder.record_stop(0);
        }
    }
}

/// Returns true when the installed systemd unit includes a *non-blocking*
/// reboot ExecStopPost branch. Without `--no-block`, `systemctl reboot` from
/// ExecStopPost deadlocks (waits for this unit to finish deactivating).
/// Without any reboot branch, exiting after writing the marker would leave the
/// agent permanently stopped (`Restart=on-failure` ignores exit 0).
fn installed_unit_supports_reboot() -> bool {
    match std::fs::read_to_string(install::SYSTEMD_SERVICE_PATH) {
        Ok(unit) => {
            unit.contains("/run/connlog/.reboot_requested")
                && unit.contains("systemctl reboot --no-block")
        }
        Err(e) => {
            warn!(
                "REBOOT: Could not read {}: {} — treating unit as not reboot-capable",
                install::SYSTEMD_SERVICE_PATH,
                e
            );
            false
        }
    }
}

/// Trigger a host reboot via the systemd ExecStopPost root hook.
///
/// Does not return when the marker was written: the process exits for the
/// hook. Returns the report for the platform when the reboot could not be
/// handed over (stale unit, marker write failure); the caller keeps running.
fn trigger_host_reboot(
    reason: &str,
    state_dir: &std::path::Path,
    boot_id: Option<&str>,
    recorder: Option<&flight_recorder::Recorder>,
) -> RebootReport {
    error!("REBOOT: {}", reason);

    if !installed_unit_supports_reboot() {
        error!(
            "REBOOT: Installed systemd unit does not include the reboot hook. \
             Refusing to exit (would leave the agent stopped without rebooting). \
             Run: sudo connlog-agent refresh-service --restart \
             (or update the agent so ExecStopPost refreshes the unit)."
        );
        return RebootReport::new(
            RebootState::RefusedUnit,
            "installed systemd unit has no reboot hook; run: sudo connlog-agent refresh-service --restart",
        );
    }

    // Written first, so the next start can tell a reboot from a hook that ran
    // and did nothing. Losing it costs the report, not the reboot.
    if !remote_reboot::record_attempt(state_dir, boot_id) {
        warn!("REBOOT: Could not record the attempt; its outcome will not be reported");
    }

    match std::fs::write(platform::REBOOT_MARKER, reason) {
        Ok(_) => {
            info!(
                "REBOOT: Marker written to {}. Exiting — ExecStopPost will reboot the host.",
                platform::REBOOT_MARKER
            );
            if let Some(recorder) = recorder {
                recorder.record_stop(flight_recorder::ring::FLAG_EXIT_REBOOT);
            }
            // Exit with 0 so systemd Restart=on-failure does not restart us
            // before ExecStopPost runs `systemctl reboot`.
            std::process::exit(0);
        }
        Err(e) => {
            error!(
                "REBOOT: Could not write reboot marker: {}. Continuing without reboot.",
                e
            );
            // No reboot is coming: the attempt record must not be read as one
            // on the next start.
            remote_reboot::clear_attempt(state_dir);
            RebootReport::new(
                RebootState::Failed,
                format!("could not write the reboot marker: {e}"),
            )
        }
    }
}

/// Response from a successful heartbeat
struct HeartbeatResult {
    config_outdated: bool,
    latest_config_version: Option<u32>,
    uninstall: bool,
    reboot: bool,
    update: Option<heartbeat::UpdateInfo>,
    quick_actions: Vec<features::quick_actions::QuickActionRequest>,
    history_request: Option<heartbeat::HistoryRequest>,
    inventory_request: bool,
    probe_request: Option<features::reachability::ProbeRequest>,
}

fn send_heartbeat(
    client: &ApiClient,
    config: &AgentConfig,
    collector: &mut MetricsCollector,
    quick_action_polling: Option<&QuickActionPollState>,
    expose_system_info: bool,
) -> Result<HeartbeatResult, ApiError> {
    // Collect system metrics. Isolated against panics inside `sysinfo` —
    // the heartbeat MUST keep going even if a metric source briefly explodes
    // (issue #2 V1 hardening). On failure we log once and send zero metrics
    // so the platform still records the agent as alive.
    let metrics = match collector.collect() {
        Ok(m) => m,
        Err(e) => {
            warn!(
                "Metrics collection failed ({e}); sending heartbeat with zero metrics so liveness still reaches the platform"
            );
            let (hostname, os, arch) = collector.identity();
            let mut fallback = features::metrics::SystemMetrics::unavailable();
            // os/arch are always sent (needed for self-update binary
            // selection); hostname remains opt-in.
            fallback.os = os.to_string();
            fallback.arch = arch.to_string();
            if expose_system_info {
                fallback.hostname = hostname.to_string();
            }
            fallback
        }
    };

    // Respect server-side metrics toggles
    let payload_metrics = if config.any_metrics_enabled() {
        heartbeat::Metrics {
            cpu_percent: if config.metrics.cpu {
                metrics.cpu_percent
            } else {
                None
            },
            cpu_peak_percent: if config.metrics.cpu {
                metrics.cpu_peak_percent
            } else {
                None
            },
            // Identity, not a reading: sent whenever it is known so the
            // dashboard can scale the load average to the machine.
            cpu_core_count: metrics.cpu_core_count,
            memory_used_mb: if config.metrics.memory {
                metrics.memory_used_mb
            } else {
                0
            },
            memory_total_mb: if config.metrics.memory {
                metrics.memory_total_mb
            } else {
                0
            },
            disk_used_mb: if config.metrics.disk {
                metrics.disk_used_mb
            } else {
                0
            },
            disk_total_mb: if config.metrics.disk {
                metrics.disk_total_mb
            } else {
                0
            },
            load_1m: if config.metrics.load {
                metrics.load_1m
            } else {
                0.0
            },
        }
    } else {
        heartbeat::Metrics {
            cpu_percent: None,
            cpu_peak_percent: None,
            cpu_core_count: metrics.cpu_core_count,
            memory_used_mb: 0,
            memory_total_mb: 0,
            disk_used_mb: 0,
            disk_total_mb: 0,
            load_1m: 0.0,
        }
    };

    // Build heartbeat payload
    let payload = HeartbeatPayload {
        agent_version: AGENT_VERSION.to_string(),
        protocol_version: PROTOCOL_VERSION,
        config_version: config.version,
        // Hostname is opt-in via CONNLOG_EXPOSE_SYSTEM_INFO=true. Defaults to
        // None (not transmitted) so operators must explicitly consent before
        // the machine's hostname leaves the host.
        hostname: expose_system_info.then(|| metrics.hostname.clone()),
        // OS/arch (e.g. "linux"/"x86_64") are always sent regardless of the
        // opt-in above — the platform needs them to select the correct
        // self-update binary, and they don't identify the machine/operator.
        os: metrics.os.clone(),
        arch: metrics.arch.clone(),
        uptime_seconds: metrics.uptime_seconds,
        metrics: payload_metrics,
        dev_mode: None,
    };

    // One-line per-heartbeat diagnostic. Visible at the default `info` log
    // level so users can see end-to-end what each agent is sending without
    // needing to flip on debug logging. Cheap (one formatted line / minute)
    // and the single best signal when "the dashboard shows zeros" — it
    // disambiguates between (a) config disabling a metric, (b) sysinfo
    // returning zero, and (c) the wire encode itself.
    let sample_cpu = metrics
        .cpu_percent
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "collecting".to_string());
    let wire_cpu = payload
        .metrics
        .cpu_percent
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "collecting".to_string());

    info!(
        "HB v={} cfg=v{}(cpu={} mem={} disk={} load={}) sample(cpu={} mem={}/{} MB disk={}/{} MB load={:.2} up={}s) → wire(cpu={} mem={}/{} MB disk={}/{} MB load={:.2})",
        AGENT_VERSION,
        config.version,
        config.metrics.cpu,
        config.metrics.memory,
        config.metrics.disk,
        config.metrics.load,
        sample_cpu,
        metrics.memory_used_mb,
        metrics.memory_total_mb,
        metrics.disk_used_mb,
        metrics.disk_total_mb,
        metrics.load_1m,
        metrics.uptime_seconds,
        wire_cpu,
        payload.metrics.memory_used_mb,
        payload.metrics.memory_total_mb,
        payload.metrics.disk_used_mb,
        payload.metrics.disk_total_mb,
        payload.metrics.load_1m,
    );

    // Enforce server-mandated payload size limit
    if config.max_payload_size_kb > 0 {
        let payload_json = serde_json::to_vec(&payload).map_err(|e| ApiError::Other(e.into()))?;
        let payload_kb = payload_json.len() as u64 / 1024;
        if payload_kb > config.max_payload_size_kb {
            warn!(
                "Payload size ({}KB) exceeds server limit ({}KB), sending anyway",
                payload_kb, config.max_payload_size_kb
            );
        }
    }

    // Send heartbeat
    let quick_action_polling_report = quick_action_polling.map(QuickActionPollState::report);
    let response = client.send_heartbeat(&payload, quick_action_polling_report.as_ref())?;

    Ok(HeartbeatResult {
        config_outdated: response.config_outdated.unwrap_or(false),
        latest_config_version: response.latest_config_version,
        uninstall: response.uninstall,
        reboot: response.reboot,
        update: response.update,
        quick_actions: response.quick_actions,
        history_request: response.history_request,
        inventory_request: response.inventory_request,
        probe_request: response.probe_request,
    })
}

#[cfg(test)]
mod jitter_tests {
    use crate::features::quick_actions::QuickActionsRegistry;
    use crate::heartbeat::{
        QuickActionsConfig, QUICK_ACTION_DEFAULT_POLL_INTERVAL_SECS,
        QUICK_ACTION_MIN_POLL_INTERVAL_SECS,
    };

    use super::{
        jittered, jittered_duration, next_heartbeat_sleep, QuickActionPollState,
        HEARTBEAT_JITTER_PCT, QUICK_ACTION_POLL_JITTER_PCT,
    };

    /// The agent's half of `packages/agent-protocol/fixtures/heartbeat-schedule.json`.
    /// The platform's half is `packages/agent-protocol/src/__tests__/schedule.test.ts`.
    /// `include_str!` reaches outside the crate only in tests, as
    /// `http::shared_fixtures` does.
    #[test]
    fn heartbeat_schedule_matches_the_shared_fixture() {
        use crate::heartbeat::{
            HEARTBEAT_EARLIEST_GAP_PERMILLE, HEARTBEAT_MAX_INTERVAL_SECS,
            HEARTBEAT_MIN_INTERVAL_SECS,
        };

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/agent-protocol/fixtures/heartbeat-schedule.json"
        ))
        .expect("schedule fixture must be JSON");
        let field = |name: &str| fixture[name].as_u64().expect(name);

        assert_eq!(HEARTBEAT_MIN_INTERVAL_SECS, field("minIntervalSecs"));
        assert_eq!(HEARTBEAT_MAX_INTERVAL_SECS, field("maxIntervalSecs"));
        assert_eq!(HEARTBEAT_JITTER_PCT, field("jitterPct"));
        assert_eq!(
            HEARTBEAT_EARLIEST_GAP_PERMILLE,
            field("earliestGapPermille")
        );

        let examples = fixture["examples"].as_array().expect("examples");
        assert!(!examples.is_empty());
        for example in examples {
            let interval = example["intervalSecs"].as_u64().unwrap();
            let earliest_ms = example["earliestGapMs"].as_u64().unwrap();
            let latest_secs = example["latestGapSecs"].as_u64().unwrap();

            // A cycle that used the whole interval sleeps only the floor.
            let floor = next_heartbeat_sleep(interval, std::time::Duration::from_secs(interval));
            assert_eq!(
                floor.as_millis(),
                u128::from(earliest_ms),
                "{interval}s floor"
            );

            // The most jitter `jittered` can add lands exactly on the bound.
            let span = (interval * HEARTBEAT_JITTER_PCT) / 100;
            assert_eq!(interval + span, latest_secs, "{interval}s latest gap");
            for _ in 0..20 {
                let gap = jittered(interval);
                assert!(
                    (interval..=latest_secs).contains(&gap),
                    "{gap} for {interval}s"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn jittered_zero_stays_zero() {
        assert_eq!(jittered(0), 0);
    }

    #[test]
    fn jittered_stays_within_bounds() {
        let base = 60u64;
        let span = (base * HEARTBEAT_JITTER_PCT) / 100;
        // Run a few times — the entropy source is SystemTime nanos so values
        // genuinely vary across calls. Jitter is positive-only: every result
        // must lie inside [base, base+span] — undershooting the interval
        // risks the platform's minimum-interval limiter.
        for _ in 0..20 {
            let v = jittered(base);
            assert!(v >= base, "{v} < {base}");
            assert!(v <= base + span, "{v} > {} + {span}", base);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn next_heartbeat_sleep_compensates_cycle_overhead() {
        // A normal cycle (sub-second work) sleeps interval + jitter − elapsed,
        // so the beat-to-beat gap stays at one jittered interval instead of
        // interval + work.
        let interval = 10u64;
        let elapsed = std::time::Duration::from_millis(300);
        for _ in 0..20 {
            let sleep = next_heartbeat_sleep(interval, elapsed);
            let gap = sleep + elapsed;
            assert!(gap >= std::time::Duration::from_secs(interval), "{gap:?}");
            // interval + max jitter (10%)
            assert!(gap <= std::time::Duration::from_secs(11), "{gap:?}");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn next_heartbeat_sleep_floors_at_ninety_percent() {
        // A slow cycle must not compress the wire gap below 0.9 × interval —
        // the platform 429s anything faster than that.
        let interval = 10u64;
        let elapsed = std::time::Duration::from_secs(5);
        for _ in 0..20 {
            let sleep = next_heartbeat_sleep(interval, elapsed);
            assert_eq!(sleep, std::time::Duration::from_secs(9), "{sleep:?}");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn jittered_floor_is_one() {
        // For very short intervals the span rounds to 0 — the result is
        // returned unchanged, which is fine: spreading a 1s herd is moot.
        assert_eq!(jittered(1), 1);
    }

    #[test]
    fn jittered_duration_stays_within_bounds() {
        let base = std::time::Duration::from_secs(5);
        let span_ms = base.as_millis() * QUICK_ACTION_POLL_JITTER_PCT as u128 / 100;
        for _ in 0..20 {
            let value = jittered_duration(base, QUICK_ACTION_POLL_JITTER_PCT);
            assert!(value.as_millis() >= base.as_millis() - span_ms);
            assert!(value.as_millis() <= base.as_millis() + span_ms);
            assert!(value.as_millis() >= 1);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn quick_action_polling_disabled_when_registry_has_no_actions() {
        let config = QuickActionsConfig {
            enabled: true,
            poll_interval_seconds: QUICK_ACTION_DEFAULT_POLL_INTERVAL_SECS,
        };
        let state = QuickActionPollState::new(&config, &QuickActionsRegistry::disabled());

        assert!(!state.report().enabled);
        assert_eq!(
            state.report().poll_interval_seconds,
            QUICK_ACTION_DEFAULT_POLL_INTERVAL_SECS
        );
        assert!(state.report().next_poll_at_unix_ms.is_none());
    }

    #[test]
    fn quick_action_polling_report_uses_configured_interval() {
        let config = QuickActionsConfig {
            enabled: false,
            poll_interval_seconds: QUICK_ACTION_MIN_POLL_INTERVAL_SECS,
        };
        let state = QuickActionPollState::new(&config, &QuickActionsRegistry::disabled());

        assert!(!state.report().enabled);
        assert_eq!(
            state.report().poll_interval_seconds,
            QUICK_ACTION_MIN_POLL_INTERVAL_SECS
        );
    }
}
