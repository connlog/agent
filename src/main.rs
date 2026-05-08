use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod config;
mod defaults;
mod extended_metrics;
mod heartbeat;
mod http;
mod identity;
mod install;
mod metrics;
mod platform;
mod quick_actions;
mod update;

#[cfg(test)]
mod simulation;

use config::Config;
use defaults::{CONFIG_FETCH_RETRY_DELAY_SECS, DEFAULT_ENDPOINT, DISABLED_BACKOFF_SECS};
use heartbeat::{AgentConfig, HeartbeatPayload};
use http::{ApiClient, ApiError};
use metrics::MetricsCollector;
use quick_actions::QuickActionsRegistry;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Wire protocol version. v1 = 32-byte little-endian binary frame over
/// `application/octet-stream`; identity metadata travels in `X-*` headers.
/// There is intentionally no JSON fallback — both ends speak binary only.
const PROTOCOL_VERSION: u32 = 1;

/// Maximum consecutive 401 errors before self-uninstall.
///
/// Only counts genuine `401 Unauthorized` responses from the platform — network
/// errors, DNS failures, machine-down scenarios, etc. are tracked separately in
/// `consecutive_errors` and never trigger self-uninstall. This guarantees the
/// agent only removes itself when the platform has authoritatively rejected the
/// token (deleted agent, deleted workspace, revoked auth) — not when the host
/// is offline or the platform is briefly unreachable.
const MAX_UNAUTHORIZED_ATTEMPTS: u32 = 50;

/// Consecutive uninstall commands required from server before acting
const UNINSTALL_CONFIRM_THRESHOLD: u32 = 3;

/// Maximum config fetch failures before using fallback
const MAX_CONFIG_FETCH_RETRIES: u32 = 3;

/// Heartbeat sleep jitter, ±10%. Spreads the thundering herd when N agents
/// installed at the same minute would otherwise all hit the platform on the
/// same second every interval.
const HEARTBEAT_JITTER_PCT: u64 = 10;

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

/// Apply ±`HEARTBEAT_JITTER_PCT`% jitter to a sleep duration. Source of
/// entropy is `SystemTime` nanos — no `rand` dependency required, no
/// cryptographic strength needed (we only want to spread the herd).
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
    // Map nanos into [-span, +span], applied to secs.
    let offset = (nanos % (2 * span + 1)) as i64 - span as i64;
    let jittered = secs as i64 + offset;
    jittered.max(1) as u64
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

    let config = Config::parse();

    // Handle --emit-service (used by ExecStopPost during self-update on Linux)
    if config.emit_service {
        print!("{}", install::SYSTEMD_SERVICE);
        return Ok(());
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
    // loop. They make running `connlog-agent --check-config` or
    // `--test-heartbeat` from a shell a fast way to confirm an install before
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
        return install::install(&token);
    }

    // Run mode - require token
    let token = config
        .token
        .clone()
        .context("Token is required. Use --token or set CONNLOG_TOKEN environment variable.")?;

    let endpoint = config.resolve_endpoint(DEFAULT_ENDPOINT);

    run_agent_with_shutdown_inner(token, endpoint, Arc::new(AtomicBool::new(false)))
}

fn run_agent_with_shutdown_inner(
    token: String,
    endpoint: String,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    info!("ConnLog Agent v{} starting", AGENT_VERSION);

    #[cfg(debug_assertions)]
    info!("Endpoint: {} (debug build)", endpoint);

    #[cfg(not(debug_assertions))]
    info!("Endpoint: {}", endpoint);

    // Validate token format
    if let Err(e) = validate_token_prefix(&token) {
        error!("{e}");
        std::process::exit(1);
    }

    let client = ApiClient::new(endpoint, token).context("Failed to initialize HTTP client")?;

    // Initialize reusable metrics collector (avoids re-creating sysinfo each heartbeat)
    let mut collector =
        MetricsCollector::new().context("Failed to initialize metrics collector")?;
    info!("✓ Metrics collector initialized");

    // Fetch runtime config from server with retry logic
    info!("Fetching runtime configuration...");
    let mut config = fetch_config_with_retry(&client);
    config.clamp();

    info!(
        "✓ Loaded config v{} (interval={}s, missed_threshold={})",
        config.version, config.heartbeat_interval_secs, config.missed_threshold
    );

    if config.version == 0 {
        warn!("Using fallback config - will retry fetching real config on next heartbeat");
    }

    let mut quick_actions = QuickActionsRegistry::load();
    let mut quick_actions_fingerprint = quick_actions.fingerprint();
    publish_quick_actions_manifest(&client, &quick_actions);

    let mut first_heartbeat = true;
    let mut consecutive_unauthorized = 0u32;
    let mut consecutive_errors = 0u32;
    let mut consecutive_uninstall_commands = 0u32;
    let mut extended_state = extended_metrics::ExtendedMetricsState::default();

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

    // Cooperative sleep helper: returns Err(()) if shutdown was requested
    // mid-sleep, otherwise Ok(()). Sleeps in 500 ms ticks for responsiveness.
    let stop_for_sleep = Arc::clone(&stop);
    let interruptible_sleep = move |total_secs: u64| -> Result<(), ()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(total_secs);
        while std::time::Instant::now() < deadline {
            if stop_for_sleep.load(Ordering::SeqCst) {
                return Err(());
            }
            thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    };

    // Main loop
    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Shutdown requested (service stop) — exiting agent loop");
            return Ok(());
        }
        match send_heartbeat(&client, &config, &mut collector) {
            Ok(response) => {
                // Reset error counters on success
                consecutive_unauthorized = 0;
                consecutive_errors = 0;

                if first_heartbeat {
                    info!("✓ Successfully registered with ConnLog");
                    first_heartbeat = false;
                }

                // Check for remote uninstall command (require consecutive confirmations)
                if response.uninstall {
                    consecutive_uninstall_commands += 1;
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
                    match update::try_apply_update(update_info, update_info.force_update) {
                        Ok(true) => {
                            info!(
                                "Update to v{} staged successfully. Restarting for update...",
                                update_info.latest_version
                            );
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
                        }
                        Err(e) => {
                            error!("Failed to fetch updated config: {}", e);
                            // Continue with old config - it still works
                        }
                    }
                }

                let reloaded_quick_actions = QuickActionsRegistry::load();
                let reloaded_fingerprint = reloaded_quick_actions.fingerprint();
                if reloaded_fingerprint != quick_actions_fingerprint {
                    quick_actions = reloaded_quick_actions;
                    quick_actions_fingerprint = reloaded_fingerprint;
                    publish_quick_actions_manifest(&client, &quick_actions);
                }

                for request in &response.quick_actions {
                    info!("Running quick action request {}", request.action_id);
                    let result = quick_actions.execute(request);
                    if let Err(e) = client.send_quick_action_result(&result) {
                        warn!("Quick action result send failed: {}", e);
                    }
                }

                // Extended Linux metrics (opt-in): discovery + compact samples
                if extended_metrics::is_linux_runtime()
                    && extended_metrics::should_collect(
                        config.extended_metrics.enabled,
                        config.extended_metrics.collect_disks,
                        config.extended_metrics.collect_network,
                    )
                {
                    if config.extended_metrics.discover_resources {
                        let discovery = extended_metrics::collect_discovery();
                        match client.send_resource_discovery(&discovery) {
                            Ok(_) => info!(
                                "Extended discovery sent (disks={}, network={})",
                                discovery.disks.len(),
                                discovery.network.len()
                            ),
                            Err(e) => warn!("Extended discovery send failed: {}", e),
                        }
                    }

                    if extended_metrics::has_monitored(
                        &config.extended_metrics.monitored_disk_keys,
                        &config.extended_metrics.monitored_network_keys,
                    ) {
                        let samples = extended_metrics::collect_samples(
                            &mut extended_state,
                            &config.extended_metrics.monitored_disk_keys,
                            &config.extended_metrics.monitored_network_keys,
                        );

                        if extended_metrics::validate_payload_size(
                            &samples,
                            config.max_payload_size_kb,
                        )
                        .unwrap_or(true)
                        {
                            if let Err(e) = client.send_resource_samples(&samples) {
                                warn!("Extended sample send failed: {}", e);
                            }
                        } else {
                            warn!("Extended sample payload exceeds server max payload size");
                        }
                    }
                }

                info!(
                    "Heartbeat sent successfully, next in {}s",
                    config.heartbeat_interval_secs
                );
                if interruptible_sleep(jittered(config.heartbeat_interval_secs)).is_err() {
                    return Ok(());
                }
            }
            Err(ApiError::Unauthorized) => {
                consecutive_unauthorized += 1;
                warn!(
                    "Unauthorized (401) - attempt {}/{}",
                    consecutive_unauthorized, MAX_UNAUTHORIZED_ATTEMPTS
                );

                if consecutive_unauthorized >= MAX_UNAUTHORIZED_ATTEMPTS {
                    error!(
                        "Token rejected {} consecutive times. Agent will self-uninstall to prevent zombie pings.",
                        MAX_UNAUTHORIZED_ATTEMPTS
                    );
                    trigger_self_uninstall(
                        "Token rejected too many times (likely deleted or revoked)",
                    );
                    return Ok(());
                }

                // Linear backoff for unauthorized — start at 30 s, ramp by 10 s per
                // attempt, cap at 120 s. A 401 is cheap on the server (the token
                // lookup is indexed, no work done), so there's no reason to back
                // off for hours; we just want enough spacing to absorb a brief
                // platform glitch. At the cap, 50 attempts ≈ 95 minutes total
                // before self-uninstall.
                let backoff = std::cmp::min(30 + 10 * consecutive_unauthorized as u64, 120);
                if interruptible_sleep(backoff).is_err() {
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
                if interruptible_sleep(DISABLED_BACKOFF_SECS).is_err() {
                    return Ok(());
                }
            }
            Err(e) => {
                consecutive_errors += 1;
                // Exponential backoff: 30, 60, 120, 240, ... capped at 3600s
                let backoff = std::cmp::min(
                    30 * 2u64.pow(consecutive_errors.saturating_sub(1).min(7)),
                    3600,
                );
                error!("Heartbeat failed: {} (retry in {}s)", e, backoff);
                if interruptible_sleep(backoff).is_err() {
                    return Ok(());
                }
            }
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
    match send_heartbeat(&client, &cfg, &mut collector) {
        Ok(result) => {
            println!("✓ Heartbeat accepted");
            println!("  config_outdated:        {}", result.config_outdated);
            if let Some(v) = result.latest_config_version {
                println!("  latest_config_version:  {v}");
            }
            println!("  uninstall:              {}", result.uninstall);
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
                 To clean up manually: sudo connlog-agent --uninstall",
                e
            );
        }
    }

    // Exit with 0 so systemd Restart=on-failure does not restart the agent.
    std::process::exit(0);
}

/// Response from a successful heartbeat
struct HeartbeatResult {
    config_outdated: bool,
    latest_config_version: Option<u32>,
    uninstall: bool,
    update: Option<heartbeat::UpdateInfo>,
    quick_actions: Vec<quick_actions::QuickActionRequest>,
}

fn send_heartbeat(
    client: &ApiClient,
    config: &AgentConfig,
    collector: &mut MetricsCollector,
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
            let mut fallback = metrics::SystemMetrics::unavailable();
            fallback.hostname = hostname.to_string();
            fallback.os = os.to_string();
            fallback.arch = arch.to_string();
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
        hostname: metrics.hostname.clone(),
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
    let response = client.send_heartbeat(&payload)?;

    Ok(HeartbeatResult {
        config_outdated: response.config_outdated.unwrap_or(false),
        latest_config_version: response.latest_config_version,
        uninstall: response.uninstall,
        update: response.update,
        quick_actions: response.quick_actions,
    })
}

#[cfg(test)]
mod jitter_tests {
    use super::{jittered, HEARTBEAT_JITTER_PCT};

    #[test]
    fn jittered_zero_stays_zero() {
        assert_eq!(jittered(0), 0);
    }

    #[test]
    fn jittered_stays_within_bounds() {
        let base = 60u64;
        let span = (base * HEARTBEAT_JITTER_PCT) / 100;
        // Run a few times — the entropy source is SystemTime nanos so values
        // genuinely vary across calls. Every result must lie inside [base-span,
        // base+span] and never drop below 1.
        for _ in 0..20 {
            let v = jittered(base);
            assert!(v >= base - span, "{v} < {} - {span}", base);
            assert!(v <= base + span, "{v} > {} + {span}", base);
            assert!(v >= 1);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn jittered_floor_is_one() {
        // For very short intervals the span rounds to 0 — the result is
        // returned unchanged, which is fine: spreading a 1s herd is moot.
        assert_eq!(jittered(1), 1);
    }
}
