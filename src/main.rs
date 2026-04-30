use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod config;
mod heartbeat;
mod http;
mod install;
mod metrics;
mod platform;
mod service;
mod update;

#[cfg(test)]
mod simulation;

use config::Config;
use heartbeat::{AgentConfig, HeartbeatPayload};
use http::{ApiClient, ApiError};
use metrics::MetricsCollector;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: u32 = 2;
const DEFAULT_ENDPOINT: &str = "https://connlog.com";

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

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Windows SCM dispatch — must happen BEFORE anything that touches stdio
    // assuming a console session. The SCM launches the binary with
    // `--run-service` (see install/windows.rs); detecting it via raw argv lets
    // us hand off without parsing the rest of the CLI.
    #[cfg(windows)]
    {
        let raw_args: Vec<String> = std::env::args().collect();
        if service::is_service_invocation(&raw_args) {
            return service::run_service();
        }
    }

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

    // Determine endpoint
    #[cfg(debug_assertions)]
    let endpoint = config
        .endpoint
        .clone()
        .or_else(|| config.get_platform_url())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());

    #[cfg(not(debug_assertions))]
    let endpoint = config
        .get_platform_url()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());

    // Interactive run — no shutdown signal, loop forever. The service path
    // (Windows) builds its own AtomicBool and calls `run_agent_with_shutdown`
    // directly.
    run_agent_with_shutdown_inner(token, endpoint, Arc::new(AtomicBool::new(false)))
}

/// Public entry used by the Windows service dispatcher. Builds an endpoint
/// from the same Config-driven precedence as the interactive path.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn run_agent_with_shutdown(cfg: Config, stop: Arc<AtomicBool>) -> Result<()> {
    let token = cfg
        .token
        .clone()
        .context("Token missing in service config (corrupt agent.conf?)")?;

    #[cfg(debug_assertions)]
    let endpoint = cfg
        .endpoint
        .clone()
        .or_else(|| cfg.get_platform_url())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    #[cfg(not(debug_assertions))]
    let endpoint = cfg
        .get_platform_url()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());

    run_agent_with_shutdown_inner(token, endpoint, stop)
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
    if !token.starts_with("agent_") {
        error!("Invalid token format - must start with 'agent_'");
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

    let mut first_heartbeat = true;
    let mut consecutive_unauthorized = 0u32;
    let mut consecutive_errors = 0u32;
    let mut consecutive_uninstall_commands = 0u32;

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
    // mid-sleep, otherwise Ok(()). Sleeps in 500 ms ticks so a Windows STOP
    // is observed in <1 s even with a long heartbeat interval.
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

                info!(
                    "Heartbeat sent successfully, next in {}s",
                    config.heartbeat_interval_secs
                );
                if interruptible_sleep(config.heartbeat_interval_secs).is_err() {
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
                const DISABLED_BACKOFF_SECS: u64 = 300;
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
                        "Config fetch attempt {}/{} failed: {}. Retrying in 5s...",
                        attempt, MAX_CONFIG_FETCH_RETRIES, e
                    );
                    thread::sleep(Duration::from_secs(5));
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
/// This writes a marker file and exits with a clean code.
/// The systemd ExecStopPost script detects the marker and performs full cleanup:
///   1. Disables the service
///   2. Removes the service file
///   3. Removes config directory
///   4. Removes the binary
///
/// If NOT running under systemd, falls back to direct uninstall.
fn trigger_self_uninstall(reason: &str) {
    error!("UNINSTALL: {}", reason);

    // Linux: prefer the marker-file path so systemd's ExecStopPost can do the
    // actual root-only cleanup. Windows: write the marker too — the install
    // flow's recovery action will spawn the elevated cleanup helper. In both
    // cases, fall back to a direct in-process uninstall if the marker write
    // fails (only succeeds when we're running with privilege).
    #[cfg(unix)]
    let is_supervised = std::env::var("INVOCATION_ID").is_ok();
    #[cfg(windows)]
    let is_supervised = true; // Windows agent always runs as a service

    if is_supervised {
        info!("UNINSTALL: Running under supervisor — writing uninstall marker");
        match std::fs::write(platform::UNINSTALL_MARKER, reason) {
            Ok(_) => {
                info!(
                    "UNINSTALL: Marker written to {}",
                    platform::UNINSTALL_MARKER
                );
                info!("UNINSTALL: Exiting process. Supervisor will complete cleanup.");
            }
            Err(e) => {
                error!(
                    "UNINSTALL: Failed to write marker file: {}. Attempting direct uninstall.",
                    e
                );
                if let Err(e) = install::uninstall() {
                    error!("UNINSTALL: Direct uninstall also failed: {}", e);
                }
            }
        }
    } else {
        info!("UNINSTALL: No supervisor detected — performing direct uninstall");
        if let Err(e) = install::uninstall() {
            error!("UNINSTALL: Direct uninstall failed: {}", e);
        }
    }

    // Exit cleanly — supervisor's restart policy is configured to NOT restart
    // us after a clean exit (Restart=on-failure on systemd, no auto-restart
    // after delete on Windows once the marker is processed).
    std::process::exit(0);
}

/// Response from a successful heartbeat
struct HeartbeatResult {
    config_outdated: bool,
    latest_config_version: Option<u32>,
    uninstall: bool,
    update: Option<heartbeat::UpdateInfo>,
}

fn send_heartbeat(
    client: &ApiClient,
    config: &AgentConfig,
    collector: &mut MetricsCollector,
) -> Result<HeartbeatResult, ApiError> {
    // Collect system metrics using reusable collector
    let metrics = collector.collect();

    // Respect server-side metrics toggles
    let payload_metrics = if config.any_metrics_enabled() {
        heartbeat::Metrics {
            cpu_percent: if config.metrics.cpu {
                metrics.cpu_percent
            } else {
                0.0
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
            cpu_percent: 0.0,
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
    })
}
