use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn};
use std::thread;
use std::time::Duration;

mod config;
mod heartbeat;
mod http;
mod metrics;
mod install;

use config::Config;
use heartbeat::{AgentConfig, HeartbeatPayload};
use http::{ApiClient, ApiError};
use metrics::SystemMetrics;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_ENDPOINT: &str = "https://connlog.com";

/// Maximum consecutive 401 errors before self-uninstall
const MAX_UNAUTHORIZED_ATTEMPTS: u32 = 50;

/// Maximum config fetch failures before using fallback
const MAX_CONFIG_FETCH_RETRIES: u32 = 3;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::parse();

    // Handle status check
    if config.status {
        return install::status();
    }

    // Handle uninstallation
    if config.uninstall {
        return install::uninstall();
    }

    // Handle installation
    if config.install {
        let token = config.token.clone().context("Token required for installation")?;
        return install::install(&token);
    }

    // Run mode - require token
    let token = config.token.clone().context("Token is required. Use --token or set CONNLOG_TOKEN environment variable.")?;

    // Determine endpoint
    #[cfg(debug_assertions)]
    let endpoint = config.endpoint.clone()
        .or_else(|| config.get_platform_url())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());

    #[cfg(not(debug_assertions))]
    let endpoint = config.get_platform_url()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());

    run_agent(token, endpoint)
}

fn run_agent(token: String, endpoint: String) -> Result<()> {
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

    let client = ApiClient::new(endpoint, token);

    // Fetch runtime config from server with retry logic
    info!("Fetching runtime configuration...");
    let mut config = fetch_config_with_retry(&client);
    config.clamp();

    info!(
        "✓ Loaded config v{} (interval={}s, missed_threshold={})",
        config.version,
        config.heartbeat_interval_secs,
        config.missed_threshold
    );

    if config.version == 0 {
        warn!("Using fallback config - will retry fetching real config on next heartbeat");
    }

    let mut first_heartbeat = true;
    let mut consecutive_unauthorized = 0u32;
    let mut consecutive_errors = 0u32;

    // Main loop
    loop {
        match send_heartbeat(&client, &config) {
            Ok(response) => {
                // Reset error counters on success
                consecutive_unauthorized = 0;
                consecutive_errors = 0;

                if first_heartbeat {
                    info!("✓ Successfully registered with ConnLog");
                    first_heartbeat = false;
                }

                // Check for remote uninstall command
                if response.uninstall {
                    warn!("Received remote uninstall command from server");
                    trigger_self_uninstall("Remote uninstall requested by workspace owner");
                    return Ok(());
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
                thread::sleep(Duration::from_secs(config.heartbeat_interval_secs));
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
                    trigger_self_uninstall("Token rejected too many times (likely deleted or revoked)");
                    return Ok(());
                }

                // Exponential backoff for unauthorized - wait longer each time
                let backoff = std::cmp::min(60 * consecutive_unauthorized as u64, 3600);
                thread::sleep(Duration::from_secs(backoff));
            }
            Err(ApiError::Decommissioned) => {
                warn!("Agent has been decommissioned (410 Gone). Self-uninstalling...");
                trigger_self_uninstall("Agent was decommissioned by the server");
                return Ok(());
            }
            Err(e) => {
                consecutive_errors += 1;
                // Exponential backoff: 30, 60, 120, 240, ... capped at 3600s
                let backoff = std::cmp::min(
                    30 * 2u64.pow(consecutive_errors.saturating_sub(1).min(7)),
                    3600,
                );
                error!("Heartbeat failed: {} (retry in {}s)", e, backoff);
                thread::sleep(Duration::from_secs(backoff));
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

    // Check if we're running as a systemd service
    let is_systemd = std::env::var("INVOCATION_ID").is_ok();

    if is_systemd {
        info!("UNINSTALL: Running as systemd service — writing uninstall marker");

        // Write uninstall marker file — ExecStopPost will detect this
        match std::fs::write("/run/connlog/.uninstall_requested", reason) {
            Ok(_) => {
                info!("UNINSTALL: Marker written to /run/connlog/.uninstall_requested");
                info!("UNINSTALL: Exiting process. systemd ExecStopPost will complete cleanup.");
            }
            Err(e) => {
                error!("UNINSTALL: Failed to write marker file: {}. Attempting direct uninstall.", e);
                // Fallback: try direct uninstall (may fail without privileges)
                if let Err(e) = install::uninstall() {
                    error!("UNINSTALL: Direct uninstall also failed: {}", e);
                }
            }
        }
    } else {
        info!("UNINSTALL: Not running as systemd service — performing direct uninstall");
        if let Err(e) = install::uninstall() {
            error!("UNINSTALL: Direct uninstall failed: {}", e);
        }
    }

    // Exit cleanly — Restart=on-failure means systemd will NOT restart us
    std::process::exit(0);
}

/// Response from a successful heartbeat
struct HeartbeatResult {
    config_outdated: bool,
    latest_config_version: Option<u32>,
    uninstall: bool,
}

fn send_heartbeat(client: &ApiClient, config: &AgentConfig) -> Result<HeartbeatResult, ApiError> {
    // Collect system metrics
    let metrics = SystemMetrics::collect().map_err(ApiError::Other)?;

    // Respect server-side metrics toggles
    let payload_metrics = if config.any_metrics_enabled() {
        heartbeat::Metrics {
            cpu_percent: if config.metrics.cpu { metrics.cpu_percent } else { 0.0 },
            memory_used_mb: if config.metrics.memory { metrics.memory_used_mb } else { 0 },
            memory_total_mb: if config.metrics.memory { metrics.memory_total_mb } else { 0 },
            disk_used_mb: if config.metrics.disk { metrics.disk_used_mb } else { 0 },
            disk_total_mb: if config.metrics.disk { metrics.disk_total_mb } else { 0 },
            load_1m: if config.metrics.load { metrics.load_1m } else { 0.0 },
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
    })
}
