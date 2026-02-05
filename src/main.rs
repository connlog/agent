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

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::parse();

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

    // Fetch runtime config from server
    info!("Fetching runtime configuration...");
    let mut config = match client.fetch_config() {
        Ok(cfg) => {
            info!("✓ Loaded config v{} (interval={}s)", cfg.version, cfg.heartbeat_interval_secs);
            cfg
        }
        Err(e) => {
            error!("Failed to fetch config: {}", e);
            error!("Agent cannot start without valid configuration");
            std::process::exit(1);
        }
    };

    let mut first_heartbeat = true;
    let mut consecutive_unauthorized = 0u32;

    // Main loop
    loop {
        match send_heartbeat(&client, &config) {
            Ok(response) => {
                // Reset unauthorized counter on success
                consecutive_unauthorized = 0;

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
                    info!("Config outdated (current: v{}, latest: v{}), fetching update...",
                          config.version, response.latest_config_version.unwrap_or(0));
                    match client.fetch_config() {
                        Ok(new_config) => {
                            info!("✓ Updated config to v{} (interval={}s)",
                                  new_config.version, new_config.heartbeat_interval_secs);
                            config = new_config;
                        }
                        Err(e) => {
                            error!("Failed to fetch updated config: {}", e);
                            // Continue with old config
                        }
                    }
                }

                info!("Heartbeat sent successfully, next in {}s", response.interval);
                thread::sleep(Duration::from_secs(response.interval));
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
                error!("Heartbeat failed: {}", e);
                // Exponential backoff on failure
                thread::sleep(Duration::from_secs(30));
            }
        }
    }
}

/// Trigger self-uninstallation of the agent
fn trigger_self_uninstall(reason: &str) {
    warn!("Self-uninstalling: {}", reason);

    // Check if we're running as a systemd service
    let is_systemd = std::env::var("INVOCATION_ID").is_ok();

    if is_systemd {
        info!("Running as systemd service - attempting graceful uninstall");

        // Spawn uninstall process in background so we can exit cleanly
        // The uninstall will stop the service which includes this process
        let _ = std::process::Command::new("sh")
            .args([
                "-c",
                "sleep 2 && sudo /usr/local/bin/connlog-agent --uninstall 2>/dev/null || \
                 (sudo systemctl stop connlog-agent && sudo systemctl disable connlog-agent && \
                  sudo rm -f /etc/systemd/system/connlog-agent.service && \
                  sudo systemctl daemon-reload && \
                  sudo rm -rf /etc/connlog && \
                  sudo rm -f /usr/local/bin/connlog-agent)"
            ])
            .spawn();

        info!("Uninstall scheduled. Agent shutting down.");
    } else {
        info!("Not running as systemd service - just exiting");
    }

    std::process::exit(0);
}

/// Response from a successful heartbeat
struct HeartbeatResult {
    interval: u64,
    config_outdated: bool,
    latest_config_version: Option<u32>,
    uninstall: bool,
}

fn send_heartbeat(client: &ApiClient, config: &AgentConfig) -> Result<HeartbeatResult, ApiError> {
    // Collect system metrics
    let metrics = SystemMetrics::collect().map_err(|e| ApiError::Other(e))?;

    // Build heartbeat payload
    let payload = HeartbeatPayload {
        agent_version: AGENT_VERSION.to_string(),
        protocol_version: PROTOCOL_VERSION,
        config_version: config.version,
        hostname: metrics.hostname.clone(),
        os: metrics.os.clone(),
        arch: metrics.arch.clone(),
        uptime_seconds: metrics.uptime_seconds,
        metrics: heartbeat::Metrics {
            cpu_percent: metrics.cpu_percent,
            memory_used_mb: metrics.memory_used_mb,
            memory_total_mb: metrics.memory_total_mb,
            disk_used_mb: metrics.disk_used_mb,
            disk_total_mb: metrics.disk_total_mb,
            load_1m: metrics.load_1m,
        },
        dev_mode: None,
    };

    // Send heartbeat
    let response = client.send_heartbeat(&payload)?;

    Ok(HeartbeatResult {
        interval: response.expected_interval_seconds,
        config_outdated: response.config_outdated.unwrap_or(false),
        latest_config_version: response.latest_config_version,
        uninstall: response.uninstall,
    })
}
