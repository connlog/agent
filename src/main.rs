use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::thread;
use std::time::Duration;

mod config;
mod heartbeat;
mod http;
mod metrics;
mod install;
#[cfg(feature = "dev-mode")]
mod dev;

use config::{Commands, Config};
use heartbeat::HeartbeatPayload;
use http::ApiClient;
use metrics::SystemMetrics;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: u32 = 1;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::parse();

    // Handle subcommands
    match config.command {
        Some(Commands::Install { token, platform_url }) => {
            return install::install(&token, &platform_url);
        }
        Some(Commands::Uninstall) => {
            return install::uninstall();
        }
        Some(Commands::Status) => {
            return install::status();
        }
        #[cfg(feature = "dev-mode")]
        Some(Commands::Dev {
            token,
            endpoint,
            interval,
            fake_metrics,
            simulate_offline,
            simulate_high_cpu,
            simulate_heartbeat_drop,
        }) => {
            let dev_config = dev::DevConfig {
                token,
                endpoint,
                interval,
                fake_metrics,
                simulate_offline,
                simulate_high_cpu,
                simulate_heartbeat_drop,
            };
            return dev::run(dev_config);
        }
        None => {
            // Run mode - require token
            if config.token.is_none() {
                error!("Token is required. Use --token or set CONNLOG_TOKEN environment variable.");
                error!("Example: connlog-agent --token agent_xxx");
                std::process::exit(1);
            }

            let token = config.token.unwrap();
            return run_agent(token, config.platform_url);
        }
    }
}

fn run_agent(token: String, platform_url: String) -> Result<()> {
    info!("ConnLog Agent v{} starting", AGENT_VERSION);
    info!("Platform URL: {}", platform_url);

    // Never log the token - security critical
    if !token.starts_with("agent_") {
        error!("Invalid token format - must start with 'agent_'");
        std::process::exit(1);
    }

    let client = ApiClient::new(platform_url, token);
    let mut first_heartbeat = true;

    // Main loop
    loop {
        match send_heartbeat(&client) {
            Ok(interval) => {
                if first_heartbeat {
                    info!("✓ Successfully registered with ConnLog");
                    first_heartbeat = false;
                }
                info!("Heartbeat sent successfully, next in {}s", interval);
                thread::sleep(Duration::from_secs(interval));
            }
            Err(e) => {
                error!("Heartbeat failed: {}", e);
                // Exponential backoff on failure
                thread::sleep(Duration::from_secs(30));
            }
        }
    }
}

fn send_heartbeat(client: &ApiClient) -> Result<u64> {
    // Collect system metrics
    let metrics = SystemMetrics::collect()?;

    // Build heartbeat payload
    let payload = HeartbeatPayload {
        agent_version: AGENT_VERSION.to_string(),
        protocol_version: PROTOCOL_VERSION,
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

    Ok(response.expected_interval_seconds)
}
