#[cfg(feature = "dev-mode")]
use anyhow::{Context, Result};
#[cfg(feature = "dev-mode")]
use log::{error, info, warn};
#[cfg(feature = "dev-mode")]
use rand::Rng;
#[cfg(feature = "dev-mode")]
use std::thread;
#[cfg(feature = "dev-mode")]
use std::time::Duration;

#[cfg(feature = "dev-mode")]
use crate::heartbeat::{HeartbeatPayload, Metrics};
#[cfg(feature = "dev-mode")]
use crate::http::ApiClient;
#[cfg(feature = "dev-mode")]
use crate::metrics::SystemMetrics;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: u32 = 1;

pub struct DevConfig {
    pub token: String,
    pub endpoint: String,
    pub interval: u64,
    pub fake_metrics: bool,
    pub simulate_offline: bool,
    pub simulate_high_cpu: bool,
    pub simulate_heartbeat_drop: Option<u64>,
}

pub fn run(config: DevConfig) -> Result<()> {
    // Print dev mode banner
    print_banner(&config);

    // Validate token format
    if !config.token.starts_with("agent_") {
        error!("Invalid token format - must start with 'agent_'");
        std::process::exit(1);
    }

    let client = ApiClient::new(config.endpoint.clone(), config.token.clone());
    let mut heartbeat_count = 0u64;
    let mut first_heartbeat = true;

    info!("Starting heartbeat loop (interval: {}s)", config.interval);

    // Main loop
    loop {
        heartbeat_count += 1;

        // Simulate heartbeat drop
        if let Some(drop_every) = config.simulate_heartbeat_drop {
            if heartbeat_count % drop_every == 0 {
                warn!("[SIMULATION] Dropping heartbeat #{}", heartbeat_count);
                thread::sleep(Duration::from_secs(config.interval));
                continue;
            }
        }

        // Simulate offline
        if config.simulate_offline && should_go_offline() {
            warn!("[SIMULATION] Going offline for 30s");
            thread::sleep(Duration::from_secs(30));
            continue;
        }

        match send_heartbeat(&client, &config, heartbeat_count) {
            Ok(interval) => {
                if first_heartbeat {
                    info!("✓ Successfully registered with ConnLog");
                    first_heartbeat = false;
                }
                info!(
                    "Heartbeat #{} sent successfully, next in {}s",
                    heartbeat_count, interval
                );
                thread::sleep(Duration::from_secs(config.interval));
            }
            Err(e) => {
                error!("Heartbeat failed: {}", e);
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

fn send_heartbeat(client: &ApiClient, config: &DevConfig, count: u64) -> Result<u64> {
    // Collect or generate metrics
    let metrics = if config.fake_metrics {
        generate_fake_metrics(config, count)
    } else {
        SystemMetrics::collect().context("Failed to collect system metrics")?
    };

    // Build heartbeat payload
    let mut payload = HeartbeatPayload {
        agent_version: AGENT_VERSION.to_string(),
        protocol_version: PROTOCOL_VERSION,
        hostname: metrics.hostname.clone(),
        os: metrics.os.clone(),
        arch: metrics.arch.clone(),
        uptime_seconds: metrics.uptime_seconds,
        metrics: Metrics {
            cpu_percent: metrics.cpu_percent,
            memory_used_mb: metrics.memory_used_mb,
            memory_total_mb: metrics.memory_total_mb,
            disk_used_mb: metrics.disk_used_mb,
            disk_total_mb: metrics.disk_total_mb,
            load_1m: metrics.load_1m,
        },
        dev_mode: Some(true),
    };

    // Apply simulation overrides
    if config.simulate_high_cpu {
        payload.metrics.cpu_percent = 95.0;
    }

    // Send heartbeat
    let response = client.send_heartbeat(&payload)?;

    Ok(response.expected_interval_seconds)
}

fn generate_fake_metrics(config: &DevConfig, count: u64) -> SystemMetrics {
    let mut rng = rand::thread_rng();

    // Generate slightly fluctuating values
    let cpu_base = if config.simulate_high_cpu { 95.0 } else { 25.0 };
    let cpu_percent = cpu_base + rng.gen_range(-5.0..5.0);

    let memory_total_mb = 16384;
    let memory_used_mb = (memory_total_mb as f64 * 0.6 + rng.gen_range(-500.0..500.0)) as u64;

    let disk_total_mb = 512000;
    let disk_used_mb = (disk_total_mb as f64 * 0.4 + rng.gen_range(-1000.0..1000.0)) as u64;

    let load_1m = 1.5 + rng.gen_range(-0.5..0.5);

    SystemMetrics {
        hostname: format!("dev-agent-{}", std::process::id()),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        uptime_seconds: count * 10,
        cpu_percent,
        memory_used_mb,
        memory_total_mb,
        disk_used_mb,
        disk_total_mb,
        load_1m,
    }
}

fn should_go_offline() -> bool {
    let mut rng = rand::thread_rng();
    rng.gen_ratio(1, 20) // 5% chance each check
}

fn print_banner(config: &DevConfig) {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                                                              ║");
    println!("║              🔧 ConnLog Agent (DEV MODE) 🔧                  ║");
    println!("║                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let masked_token = mask_token(&config.token);
    println!("  Version:          v{}", AGENT_VERSION);
    println!("  Token:            {}", masked_token);
    println!("  Endpoint:         {}", config.endpoint);
    println!("  Interval:         {}s", config.interval);
    println!("  Fake Metrics:     {}", config.fake_metrics);

    if config.simulate_offline {
        println!("  ⚠️  SIMULATION:     Random offline");
    }
    if config.simulate_high_cpu {
        println!("  ⚠️  SIMULATION:     High CPU (95%)");
    }
    if let Some(n) = config.simulate_heartbeat_drop {
        println!("  ⚠️  SIMULATION:     Drop every {}th heartbeat", n);
    }

    println!("\n{}", "─".repeat(64));
    println!("  Press Ctrl+C to stop\n");
}

fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        return "*".repeat(token.len());
    }
    let visible = &token[token.len() - 4..];
    format!("********{}", visible)
}
