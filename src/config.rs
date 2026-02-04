use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "connlog-agent")]
#[command(about = "ConnLog monitoring agent", long_about = None)]
#[command(version)]
pub struct Config {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Agent authentication token (required for run mode)
    #[arg(short, long, env = "CONNLOG_TOKEN", global = true)]
    pub token: Option<String>,

    /// Platform API URL
    #[arg(
        short,
        long,
        env = "CONNLOG_PLATFORM_URL",
        default_value = "http://localhost:3000",
        global = true
    )]
    pub platform_url: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install agent as systemd service
    Install {
        /// Agent authentication token
        #[arg(short, long, env = "CONNLOG_TOKEN")]
        token: String,

        /// Platform API URL
        #[arg(
            short,
            long,
            env = "CONNLOG_PLATFORM_URL",
            default_value = "https://connlog.com"
        )]
        platform_url: String,
    },
    /// Uninstall agent systemd service
    Uninstall,
    /// Show agent status
    Status,
    #[cfg(feature = "dev-mode")]
    /// Run agent in development mode (foreground, localhost, shorter intervals)
    Dev {
        /// Agent authentication token
        #[arg(short, long, env = "CONNLOG_TOKEN")]
        token: String,

        /// Platform API URL
        #[arg(
            short,
            long,
            env = "CONNLOG_PLATFORM_URL",
            default_value = "http://localhost:3000"
        )]
        endpoint: String,

        /// Heartbeat interval in seconds
        #[arg(long, default_value = "10")]
        interval: u64,

        /// Use fake metrics instead of real system metrics
        #[arg(long)]
        fake_metrics: bool,

        /// Simulate random offline behavior (skip heartbeats)
        #[arg(long)]
        simulate_offline: bool,

        /// Simulate high CPU usage (95%)
        #[arg(long)]
        simulate_high_cpu: bool,

        /// Drop every Nth heartbeat
        #[arg(long)]
        simulate_heartbeat_drop: Option<u64>,
    },
}
