use clap::Parser;
use std::fmt;

#[derive(Parser)]
#[command(name = "connlog-agent")]
#[command(about = "ConnLog monitoring agent", long_about = None)]
#[command(version)]
pub struct Config {
    /// Agent authentication token
    #[arg(short, long, env = "CONNLOG_TOKEN")]
    pub token: Option<String>,

    /// Install agent as systemd service and start it
    #[arg(short, long)]
    pub install: bool,

    /// Uninstall agent (stop service, remove files)
    #[arg(short, long)]
    pub uninstall: bool,

    /// Show agent service status
    #[arg(short, long)]
    pub status: bool,

    /// Print the embedded systemd service file and exit (used by self-updater)
    #[arg(long = "emit-service", hide = true)]
    pub emit_service: bool,

    #[cfg(debug_assertions)]
    /// Custom platform endpoint (debug builds only)
    #[arg(
        short,
        long,
        env = "CONNLOG_ENDPOINT",
        help = "Platform endpoint URL (debug builds only)"
    )]
    pub endpoint: Option<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("install", &self.install)
            .field("uninstall", &self.uninstall)
            .field("status", &self.status)
            .field("emit_service", &self.emit_service)
            .finish()
    }
}

impl Config {
    pub fn get_platform_url(&self) -> Option<String> {
        // Check environment variable set by systemd service
        std::env::var("CONNLOG_PLATFORM_URL").ok()
    }
}
