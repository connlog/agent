use clap::Parser;

#[derive(Parser, Debug)]
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

impl Config {
    pub fn get_platform_url(&self) -> Option<String> {
        // Check environment variable set by systemd service
        std::env::var("CONNLOG_PLATFORM_URL").ok()
    }
}
