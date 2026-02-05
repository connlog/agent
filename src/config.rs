use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "connlog-agent")]
#[command(about = "ConnLog monitoring agent", long_about = None)]
#[command(version)]
pub struct Config {
    /// Agent authentication token
    #[arg(short, long, env = "CONNLOG_TOKEN")]
    pub token: Option<String>,

    /// Install agent as systemd service
    #[arg(long)]
    pub install: bool,

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
