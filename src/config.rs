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

    /// Check for and apply the latest update from GitHub
    #[arg(long)]
    pub update: bool,

    /// Force-apply the latest update, bypassing the compiled-in Ed25519 signing-key check.
    /// Use this to bootstrap agents that were built without CONNLOG_SIGNING_PUBLIC_KEY.
    /// SHA-256 integrity is still verified. Requires root (writes to /usr/local/bin).
    #[arg(long = "force-update")]
    pub force_update: bool,

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
            .field("update", &self.update)
            .field("force_update", &self.force_update)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// SECURITY-CRITICAL: the bearer token must NEVER appear in any rendered
    /// `Config`. Regressing this would leak tokens into journalctl, panics, etc.
    /// Lifted to a hard test so a careless `#[derive(Debug)]` swap can't sneak
    /// past review.
    #[test]
    fn debug_redacts_token() {
        let cfg = Config::parse_from(["connlog-agent", "--token", "agent_super_secret_xyz"]);
        let rendered = format!("{:?}", cfg);
        assert!(
            !rendered.contains("agent_super_secret_xyz"),
            "Debug must NEVER include the raw token, got: {}",
            rendered
        );
        assert!(
            rendered.contains("REDACTED"),
            "Expected [REDACTED] marker, got: {}",
            rendered
        );
    }

    #[test]
    fn debug_handles_missing_token_without_panic() {
        let cfg = Config::parse_from(["connlog-agent", "--status"]);
        let rendered = format!("{:?}", cfg);
        // Either "None" or absence of REDACTED is fine — the only thing that's
        // not fine is a panic or a leaked token (and there's no token here).
        assert!(rendered.contains("token"));
    }
}
