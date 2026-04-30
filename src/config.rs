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

    /// Print the embedded systemd service file and exit (used by self-updater)
    #[arg(long = "emit-service", hide = true)]
    pub emit_service: bool,

    /// Internal: process was launched by the Windows SCM. Hand off to the
    /// service dispatcher instead of running interactively.
    #[arg(long = "run-service", hide = true)]
    pub run_service: bool,

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
            .field("emit_service", &self.emit_service)
            .field("run_service", &self.run_service)
            .finish()
    }
}

impl Config {
    pub fn get_platform_url(&self) -> Option<String> {
        // Check environment variable set by systemd service
        std::env::var("CONNLOG_PLATFORM_URL").ok()
    }

    /// Resolve the platform endpoint using the same precedence on every code
    /// path (interactive run + Windows service dispatcher):
    ///   1. `--endpoint` CLI flag (debug builds only)
    ///   2. `CONNLOG_PLATFORM_URL` env (set by systemd / DPAPI config)
    ///   3. `default` (the compiled-in `DEFAULT_ENDPOINT`)
    pub fn resolve_endpoint(&self, default: &str) -> String {
        #[cfg(debug_assertions)]
        {
            self.endpoint
                .clone()
                .or_else(|| self.get_platform_url())
                .unwrap_or_else(|| default.to_string())
        }
        #[cfg(not(debug_assertions))]
        {
            self.get_platform_url()
                .unwrap_or_else(|| default.to_string())
        }
    }

    /// Build a Config out of band — used by the Windows service dispatcher
    /// which loads the token from the DPAPI-encrypted on-disk config rather
    /// than from CLI flags.
    #[cfg(windows)]
    pub fn for_service(token: String, platform_url: String) -> Self {
        // Stash the URL in env so `get_platform_url()` finds it (keeps the
        // existing endpoint-resolution code path unchanged).
        // SAFETY: set_var is unsafe in std 1.78+ but we're early in the
        // service start-up before any threads exist.
        unsafe {
            std::env::set_var("CONNLOG_PLATFORM_URL", &platform_url);
        }
        Self {
            token: Some(token),
            install: false,
            uninstall: false,
            status: false,
            update: false,
            emit_service: false,
            run_service: true,
            #[cfg(debug_assertions)]
            endpoint: None,
        }
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
