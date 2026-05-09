use clap::{Parser, Subcommand};
use std::fmt;

#[derive(Parser)]
#[command(name = "connlog-agent")]
#[command(about = "ConnLog monitoring agent")]
#[command(
    long_about = "ConnLog monitoring agent\n\nRegister with a token from the ConnLog dashboard, then keep sending heartbeats. For production hosts, install the agent as a systemd service instead of leaving a foreground shell running."
)]
#[command(
    after_help = "Common usage:\n  Register and run in the foreground:\n    connlog-agent register --token agent_xxxxxxxxxxxx\n\n  Install, register, and start as a systemd service:\n    sudo connlog-agent install --token agent_xxxxxxxxxxxx\n\n  Use an environment variable instead of putting the token in shell history:\n    sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent install\n\n  Verify an existing install without starting another heartbeat loop:\n    sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent check-config\n    sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent test-heartbeat\n\nNotes:\n  The token is shown once in ConnLog under Agents -> Add Agent and must start with agent_.\n  The register command does not install a service; it runs until stopped. Use install for servers."
)]
#[command(version)]
pub struct Config {
    #[command(subcommand)]
    pub command: Option<AgentCommand>,

    /// Agent authentication token
    #[arg(
        short,
        long,
        env = "CONNLOG_TOKEN",
        global = true,
        value_name = "TOKEN"
    )]
    pub token: Option<String>,

    /// Legacy alias for `install`
    #[arg(short, long, help_heading = "Legacy flags")]
    pub install: bool,

    /// Legacy alias for `uninstall`
    #[arg(short, long, help_heading = "Legacy flags")]
    pub uninstall: bool,

    /// Legacy alias for `status`
    #[arg(short, long, help_heading = "Legacy flags")]
    pub status: bool,

    /// Legacy alias for `update`
    #[arg(long, help_heading = "Legacy flags")]
    pub update: bool,

    /// Diagnostic: fetch + print the agent config from the platform without
    /// starting the heartbeat loop. Exits non-zero on auth/network failure.
    #[arg(long = "check-config", help_heading = "Legacy flags")]
    pub check_config: bool,

    /// Diagnostic: send exactly one heartbeat and print the platform's
    /// response, then exit. Exits non-zero on auth/network failure.
    #[arg(long = "test-heartbeat", help_heading = "Legacy flags")]
    pub test_heartbeat: bool,

    /// Print the embedded systemd service file and exit (used by self-updater)
    #[arg(long = "emit-service", hide = true)]
    pub emit_service: bool,

    #[cfg(debug_assertions)]
    /// Custom platform endpoint (debug builds only)
    #[arg(
        short,
        long,
        env = "CONNLOG_ENDPOINT",
        help = "Platform endpoint URL (debug builds only)",
        global = true
    )]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum AgentCommand {
    /// Register with ConnLog and run in the foreground
    #[command(
        long_about = "Register with ConnLog using an agent token and run the heartbeat loop in the foreground.\n\nThis command is useful for manual testing and containers. It does not install or start a systemd service, and it keeps running until stopped.\n\nExamples:\n  connlog-agent register --token agent_xxxxxxxxxxxx\n  CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent register"
    )]
    Register,

    /// Install, register, and start as a systemd service
    #[command(
        long_about = "Install connlog-agent as a systemd service, write the token to /etc/connlog/agent.conf, start the service, and let the service register with ConnLog.\n\nUse this on normal Linux servers.\n\nExamples:\n  sudo connlog-agent install --token agent_xxxxxxxxxxxx\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent install"
    )]
    Install,

    /// Uninstall the systemd service and remove agent files
    Uninstall,

    /// Show the systemd service status
    Status,

    /// Check for and apply the latest release
    Update,

    /// Fetch and print platform config, then exit
    #[command(
        long_about = "Fetch the agent config from the platform and print it, then exit without starting another heartbeat loop.\n\nUse this after installing to verify that the token and platform connectivity are correct.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent check-config\n  connlog-agent check-config --token agent_xxxxxxxxxxxx"
    )]
    CheckConfig,

    /// Send one heartbeat, print the response, then exit
    #[command(
        long_about = "Send exactly one heartbeat to the platform, print the response, then exit without starting the normal retry loop.\n\nUse this as a smoke test after registration or service changes.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent test-heartbeat\n  connlog-agent test-heartbeat --token agent_xxxxxxxxxxxx"
    )]
    TestHeartbeat,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("command", &self.command)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("install", &self.install)
            .field("uninstall", &self.uninstall)
            .field("status", &self.status)
            .field("update", &self.update)
            .field("check_config", &self.check_config)
            .field("test_heartbeat", &self.test_heartbeat)
            .field("emit_service", &self.emit_service)
            .finish()
    }
}

impl Config {
    pub fn get_platform_url(&self) -> Option<String> {
        // Check environment variable set by systemd service
        std::env::var("CONNLOG_PLATFORM_URL").ok()
    }

    /// Resolve the platform endpoint:
    ///   1. `--endpoint` CLI flag (debug builds only)
    ///   2. `CONNLOG_PLATFORM_URL` env (set by systemd EnvironmentFile)
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

    #[test]
    fn register_subcommand_accepts_token_after_command() {
        let cfg = Config::parse_from(["connlog-agent", "register", "--token", "agent_example"]);
        assert_eq!(cfg.command, Some(AgentCommand::Register));
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));
    }

    #[test]
    fn install_subcommand_accepts_env_token_style() {
        let cfg = Config::parse_from(["connlog-agent", "install"]);
        assert_eq!(cfg.command, Some(AgentCommand::Install));
    }

    #[test]
    fn legacy_install_flag_still_parses() {
        let cfg = Config::parse_from(["connlog-agent", "--install", "--token", "agent_example"]);
        assert!(cfg.install);
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));
    }

    #[test]
    fn diagnostic_subcommands_parse() {
        let cfg = Config::parse_from(["connlog-agent", "check-config", "--token", "agent_example"]);
        assert_eq!(cfg.command, Some(AgentCommand::CheckConfig));
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));

        let cfg = Config::parse_from([
            "connlog-agent",
            "test-heartbeat",
            "--token",
            "agent_example",
        ]);
        assert_eq!(cfg.command, Some(AgentCommand::TestHeartbeat));
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));
    }

    #[test]
    fn help_explains_register_command() {
        use clap::CommandFactory;

        let help = Config::command().render_long_help().to_string();
        assert!(help.contains("connlog-agent register --token agent_xxxxxxxxxxxx"));
        assert!(help.contains("The register command does not install a service"));
        assert!(help.contains("sudo connlog-agent install --token agent_xxxxxxxxxxxx"));
        assert!(help.contains("Commands:"));
        assert!(help.contains("check-config"));
        assert!(help.contains("test-heartbeat"));
    }
}
