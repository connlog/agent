use clap::{Args, Parser, Subcommand, ValueEnum};
use std::fmt;

#[derive(Parser)]
#[command(name = "connlog-agent")]
#[command(about = "ConnLog monitoring agent")]
#[command(long_about = "ConnLog monitoring agent")]
#[command(
    after_help = "Common usage:\n  sudo connlog-agent install --token agent_xxxxxxxxxxxx\n  sudo connlog-agent action add\n  sudo connlog-agent status\n\nTip:\n  Use `connlog-agent action --help` to manage dashboard buttons.\n  Use `connlog-agent diagnostics --help` for heartbeat/config checks.\n\nLegacy flags still work for existing scripts: --install, --uninstall, --status, --update, --check-config, --test-heartbeat."
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
    #[arg(short, long, hide = true)]
    pub install: bool,

    /// Legacy alias for `uninstall`
    #[arg(short, long, hide = true)]
    pub uninstall: bool,

    /// Legacy alias for `status`
    #[arg(short, long, hide = true)]
    pub status: bool,

    /// Legacy alias for `update`
    #[arg(long, hide = true)]
    pub update: bool,

    /// Diagnostic: fetch + print the agent config from the platform without
    /// starting the heartbeat loop. Exits non-zero on auth/network failure.
    #[arg(long = "check-config", hide = true)]
    pub check_config: bool,

    /// Diagnostic: send exactly one heartbeat and print the platform's
    /// response, then exit. Exits non-zero on auth/network failure.
    #[arg(long = "test-heartbeat", hide = true)]
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

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum AgentCommand {
    /// Install, register, and start as a systemd service
    #[command(
        long_about = "Install connlog-agent as a systemd service, write the token to /etc/connlog/agent.conf, start the service, and let the service register with ConnLog.\n\nUse this on normal Linux servers.\n\nExamples:\n  sudo connlog-agent install --token agent_xxxxxxxxxxxx\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent install"
    )]
    Install,

    /// Register with ConnLog and run in the foreground
    #[command(
        long_about = "Register with ConnLog using an agent token and run the heartbeat loop in the foreground.\n\nThis command is useful for manual testing and containers. It does not install or start a systemd service, and it keeps running until stopped.\n\nExamples:\n  connlog-agent register --token agent_xxxxxxxxxxxx\n  CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent register"
    )]
    Register,

    /// Show the systemd service status
    Status,

    /// Check for and apply the latest release
    Update,

    /// Manage local dashboard actions
    #[command(
        alias = "actions",
        long_about = "Manage dashboard actions registered on this agent host.\n\nActions are stored locally in /etc/connlog/actions.toml by default. The running agent reloads that file and publishes action metadata to ConnLog on the next heartbeat.\n\nThe dashboard can request registered action IDs only. Command argv stays on the agent host.",
        after_help = "Examples:\n  sudo connlog-agent action add\n  sudo connlog-agent action list\n  sudo connlog-agent action test check_disk_usage\n  sudo connlog-agent action remove check_disk_usage"
    )]
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },

    /// Diagnostic tools
    Diagnostics {
        #[command(subcommand)]
        command: DiagnosticCommand,
    },

    /// Uninstall the agent
    Uninstall,

    /// Fetch and print platform config, then exit
    #[command(
        hide = true,
        long_about = "Fetch the agent config from the platform and print it, then exit without starting another heartbeat loop.\n\nUse this after installing to verify that the token and platform connectivity are correct.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent check-config\n  connlog-agent check-config --token agent_xxxxxxxxxxxx"
    )]
    CheckConfig,

    /// Send one heartbeat, print the response, then exit
    #[command(
        hide = true,
        long_about = "Send exactly one heartbeat to the platform, print the response, then exit without starting the normal retry loop.\n\nUse this as a smoke test after registration or service changes.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent test-heartbeat\n  connlog-agent test-heartbeat --token agent_xxxxxxxxxxxx"
    )]
    TestHeartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum DiagnosticCommand {
    /// Fetch and print platform config, then exit
    #[command(
        long_about = "Fetch the agent config from the platform and print it, then exit without starting another heartbeat loop.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent diagnostics check-config\n  connlog-agent diagnostics check-config --token agent_xxxxxxxxxxxx"
    )]
    CheckConfig,

    /// Send one heartbeat, print the response, then exit
    #[command(
        long_about = "Send exactly one heartbeat to the platform, print the response, then exit without starting the normal retry loop.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent diagnostics test-heartbeat\n  connlog-agent diagnostics test-heartbeat --token agent_xxxxxxxxxxxx"
    )]
    TestHeartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum ActionCommand {
    /// Add a local dashboard action
    #[command(
        long_about = "Add a local dashboard action.\n\nRun without arguments for a beginner-friendly prompt:\n  sudo connlog-agent action add\n\nScripted usage keeps command argv local and executes without a shell:\n  sudo connlog-agent action add disk_usage --label \"Check disk usage\" --description \"Shows disk usage\" --output -- df -h"
    )]
    Add(AddActionArgs),

    /// Advanced/backward-compatible action registration
    #[command(
        long_about = "Advanced registration for local dashboard actions.\n\nThis keeps the original `actions register` workflow working. Everything after `--` is stored as an argv array and executed directly by the agent. No shell is used, and the dashboard cannot provide command text or arguments.\n\nExample:\n  sudo connlog-agent actions register disk_usage \\\n    --label \"Check disk usage\" \\\n    --description \"Shows mounted filesystem usage\" \\\n    --category Diagnostics \\\n    --risk low \\\n    --output-mode ephemeral \\\n    --timeout-seconds 10 \\\n    --max-output-bytes 8192 \\\n    -- df -h"
    )]
    Register(RegisterActionArgs),

    /// List local dashboard actions from this host
    List,

    /// Remove a local dashboard action from this host
    Remove {
        /// Local action ID to remove
        action_id: String,
    },

    /// Enable a local dashboard action
    Enable {
        /// Local action ID to enable
        action_id: String,
    },

    /// Disable a local dashboard action
    Disable {
        /// Local action ID to disable
        action_id: String,
    },

    /// Run a local action directly on this host
    Test {
        /// Local action ID to run
        action_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddActionArgs {
    /// Stable local action ID, for example `disk_usage`
    pub action_id: Option<String>,

    /// Label shown in the dashboard
    #[arg(long)]
    pub label: Option<String>,

    /// Optional dashboard description
    #[arg(long)]
    pub description: Option<String>,

    /// Optional dashboard category
    #[arg(long)]
    pub category: Option<String>,

    /// Risk level shown in the dashboard
    #[arg(long, value_enum)]
    pub risk: Option<CliActionRisk>,

    /// Require confirmation before the dashboard can request this action
    #[arg(long)]
    pub requires_confirmation: bool,

    /// Do not require confirmation, even if the command looks risky
    #[arg(long, conflicts_with = "requires_confirmation")]
    pub no_confirmation: bool,

    /// Show command output once in the dashboard
    #[arg(long, conflicts_with = "no_output")]
    pub output: bool,

    /// Hide command output from the dashboard
    #[arg(long, conflicts_with = "output")]
    pub no_output: bool,

    /// Advanced output mode override
    #[arg(long, value_enum)]
    pub output_mode: Option<CliActionOutputMode>,

    /// Action timeout in seconds, 1..=60
    #[arg(long)]
    pub timeout_seconds: Option<u64>,

    /// Maximum combined stdout/stderr bytes, up to 65536
    #[arg(long)]
    pub max_output_bytes: Option<usize>,

    /// Command argv to run on this host. Put this after `--`, for example `-- df -h`.
    #[arg(last = true, num_args = 1.., value_name = "EXEC_ARG")]
    pub exec: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct RegisterActionArgs {
    /// Stable local action ID, for example `disk_usage`
    pub action_id: Option<String>,

    /// Label shown in the dashboard
    #[arg(long)]
    pub label: Option<String>,

    /// Optional dashboard description
    #[arg(long)]
    pub description: Option<String>,

    /// Optional dashboard category
    #[arg(long)]
    pub category: Option<String>,

    /// Risk level shown in the dashboard
    #[arg(long, value_enum)]
    pub risk: Option<CliActionRisk>,

    /// Require confirmation before the dashboard can request this action
    #[arg(long)]
    pub requires_confirmation: bool,

    /// Do not require confirmation, even if the command looks risky
    #[arg(long, conflicts_with = "requires_confirmation")]
    pub no_confirmation: bool,

    /// Show command output once in the dashboard
    #[arg(long, conflicts_with = "no_output")]
    pub output: bool,

    /// Hide command output from the dashboard
    #[arg(long, conflicts_with = "output")]
    pub no_output: bool,

    /// Whether command output is hidden or shown once to the requesting browser
    #[arg(long, value_enum)]
    pub output_mode: Option<CliActionOutputMode>,

    /// Action timeout in seconds, 1..=60
    #[arg(long)]
    pub timeout_seconds: Option<u64>,

    /// Maximum combined stdout/stderr bytes, up to 65536
    #[arg(long)]
    pub max_output_bytes: Option<usize>,

    /// Command argv to run on this host. Put this after `--`, for example `-- df -h`.
    #[arg(last = true, num_args = 1.., value_name = "EXEC_ARG")]
    pub exec: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliActionRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliActionOutputMode {
    Hidden,
    Ephemeral,
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

        let cfg = Config::parse_from([
            "connlog-agent",
            "diagnostics",
            "check-config",
            "--token",
            "agent_example",
        ]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Diagnostics {
                command: DiagnosticCommand::CheckConfig
            })
        );
    }

    #[test]
    fn actions_register_subcommand_captures_exec_argv() {
        let cfg = Config::parse_from([
            "connlog-agent",
            "actions",
            "register",
            "disk_usage",
            "--label",
            "Check disk usage",
            "--output-mode",
            "ephemeral",
            "--",
            "df",
            "-h",
        ]);

        let Some(AgentCommand::Action {
            command: ActionCommand::Register(args),
        }) = cfg.command
        else {
            panic!("expected actions register command");
        };

        assert_eq!(args.action_id.as_deref(), Some("disk_usage"));
        assert_eq!(args.label.as_deref(), Some("Check disk usage"));
        assert_eq!(args.output_mode, Some(CliActionOutputMode::Ephemeral));
        assert_eq!(args.exec, ["df", "-h"]);
    }

    #[test]
    fn action_add_subcommand_supports_simple_and_scripted_forms() {
        let cfg = Config::parse_from(["connlog-agent", "action", "add"]);
        let Some(AgentCommand::Action {
            command: ActionCommand::Add(args),
        }) = cfg.command
        else {
            panic!("expected action add command");
        };
        assert!(args.action_id.is_none());
        assert!(args.exec.is_empty());

        let cfg = Config::parse_from([
            "connlog-agent",
            "action",
            "add",
            "disk_usage",
            "--label",
            "Check disk usage",
            "--description",
            "Shows disk usage",
            "--output",
            "--",
            "df",
            "-h",
        ]);
        let Some(AgentCommand::Action {
            command: ActionCommand::Add(args),
        }) = cfg.command
        else {
            panic!("expected action add command");
        };
        assert_eq!(args.action_id.as_deref(), Some("disk_usage"));
        assert_eq!(args.label.as_deref(), Some("Check disk usage"));
        assert!(args.output);
        assert_eq!(args.exec, ["df", "-h"]);

        let cfg = Config::parse_from(["connlog-agent", "actions", "add"]);
        assert!(matches!(
            cfg.command,
            Some(AgentCommand::Action {
                command: ActionCommand::Add(_)
            })
        ));
    }

    #[test]
    fn help_explains_register_command() {
        use clap::CommandFactory;

        let help = Config::command().render_long_help().to_string();
        assert!(help.contains("sudo connlog-agent install --token agent_xxxxxxxxxxxx"));
        assert!(help.contains("sudo connlog-agent action add"));
        assert!(help.contains("Commands:"));
        assert!(help.contains("action"));
        assert!(help.contains("diagnostics"));
        assert!(help.contains("Legacy flags still work"));
    }

    #[test]
    fn action_help_contains_action_examples() {
        use clap::CommandFactory;

        let mut command = Config::command();
        let action = command
            .find_subcommand_mut("action")
            .expect("action command exists");
        let help = action.render_long_help().to_string();

        assert!(help.contains("add"));
        assert!(help.contains("list"));
        assert!(help.contains("remove"));
        assert!(help.contains("enable"));
        assert!(help.contains("disable"));
        assert!(help.contains("test"));
        assert!(help.contains("sudo connlog-agent action add"));
    }
}
