//! `connlog-agent` with no arguments, typed by a person in a terminal: an
//! arrow-key menu for this machine's agent instead of a list of subcommands.
//!
//! Who gets the menu is decided once, by [`opens_menu`], before anything else
//! runs. The systemd unit starts the daemon with the same bare command
//! (`ExecStart=/usr/local/bin/connlog-agent`), on every host, including ones
//! whose unit was never refreshed, so the rule is strict: only no arguments,
//! a terminal on both stdin and stdout, no systemd `INVOCATION_ID` and no
//! `CONNLOG_TOKEN` in the environment. Anything else runs exactly what it ran
//! before this module existed.
//!
//! Every setting goes through the same `install::set_*` functions the
//! `config` subcommands call, so the menu and the CLI cannot drift. Settings
//! live in the root-only `/etc/connlog/agent.conf`: without root the menu
//! shows what it can and offers to reopen itself with sudo. It never prints
//! the token or the BMC password, and passes nothing to sudo but the binary.

use anyhow::Result;
use dialoguer::console::{style, Term};
use dialoguer::{Confirm, Input, Select};
use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::DiagnosticsFormat;
use crate::defaults::DEFAULT_ENDPOINT;
use crate::features::heartbeat_telemetry::{default_state_dir, load_events};
use crate::install;
use crate::platform::SAFE_PATH;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What [`opens_menu`] decides from: the process's arguments, its terminals
/// and the two environment variables that say it is not a person at a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// Arguments after the program name.
    pub args: usize,
    pub stdin_tty: bool,
    pub stdout_tty: bool,
    /// systemd sets `INVOCATION_ID` for every unit it starts.
    pub under_systemd: bool,
    /// `CONNLOG_TOKEN` in the environment is run-mode configuration: whoever
    /// set it wants the agent, not a menu.
    pub token_in_env: bool,
}

impl Launch {
    pub fn from_parts(
        argv: impl IntoIterator<Item = OsString>,
        stdin_tty: bool,
        stdout_tty: bool,
        env_has: impl Fn(&str) -> bool,
    ) -> Self {
        Self {
            args: argv.into_iter().count().saturating_sub(1),
            stdin_tty,
            stdout_tty,
            under_systemd: env_has("INVOCATION_ID"),
            token_in_env: env_has("CONNLOG_TOKEN"),
        }
    }

    pub fn current() -> Self {
        Self::from_parts(
            std::env::args_os(),
            io::stdin().is_terminal(),
            io::stdout().is_terminal(),
            |name| std::env::var_os(name).is_some(),
        )
    }
}

/// True only for a bare `connlog-agent` typed into a terminal. Everything
/// else, the systemd unit above all, keeps running the daemon or the
/// subcommand it asked for.
pub fn opens_menu(launch: &Launch) -> bool {
    launch.args == 0
        && launch.stdin_tty
        && launch.stdout_tty
        && !launch.under_systemd
        && !launch.token_in_env
}

/// The settings the menu toggles, as this host's agent.conf has them. `None`
/// for all of them without root: the file is not readable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct HostSettings {
    remote_reboot: Option<bool>,
    hostname: Option<bool>,
    postmortem: Option<bool>,
}

impl HostSettings {
    fn from_conf(conf: Option<&str>) -> Self {
        let Some(conf) = conf else {
            return Self::default();
        };
        Self {
            remote_reboot: Some(install::conf_allows_remote_reboot(conf)),
            hostname: Some(install::conf_bool(conf, "CONNLOG_EXPOSE_SYSTEM_INFO").unwrap_or(false)),
            postmortem: Some(install::conf_bool(conf, "CONNLOG_SHARE_POSTMORTEM").unwrap_or(false)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    RemoteReboot,
    Hostname,
    Postmortem,
    Status,
    CheckConfig,
    TestHeartbeat,
    Diagnostics,
    Uninstall,
    Quit,
}

/// Which choices need root (they read or write agent.conf, or remove the agent).
fn needs_root(choice: Choice) -> bool {
    matches!(
        choice,
        Choice::RemoteReboot
            | Choice::Hostname
            | Choice::Postmortem
            | Choice::CheckConfig
            | Choice::TestHeartbeat
            | Choice::Uninstall
    )
}

fn setting_label(name: &str, value: Option<bool>) -> String {
    let value = match value {
        Some(true) => "on".to_string(),
        Some(false) => "off".to_string(),
        None => "needs sudo".to_string(),
    };
    format!("{name:<20}{value}")
}

/// The menu, in order: the three toggles, then the one-off actions.
fn menu_items(settings: &HostSettings) -> Vec<(Choice, String)> {
    vec![
        (
            Choice::RemoteReboot,
            setting_label("Remote reboot", settings.remote_reboot),
        ),
        (
            Choice::Hostname,
            setting_label("Hostname sharing", settings.hostname),
        ),
        (
            Choice::Postmortem,
            setting_label("Crash reports", settings.postmortem),
        ),
        (Choice::Status, "Service status".to_string()),
        (Choice::CheckConfig, "Check config with ConnLog".to_string()),
        (Choice::TestHeartbeat, "Send a test heartbeat".to_string()),
        (
            Choice::Diagnostics,
            "Heartbeat diagnostics (last 24 hours)".to_string(),
        ),
        (Choice::Uninstall, "Uninstall the agent".to_string()),
        (Choice::Quit, "Quit".to_string()),
    ]
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// `systemctl is-active connlog-agent`, in its own words.
fn service_state() -> String {
    Command::new("systemctl")
        .env("PATH", SAFE_PATH)
        .args(["is-active", "connlog-agent"])
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|state| !state.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// When the platform last accepted a heartbeat, from the telemetry the
/// running agent writes (readable by root and the service account).
fn last_heartbeat() -> String {
    let loaded = load_events(
        &default_state_dir(),
        Duration::from_secs(7 * 24 * 60 * 60),
        500,
        SystemTime::now(),
    );
    if loaded.unreadable {
        return "not readable without sudo".to_string();
    }
    loaded
        .events
        .iter()
        .rev()
        .find(|event| event.outcome == "accepted")
        .map(|event| event.timestamp_utc.clone())
        .unwrap_or_else(|| "none in the last 7 days".to_string())
}

fn print_header(term: &Term, root: bool) {
    let _ = term.clear_screen();
    println!(
        "{}",
        style(format!("ConnLog agent v{AGENT_VERSION}")).bold()
    );
    println!("  Service          {}", service_state());
    println!("  Last heartbeat   {}", last_heartbeat());
    if !root {
        println!(
            "  {}",
            style("Settings are in /etc/connlog/agent.conf, which needs sudo to read or change.")
                .dim()
        );
    } else if !std::path::Path::new(install::SYSTEMD_SERVICE_PATH).exists() {
        println!(
            "  {}",
            style("Not installed here. Install with: sudo connlog-agent install --token <token>")
                .dim()
        );
    }
    println!();
}

/// Run the menu until the person quits, presses Esc, or presses Ctrl-C.
pub fn run() -> Result<()> {
    // Ctrl-C while a prompt reads a key: console restores the terminal mode
    // and raises SIGINT. With the stop handler installed that only sets a
    // flag, the prompt returns an error, and the loop below shows the cursor
    // again and leaves. A second Ctrl-C exits at once, as for the daemon.
    let interrupted = Arc::new(AtomicBool::new(false));
    crate::platform::signals::install_stop_handlers(&interrupted);

    let term = Term::stdout();
    let result = menu_loop(&term);
    let _ = term.show_cursor();
    match result {
        Ok(()) => Ok(()),
        Err(err) if is_interrupt(&err) => {
            println!();
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn is_interrupt(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let io = match cause.downcast_ref::<dialoguer::Error>() {
            Some(dialoguer::Error::IO(io)) => Some(io),
            None => cause.downcast_ref::<io::Error>(),
        };
        io.is_some_and(|io| io.kind() == io::ErrorKind::Interrupted)
    })
}

fn menu_loop(term: &Term) -> Result<()> {
    let mut selected = 0;
    loop {
        let root = is_root();
        // Root with no file is a host the agent was never installed on (or
        // was removed from): every setting is at its default, not unknown.
        let conf = root.then(|| install::read_agent_conf().unwrap_or_default());
        let settings = HostSettings::from_conf(conf.as_deref());
        let items = menu_items(&settings);

        print_header(term, root);
        let labels: Vec<&str> = items.iter().map(|(_, label)| label.as_str()).collect();
        let Some(index) = Select::new()
            .with_prompt("Choose with the arrow keys, Enter to select, Esc to quit")
            .items(&labels)
            .default(selected)
            .interact_on_opt(term)?
        else {
            return Ok(());
        };
        selected = index;
        let choice = items[index].0;
        if choice == Choice::Quit {
            return Ok(());
        }

        if needs_root(choice) && !root {
            offer_sudo(term)?;
            continue;
        }

        if let Err(err) = act(choice, &settings, conf.as_deref()) {
            if is_interrupt(&err) {
                return Err(err);
            }
            println!("{} {err:#}", style("Error:").red().bold());
        }
        if choice == Choice::Uninstall
            && !std::path::Path::new(install::SYSTEMD_SERVICE_PATH).exists()
        {
            return Ok(());
        }
        pause(term)?;
    }
}

/// Reopen with sudo: replaces this process with `sudo <this binary>`, no
/// arguments, so nothing secret is ever on a command line. Comes back here
/// only if the person says no or sudo cannot be started.
fn offer_sudo(term: &Term) -> Result<()> {
    let yes = Confirm::new()
        .with_prompt("This needs root. Reopen the menu with sudo?")
        .default(true)
        .interact_on(term)?;
    if !yes {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let err = Command::new("sudo").arg(exe).exec();
    println!(
        "{} could not start sudo ({err}). Run `sudo connlog-agent` yourself.",
        style("Error:").red().bold()
    );
    pause(term)
}

fn pause(term: &Term) -> Result<()> {
    println!();
    println!("{}", style("Press any key to go back to the menu.").dim());
    term.read_key()?;
    Ok(())
}

fn confirm_toggle(name: &str, now: bool) -> Result<bool> {
    let verb = if now { "off" } else { "on" };
    Ok(Confirm::new()
        .with_prompt(format!(
            "Turn {name} {verb}? The agent restarts to apply it."
        ))
        .default(false)
        .interact()?)
}

fn act(choice: Choice, settings: &HostSettings, conf: Option<&str>) -> Result<()> {
    match choice {
        Choice::RemoteReboot => {
            let now = settings.remote_reboot.unwrap_or(false);
            if confirm_toggle("remote reboot", now)? {
                install::set_remote_reboot(!now)?;
            }
        }
        Choice::Hostname => {
            let now = settings.hostname.unwrap_or(false);
            if confirm_toggle("hostname sharing", now)? {
                install::set_hostname_sharing(!now)?;
            }
        }
        Choice::Postmortem => {
            let now = settings.postmortem.unwrap_or(false);
            if confirm_toggle("crash reports", now)? {
                install::set_postmortem_sharing(!now)?;
            }
        }
        Choice::Status => install::status()?,
        Choice::CheckConfig | Choice::TestHeartbeat => {
            let conf = conf.unwrap_or_default();
            let Some(token) = install::conf_value(conf, "CONNLOG_TOKEN") else {
                anyhow::bail!("No token in /etc/connlog/agent.conf. Is the agent installed?");
            };
            let endpoint = install::conf_value(conf, "CONNLOG_PLATFORM_URL")
                .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
            if choice == Choice::CheckConfig {
                crate::run_check_config(token, endpoint)?;
            } else {
                crate::run_test_heartbeat(token, endpoint)?;
            }
        }
        Choice::Diagnostics => {
            crate::features::heartbeat_telemetry::run_diagnostics_cli(
                "24h",
                100,
                DiagnosticsFormat::Text,
            )?;
        }
        Choice::Uninstall => {
            let typed: String = Input::new()
                .with_prompt(
                    "This stops the agent and removes it, its settings and its local history. Type uninstall to confirm",
                )
                .allow_empty(true)
                .interact_text()?;
            if typed.trim() == "uninstall" {
                install::uninstall()?;
            } else {
                println!("Not uninstalled.");
            }
        }
        Choice::Quit => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(argv: &[&str], tty: bool, env: &[&str]) -> Launch {
        Launch::from_parts(argv.iter().map(OsString::from), tty, tty, |name| {
            env.contains(&name)
        })
    }

    #[test]
    fn a_bare_command_in_a_terminal_opens_the_menu() {
        assert!(opens_menu(&launch(&["connlog-agent"], true, &[])));
    }

    #[test]
    fn systemd_always_gets_the_daemon() {
        // As the unit starts it: no arguments, no terminal, INVOCATION_ID and
        // the token from the EnvironmentFile.
        assert!(!opens_menu(&launch(
            &["/usr/local/bin/connlog-agent"],
            false,
            &["INVOCATION_ID", "CONNLOG_TOKEN"]
        )));
        // INVOCATION_ID alone is enough, even with a terminal attached
        // (`systemd-run --pty`, `StandardInput=tty`).
        assert!(!opens_menu(&launch(
            &["connlog-agent"],
            true,
            &["INVOCATION_ID"]
        )));
        // No terminal alone is enough, without systemd (a container
        // entrypoint, a pipe, cron).
        assert!(!opens_menu(&launch(&["connlog-agent"], false, &[])));
    }

    #[test]
    fn the_unit_still_starts_the_bare_binary() {
        // If the unit ever gained arguments this module's rule would need
        // revisiting; if it lost INVOCATION_ID's guarantee, the test above
        // says what still protects it.
        let exec = install::SYSTEMD_SERVICE
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .expect("ExecStart");
        assert_eq!(exec, "ExecStart=/usr/local/bin/connlog-agent");
    }

    #[test]
    fn a_single_stdio_terminal_is_not_enough() {
        let mut half = launch(&["connlog-agent"], true, &[]);
        half.stdout_tty = false;
        assert!(!opens_menu(&half));
        let mut half = launch(&["connlog-agent"], true, &[]);
        half.stdin_tty = false;
        assert!(!opens_menu(&half));
    }

    #[test]
    fn every_argument_keeps_its_meaning() {
        for argv in [
            &["connlog-agent", "install"][..],
            &["connlog-agent", "status"],
            &["connlog-agent", "register"],
            &["connlog-agent", "config", "enable-hostname"],
            &["connlog-agent", "diagnostics", "heartbeats"],
            &["connlog-agent", "--install"],
            &["connlog-agent", "--status"],
            &["connlog-agent", "--update"],
            &["connlog-agent", "--check-config"],
            &["connlog-agent", "--test-heartbeat"],
            &["connlog-agent", "--emit-service"],
            &["connlog-agent", "--token", "agent_x"],
            &["connlog-agent", "--help"],
            &["connlog-agent", "--version"],
        ] {
            assert!(!opens_menu(&launch(argv, true, &[])), "{argv:?}");
        }
    }

    #[test]
    fn a_token_in_the_environment_runs_the_agent() {
        assert!(!opens_menu(&launch(
            &["connlog-agent"],
            true,
            &["CONNLOG_TOKEN"]
        )));
    }

    #[test]
    fn settings_read_as_the_agent_reads_them() {
        let conf = "CONNLOG_TOKEN=\"agent_secret\"\nCONNLOG_EXPOSE_SYSTEM_INFO=\"true\"\nCONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\n";
        assert_eq!(
            HostSettings::from_conf(Some(conf)),
            HostSettings {
                remote_reboot: Some(false),
                hostname: Some(true),
                postmortem: Some(false),
            }
        );
        assert_eq!(HostSettings::from_conf(None), HostSettings::default());
    }

    #[test]
    fn remote_reboot_reads_off_unless_set_to_true() {
        for (line, allowed) in [
            ("", false),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=maybe\n", false),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\n", false),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=\"true\"\n", true),
        ] {
            let conf = format!("CONNLOG_TOKEN=\"agent_x\"\n{line}");
            assert_eq!(
                HostSettings::from_conf(Some(&conf)).remote_reboot,
                Some(allowed),
                "{line:?}"
            );
        }
    }

    #[test]
    fn the_menu_never_shows_a_secret() {
        let conf = concat!(
            "CONNLOG_TOKEN=\"agent_0123456789abcdef\"\n",
            "CONNLOG_BMC_ENDPOINT=\"https://10.0.0.120\"\n",
            "CONNLOG_BMC_USERNAME=\"root\"\n",
            "CONNLOG_BMC_PASSWORD=\"hunter2-bmc\"\n",
        );
        for settings in [HostSettings::from_conf(Some(conf)), HostSettings::default()] {
            for (_, label) in menu_items(&settings) {
                for secret in ["agent_0123456789abcdef", "hunter2-bmc", "10.0.0.120"] {
                    assert!(!label.contains(secret), "{label}");
                }
            }
        }
    }

    #[test]
    fn without_root_settings_say_so_and_ask_for_sudo() {
        let items = menu_items(&HostSettings::default());
        assert!(items[..3]
            .iter()
            .all(|(_, label)| label.ends_with("needs sudo")));
        for (choice, _) in &items {
            let expected = !matches!(choice, Choice::Status | Choice::Diagnostics | Choice::Quit);
            assert_eq!(needs_root(*choice), expected, "{choice:?}");
        }
    }
}
