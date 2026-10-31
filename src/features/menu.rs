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
//! Every setting is one of `features::settings`, the table `config set`
//! reads, and is written by the same `install::set_agent_conf_values`, so the
//! menu and the CLI cannot drift. Changes are staged and applied together,
//! with one restart the agent is watched through (owner, 2026-10-31); a
//! setting says what it sends before it is turned on. Settings live in the
//! root-only agent.conf: without root the menu shows what it can and offers
//! to reopen itself with sudo. It never prints the token, the BMC password
//! or the BMC's address, and passes nothing to sudo but the binary.

use anyhow::Result;
use dialoguer::console::{style, Term};
use dialoguer::{Confirm, Input, Password, Select};
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
use crate::features::settings::{switch_word, Kind, LEVELS, SETTINGS};
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

/// The settings the menu shows, by their place in `SETTINGS`, in its order.
/// The BMC's are one item of their own.
const SHOWN: &[&str] = &[
    "hostname",
    "remote-reboot",
    "postmortem",
    "discovery",
    "network-site",
    "network-map-ports",
    "probe-public",
    "checks",
    "collector",
];
const BMC: [&str; 4] = [
    "bmc-endpoint",
    "bmc-username",
    "bmc-password",
    "bmc-insecure-tls",
];

fn index(name: &str) -> usize {
    SETTINGS
        .iter()
        .position(|s| s.name == name)
        .expect("a setting the menu names is in the table")
}

/// The settings as the menu shows and changes them: the file as read (`None`
/// without root, which cannot read it) and the changes staged until Apply.
#[derive(Debug, Clone, Default)]
struct Draft {
    conf: Option<String>,
    staged: Vec<(usize, String)>,
}

impl Draft {
    /// A setting's value in the file.
    fn saved(&self, at: usize) -> Option<String> {
        self.conf
            .as_deref()
            .and_then(|conf| install::conf_value(conf, SETTINGS[at].key))
    }

    fn staged(&self, at: usize) -> Option<&str> {
        self.staged
            .iter()
            .find(|(i, _)| *i == at)
            .map(|(_, v)| v.as_str())
    }

    /// What the menu works from: the staged value, else the file's.
    fn value(&self, at: usize) -> Option<String> {
        self.staged(at)
            .map(str::to_string)
            .or_else(|| self.saved(at))
    }

    /// Stage `value`; staging what the file already means drops the change.
    fn stage(&mut self, at: usize, value: String) {
        self.staged.retain(|(i, _)| *i != at);
        if !same(at, self.saved(at).as_deref(), &value) {
            self.staged.push((at, value));
        }
    }

    fn bmc_set_up(&self) -> bool {
        BMC[..3]
            .iter()
            .all(|name| self.value(index(name)).is_some_and(|v| !v.is_empty()))
    }

    fn pairs(&self) -> Vec<(&'static str, &str)> {
        self.staged
            .iter()
            .map(|(i, v)| (SETTINGS[*i].key, v.as_str()))
            .collect()
    }
}

/// Whether `value` means what the file's `saved` does: a switch's word, a
/// level, else the text; unset is off, the lowest level or empty.
fn same(at: usize, saved: Option<&str>, value: &str) -> bool {
    match SETTINGS[at].kind {
        Kind::Switch { .. } => {
            saved.and_then(switch_word).unwrap_or(false) == switch_word(value).unwrap_or(false)
        }
        Kind::Level => saved.unwrap_or("off").eq_ignore_ascii_case(value),
        _ => saved.unwrap_or_default() == value,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    Setting(usize),
    Bmc,
    Apply,
    Discard,
    CheckSettings,
    Status,
    CheckConfig,
    TestHeartbeat,
    Diagnostics,
    Uninstall,
    Quit,
}

/// Which choices need root (they read or write agent.conf, or remove the agent).
fn needs_root(choice: Choice) -> bool {
    !matches!(choice, Choice::Status | Choice::Diagnostics | Choice::Quit)
}

fn setting_label(draft: &Draft, at: usize) -> String {
    let setting = &SETTINGS[at];
    if draft.conf.is_none() {
        return format!("{:<20}needs sudo", setting.title);
    }
    let saved = setting.shown(draft.saved(at).as_deref());
    match draft.staged(at) {
        Some(next) => format!(
            "{:<20}{saved} → {}",
            setting.title,
            setting.shown(Some(next))
        ),
        None => format!("{:<20}{saved}", setting.title),
    }
}

fn bmc_label(draft: &Draft) -> String {
    let title = "BMC hardware health";
    if draft.conf.is_none() {
        return format!("{title:<20}needs sudo");
    }
    let mut saved = draft.clone();
    saved.staged.clear();
    let word = |set_up: bool| if set_up { "set up" } else { "not set up" };
    let now = word(saved.bmc_set_up());
    if BMC.iter().any(|name| draft.staged(index(name)).is_some()) {
        format!("{title:<20}{now} → {}", word(draft.bmc_set_up()))
    } else {
        format!("{title:<20}{now}")
    }
}

/// The menu, in order: the settings, Apply and Discard while changes are
/// staged, then the one-off actions.
fn menu_items(draft: &Draft) -> Vec<(Choice, String)> {
    let mut items: Vec<(Choice, String)> = SHOWN
        .iter()
        .map(|name| {
            let at = index(name);
            (Choice::Setting(at), setting_label(draft, at))
        })
        .collect();
    items.push((Choice::Bmc, bmc_label(draft)));
    let staged = draft.staged.len();
    if staged > 0 {
        let s = if staged == 1 { "" } else { "s" };
        items.push((
            Choice::Apply,
            format!("Apply {staged} change{s} (the agent restarts once)"),
        ));
        items.push((Choice::Discard, "Discard changes".to_string()));
    }
    items.extend([
        (Choice::CheckSettings, "Check these settings".to_string()),
        (Choice::Status, "Service status".to_string()),
        (Choice::CheckConfig, "Check config with ConnLog".to_string()),
        (Choice::TestHeartbeat, "Send a test heartbeat".to_string()),
        (
            Choice::Diagnostics,
            "Heartbeat diagnostics (last 24 hours)".to_string(),
        ),
        (Choice::Uninstall, "Uninstall the agent".to_string()),
        (Choice::Quit, "Quit".to_string()),
    ]);
    items
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
    let mut staged = Vec::new();
    loop {
        let root = is_root();
        // Root with no file is a host the agent was never installed on (or
        // was removed from): every setting is at its default, not unknown.
        let conf = root.then(|| {
            install::conf::Host::current()
                .and_then(install::conf::Host::read)
                .unwrap_or_default()
        });
        let mut draft = Draft {
            conf,
            staged: std::mem::take(&mut staged),
        };
        let items = menu_items(&draft);

        print_header(term, root);
        let labels: Vec<&str> = items.iter().map(|(_, label)| label.as_str()).collect();
        let picked = Select::new()
            .with_prompt("Choose with the arrow keys, Enter to select, Esc to quit")
            .items(&labels)
            .default(selected.min(items.len() - 1))
            .interact_on_opt(term)?;
        let choice = picked.map_or(Choice::Quit, |i| items[i].0);
        selected = picked.unwrap_or(selected);
        if choice == Choice::Quit {
            return leave(&mut draft);
        }

        if needs_root(choice) && !root {
            offer_sudo(term)?;
            continue;
        }

        let outcome = act(choice, &mut draft);
        staged = std::mem::take(&mut draft.staged);
        if let Err(err) = outcome {
            if is_interrupt(&err) {
                return Err(err);
            }
            println!("{} {err:#}", style("Error:").red().bold());
        } else if matches!(choice, Choice::Setting(_) | Choice::Bmc | Choice::Discard) {
            // Staged: back to the list, which shows it.
            continue;
        }
        if choice == Choice::Uninstall
            && !std::path::Path::new(install::SYSTEMD_SERVICE_PATH).exists()
        {
            return Ok(());
        }
        pause(term)?;
    }
}

/// Leaving with staged changes: apply them (one restart) or let them go.
fn leave(draft: &mut Draft) -> Result<()> {
    let staged = draft.staged.len();
    if staged == 0 {
        return Ok(());
    }
    let s = if staged == 1 { "" } else { "s" };
    let apply = Confirm::new()
        .with_prompt(format!(
            "Apply {staged} staged change{s} before leaving? The agent restarts once."
        ))
        .default(true)
        .interact()?;
    if apply {
        install::set_agent_conf_values(&draft.pairs())?;
    } else {
        println!("Left without changing anything.");
    }
    Ok(())
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

fn edit(draft: &mut Draft, at: usize) -> Result<()> {
    let setting = &SETTINGS[at];
    println!("\n{}\n{}", style(setting.title).bold(), setting.about);
    match setting.kind {
        Kind::Switch { .. } => {
            let on = !draft
                .value(at)
                .as_deref()
                .and_then(switch_word)
                .unwrap_or(false);
            if on && !setting.sends.is_empty() {
                println!("\n{}", setting.sends);
            }
            let verb = if on { "on" } else { "off" };
            if Confirm::new()
                .with_prompt(format!("Turn {} {verb}?", setting.title.to_lowercase()))
                .default(false)
                .interact()?
            {
                draft.stage(at, on.to_string());
            }
        }
        Kind::Level => {
            println!();
            for (level, sends) in LEVELS {
                println!("  {level:<8} {sends}");
            }
            let now = draft.value(at).unwrap_or_else(|| "off".to_string());
            let levels: Vec<&str> = LEVELS.iter().map(|(level, _)| *level).collect();
            let default = levels.iter().position(|l| *l == now).unwrap_or(0);
            if let Some(i) = Select::new()
                .with_prompt("Choose a level, Esc to leave it as it is")
                .items(&levels)
                .default(default)
                .interact_opt()?
            {
                draft.stage(at, levels[i].to_string());
            }
        }
        _ => {
            let typed: String = Input::new()
                .with_prompt(format!("{} (empty clears it)", setting.title))
                .with_initial_text(draft.value(at).unwrap_or_default())
                .allow_empty(true)
                .validate_with(|v: &String| setting.parse(v).map(|_| ()))
                .interact_text()?;
            let value = setting.parse(&typed).map_err(anyhow::Error::msg)?;
            draft.stage(at, value);
        }
    }
    Ok(())
}

/// The BMC's address, user, password (never shown) and certificate choice,
/// staged together; an empty address clears all of them.
fn edit_bmc(draft: &mut Draft) -> Result<()> {
    let [endpoint, user, password, self_signed] = BMC.map(index);
    println!(
        "\n{}\n{}",
        style("BMC hardware health").bold(),
        SETTINGS[endpoint].sends
    );
    let address: String = Input::new()
        .with_prompt("Its address, such as https://10.0.0.120 (empty turns it off)")
        .with_initial_text(draft.value(endpoint).unwrap_or_default())
        .allow_empty(true)
        .validate_with(|v: &String| SETTINGS[endpoint].parse(v).map(|_| ()))
        .interact_text()?;
    if address.trim().is_empty() {
        for at in [endpoint, user, password] {
            draft.stage(at, String::new());
        }
        return Ok(());
    }
    let name: String = Input::new()
        .with_prompt("User")
        .with_initial_text(draft.value(user).unwrap_or_default())
        .interact_text()?;
    let secret = Password::new()
        .with_prompt("Password (not shown)")
        .with_confirmation("Once more", "The two differ; try again")
        .interact()?;
    let accept = Confirm::new()
        .with_prompt("Accept its self-signed certificate? iDRAC and iLO usually have one.")
        .default(
            draft
                .value(self_signed)
                .as_deref()
                .and_then(switch_word)
                .unwrap_or(true),
        )
        .interact()?;
    draft.stage(endpoint, address.trim().to_string());
    draft.stage(user, name.trim().to_string());
    draft.stage(password, secret);
    draft.stage(self_signed, accept.to_string());
    Ok(())
}

fn act(choice: Choice, draft: &mut Draft) -> Result<()> {
    match choice {
        Choice::Setting(at) => edit(draft, at)?,
        Choice::Bmc => edit_bmc(draft)?,
        Choice::Apply => {
            install::set_agent_conf_values(&draft.pairs())?;
            draft.staged.clear();
        }
        Choice::Discard => draft.staged.clear(),
        Choice::CheckSettings => crate::features::settings::run_check()?,
        Choice::Status => install::status()?,
        Choice::CheckConfig | Choice::TestHeartbeat => {
            let conf = draft.conf.as_deref().unwrap_or_default();
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

    fn draft(conf: &str) -> Draft {
        Draft {
            conf: Some(conf.to_string()),
            staged: Vec::new(),
        }
    }

    fn label(items: &[(Choice, String)], title: &str) -> String {
        items
            .iter()
            .find(|(_, label)| label.starts_with(title))
            .map(|(_, label)| label.clone())
            .unwrap_or_else(|| panic!("no {title} in the menu"))
    }

    #[test]
    fn settings_read_as_the_agent_reads_them() {
        let conf = "CONNLOG_TOKEN=\"agent_secret\"\nCONNLOG_EXPOSE_SYSTEM_INFO=\"true\"\nCONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\nCONNLOG_DISCOVERY=\"passive\"\n";
        let items = menu_items(&draft(conf));
        assert!(label(&items, "Hostname sharing").ends_with("on"));
        assert!(label(&items, "Remote reboot").ends_with("off"));
        assert!(label(&items, "Crash reports").ends_with("off (default)"));
        assert!(label(&items, "Discovery").ends_with("passive"));
        assert!(label(&items, "BMC hardware health").ends_with("not set up"));
        // Nothing staged, nothing to apply.
        assert!(!items.iter().any(|(choice, _)| *choice == Choice::Apply));
    }

    #[test]
    fn changes_are_staged_shown_and_applied_together() {
        let mut d = draft("CONNLOG_TOKEN=\"agent_x\"\nCONNLOG_DISCOVERY=\"peers\"\n");
        d.stage(index("discovery"), "active".into());
        d.stage(index("checks"), "true".into());
        // What the file already means is no change: unset is off.
        d.stage(index("postmortem"), "false".into());
        let items = menu_items(&d);
        assert_eq!(
            label(&items, "Discovery"),
            format!("{:<20}peers → active", "Discovery")
        );
        assert!(label(&items, "Checks").ends_with("off (default) → on"));
        assert!(label(&items, "Crash reports").ends_with("off (default)"));
        assert_eq!(
            label(&items, "Apply"),
            "Apply 2 changes (the agent restarts once)"
        );
        assert_eq!(
            d.pairs(),
            vec![("CONNLOG_DISCOVERY", "active"), ("CONNLOG_CHECKS", "true")]
        );
        // Staging the file's value again drops the change.
        d.stage(index("discovery"), "peers".into());
        assert_eq!(d.pairs(), vec![("CONNLOG_CHECKS", "true")]);
    }

    #[test]
    fn remote_reboot_reads_off_unless_set_to_true() {
        for (line, word) in [
            ("", "off (default)"),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\n", "off"),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=\"true\"\n", "on"),
        ] {
            let conf = format!("CONNLOG_TOKEN=\"agent_x\"\n{line}");
            assert!(
                label(&menu_items(&draft(&conf)), "Remote reboot").ends_with(word),
                "{line:?}"
            );
        }
        let odd = draft("CONNLOG_ALLOW_REMOTE_REBOOT=maybe\n");
        assert!(label(&menu_items(&odd), "Remote reboot").contains("not on or off"));
    }

    #[test]
    fn the_menu_never_shows_a_secret() {
        let conf = concat!(
            "CONNLOG_TOKEN=\"agent_0123456789abcdef\"\n",
            "CONNLOG_BMC_ENDPOINT=\"https://10.0.0.120\"\n",
            "CONNLOG_BMC_USERNAME=\"root\"\n",
            "CONNLOG_BMC_PASSWORD=\"hunter2-bmc\"\n",
        );
        let mut staged = draft(conf);
        staged.stage(index("bmc-password"), "an0ther-secret".into());
        for d in [draft(conf), staged, Draft::default()] {
            for (_, label) in menu_items(&d) {
                for secret in [
                    "agent_0123456789abcdef",
                    "hunter2-bmc",
                    "an0ther-secret",
                    "10.0.0.120",
                ] {
                    assert!(!label.contains(secret), "{label}");
                }
            }
        }
        assert!(label(&menu_items(&draft(conf)), "BMC hardware health").ends_with("set up"));
    }

    #[test]
    fn without_root_settings_say_so_and_ask_for_sudo() {
        let items = menu_items(&Draft::default());
        for (choice, label) in &items {
            if matches!(choice, Choice::Setting(_) | Choice::Bmc) {
                assert!(label.ends_with("needs sudo"), "{label}");
            }
            let expected = !matches!(choice, Choice::Status | Choice::Diagnostics | Choice::Quit);
            assert_eq!(needs_root(*choice), expected, "{choice:?}");
        }
    }
}
