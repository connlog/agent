//! `agent.conf` as each kind of host keeps it, and how a change is put in
//! place: written beside the file and renamed over it, the agent restarted on
//! it and watched until ConnLog accepts a heartbeat. When the agent does not
//! come back, the previous file goes back and the agent is restarted on that
//! (owner, 2026-10-31): a typo in a setting must never leave a host unwatched,
//! and the command must never say "Restarted" over an agent that is down.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use super::freebsd;
use super::linux::{
    create_config_dir, escape_env_value, is_root, restrict, system_command, SYSTEMD_SERVICE_PATH,
};
use crate::features::heartbeat_telemetry;
use crate::platform::{Packaging, STATE_DIR};

/// How long a restarted agent has to show it is back: its first heartbeat
/// follows its config fetch, seconds after it starts.
const COMEBACK: Duration = Duration::from_secs(45);
const LOOK_EVERY: Duration = Duration::from_millis(500);

/// Where, and in what form, a host keeps `agent.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// install.sh's systemd service: `NAME="value"`, escaped as systemd reads
    /// an EnvironmentFile, in a 0600 root:root file.
    Systemd,
    /// The FreeBSD package (OPNsense, pfSense): `NAME=value`, which the rc
    /// script reads line by line and never evaluates, so nothing is quoted,
    /// in a 0640 root:connlog file.
    Freebsd,
}

impl Host {
    /// This host; `None` in a container, whose settings are its environment.
    pub fn current() -> Option<Self> {
        match Packaging::current() {
            Packaging::Docker => None,
            Packaging::Freebsd => Some(Host::Freebsd),
            Packaging::Systemd => Some(Host::Systemd),
        }
    }

    pub fn path(self) -> &'static Path {
        Path::new(match self {
            Host::Systemd => AGENT_CONF_PATH,
            Host::Freebsd => freebsd::CONF,
        })
    }

    /// The file as it is, when this process may read it (root).
    pub fn read(self) -> Option<String> {
        fs::read_to_string(self.path()).ok()
    }

    /// `key=value` as this host's file writes it.
    fn line(self, key: &str, value: &str) -> String {
        match self {
            Host::Systemd => format!("{key}=\"{}\"\n", escape_env_value(value)),
            Host::Freebsd => format!("{key}={value}\n"),
        }
    }

    /// What may be written: no control character anywhere (a value is one
    /// line), and on FreeBSD no quote or backslash, which the rc script would
    /// take literally and `conf_value` would read differently.
    pub fn check_value(self, key: &str, value: &str) -> Result<()> {
        if value.chars().any(char::is_control) {
            anyhow::bail!("{key} cannot hold a control character");
        }
        if self == Host::Freebsd && value.contains(['"', '\\']) {
            anyhow::bail!("{key} cannot hold a quote or a backslash on FreeBSD");
        }
        Ok(())
    }

    /// `existing` with `key` set to `value`: the first assignment replaced,
    /// any later one dropped (the last would win), else a line appended.
    pub fn upsert(self, existing: &str, key: &str, value: &str) -> String {
        let assignment = self.line(key, value);
        let prefix = format!("{key}=");
        let mut found = false;
        let mut out = String::with_capacity(existing.len() + assignment.len());
        for line in existing.lines() {
            if line.trim_start().starts_with(&prefix) {
                if !found {
                    out.push_str(&assignment);
                    found = true;
                }
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        if !found {
            out.push_str(&assignment);
        }
        out
    }

    /// `existing` without any `key=` line: the setting back to its default.
    pub fn remove(self, existing: &str, key: &str) -> String {
        let prefix = format!("{key}=");
        existing
            .lines()
            .filter(|line| !line.trim_start().starts_with(&prefix))
            .map(|line| format!("{line}\n"))
            .collect()
    }

    /// Put `contents` in place of the file, creating its directory as the
    /// installer would.
    pub fn write(self, contents: &str) -> Result<()> {
        let dir = self
            .path()
            .parent()
            .context("agent.conf has no directory")?;
        if !dir.exists() {
            match self {
                Host::Systemd => create_config_dir()?,
                Host::Freebsd => {
                    fs::create_dir_all(dir)
                        .with_context(|| format!("Failed to create {}", dir.display()))?;
                    restrict(dir, 0o750)?;
                }
            }
        }
        match self {
            Host::Systemd => replace_file(self.path(), contents, 0o600, Owner::Root),
            Host::Freebsd => replace_file(self.path(), contents, 0o640, Owner::RootAndService),
        }
    }

    fn installed(self) -> bool {
        Path::new(match self {
            Host::Systemd => SYSTEMD_SERVICE_PATH,
            Host::Freebsd => FREEBSD_RC_SCRIPT,
        })
        .exists()
    }

    fn restart(self) -> Result<()> {
        let output = match self {
            Host::Systemd => system_command("systemctl")
                .args(["restart", "connlog-agent"])
                .output(),
            Host::Freebsd => system_command("service")
                .args(["connlog_agent", "restart"])
                .output(),
        }
        .context("Failed to restart connlog-agent")?;
        if !output.status.success() {
            let said = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to restart connlog-agent: {}", said.trim());
        }
        Ok(())
    }

    /// One look at the agent after its restart.
    fn look(self, since: SystemTime) -> Look {
        let (running, failed, restarts) = match self {
            Host::Systemd => (
                quiet_success("systemctl", &["is-active", "--quiet", "connlog-agent"]),
                quiet_success("systemctl", &["is-failed", "--quiet", "connlog-agent"]),
                systemd_restarts(),
            ),
            // daemon(8) restarts a child that exits, unseen: its status is the
            // supervisor's, and there is no count of restarts to read.
            Host::Freebsd => (
                quiet_success("service", &["connlog_agent", "status"]),
                false,
                None,
            ),
        };
        Look {
            heard: self.heard(since),
            running,
            failed,
            restarts,
        }
    }

    /// What the agent's own heartbeat log says since `since`: the outcome of
    /// a heartbeat that finished, if one did.
    fn heard(self, since: SystemTime) -> Option<Heard> {
        let now = SystemTime::now();
        let window = now.duration_since(since).unwrap_or_default() + Duration::from_secs(5);
        let since_ms = since
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let log = heartbeat_telemetry::load_events(&self.state_dir(), window, 200, now);
        let recent = log.events.iter().filter(|e| e.ts_unix_ms >= since_ms);
        let mut failed = None;
        for event in recent {
            match event.outcome.as_str() {
                "accepted" => return Some(Heard::Accepted),
                "failed" if failed.is_none() => {
                    failed = Some(
                        event
                            .detail
                            .clone()
                            .or_else(|| event.error_category.clone())
                            .unwrap_or_else(|| "no reason recorded".to_string()),
                    );
                }
                _ => {}
            }
        }
        failed.map(Heard::Failed)
    }

    /// Where the agent keeps its heartbeat log. The service is told by its
    /// unit or rc script; a root shell is not, so this says it here.
    fn state_dir(self) -> PathBuf {
        PathBuf::from(match self {
            Host::Systemd => STATE_DIR,
            Host::Freebsd => FREEBSD_STATE_DIR,
        })
    }

    /// The agent's last words since `since`, for the message when it did not
    /// come back.
    fn last_words(self, since: SystemTime) -> String {
        match self {
            Host::Systemd => {
                let at = since
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                system_command("journalctl")
                    .args(["-u", "connlog-agent", "--no-pager", "-o", "cat", "-n", "6"])
                    .arg(format!("--since=@{at}"))
                    .output()
                    .ok()
                    .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
                    .filter(|said| !said.is_empty())
                    .map(|said| format!("\nIt said:\n{}", indent(&said)))
                    .unwrap_or_default()
            }
            Host::Freebsd => "\nIts log is in /var/log/messages, tagged connlog_agent.".to_string(),
        }
    }

    /// Restart the agent on the file just written, watch it come back, and
    /// put `previous` back (or remove the file, when there was none) if it
    /// does not.
    pub fn restart_on(self, previous: Option<&str>) -> Result<()> {
        if !self.installed() {
            println!("  The agent service is not installed. The settings are saved; start the agent to apply them.");
            return Ok(());
        }
        let before = self.look(SystemTime::now()).restarts;
        let since = SystemTime::now();
        self.restart()?;
        println!("  Restarted connlog-agent; waiting for its first heartbeat…");
        let started = std::time::Instant::now();
        let verdict = loop {
            if let Some(verdict) = judge(&self.look(since), before, started.elapsed()) {
                break verdict;
            }
            std::thread::sleep(LOOK_EVERY);
        };
        match verdict {
            Verdict::Back => println!("  ✓ Back: ConnLog accepted its heartbeat."),
            Verdict::Unreachable(why) => println!(
                "  ! It runs, but its heartbeat did not reach ConnLog ({why}). The settings stay; \
                 `connlog-agent diagnostics heartbeats` shows more."
            ),
            Verdict::Running => println!(
                "  It runs; no heartbeat yet. `connlog-agent diagnostics heartbeats` shows when one goes through."
            ),
            Verdict::Down(why) => {
                let words = self.last_words(since);
                match previous {
                    Some(previous) => self.write(previous)?,
                    None => fs::remove_file(self.path()).with_context(|| {
                        format!("Failed to remove {}", self.path().display())
                    })?,
                }
                let again = self.restart();
                anyhow::bail!(
                    "connlog-agent did not come back on the new settings: {why}.{words}\n\
                     The previous settings are back{}.",
                    if again.is_ok() {
                        " and it was restarted on them"
                    } else {
                        "; restart it with `sudo systemctl restart connlog-agent`"
                    }
                );
            }
        }
        Ok(())
    }
}

const AGENT_CONF_PATH: &str = "/etc/connlog/agent.conf";
const FREEBSD_RC_SCRIPT: &str = "/usr/local/etc/rc.d/connlog_agent";
/// The rc script's `CONNLOG_STATE_DIR`.
const FREEBSD_STATE_DIR: &str = "/var/db/connlog";

/// Set each `(key, value)` in this host's agent.conf, then restart the agent
/// on it and watch it come back. Nothing is written, and nothing restarted,
/// when the file already says all of it.
pub fn set(host: Host, pairs: &[(&str, &str)]) -> Result<()> {
    if !is_root() {
        anyhow::bail!("This command requires root. Please run with sudo.");
    }
    let previous = host.read();
    let mut next = previous.clone().unwrap_or_default();
    for (key, value) in pairs {
        host.check_value(key, value)?;
        // Empty clears a setting: its line goes, rather than an empty value
        // the agent might read as set.
        next = if value.is_empty() {
            host.remove(&next, key)
        } else {
            host.upsert(&next, key, value)
        };
    }
    if previous.as_deref() == Some(next.as_str()) {
        println!(
            "  Nothing to change: {} already says that.",
            host.path().display()
        );
        return Ok(());
    }
    host.write(&next)?;
    if previous.is_none() {
        println!("  Created {}", host.path().display());
    }
    for (key, value) in pairs {
        if value.is_empty() {
            println!("  Cleared {key}");
        } else {
            println!("  Set {key}={}", shown(key, value));
        }
    }
    host.restart_on(previous.as_deref())
}

/// What a container takes in place of `config`: the same settings in its
/// environment, as `docker run` flags and as Compose lines. A secret is a
/// placeholder: this is printed, and a password never is.
pub fn docker_hint(pairs: &[(&str, &str)]) -> String {
    let value = |key: &str, value: &str| {
        if shown(key, value) == "(hidden)" {
            "<secret>".to_string()
        } else {
            value.to_string()
        }
    };
    let (cleared, set): (Vec<_>, Vec<_>) = pairs.iter().partition(|(_, v)| v.is_empty());
    let pairs = set;
    let flags = pairs
        .iter()
        .map(|(key, v)| format!("-e {}", shell_word(&format!("{key}={}", value(key, v)))))
        .collect::<Vec<_>>()
        .join(" ");
    let cleared = if cleared.is_empty() {
        String::new()
    } else {
        format!(
            "\nand remove {} from it",
            cleared
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let compose = pairs
        .iter()
        .map(|(key, v)| format!("      {key}: \"{}\"", value(key, v).replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "In Docker the agent's settings are the container's environment, not agent.conf. \
         Add to `docker run`:\n  {flags}\nor under the service's `environment:` in the Compose \
         file:\n{compose}\n{cleared}\nthen recreate the container (`docker compose up -d`)."
    )
}

/// `word` as one shell word: as it is when it is plain, else single-quoted.
fn shell_word(word: &str) -> String {
    let plain = word
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-.,:/@+=<>".contains(c));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// A value as a terminal may show it: secrets never.
fn shown<'a>(key: &str, value: &'a str) -> &'a str {
    if key.ends_with("_PASSWORD") || key == "CONNLOG_TOKEN" {
        "(hidden)"
    } else {
        value
    }
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn quiet_success(program: &str, args: &[&str]) -> bool {
    system_command(program)
        .args(args)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn systemd_restarts() -> Option<u32> {
    let out = system_command("systemctl")
        .args(["show", "connlog-agent", "--property=NRestarts", "--value"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Who may read a file besides root.
pub(super) enum Owner {
    Root,
    /// root and the service account's group (`restrict`).
    RootAndService,
}

/// Replace `path` with `contents`: written beside it, unreadable by anyone
/// else from its first byte, synced, then renamed over it, so a reader sees
/// the old file or the new one and never a part. A full disk or a crash
/// mid-write once could leave agent.conf without its token.
pub(super) fn replace_file(path: &Path, contents: &str, mode: u32, owner: Owner) -> Result<()> {
    let name = path
        .file_name()
        .context("a file to write has no name")?
        .to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.new"));
    // A leftover from a write that died is replaced, never reused: it could
    // carry looser permissions than `mode`.
    let _ = fs::remove_file(&tmp);
    let written = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        match owner {
            Owner::Root => fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?,
            Owner::RootAndService => restrict(&tmp, mode)?,
        }
        fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent().and_then(|dir| fs::File::open(dir).ok()) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.with_context(|| format!("Failed to write {}", path.display()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Heard {
    Accepted,
    /// It runs; its heartbeat failed, for a reason that is not the file's.
    Failed(String),
}

#[derive(Debug, Clone)]
struct Look {
    heard: Option<Heard>,
    running: bool,
    failed: bool,
    restarts: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Back,
    Unreachable(String),
    /// Running at the deadline with no heartbeat yet, where a crash would show.
    Running,
    Down(&'static str),
}

/// Whether the agent is back, from one look `waited` after its restart; `None`
/// to look again. A heartbeat says it, either way it went; a failed unit or a
/// restart systemd counted says it is not. Out of time, running is enough
/// where restarts are counted; elsewhere (FreeBSD's daemon(8) restarts a
/// child unseen) silence means it is not back.
fn judge(look: &Look, restarts_before: Option<u32>, waited: Duration) -> Option<Verdict> {
    match &look.heard {
        Some(Heard::Accepted) => return Some(Verdict::Back),
        Some(Heard::Failed(why)) => return Some(Verdict::Unreachable(why.clone())),
        None => {}
    }
    if look.failed {
        return Some(Verdict::Down("it stopped"));
    }
    if let (Some(before), Some(now)) = (restarts_before, look.restarts) {
        if now > before {
            return Some(Verdict::Down("it stopped right after starting"));
        }
    }
    if waited < COMEBACK {
        return None;
    }
    Some(if look.running && look.restarts.is_some() {
        Verdict::Running
    } else if look.running {
        Verdict::Down("it sent no heartbeat")
    } else {
        Verdict::Down("it is not running")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn look(heard: Option<Heard>, running: bool, failed: bool, restarts: Option<u32>) -> Look {
        Look {
            heard,
            running,
            failed,
            restarts,
        }
    }

    #[test]
    fn upsert_writes_each_hosts_form() {
        let linux = Host::Systemd.upsert("CONNLOG_TOKEN=\"agent_x\"\n", "CONNLOG_CHECKS", "true");
        assert_eq!(
            linux,
            "CONNLOG_TOKEN=\"agent_x\"\nCONNLOG_CHECKS=\"true\"\n"
        );
        let bsd = Host::Freebsd.upsert("CONNLOG_TOKEN=agent_x\n", "CONNLOG_CHECKS", "true");
        assert_eq!(bsd, "CONNLOG_TOKEN=agent_x\nCONNLOG_CHECKS=true\n");
    }

    #[test]
    fn upsert_replaces_the_first_assignment_and_drops_the_rest() {
        let body = "CONNLOG_CHECKS=\"false\"\n# kept\nCONNLOG_CHECKS=\"maybe\"\n";
        assert_eq!(
            Host::Systemd.upsert(body, "CONNLOG_CHECKS", "true"),
            "CONNLOG_CHECKS=\"true\"\n# kept\n"
        );
        assert_eq!(
            Host::Systemd.upsert("", "CONNLOG_SITE", "a\"b$c"),
            "CONNLOG_SITE=\"a\\\"b\\$c\"\n"
        );
    }

    #[test]
    fn remove_takes_every_line_of_a_setting_and_nothing_else() {
        let body = "CONNLOG_TOKEN=\"t\"\nCONNLOG_NETWORK_SITE=\"hq\"\n# note\nCONNLOG_NETWORK_SITE=\"x\"\n";
        assert_eq!(
            Host::Systemd.remove(body, "CONNLOG_NETWORK_SITE"),
            "CONNLOG_TOKEN=\"t\"\n# note\n"
        );
    }

    #[test]
    fn refuses_what_a_host_would_read_otherwise() {
        assert!(Host::Systemd
            .check_value("CONNLOG_NETWORK_SITE", "hq\nX=1")
            .is_err());
        assert!(Host::Systemd
            .check_value("CONNLOG_NETWORK_SITE", "a\"b")
            .is_ok());
        assert!(Host::Freebsd
            .check_value("CONNLOG_NETWORK_SITE", "a\"b")
            .is_err());
        assert!(Host::Freebsd
            .check_value("CONNLOG_NETWORK_SITE", "a\\b")
            .is_err());
        assert!(Host::Freebsd
            .check_value("CONNLOG_NETWORK_SITE", "hq")
            .is_ok());
    }

    #[test]
    fn a_heartbeat_ends_the_wait_either_way() {
        let soon = Duration::from_secs(2);
        assert_eq!(
            judge(
                &look(Some(Heard::Accepted), true, false, Some(0)),
                Some(0),
                soon
            ),
            Some(Verdict::Back)
        );
        assert_eq!(
            judge(
                &look(Some(Heard::Failed("timeout".into())), true, false, Some(0)),
                Some(0),
                soon
            ),
            Some(Verdict::Unreachable("timeout".into()))
        );
    }

    #[test]
    fn a_crash_is_seen_before_the_deadline() {
        let soon = Duration::from_secs(2);
        assert_eq!(
            judge(&look(None, false, true, Some(0)), Some(0), soon),
            Some(Verdict::Down("it stopped"))
        );
        assert_eq!(
            judge(&look(None, true, false, Some(3)), Some(1), soon),
            Some(Verdict::Down("it stopped right after starting"))
        );
        assert_eq!(
            judge(&look(None, true, false, Some(1)), Some(1), soon),
            None
        );
    }

    #[test]
    fn silence_at_the_deadline_counts_only_where_crashes_are_unseen() {
        let late = COMEBACK;
        assert_eq!(
            judge(&look(None, true, false, Some(0)), Some(0), late),
            Some(Verdict::Running)
        );
        assert_eq!(
            judge(&look(None, true, false, None), None, late),
            Some(Verdict::Down("it sent no heartbeat"))
        );
        assert_eq!(
            judge(&look(None, false, false, Some(0)), Some(0), late),
            Some(Verdict::Down("it is not running"))
        );
    }

    #[test]
    fn docker_hint_gives_flags_and_compose_lines_never_a_secret() {
        let hint = docker_hint(&[
            ("CONNLOG_DISCOVERY", "passive"),
            ("CONNLOG_NETWORK_SITE", "head office"),
            ("CONNLOG_BMC_PASSWORD", "hunter2"),
        ]);
        assert!(hint.contains("-e CONNLOG_DISCOVERY=passive"), "{hint}");
        assert!(
            hint.contains("-e 'CONNLOG_NETWORK_SITE=head office'"),
            "{hint}"
        );
        assert!(
            hint.contains("      CONNLOG_DISCOVERY: \"passive\""),
            "{hint}"
        );
        assert!(hint.contains("CONNLOG_BMC_PASSWORD=<secret>"), "{hint}");
        assert!(!hint.contains("hunter2"), "{hint}");
    }

    #[test]
    fn replace_file_swaps_in_the_whole_file_with_its_mode() {
        let dir = std::env::temp_dir().join(format!("connlog-conf-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.conf");
        fs::write(&path, "OLD=1\n").unwrap();
        // A leftover from a write that died, with loose permissions.
        let stale = dir.join(".agent.conf.new");
        fs::write(&stale, "stale").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).unwrap();

        replace_file(&path, "NEW=2\n", 0o600, Owner::Root).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "NEW=2\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!stale.exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
