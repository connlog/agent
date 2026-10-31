//! Every setting in agent.conf, by the name a person types (owner,
//! 2026-10-31). `config set`, `get`, `show` and `check`, the menu and the
//! console's one-line command all read this table, so a setting is spelled,
//! checked and explained one way. A test holds the table to the arguments
//! `Config` parses at startup, and to the protocol fixture the console reads.

use anyhow::{Context, Result};

use crate::features::checks::CONF_CHECKS;
use crate::features::discovery::{DiscoveryLevel, CONF_DISCOVERY};
use crate::features::integrations::CONF_COLLECTOR;
use crate::features::network_map::{
    parse_ports, parse_site, CONF_NETWORK_MAP, CONF_NETWORK_MAP_PORTS, CONF_NETWORK_SITE,
    CONF_PROBE_PUBLIC,
};
use crate::install::conf::Host;

/// One setting.
#[derive(Debug, Clone, Copy)]
pub struct Setting {
    /// What `config set` and the console call it: `discovery`.
    pub name: &'static str,
    /// Its line in agent.conf: `CONNLOG_DISCOVERY`.
    pub key: &'static str,
    pub kind: Kind,
    /// Its name in the menu: `Discovery`.
    pub title: &'static str,
    /// What it does, in one line, for `show` and the menu.
    pub about: &'static str,
    /// What turning it on sends or allows, said before the menu turns it on.
    pub sends: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// On or off, written `true` or `false`. Strict: the agent refuses to
    /// start on any other word (clap's boolish parser). Otherwise anything
    /// but a false word reads as on.
    Switch { strict: bool },
    /// One of the discovery levels.
    Level,
    /// A site name, as the network map takes it; others are ignored.
    Site,
    /// TCP port numbers, as the network map takes them; others are ignored.
    Ports,
    /// The BMC's address: an http(s) URL with a host, as the poller takes it.
    Address,
    /// Plain text: the BMC's user.
    Text,
    /// Whole seconds; anything else and the agent refuses to start.
    Seconds,
    /// Never on a command line and never shown: asked for, or read from stdin.
    Secret,
    /// Written by `install`; shown, never set here.
    Fixed,
}

pub const SETTINGS: &[Setting] = &[
    Setting {
        name: "hostname",
        key: "CONNLOG_EXPOSE_SYSTEM_INFO",
        kind: Kind::Switch { strict: false },
        title: "Hostname sharing",
        about: "Share this machine's hostname, kernel and exact OS version",
        sends: "ConnLog shows and keeps this machine's hostname, kernel, architecture and exact OS version (without it, only the distribution is kept).",
    },
    Setting {
        name: "remote-reboot",
        key: "CONNLOG_ALLOW_REMOTE_REBOOT",
        kind: Kind::Switch { strict: true },
        title: "Remote reboot",
        about: "Let the dashboard reboot this host",
        sends: "Nothing more is sent. The dashboard's Reboot button can restart this host; the root-side hook checks this file too.",
    },
    Setting {
        name: "postmortem",
        key: "CONNLOG_SHARE_POSTMORTEM",
        kind: Kind::Switch { strict: true },
        title: "Crash reports",
        about: "Send a crash's last warnings with its outage report",
        sends: "After a crash, power cut or hard reset: the previous boot's last journal and kernel warnings, secrets masked, at most 8 KB, with the outage report. Needs a persistent journal.",
    },
    Setting {
        name: "discovery",
        key: CONF_DISCOVERY,
        kind: Kind::Level,
        title: "Discovery",
        about: "How much this host may find out about its network: off, peers, passive, active",
        sends: "",
    },
    Setting {
        name: "network-site",
        key: CONF_NETWORK_SITE,
        kind: Kind::Site,
        title: "Network site",
        about: "The site this host's network belongs to",
        sends: "",
    },
    Setting {
        name: "network-map-ports",
        key: CONF_NETWORK_MAP_PORTS,
        kind: Kind::Ports,
        title: "Extra map ports",
        about: "Extra TCP ports the network map tests",
        sends: "",
    },
    Setting {
        name: "probe-public",
        key: CONF_PROBE_PUBLIC,
        kind: Kind::Switch { strict: true },
        title: "Public probes",
        about: "Let reachability tests reach public addresses",
        sends: "Reachability tests may reach public addresses too, not only private ones.",
    },
    Setting {
        name: "checks",
        key: CONF_CHECKS,
        kind: Kind::Switch { strict: true },
        title: "Checks",
        about: "Run the checks ConnLog assigns: ping, TCP, HTTP(S), DNS",
        sends: "Runs the checks ConnLog assigns (ping, TCP connect, HTTP(S) status and timing, DNS) and sends their results, never a response body.",
    },
    Setting {
        name: "collector",
        key: CONF_COLLECTOR,
        kind: Kind::Switch { strict: true },
        title: "Collector",
        about: "Read the integrations set up on this host",
        sends: "Reads the integrations in /etc/connlog/integrations.d every five minutes while ConnLog asks, and sends what they report. Their credentials stay on this host.",
    },
    Setting {
        name: "bmc-endpoint",
        key: "CONNLOG_BMC_ENDPOINT",
        kind: Kind::Address,
        title: "BMC address",
        about: "The BMC's Redfish address (iDRAC, iLO, OpenBMC)",
        sends: "Polls the BMC over Redfish and sends hardware health: fans, temperatures, power supplies, drives. The password stays in agent.conf.",
    },
    Setting {
        name: "bmc-username",
        key: "CONNLOG_BMC_USERNAME",
        kind: Kind::Text,
        title: "BMC user",
        about: "The BMC user",
        sends: "",
    },
    Setting {
        name: "bmc-password",
        key: "CONNLOG_BMC_PASSWORD",
        kind: Kind::Secret,
        title: "BMC password",
        about: "The BMC user's password",
        sends: "",
    },
    Setting {
        name: "bmc-poll-interval",
        key: "CONNLOG_BMC_POLL_INTERVAL_SECS",
        kind: Kind::Seconds,
        title: "BMC interval",
        about: "Seconds between BMC readings (60 to 3600, 300 unset)",
        sends: "",
    },
    Setting {
        name: "bmc-insecure-tls",
        key: "CONNLOG_BMC_INSECURE_TLS",
        kind: Kind::Switch { strict: false },
        title: "BMC self-signed",
        about: "Accept the BMC's self-signed certificate",
        sends: "",
    },
    Setting {
        name: "token",
        key: "CONNLOG_TOKEN",
        kind: Kind::Fixed,
        title: "Token",
        about: "This agent's token, written by install",
        sends: "",
    },
    Setting {
        name: "platform-url",
        key: "CONNLOG_PLATFORM_URL",
        kind: Kind::Fixed,
        title: "Platform",
        about: "Where the agent reports, written by install",
        sends: "",
    },
];

/// The discovery levels, each with what it lets the agent send.
pub const LEVELS: &[(&str, &str)] = &[
    ("off", "Nothing about the network."),
    (
        "peers",
        "The network map: this host's addresses, listening TCP port numbers, gateway and its MAC, and reachability tests to your other opted-in hosts.",
    ),
    (
        "passive",
        "Peers, and what the host already knows: VLAN ids, its neighbour table (private addresses, MAC and state) and its path out.",
    ),
    (
        "active",
        "Passive, and sweeps of its own subnets when ConnLog asks: what answers, its open well-known ports and what it announces.",
    ),
];

/// Lines the agent reads that are not settings a person changes, and why.
const OTHERS: &[(&str, &str)] = &[
    (
        CONF_NETWORK_MAP,
        "the old network map switch; `discovery` replaced it and wins over it",
    ),
    ("CONNLOG_ENDPOINT", "an override for development builds"),
    (
        "CONNLOG_ALLOWED_ENDPOINT_DOMAINS",
        "an override for development builds",
    ),
    (
        "CONNLOG_QUICK_ACTIONS_CONFIG",
        "where quick actions are kept",
    ),
    ("CONNLOG_QUICK_ACTIONS_ENABLED", "quick actions on or off"),
    ("CONNLOG_STATE_DIR", "set by the service"),
    ("CONNLOG_PACKAGING", "set by the image or the package"),
    ("CONNLOG_HOST_ROOT", "set by the image's Compose file"),
];

pub fn find(name: &str) -> Option<&'static Setting> {
    let name = name.trim();
    SETTINGS
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(name) || s.key.eq_ignore_ascii_case(name))
}

/// A switch's word as clap's boolish parser reads it.
pub(crate) fn switch_word(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "y" | "t" => Some(true),
        "false" | "0" | "no" | "off" | "n" | "f" => Some(false),
        _ => None,
    }
}

impl Setting {
    /// What a person typed, as the file holds it: `on` becomes `true`, a
    /// level is lowercased. An error says what would have been accepted.
    pub fn parse(&self, raw: &str) -> Result<String, String> {
        let value = raw.trim();
        match self.kind {
            Kind::Switch { .. } => switch_word(value)
                .map(|on| on.to_string())
                .ok_or_else(|| format!("{} is on or off, not {value:?}", self.name)),
            Kind::Level => DiscoveryLevel::parse(value)
                .map(|level| level.as_str().to_string())
                .ok_or_else(|| {
                    format!(
                        "{} is off, peers, passive or active, not {value:?}",
                        self.name
                    )
                }),
            Kind::Site => parse_site(Some(value)).map(|site| site.unwrap_or_default()),
            Kind::Ports => parse_ports(Some(value)).map(|ports| {
                ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }),
            Kind::Address => valid_address(value).map(|()| value.to_string()),
            Kind::Text => Ok(value.to_string()),
            Kind::Seconds => value
                .parse::<u64>()
                .map(|secs| secs.to_string())
                .map_err(|_| format!("{} is a whole number of seconds, not {value:?}", self.name)),
            Kind::Secret => Err(format!(
                "{} is never typed on a command line, where `ps` and the shell's history keep it: \
                 leave out the value (`config set {}`) to be asked for it",
                self.name, self.name
            )),
            Kind::Fixed => Err(format!(
                "{} is written by `connlog-agent install`, not by `config`",
                self.name
            )),
        }
    }

    /// How `show` writes a value the file holds.
    pub(crate) fn shown(&self, value: Option<&str>) -> String {
        let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
            return match self.kind {
                Kind::Switch { .. } => "off (default)".into(),
                Kind::Level => "off (default)".into(),
                Kind::Seconds => "300 (default)".into(),
                Kind::Secret => "not set".into(),
                _ => "not set".into(),
            };
        };
        match self.kind {
            Kind::Switch { strict } => match switch_word(value) {
                Some(true) => "on".into(),
                Some(false) => "off".into(),
                None if strict => format!("{value:?} (not on or off: see `config check`)"),
                None => format!("{value:?} (read as on)"),
            },
            Kind::Secret => "set".into(),
            Kind::Fixed if self.key == "CONNLOG_TOKEN" => masked_token(value),
            _ => value.to_string(),
        }
    }
}

/// An http(s) URL with a host, as the BMC poller takes it; empty clears it.
fn valid_address(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    match reqwest::Url::parse(value) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => Ok(()),
        _ => Err(format!(
            "{value:?} is not an http(s) address with a host, such as https://10.0.0.120"
        )),
    }
}

/// `agent_…3f2a`: enough to tell two tokens apart, never enough to use one.
fn masked_token(token: &str) -> String {
    let tail: String = token
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("agent_…{tail}")
}

/// A problem `check` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The agent will not start, or will not do what the line asks.
    pub serious: bool,
    pub line: String,
    pub says: String,
}

/// Every problem in an agent.conf body, in file order.
pub fn check(conf: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for line in conf.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, _)) = trimmed.split_once('=') else {
            findings.push(Finding {
                serious: false,
                line: trimmed.to_string(),
                says: "not a NAME=value line; the agent skips it".into(),
            });
            continue;
        };
        let key = key.trim();
        let value = crate::install::conf_value(trimmed, key).unwrap_or_default();
        if seen.contains(&key) {
            findings.push(Finding {
                serious: false,
                line: trimmed.to_string(),
                says: format!("{key} is set twice; the last line counts"),
            });
        }
        seen.push(key);
        if let Some(says) = judge_line(key, &value) {
            findings.push(Finding {
                serious: says.0,
                line: trimmed.to_string(),
                says: says.1,
            });
        }
    }
    if !seen.contains(&"CONNLOG_TOKEN") {
        findings.push(Finding {
            serious: true,
            line: String::new(),
            says: "CONNLOG_TOKEN is missing: the agent cannot report".into(),
        });
    }
    findings
}

/// What is wrong with one `key=value`, if anything: (serious, why).
fn judge_line(key: &str, value: &str) -> Option<(bool, String)> {
    let Some(setting) = SETTINGS.iter().find(|s| s.key == key) else {
        if OTHERS.iter().any(|(other, _)| *other == key) {
            return None;
        }
        let near = nearest(key)
            .map(|s| format!("; did you mean {} ({})?", s.key, s.name))
            .unwrap_or_default();
        return Some((
            true,
            format!("{key} is not a setting the agent reads{near}"),
        ));
    };
    let value = value.trim();
    match setting.kind {
        Kind::Switch { strict } if switch_word(value).is_none() => Some(if strict {
            (
                true,
                format!("{value:?} is not on or off: the agent will not start"),
            )
        } else {
            (
                false,
                format!("{value:?} is not on or off: the agent reads it as on"),
            )
        }),
        Kind::Level if !value.is_empty() && DiscoveryLevel::parse(value).is_none() => Some((
            true,
            format!("{value:?} is not off, peers, passive or active: the agent ignores it"),
        )),
        Kind::Site => parse_site(Some(value))
            .err()
            .map(|e| (true, format!("{e}: the agent ignores it"))),
        Kind::Ports => parse_ports(Some(value))
            .err()
            .map(|e| (true, format!("{e}: the agent ignores it"))),
        Kind::Address => valid_address(value)
            .err()
            .map(|e| (true, format!("{e}: the agent polls no BMC"))),
        Kind::Seconds if !value.is_empty() => match value.parse::<u64>() {
            Err(_) => Some((
                true,
                format!("{value:?} is not a whole number of seconds: the agent will not start"),
            )),
            Ok(secs) if !(60..=3600).contains(&secs) => Some((
                false,
                format!("{secs} seconds is outside 60 to 3600: the agent uses the nearest"),
            )),
            Ok(_) => None,
        },
        _ => None,
    }
}

/// The setting a mistyped key most likely meant, if one is close.
fn nearest(key: &str) -> Option<&'static Setting> {
    SETTINGS
        .iter()
        .map(|s| (distance(key, s.key), s))
        .filter(|(d, _)| *d <= 3)
        .min_by_key(|(d, _)| *d)
        .map(|(_, s)| s)
}

/// Levenshtein distance, case-insensitive.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.to_ascii_uppercase().chars().collect();
    let b: Vec<char> = b.to_ascii_uppercase().chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitute = previous + usize::from(ca != cb);
            previous = row[j + 1];
            row[j + 1] = substitute.min(row[j] + 1).min(previous + 1);
        }
    }
    row[b.len()]
}

/// The settings as this host holds them: the file, or in a container the
/// environment. An error says how to read them when this process may not.
fn current() -> Result<(String, &'static str)> {
    match Host::current() {
        None => Ok((
            std::env::vars()
                .filter(|(key, _)| key.starts_with("CONNLOG_"))
                .map(|(key, value)| format!("{key}={value}\n"))
                .collect(),
            "the container's environment",
        )),
        Some(host) => host
            .read()
            .map(|conf| {
                (
                    conf,
                    if host == Host::Systemd {
                        "/etc/connlog/agent.conf"
                    } else {
                        crate::install::freebsd::CONF
                    },
                )
            })
            .with_context(|| {
                format!(
                    "{} is root's to read: run this with sudo",
                    host.path().display()
                )
            }),
    }
}

/// `config set name=value ...`: every pair checked before anything is
/// written, then one write and one restart. A secret named without a value is
/// asked for, never echoed; without a terminal it is read from stdin.
pub fn run_set(pairs: &[String]) -> Result<()> {
    let mut chosen: Vec<(&'static str, String)> = Vec::new();
    for pair in pairs {
        let (name, raw) = match pair.split_once('=') {
            Some((name, raw)) => (name, Some(raw)),
            None => (pair.as_str(), None),
        };
        let setting = find(name).with_context(|| {
            let near = nearest(&format!(
                "CONNLOG_{}",
                name.replace('-', "_").to_ascii_uppercase()
            ))
            .map(|s| format!(" Did you mean {}?", s.name))
            .unwrap_or_default();
            format!("{name:?} is not a setting; `connlog-agent config show` lists them.{near}")
        })?;
        let value = match (setting.kind, raw) {
            (Kind::Secret, None) => ask_secret(setting)?,
            (_, None) => anyhow::bail!("{name} needs a value: {name}=..."),
            (_, Some(raw)) => setting.parse(raw).map_err(anyhow::Error::msg)?,
        };
        chosen.push((setting.key, value));
    }
    let pairs: Vec<(&str, &str)> = chosen.iter().map(|(k, v)| (*k, v.as_str())).collect();
    crate::install::set_agent_conf_values(&pairs)
}

fn ask_secret(setting: &Setting) -> Result<String> {
    use std::io::IsTerminal;
    let value = if std::io::stdin().is_terminal() {
        dialoguer::Password::new()
            .with_prompt(setting.about)
            .interact()
            .context("No value given")?
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("Failed to read the value from stdin")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    if value.is_empty() {
        anyhow::bail!("{} is empty; nothing was changed", setting.name);
    }
    Ok(value)
}

/// `config get name`: the value alone, for scripts; a secret is `set` or
/// `not set`.
pub fn run_get(name: &str) -> Result<()> {
    let setting = find(name).with_context(|| format!("{name:?} is not a setting"))?;
    let (conf, _) = current()?;
    let value = crate::install::conf_value(&conf, setting.key);
    let printed = match setting.kind {
        Kind::Secret | Kind::Fixed => setting.shown(value.as_deref()),
        Kind::Switch { .. } => match value.as_deref().and_then(switch_word) {
            Some(true) => "on".into(),
            _ if value.as_deref().is_some_and(|v| !v.trim().is_empty()) => {
                setting.shown(value.as_deref())
            }
            _ => "off".into(),
        },
        _ => value.unwrap_or_default(),
    };
    println!("{printed}");
    Ok(())
}

/// `config show`: every setting, its value or default, and what `check`
/// would say, in one screen.
pub fn run_show() -> Result<()> {
    let (conf, from) = current()?;
    println!("Settings in {from}:\n");
    for setting in SETTINGS {
        let value = crate::install::conf_value(&conf, setting.key);
        println!(
            "  {:<19} {:<26} {}",
            setting.name,
            setting.shown(value.as_deref()),
            setting.about
        );
    }
    let problems = check(&conf).len();
    if problems > 0 {
        println!(
            "\n{problems} problem{} found: `sudo connlog-agent config check` says what.",
            if problems == 1 { "" } else { "s" }
        );
    }
    println!("\nChange one with: sudo connlog-agent config set name=value");
    Ok(())
}

/// `config check`: what the agent would refuse, ignore or misread. Fails
/// when the agent would not start or not report.
pub fn run_check() -> Result<()> {
    let (conf, from) = current()?;
    let findings = check(&conf);
    if findings.is_empty() {
        println!("✓ {from}: every line is one the agent reads as it says.");
        return Ok(());
    }
    for finding in &findings {
        let mark = if finding.serious { "✗" } else { "!" };
        if finding.line.is_empty() {
            println!("{mark} {}", finding.says);
        } else {
            println!("{mark} {}\n    {}", redacted(&finding.line), finding.says);
        }
    }
    if findings.iter().any(|f| f.serious) {
        anyhow::bail!("{from} has settings the agent will refuse or ignore");
    }
    Ok(())
}

/// A line as `check` may print it: a token or password replaced.
fn redacted(line: &str) -> String {
    match line.split_once('=') {
        Some((key, _)) if key.ends_with("_PASSWORD") || key.trim() == "CONNLOG_TOKEN" => {
            format!("{key}=(hidden)")
        }
        _ => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Each setting is an argument `Config` reads from the environment at
    /// startup, and a strict switch is exactly one clap would refuse a bad
    /// word for: the table cannot drift from what the agent parses.
    #[test]
    fn the_table_is_what_the_agent_parses() {
        let command = crate::config::Config::command();
        let env_args: Vec<_> = command
            .get_arguments()
            .filter_map(|arg| {
                arg.get_env()
                    .map(|env| (env.to_string_lossy().to_string(), arg))
            })
            .collect();
        // What install writes is read apart from clap (the platform URL is).
        for setting in SETTINGS.iter().filter(|s| s.kind != Kind::Fixed) {
            let (_, arg) = env_args
                .iter()
                .find(|(env, _)| env == setting.key)
                .unwrap_or_else(|| panic!("{} is not an argument Config reads", setting.key));
            if let Kind::Switch { strict } = setting.kind {
                let sets = matches!(arg.get_action(), clap::ArgAction::Set);
                assert_eq!(
                    strict, sets,
                    "{}: strict must match ArgAction::Set",
                    setting.key
                );
            }
        }
        // And every environment argument is a setting or one of the others.
        for (env, _) in &env_args {
            assert!(
                SETTINGS.iter().any(|s| s.key == env) || OTHERS.iter().any(|(o, _)| o == env),
                "{env} is read at startup but is neither a setting nor listed in OTHERS"
            );
        }
    }

    /// The console builds `config set` lines from the same names.
    #[test]
    fn the_table_matches_the_protocol_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(protocol_fixture!("config-settings.json")).unwrap();
        let listed: Vec<(String, String)> = fixture["settings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["name"].as_str().unwrap().to_string(),
                    s["key"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let ours: Vec<(String, String)> = SETTINGS
            .iter()
            .filter(|s| !matches!(s.kind, Kind::Fixed | Kind::Secret))
            .map(|s| (s.name.to_string(), s.key.to_string()))
            .collect();
        assert_eq!(listed, ours);
    }

    #[test]
    fn parse_takes_what_a_person_types_and_writes_what_the_agent_reads() {
        let get = |name| find(name).unwrap();
        assert_eq!(get("checks").parse("ON").as_deref(), Ok("true"));
        assert_eq!(get("hostname").parse("no").as_deref(), Ok("false"));
        assert_eq!(
            get("discovery").parse(" Passive ").as_deref(),
            Ok("passive")
        );
        // As the agent reads them: in order, once each.
        assert_eq!(
            get("network-map-ports").parse("8443, 443,443").as_deref(),
            Ok("443,8443")
        );
        assert_eq!(get("network-site").parse("hq").as_deref(), Ok("hq"));
        assert!(get("network-site").parse("Head Office").is_err());
        assert!(get("checks").parse("maybe").is_err());
        assert!(get("discovery").parse("all").is_err());
        assert!(get("bmc-poll-interval").parse("5m").is_err());
        assert!(get("bmc-password").parse("hunter2").is_err());
        assert!(get("token").parse("agent_x").is_err());
        // Its line's key works too.
        assert_eq!(find("CONNLOG_CHECKS").unwrap().name, "checks");
    }

    #[test]
    fn check_says_what_the_agent_would_do_with_each_line() {
        let conf = "CONNLOG_TOKEN=\"agent_0123\"\n\
                    CONNLOG_DISCOVER=\"active\"\n\
                    CONNLOG_CHECKS=\"maybe\"\n\
                    CONNLOG_EXPOSE_SYSTEM_INFO=\"sure\"\n\
                    CONNLOG_NETWORK_SITE=\"Head Office\"\n\
                    CONNLOG_BMC_POLL_INTERVAL_SECS=\"30\"\n\
                    CONNLOG_NETWORK_MAP=\"true\"\n\
                    # a comment\n\
                    CONNLOG_CHECKS=\"true\"\n";
        let findings = check(conf);
        let says: Vec<&str> = findings.iter().map(|f| f.says.as_str()).collect();
        assert!(
            says[0].contains("did you mean CONNLOG_DISCOVERY (discovery)?"),
            "{says:?}"
        );
        assert!(findings[0].serious);
        assert!(says[1].contains("the agent will not start"), "{says:?}");
        assert!(
            says[2].contains("reads it as on") && !findings[2].serious,
            "{says:?}"
        );
        assert!(says[3].contains("the agent ignores it"), "{says:?}");
        assert!(
            says[4].contains("outside 60 to 3600") && !findings[4].serious,
            "{says:?}"
        );
        assert!(says[5].contains("set twice"), "{says:?}");
        assert_eq!(findings.len(), 6, "{says:?}");
        assert!(check("CONNLOG_CHECKS=\"true\"\n")
            .iter()
            .any(|f| f.serious && f.says.contains("CONNLOG_TOKEN is missing")));
    }

    #[test]
    fn show_never_prints_a_secret() {
        let token = find("token").unwrap();
        assert_eq!(token.shown(Some("agent_0123456789abcdef")), "agent_…cdef");
        assert_eq!(find("bmc-password").unwrap().shown(Some("hunter2")), "set");
        assert_eq!(
            redacted("CONNLOG_BMC_PASSWORD=\"hunter2\""),
            "CONNLOG_BMC_PASSWORD=(hidden)"
        );
        assert_eq!(redacted("CONNLOG_TOKEN=agent_x"), "CONNLOG_TOKEN=(hidden)");
    }

    #[test]
    fn a_near_miss_is_named() {
        assert_eq!(nearest("CONNLOG_DISCOVER").unwrap().name, "discovery");
        assert_eq!(nearest("CONNLOG_CHEKS").unwrap().name, "checks");
        assert!(nearest("CONNLOG_SOMETHING_ELSE").is_none());
    }
}
