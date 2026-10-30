//! Integrations (docs/topology/PLAN.md, Phase 10, Tier 1): a host made a
//! collector (`CONNLOG_COLLECTOR=true`, root's choice) reads the customer's
//! own equipment and reports it to ConnLog: Proxmox VE (T10.1), OPNsense
//! (T10.2), and switches and routers over SNMP (T10.3).
//!
//! Each integration is a file in `/etc/connlog/integrations.d/`, written by
//! `connlog-agent integration add` as root, owned `root:connlog-agent`, mode
//! 0640: root and the service account read it, no other user (T10.0). Its
//! secret never leaves the host: a report names each integration, its kind,
//! and on failure one word from a fixed list, never an error's text.
//!
//! Nothing is read until the platform asks for reports on a heartbeat
//! (`integrations: true`), and then every five minutes, on a thread of its
//! own so an integration that hangs never delays a heartbeat.

pub mod cli;
pub mod https;
pub mod opnsense;
pub mod pinning;
pub mod proxmox;
pub mod snmp;
pub mod switch;
pub mod values;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;

pub const CONF_COLLECTOR: &str = "CONNLOG_COLLECTOR";
pub const COLLECTOR_HEADER: &str = "X-Collector";
pub const COLLECTOR_ENABLED: &str = "enabled";
pub const COLLECTOR_DISABLED: &str = "disabled";
#[cfg(not(target_os = "freebsd"))]
pub const DIR: &str = "/etc/connlog/integrations.d";
/// The FreeBSD package keeps its files under /usr/local (T13.5d).
#[cfg(target_os = "freebsd")]
pub const DIR: &str = crate::install::freebsd::INTEGRATIONS_DIR;
/// `INTEGRATION_MAX` in the protocol.
pub const MAX: usize = 16;
pub const PATH: &str = "/api/agents/integrations";
pub const CONTENT_TYPE: &str = "application/vnd.connlog.integrations.v1+json";
const INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Why an integration read nothing: `INTEGRATION_ERRORS` in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Failure {
    Unreachable,
    Timeout,
    Tls,
    Fingerprint,
    Auth,
    Forbidden,
    Status,
    Invalid,
}

impl Failure {
    /// What an operator reads at the terminal.
    pub fn explain(self, kind: Kind) -> &'static str {
        match (self, kind) {
            (Self::Forbidden, Kind::Proxmox) => {
                "the token's role cannot read this (give it PVEAuditor on /)"
            }
            (Self::Forbidden, Kind::Opnsense) => {
                "the key's user cannot read this (give its group the pages listed in `integration add --help`)"
            }
            (Self::Timeout, Kind::Snmp) => {
                "no answer in time (with v2c, a wrong community gets no answer at all)"
            }
            (Self::Auth, Kind::Snmp) => {
                "the user, its passwords or its security level were refused"
            }
            (Self::Forbidden, Kind::Snmp) => "the community's or user's view does not cover this",
            (failure, _) => failure.words(),
        }
    }

    fn words(self) -> &'static str {
        match self {
            Self::Unreachable => "could not connect",
            Self::Timeout => "no answer in time",
            Self::Tls => "the TLS handshake failed",
            Self::Fingerprint => "the certificate is not the one pinned",
            Self::Auth => "the token was refused",
            Self::Forbidden => "not allowed to read this",
            Self::Status => "an error answer",
            Self::Invalid => "an answer that could not be read",
        }
    }
}

/// The kinds built: `INTEGRATION_KINDS` in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Proxmox,
    Opnsense,
    Snmp,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Self::Proxmox => "proxmox",
            Self::Opnsense => "opnsense",
            Self::Snmp => "snmp",
        }
    }
}

/// One integration as its file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integration {
    pub name: String,
    pub kind: Kind,
    pub access: Access,
}

/// How the collector reaches the device, and the credentials it uses.
#[derive(Clone, PartialEq, Eq)]
pub enum Access {
    /// Proxmox and OPNsense: an HTTPS API. `token_id` and `token_secret`
    /// are Proxmox's token and OPNsense's API key and secret.
    Https {
        url: String,
        token_id: String,
        token_secret: String,
        fingerprint: Option<pinning::Fingerprint>,
    },
    /// A switch or router: SNMP over UDP, at `snmp://host[:port]`.
    Snmp {
        host: String,
        port: u16,
        security: snmp::Security,
    },
}

/// Never a secret, wherever an integration is printed or logged.
impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Https { url, token_id, .. } => f
                .debug_struct("Https")
                .field("url", url)
                .field("token_id", token_id)
                .field("token_secret", &"[redacted]")
                .finish(),
            Self::Snmp {
                host,
                port,
                security,
            } => {
                let mut d = f.debug_struct("Snmp");
                d.field("host", host).field("port", port);
                match security {
                    snmp::Security::V2c { .. } => d.field("community", &"[redacted]"),
                    snmp::Security::V3 { user, auth, .. } => d
                        .field("user", user)
                        .field("auth", auth)
                        .field("passwords", &"[redacted]"),
                };
                d.finish()
            }
        }
    }
}

impl Access {
    /// What `integration list` shows of it: where it goes and as whom, never a secret.
    pub fn describe(&self) -> String {
        match self {
            Self::Https {
                url,
                token_id,
                fingerprint,
                ..
            } => format!(
                "{url}  {token_id}  {}",
                if fingerprint.is_some() {
                    "certificate pinned"
                } else {
                    "public authority"
                }
            ),
            Self::Snmp {
                host,
                port,
                security,
            } => match security {
                snmp::Security::V2c { .. } => format!("{}  v2c", snmp_url(host, *port)),
                snmp::Security::V3 {
                    user,
                    auth,
                    priv_password,
                    ..
                } => format!(
                    "{}  v3 {user}  {}{}",
                    snmp_url(host, *port),
                    auth.word(),
                    if priv_password.is_some() { "+aes" } else { "" }
                ),
            },
        }
    }

    fn parse_snmp(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let (host, port) = get("url")
            .as_deref()
            .and_then(parse_snmp_url)
            .ok_or("url: expected snmp://host[:port]")?;
        let password = |key: &'static str| {
            get(key)
                .filter(|p| p.len() >= 8)
                .ok_or(format!("{key}: at least 8 characters"))
        };
        let security = match get("version").as_deref() {
            Some("2c") => snmp::Security::V2c {
                community: get("community").ok_or("community: missing")?,
            },
            Some("3") => snmp::Security::V3 {
                user: get("user").ok_or("user: missing")?,
                auth: get("auth")
                    .as_deref()
                    .and_then(snmp::usm::AuthProtocol::parse)
                    .ok_or("auth: expected sha or sha256")?,
                auth_password: password("auth_password")?,
                priv_password: match get("priv_password") {
                    Some(_) => Some(password("priv_password")?),
                    None => None,
                },
            },
            _ => return Err("version: expected 2c or 3".into()),
        };
        Ok(Self::Snmp {
            host,
            port,
            security,
        })
    }

    fn parse_https(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let url = get("url")
            .filter(|u| valid_url(u))
            .ok_or("url: expected https://host[:port]")?;
        let fingerprint = match get("fingerprint") {
            Some(text) => Some(pinning::parse(&text).ok_or("fingerprint: expected SHA-256 hex")?),
            None => None,
        };
        Ok(Self::Https {
            url,
            token_id: get("token_id").ok_or("token_id: missing")?,
            token_secret: get("token_secret").ok_or("token_secret: missing")?,
            fingerprint,
        })
    }

    fn to_lines(&self) -> String {
        match self {
            Self::Https {
                url,
                token_id,
                token_secret,
                fingerprint,
            } => {
                let mut text =
                    format!("url={url}\ntoken_id={token_id}\ntoken_secret={token_secret}\n");
                if let Some(fp) = fingerprint {
                    text.push_str(&format!("fingerprint={}\n", pinning::format(fp)));
                }
                text
            }
            Self::Snmp {
                host,
                port,
                security,
            } => {
                let url = snmp_url(host, *port);
                match security {
                    snmp::Security::V2c { community } => {
                        format!("url={url}\nversion=2c\ncommunity={community}\n")
                    }
                    snmp::Security::V3 {
                        user,
                        auth,
                        auth_password,
                        priv_password,
                    } => {
                        let mut text = format!(
                            "url={url}\nversion=3\nuser={user}\nauth={}\nauth_password={auth_password}\n",
                            auth.word()
                        );
                        if let Some(p) = priv_password {
                            text.push_str(&format!("priv_password={p}\n"));
                        }
                        text
                    }
                }
            }
        }
    }
}

/// `snmp://host[:port]` (RFC 4088): its host and port, 161 when none is given.
pub fn parse_snmp_url(url: &str) -> Option<(String, u16)> {
    let u = reqwest::Url::parse(url).ok()?;
    if u.scheme() != "snmp" || !matches!(u.path(), "" | "/") {
        return None;
    }
    // An IPv6 host comes bracketed; the socket wants it bare.
    let host = u
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    Some((host, u.port().unwrap_or(snmp::DEFAULT_PORT)))
}

fn snmp_url(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == snmp::DEFAULT_PORT {
        format!("snmp://{host}")
    } else {
        format!("snmp://{host}:{port}")
    }
}

/// `INTEGRATION_NAME` in the protocol: also the file's name.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let first = chars.next();
    name.len() <= 32
        && first.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// An `https://` URL with a host and nothing after it but a port.
pub fn valid_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https" && u.host_str().is_some() && matches!(u.path(), "" | "/")
    })
}

fn one_line(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c.is_control())
}

impl Integration {
    /// A file's `key=value` lines; an error says which key is wrong, never its value.
    pub fn parse(name: &str, text: &str) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                values.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        let get = |key: &str| values.get(key).filter(|v| one_line(v)).cloned();
        let kind = match get("kind").as_deref() {
            Some("proxmox") => Kind::Proxmox,
            Some("opnsense") => Kind::Opnsense,
            Some("snmp") => Kind::Snmp,
            _ => return Err("kind: expected proxmox, opnsense or snmp".into()),
        };
        let access = match kind {
            Kind::Snmp => Access::parse_snmp(&get)?,
            Kind::Proxmox | Kind::Opnsense => Access::parse_https(&get)?,
        };
        Ok(Self {
            name: name.to_string(),
            kind,
            access,
        })
    }

    pub fn to_file(&self) -> String {
        format!(
            "# A ConnLog integration, written by `connlog-agent integration add`.\n\
             # Root and the agent's service account read it; nobody else.\n\
             kind={}\n{}",
            self.kind.word(),
            self.access.to_lines()
        )
    }
}

/// The integrations in `dir`, by name, at most 16; a file that does not
/// read is warned about once and left out.
pub fn load_all(dir: &Path) -> Vec<Integration> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|f| f.strip_suffix(".conf").map(str::to_string))
        .filter(|n| valid_name(n))
        .collect();
    names.sort();
    names.truncate(MAX);
    names
        .into_iter()
        .filter_map(|name| {
            let text = std::fs::read_to_string(dir.join(format!("{name}.conf"))).ok()?;
            Integration::parse(&name, &text)
                .map_err(|why| log::warn!("Integration {name} is left out: {why}"))
                .ok()
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct State {
    pub name: String,
    pub kind: Kind,
    pub error: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<proxmox::Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opnsense: Option<opnsense::Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switch: Option<switch::Report>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub version: u8,
    pub integrations: Vec<State>,
}

/// One integration read now. `names`: whether the workspace takes device
/// names, which only a firewall's leases carry.
pub fn read_one(integration: &Integration, names: bool) -> State {
    let mut state = State {
        name: integration.name.clone(),
        kind: integration.kind,
        error: None,
        proxmox: None,
        opnsense: None,
        switch: None,
    };
    let read = match &integration.access {
        Access::Https {
            url,
            token_id: id,
            token_secret: secret,
            fingerprint: pin,
        } => match integration.kind {
            Kind::Opnsense => opnsense::HttpApi::new(url, id, secret, *pin)
                .and_then(|api| opnsense::read(&api, names))
                .map(|report| state.opnsense = Some(report)),
            _ => proxmox::HttpApi::new(url, id, secret, *pin)
                .and_then(|api| proxmox::read(&api))
                .map(|report| state.proxmox = Some(report)),
        },
        Access::Snmp {
            host,
            port,
            security,
        } => snmp::Udp::connect(host, *port)
            .and_then(|wire| switch::read(&mut snmp::Client::new(wire, security)))
            .map(|mut report| {
                report.address = host.parse::<std::net::IpAddr>().ok().map(|a| a.to_string());
                state.switch = Some(report);
            }),
    };
    state.error = read.err();
    state
}

pub fn read_all(integrations: &[Integration], names: bool) -> Report {
    Report {
        version: 1,
        integrations: integrations.iter().map(|i| read_one(i, names)).collect(),
    }
}

/// The collector's thread, and the platform's latest word on whether it
/// takes reports.
pub struct Integrations {
    granted: Option<Arc<AtomicBool>>,
    names: Arc<AtomicBool>,
}

impl Integrations {
    pub fn start(enabled: bool, base_url: String, token: String, stop: Arc<AtomicBool>) -> Self {
        let names = Arc::new(AtomicBool::new(false));
        if !enabled {
            return Self {
                granted: None,
                names,
            };
        }
        let granted = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&granted);
        let named = Arc::clone(&names);
        let started = std::thread::Builder::new()
            .name("integrations".into())
            .spawn(move || {
                let client = match crate::http::ApiClient::new(base_url, token) {
                    Ok(client) => client,
                    Err(e) => {
                        log::warn!("Integrations are off: no HTTP client ({e})");
                        return;
                    }
                };
                let mut last: Option<Instant> = None;
                while !stop.load(Ordering::SeqCst) {
                    let due = last.is_none_or(|at| at.elapsed() >= INTERVAL);
                    if flag.load(Ordering::SeqCst) && due {
                        last = Some(Instant::now());
                        let integrations = load_all(Path::new(DIR));
                        let with_names = named.load(Ordering::SeqCst);
                        let report =
                            std::panic::catch_unwind(|| read_all(&integrations, with_names));
                        match report {
                            Ok(report) => upload(&client, &report),
                            Err(_) => log::warn!("Reading the integrations panicked; skipped"),
                        }
                    }
                    std::thread::sleep(Duration::from_secs(5));
                }
            });
        match started {
            Ok(_) => {
                log::info!("This host is a collector (CONNLOG_COLLECTOR=true)");
                Self {
                    granted: Some(granted),
                    names,
                }
            }
            Err(e) => {
                log::warn!("Integrations are off: could not start their thread ({e})");
                Self {
                    granted: None,
                    names,
                }
            }
        }
    }

    /// A heartbeat's `integrations` and `device_names` flags: whether the
    /// platform takes reports now, and the leases' hostnames in them.
    pub fn on_heartbeat(&self, granted: bool, names: bool) {
        if let Some(flag) = &self.granted {
            flag.store(granted, Ordering::SeqCst);
        }
        self.names.store(granted && names, Ordering::SeqCst);
    }
}

fn upload(client: &crate::http::ApiClient, report: &Report) {
    let Ok(body) = serde_json::to_vec(report) else {
        return;
    };
    if let Err(e) = client.upload_network(PATH, CONTENT_TYPE, body) {
        log::warn!("Sending the integration report failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# comment\nkind=proxmox\nurl=https://pve.lan:8006\ntoken_id=connlog@pve!collector\ntoken_secret=0b9f3c1e-5a2d-4c7e-9f10-2b3c4d5e6f70\n";

    #[test]
    fn reads_a_file_and_writes_it_back_the_same() {
        let integration = Integration::parse("pve", FILE).unwrap();
        assert_eq!(integration.kind, Kind::Proxmox);
        let Access::Https { token_id, .. } = &integration.access else {
            panic!("a Proxmox file is reached over HTTPS");
        };
        assert_eq!(token_id, "connlog@pve!collector");
        let again = Integration::parse("pve", &integration.to_file()).unwrap();
        assert!(again == integration);
        let Access::Https {
            url,
            token_id,
            token_secret,
            ..
        } = integration.access.clone()
        else {
            panic!("a Proxmox file is reached over HTTPS");
        };
        let pinned = Integration {
            access: Access::Https {
                url,
                token_id,
                token_secret,
                fingerprint: Some(pinning::sha256(b"cert")),
            },
            ..integration
        };
        assert!(Integration::parse("pve", &pinned.to_file()).unwrap() == pinned);
    }

    #[test]
    fn reads_and_writes_an_opnsense_file() {
        let file = FILE.replace("kind=proxmox", "kind=opnsense");
        let integration = Integration::parse("fw", &file).unwrap();
        assert_eq!(integration.kind, Kind::Opnsense);
        assert!(integration.to_file().contains("kind=opnsense\n"));
        assert!(Integration::parse("fw", &FILE.replace("kind=proxmox", "kind=unifi")).is_err());
    }

    #[test]
    fn reads_and_writes_snmp_files_and_never_prints_their_secrets() {
        let v2c = "kind=snmp\nurl=snmp://10.0.0.2\nversion=2c\ncommunity=s3cret-community\n";
        let integration = Integration::parse("sw", v2c).unwrap();
        assert_eq!(integration.kind, Kind::Snmp);
        assert!(Integration::parse("sw", &integration.to_file()).unwrap() == integration);
        assert!(!format!("{integration:?}").contains("s3cret"));
        assert_eq!(integration.access.describe(), "snmp://10.0.0.2  v2c");

        let v3 = "kind=snmp\nurl=snmp://[fe80::2]:1161\nversion=3\nuser=connlog\nauth=sha256\nauth_password=authpassword\npriv_password=privpassword\n";
        let integration = Integration::parse("sw", v3).unwrap();
        assert!(Integration::parse("sw", &integration.to_file()).unwrap() == integration);
        let printed = format!("{integration:?}");
        assert!(!printed.contains("authpassword") && !printed.contains("privpassword"));
        assert_eq!(
            integration.access.describe(),
            "snmp://[fe80::2]:1161  v3 connlog  sha256+aes"
        );

        let short = v3.replace("auth_password=authpassword", "auth_password=short");
        assert_eq!(
            Integration::parse("sw", &short).unwrap_err(),
            "auth_password: at least 8 characters"
        );
        let md5 = v3.replace("auth=sha256", "auth=md5");
        assert!(Integration::parse("sw", &md5)
            .unwrap_err()
            .starts_with("auth:"));
        assert!(Integration::parse("sw", &v2c.replace("snmp://", "https://")).is_err());
    }

    #[test]
    fn says_which_key_is_wrong_and_never_its_value() {
        let plain = FILE.replace("https://", "http://");
        let err = Integration::parse("pve", &plain).unwrap_err();
        assert!(err.starts_with("url:"));
        let err = Integration::parse("pve", &FILE.replace("token_secret=", "x=")).unwrap_err();
        assert_eq!(err, "token_secret: missing");
        let err = Integration::parse("pve", &format!("{FILE}fingerprint=nope\n")).unwrap_err();
        assert!(!err.contains("nope"));
    }

    #[test]
    fn never_prints_the_secret() {
        let integration = Integration::parse("pve", FILE).unwrap();
        let printed = format!("{integration:?}");
        assert!(!printed.contains("0b9f3c1e"));
        assert!(printed.contains("[redacted]"));
    }

    #[test]
    fn names_and_urls_it_accepts() {
        assert!(valid_name("pve") && valid_name("lab-cluster-2"));
        assert!(
            !valid_name("../etc") && !valid_name("PVE") && !valid_name("-x") && !valid_name("")
        );
        assert!(valid_url("https://pve.lan:8006") && valid_url("https://10.0.20.2:8006/"));
        assert!(!valid_url("http://pve.lan:8006") && !valid_url("https://pve.lan:8006/api2/json"));
    }

    #[test]
    fn loads_the_readable_files_by_name_and_leaves_the_rest_out() {
        let dir = std::env::temp_dir().join(format!("connlog-int-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.conf"), FILE).unwrap();
        std::fs::write(dir.join("a.conf"), FILE).unwrap();
        std::fs::write(dir.join("broken.conf"), "kind=unifi\n").unwrap();
        std::fs::write(dir.join("Bad Name.conf"), FILE).unwrap();
        std::fs::write(dir.join("notes.txt"), FILE).unwrap();
        let names: Vec<String> = load_all(&dir).into_iter().map(|i| i.name).collect();
        assert_eq!(names, ["a", "b"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reports_a_failure_in_one_word() {
        let state = State {
            name: "pve".into(),
            kind: Kind::Proxmox,
            error: Some(Failure::Fingerprint),
            proxmox: None,
            opnsense: None,
            switch: None,
        };
        let json = serde_json::to_value(Report {
            version: 1,
            integrations: vec![state],
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"version": 1, "integrations": [{"name": "pve", "kind": "proxmox", "error": "fingerprint"}]})
        );
    }
}
