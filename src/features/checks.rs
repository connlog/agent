//! Checks for what has no agent (docs/topology/PLAN.md, T9.0 and T9.1): what
//! a host with `CONNLOG_CHECKS=true` does with the `check_request` a
//! heartbeat answer carries.
//!
//! The agent bounds what it will do, whatever it is told. These caps are
//! compiled in, not configuration:
//!
//! - at most 16 checks per request, in the order given; the rest is dropped
//!   before anything is read, and a check the agent cannot read is dropped;
//! - at most 10 s a check, one check at a time, one request at a time;
//! - each target at most once a minute (`too-soon` otherwise);
//! - a private target only at the passive discovery level (`not-allowed`
//!   otherwise), and never loopback, multicast or an unspecified address;
//! - ping is 3 echoes on the unprivileged ping socket (`unsupported` where
//!   the host does not allow it);
//! - HTTP is one GET to the address the name resolved to (pinned, so a name
//!   cannot be pointed elsewhere between the check and the request), no
//!   redirect followed, and never a byte of the body read: its status, its
//!   time to the first byte and the certificate's days left are all that
//!   come back. No keyword matching: a keyword's yes or no would read a
//!   private page one guess at a time;
//! - DNS is one query for A or AAAA to the resolver given, at most 16
//!   answers kept.
//!
//! Results are `application/vnd.connlog.checks.v1+json`, pinned by
//! `check-requests.json` and `check-results.json`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

use super::reachability::{self, Outcome};

pub const CONTENT_TYPE: &str = "application/vnd.connlog.checks.v1+json";
pub const CHECKS_PATH: &str = "/api/agents/checks";
pub const FORMAT_VERSION: u8 = 1;

/// `X-Checks` on every heartbeat the daemon sends (CONNLOG_CHECKS).
pub const CHECKS_HEADER: &str = "X-Checks";
pub const CHECKS_ENABLED: &str = "enabled";
pub const CHECKS_DISABLED: &str = "disabled";
/// The agent.conf key, as `install` and `config` write it.
pub const CONF_CHECKS: &str = "CONNLOG_CHECKS";

/// `CHECK_MAX_PER_REQUEST`, `CHECK_TIMEOUT_MS`, `CHECK_PING_COUNT` and
/// `CHECK_DNS_MAX_ANSWERS` in the protocol.
pub const MAX_PER_REQUEST: usize = 16;
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
pub const PING_COUNT: u32 = 3;
pub const MAX_DNS_ANSWERS: usize = 16;
/// The same target is checked at most this often.
pub const MIN_INTERVAL_PER_TARGET: Duration = Duration::from_secs(60);
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ID_LEN: usize = 64;
const MAX_URL_LEN: usize = 512;
const MAX_NAME_LEN: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
}

impl RecordType {
    const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    Ping {
        target: String,
    },
    Tcp {
        target: String,
        port: u16,
    },
    Http {
        url: reqwest::Url,
    },
    Dns {
        name: String,
        record: RecordType,
        resolver: IpAddr,
    },
}

impl Spec {
    /// What "the same target" means for the once-a-minute cap.
    fn target_key(&self) -> String {
        match self {
            Self::Ping { target } => format!("ping {target}"),
            Self::Tcp { target, port } => format!("tcp {target}:{port}"),
            Self::Http { url } => format!(
                "http {}:{}",
                url.host_str().unwrap_or(""),
                url.port_or_known_default().unwrap_or(0)
            ),
            Self::Dns { resolver, .. } => format!("dns {resolver}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: String,
    pub spec: Spec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    pub id: String,
    pub checks: Vec<Check>,
}

fn valid_id(id: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A host name or an address, as a ping or TCP target: no spaces, no
/// scheme, at most 253.
fn target_of(value: &Value) -> Option<String> {
    let target = value.as_str()?.trim();
    let ok = !target.is_empty()
        && target.len() <= MAX_NAME_LEN
        && target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
    ok.then(|| target.to_string())
}

fn spec_of(check: &Value) -> Option<Spec> {
    Some(match check.get("kind")?.as_str()? {
        "ping" => Spec::Ping {
            target: target_of(check.get("target")?)?,
        },
        "tcp" => Spec::Tcp {
            target: target_of(check.get("target")?)?,
            port: u16::try_from(check.get("port")?.as_u64()?)
                .ok()
                .filter(|p| *p != 0)?,
        },
        "http" => {
            let raw = check.get("url")?.as_str()?;
            if raw.len() > MAX_URL_LEN {
                return None;
            }
            let url = reqwest::Url::parse(raw).ok()?;
            let http = matches!(url.scheme(), "http" | "https");
            if !http || url.host_str().is_none() || !url.username().is_empty() {
                return None;
            }
            Spec::Http { url }
        }
        "dns" => Spec::Dns {
            name: target_of(check.get("name")?)?,
            record: match check.get("recordType")?.as_str()? {
                "A" => RecordType::A,
                "AAAA" => RecordType::Aaaa,
                _ => return None,
            },
            resolver: check.get("resolver")?.as_str()?.parse().ok()?,
        },
        _ => return None,
    })
}

impl CheckRequest {
    /// A `check_request` as the platform writes it, cut to the caps: the
    /// first 16 checks, each one the agent can read; `None` without a valid
    /// id or a list of checks.
    pub fn from_json(value: &Value) -> Option<Self> {
        let id = value.get("id")?.as_str()?;
        if !valid_id(id) {
            return None;
        }
        let checks = value
            .get("checks")?
            .as_array()?
            .iter()
            .take(MAX_PER_REQUEST)
            .filter_map(|check| {
                let id = check.get("id")?.as_str()?;
                valid_id(id).then_some(())?;
                Some(Check {
                    id: id.to_string(),
                    spec: spec_of(check)?,
                })
            })
            .collect();
        Some(Self {
            id: id.to_string(),
            checks,
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PingStats {
    pub sent: u32,
    pub received: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpStats {
    pub status: Option<u16>,
    pub cert_days_left: Option<i64>,
    pub tls_valid: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsStats {
    pub rcode: &'static str,
    pub answers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub id: String,
    pub outcome: &'static str,
    pub reason: Option<&'static str>,
    pub ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping: Option<PingStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsStats>,
}

impl CheckResult {
    fn of(id: &str, outcome: &'static str, reason: Option<&'static str>, ms: Option<u32>) -> Self {
        Self {
            id: id.to_string(),
            outcome,
            reason,
            ms,
            ping: None,
            http: None,
            dns: None,
        }
    }
    fn up(id: &str, ms: Option<u32>) -> Self {
        Self::of(id, "up", None, ms)
    }
    fn down(id: &str, reason: &'static str) -> Self {
        Self::of(id, "down", Some(reason), None)
    }
    fn skipped(id: &str, reason: &'static str) -> Self {
        Self::of(id, "skipped", Some(reason), None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResults {
    pub version: u8,
    pub id: String,
    pub results: Vec<CheckResult>,
}

impl CheckResults {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Milliseconds, within the protocol's ceiling.
fn millis(d: Duration) -> u32 {
    d.as_millis().min(CHECK_TIMEOUT.as_millis()) as u32
}

// ── What a check asks of the host ───────────────────────────────────────

/// What an HTTP check got back: a status and its first byte, or why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpAnswer {
    pub status: Option<u16>,
    pub first_byte: Option<Duration>,
    pub cert_days_left: Option<i64>,
    pub tls_valid: Option<bool>,
    pub failure: Option<&'static str>,
}

/// What a DNS check got back; `None` from `dns` is no answer at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub rcode: &'static str,
    pub answers: Vec<IpAddr>,
    pub took: Duration,
}

/// The network a check runs against: the host, or a stand-in in tests.
pub trait CheckHost {
    fn resolve(&self, host: &str) -> Option<IpAddr>;
    fn echo(&self, address: IpAddr) -> reachability::Probe;
    fn connect(&self, address: SocketAddr) -> Result<Duration, Outcome>;
    fn http(&self, url: &reqwest::Url, address: IpAddr) -> HttpAnswer;
    fn dns(&self, resolver: IpAddr, name: &str, record: RecordType) -> Option<DnsAnswer>;
}

/// Whether a check may go to `address` at all, and from this host: never
/// loopback, unspecified or multicast; a private address only at passive.
fn allowed(address: IpAddr, allow_private: bool) -> bool {
    let never = address.is_loopback() || address.is_unspecified() || address.is_multicast();
    let broadcast = matches!(address, IpAddr::V4(v4) if v4.is_broadcast());
    !(never || broadcast) && (allow_private || !reachability::is_private(&address))
}

/// A target as an address: itself, or what its name resolves to.
fn address_of(target: &str, host: &dyn CheckHost) -> Option<IpAddr> {
    target.parse().ok().or_else(|| host.resolve(target))
}

fn ping(id: &str, target: &str, allow_private: bool, host: &dyn CheckHost) -> CheckResult {
    let Some(address) = address_of(target, host) else {
        return CheckResult::down(id, "dns");
    };
    if !allowed(address, allow_private) {
        return CheckResult::skipped(id, "not-allowed");
    }
    let mut rtts = Vec::new();
    for _ in 0..PING_COUNT {
        let probe = host.echo(address);
        match probe.outcome {
            Outcome::Skipped => return CheckResult::skipped(id, "unsupported"),
            Outcome::Open => rtts.push(probe.rtt_ms.unwrap_or(0)),
            _ => {}
        }
    }
    let received = rtts.len() as u32;
    let stats = Some(PingStats {
        sent: PING_COUNT,
        received,
    });
    let mut result = match rtts.iter().sum::<u32>().checked_div(received) {
        Some(mean) => CheckResult::up(id, Some(mean)),
        None => CheckResult::down(id, "timeout"),
    };
    result.ping = stats;
    result
}

fn tcp(
    id: &str,
    target: &str,
    port: u16,
    allow_private: bool,
    host: &dyn CheckHost,
) -> CheckResult {
    let Some(address) = address_of(target, host) else {
        return CheckResult::down(id, "dns");
    };
    if !allowed(address, allow_private) {
        return CheckResult::skipped(id, "not-allowed");
    }
    match host.connect(SocketAddr::new(address, port)) {
        Ok(took) => CheckResult::up(id, Some(millis(took))),
        Err(Outcome::Refused) => CheckResult::down(id, "refused"),
        Err(Outcome::Timeout) => CheckResult::down(id, "timeout"),
        Err(_) => CheckResult::down(id, "unreachable"),
    }
}

fn http(id: &str, url: &reqwest::Url, allow_private: bool, host: &dyn CheckHost) -> CheckResult {
    let Some(address) = url
        .host_str()
        .and_then(|h| address_of(h.trim_matches(['[', ']']), host))
    else {
        return CheckResult::down(id, "dns");
    };
    if !allowed(address, allow_private) {
        return CheckResult::skipped(id, "not-allowed");
    }
    let answer = host.http(url, address);
    let mut result = match (answer.failure, answer.status) {
        (Some(reason), _) => CheckResult::down(id, reason),
        (None, Some(status)) if (200..400).contains(&status) => {
            CheckResult::up(id, answer.first_byte.map(millis))
        }
        (None, Some(_)) => {
            CheckResult::of(id, "down", Some("status"), answer.first_byte.map(millis))
        }
        (None, None) => CheckResult::down(id, "unreachable"),
    };
    result.http = Some(HttpStats {
        status: answer.status,
        cert_days_left: answer.cert_days_left,
        tls_valid: answer.tls_valid,
    });
    result
}

fn dns(
    id: &str,
    name: &str,
    record: RecordType,
    resolver: IpAddr,
    allow_private: bool,
    host: &dyn CheckHost,
) -> CheckResult {
    if !allowed(resolver, allow_private) {
        return CheckResult::skipped(id, "not-allowed");
    }
    let Some(answer) = host.dns(resolver, name, record) else {
        return CheckResult::down(id, "timeout");
    };
    let ms = Some(millis(answer.took));
    let mut result = if answer.rcode == "noerror" && !answer.answers.is_empty() {
        CheckResult::up(id, ms)
    } else {
        CheckResult::of(id, "down", Some("no-answer"), ms)
    };
    result.dns = Some(DnsStats {
        rcode: answer.rcode,
        answers: answer
            .answers
            .iter()
            .take(MAX_DNS_ANSWERS)
            .map(IpAddr::to_string)
            .collect(),
    });
    result
}

/// Run a request, in order, within the caps. `last` remembers when each
/// target was last checked, across requests; `allow_private` is whether the
/// host runs at the passive level now.
pub fn run(
    request: &CheckRequest,
    allow_private: bool,
    host: &dyn CheckHost,
    last: &mut HashMap<String, Instant>,
    now: Instant,
) -> CheckResults {
    let results = request
        .checks
        .iter()
        .take(MAX_PER_REQUEST)
        .map(|check| {
            let key = check.spec.target_key();
            if last
                .get(&key)
                .is_some_and(|at| now.duration_since(*at) < MIN_INTERVAL_PER_TARGET)
            {
                return CheckResult::skipped(&check.id, "too-soon");
            }
            last.insert(key, now);
            let id = check.id.as_str();
            match &check.spec {
                Spec::Ping { target } => ping(id, target, allow_private, host),
                Spec::Tcp { target, port } => tcp(id, target, *port, allow_private, host),
                Spec::Http { url } => http(id, url, allow_private, host),
                Spec::Dns {
                    name,
                    record,
                    resolver,
                } => dns(id, name, *record, *resolver, allow_private, host),
            }
        })
        .collect();
    CheckResults {
        version: FORMAT_VERSION,
        id: request.id.clone(),
        results,
    }
}

// ── The certificate's expiry (DER, X.509) ───────────────────────────────

/// One DER element at the start of `bytes`: its tag, its contents and the
/// rest after it.
fn der(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let first = usize::from(*bytes.get(1)?);
    let (len, head) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let len = bytes
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    Some((tag, bytes.get(head..end)?, bytes.get(end..)?))
}

/// Days from 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`), as unix seconds.
fn der_time(tag: u8, value: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(value).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if text.len() == 12 => {
            let yy: i64 = text.get(0..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, text.get(2..)?)
        }
        0x18 if text.len() == 14 => (text.get(0..4)?.parse().ok()?, text.get(4..)?),
        _ => return None,
    };
    let field = |i: usize| -> Option<i64> { rest.get(i..i + 2)?.parse().ok() };
    let days = days_from_civil(year, field(0)?, field(2)?);
    Some(days * 86_400 + field(4)? * 3_600 + field(6)? * 60 + field(8)?)
}

/// A certificate's notAfter, as unix seconds.
pub fn cert_not_after(cert: &[u8]) -> Option<i64> {
    let (_, certificate, _) = der(cert)?;
    let (_, tbs, _) = der(certificate)?;
    let mut rest = tbs;
    // [0] version, when present.
    if rest.first() == Some(&0xa0) {
        rest = der(rest)?.2;
    }
    // serialNumber, signature, issuer, then validity.
    for _ in 0..3 {
        rest = der(rest)?.2;
    }
    let (_, validity, _) = der(rest)?;
    let (_, _, after) = der(validity)?;
    let (tag, value, _) = der(after)?;
    der_time(tag, value)
}

/// Whole days from `now` to `not_after`, negative once it has passed.
fn days_left(not_after: i64, now: i64) -> i64 {
    (not_after - now).div_euclid(86_400)
}

// ── DNS (one query, UDP) ────────────────────────────────────────────────

/// A query for `name`'s `record`, recursion desired.
pub fn dns_query(id: u16, name: &str, record: RecordType) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&record.code().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Some(out)
}

/// The end of a (possibly compressed) name starting at `at`.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)?;
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        if len == 0 {
            return Some(at + 1);
        }
        at += 1 + usize::from(len);
    }
}

fn rcode_word(code: u8) -> &'static str {
    match code {
        0 => "noerror",
        1 => "formerr",
        2 => "servfail",
        3 => "nxdomain",
        4 => "notimp",
        5 => "refused",
        _ => "other",
    }
}

/// A response to query `id`: its rcode and the addresses it answers with.
pub fn dns_answer(msg: &[u8], id: u16) -> Option<(&'static str, Vec<IpAddr>)> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id || msg[2] & 0x80 == 0 {
        return None;
    }
    let rcode = rcode_word(msg[3] & 0x0f);
    let questions = u16::from_be_bytes([msg[4], msg[5]]);
    let answers = u16::from_be_bytes([msg[6], msg[7]]);
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(msg, at)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..answers {
        at = skip_name(msg, at)?;
        let kind = u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]);
        let len = usize::from(u16::from_be_bytes([*msg.get(at + 8)?, *msg.get(at + 9)?]));
        let data = msg.get(at + 10..at + 10 + len)?;
        match (kind, len) {
            (1, 4) => out.push(IpAddr::from([data[0], data[1], data[2], data[3]])),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                out.push(IpAddr::from(octets));
            }
            _ => {}
        }
        if out.len() >= MAX_DNS_ANSWERS {
            break;
        }
        at += 10 + len;
    }
    Some((rcode, out))
}

// ── The host itself ─────────────────────────────────────────────────────

pub struct SystemHost;

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// One GET, pinned to `address`, no redirect followed; `insecure` accepts any
/// certificate, to read the expiry of one that is not trusted.
fn fetch(
    url: &reqwest::Url,
    address: IpAddr,
    insecure: bool,
) -> Result<(u16, Duration, Option<i64>), reqwest::Error> {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(443);
    let client = reqwest::blocking::Client::builder()
        .timeout(CHECK_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // Direct, never through a proxy the host's environment names: the
        // check measures the path to this address.
        .no_proxy()
        .resolve(host, SocketAddr::new(address, port))
        .tls_info(true)
        .danger_accept_invalid_certs(insecure)
        .user_agent(concat!(
            "connlog-agent/",
            env!("CARGO_PKG_VERSION"),
            " (check)"
        ))
        .build()?;
    let started = Instant::now();
    let response = client.get(url.clone()).send()?;
    let first_byte = started.elapsed();
    let not_after = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .and_then(cert_not_after);
    // The body is never read: the response is dropped here.
    Ok((response.status().as_u16(), first_byte, not_after))
}

fn failure_of(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        return "timeout";
    }
    let mut source = std::error::Error::source(e);
    while let Some(inner) = source {
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::ConnectionRefused {
                return "refused";
            }
        }
        source = inner.source();
    }
    "unreachable"
}

impl CheckHost for SystemHost {
    fn resolve(&self, host: &str) -> Option<IpAddr> {
        (host, 0)
            .to_socket_addrs()
            .ok()?
            .next()
            .map(|addr| addr.ip())
    }

    fn echo(&self, address: IpAddr) -> reachability::Probe {
        reachability::icmp_echo(address, PING_TIMEOUT)
    }

    fn connect(&self, address: SocketAddr) -> Result<Duration, Outcome> {
        let started = Instant::now();
        std::net::TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
            .map(|_| started.elapsed())
            .map_err(|e| reachability::connect_error_outcome(&e))
    }

    fn http(&self, url: &reqwest::Url, address: IpAddr) -> HttpAnswer {
        let https = url.scheme() == "https";
        let tls = |valid: bool, not_after: Option<i64>| {
            https.then(|| (valid, not_after.map(|t| days_left(t, unix_now()))))
        };
        match fetch(url, address, false) {
            Ok((status, first_byte, not_after)) => {
                let tls = tls(true, not_after);
                HttpAnswer {
                    status: Some(status),
                    first_byte: Some(first_byte),
                    cert_days_left: tls.and_then(|t| t.1),
                    tls_valid: tls.map(|t| t.0),
                    failure: None,
                }
            }
            Err(e) => {
                let failure = failure_of(&e);
                // A handshake that failed on the certificate: read its expiry
                // anyway, accepting it this once, and say it is not trusted.
                if https && e.is_connect() && failure == "unreachable" {
                    if let Ok((_, _, not_after)) = fetch(url, address, true) {
                        return HttpAnswer {
                            status: None,
                            first_byte: None,
                            cert_days_left: not_after.map(|t| days_left(t, unix_now())),
                            tls_valid: Some(false),
                            failure: Some("tls"),
                        };
                    }
                }
                HttpAnswer {
                    status: None,
                    first_byte: None,
                    cert_days_left: None,
                    tls_valid: None,
                    failure: Some(failure),
                }
            }
        }
    }

    fn dns(&self, resolver: IpAddr, name: &str, record: RecordType) -> Option<DnsAnswer> {
        let id = (unix_now() as u16) ^ 0x5a5a;
        let query = dns_query(id, name, record)?;
        let bind: SocketAddr = if resolver.is_ipv4() {
            "0.0.0.0:0".parse().ok()?
        } else {
            "[::]:0".parse().ok()?
        };
        let socket = UdpSocket::bind(bind).ok()?;
        socket.set_read_timeout(Some(DNS_TIMEOUT)).ok()?;
        let started = Instant::now();
        socket.send_to(&query, SocketAddr::new(resolver, 53)).ok()?;
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut buf).ok()?;
            if from.ip() != resolver {
                continue;
            }
            if let Some((rcode, answers)) = dns_answer(&buf[..n], id) {
                return Some(DnsAnswer {
                    rcode,
                    answers,
                    took: started.elapsed(),
                });
            }
        }
    }
}

// ── The thread ──────────────────────────────────────────────────────────

/// A failed results upload is tried once more after this; never one the
/// platform answered.
const UPLOAD_RETRY_DELAY: Duration = Duration::from_secs(5);

/// The daemon's handle on checks. With CONNLOG_CHECKS off it is inert: no
/// thread, nothing run, whatever a heartbeat says.
pub struct Checks {
    lane: Option<Lane>,
}

struct Lane {
    requests: std::sync::mpsc::Sender<(CheckRequest, bool)>,
    busy: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Checks {
    pub fn start(
        enabled: bool,
        base_url: String,
        token: String,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self::start_with(
            enabled,
            base_url,
            token,
            stop,
            std::sync::Arc::new(SystemHost),
        )
    }

    pub fn start_with(
        enabled: bool,
        base_url: String,
        token: String,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        host: std::sync::Arc<dyn CheckHost + Send + Sync>,
    ) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        if !enabled {
            return Self { lane: None };
        }
        let (tx, rx) = std::sync::mpsc::channel::<(CheckRequest, bool)>();
        let busy = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&busy);
        let lane = std::thread::Builder::new()
            .name("checks".into())
            .spawn(move || {
                let client = match crate::http::ApiClient::new(base_url, token) {
                    Ok(client) => client,
                    Err(e) => {
                        log::warn!("Checks are off: no HTTP client ({e})");
                        return;
                    }
                };
                let mut last = HashMap::new();
                while let Ok((request, allow_private)) = rx.recv() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run(
                            &request,
                            allow_private,
                            host.as_ref(),
                            &mut last,
                            Instant::now(),
                        )
                    }));
                    match ran {
                        Ok(results) => upload(&client, &results, &stop),
                        Err(_) => {
                            log::warn!("Running check request {} panicked; dropped", request.id)
                        }
                    }
                    flag.store(false, Ordering::SeqCst);
                }
            })
            .map_err(|e| log::warn!("Checks are off: could not start their thread ({e})"))
            .ok()
            .map(|_| Lane { requests: tx, busy });
        log::info!("Checks are on (CONNLOG_CHECKS=true)");
        Self { lane }
    }

    /// A heartbeat's `check_request`, handed to the thread unless one is
    /// still running (then it is dropped). `allow_private`: the host runs at
    /// the passive level now. Never blocks.
    pub fn on_heartbeat(&self, request: Option<CheckRequest>, allow_private: bool) {
        use std::sync::atomic::Ordering;
        let (Some(request), Some(lane)) = (request, &self.lane) else {
            return;
        };
        if lane
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            log::info!(
                "Dropping check request {}: the previous one is still running",
                request.id
            );
            return;
        }
        if lane.requests.send((request, allow_private)).is_err() {
            lane.busy.store(false, Ordering::SeqCst);
        }
    }
}

/// Send the results once; a delivery failure is tried once more.
fn upload(
    client: &crate::http::ApiClient,
    results: &CheckResults,
    stop: &std::sync::atomic::AtomicBool,
) {
    use crate::features::network_map::UploadOutcome;
    let body = results.to_json();
    for attempt in 1..=2 {
        let result = client.upload_network(CHECKS_PATH, CONTENT_TYPE, body.clone());
        let retry = attempt == 1 && UploadOutcome::of(&result) == UploadOutcome::Failed;
        match result {
            Ok(accepted) => {
                log::info!(
                    "Sent check results for {}: {} results, {}",
                    results.id,
                    results.results.len(),
                    if accepted { "accepted" } else { "not accepted" }
                );
                return;
            }
            Err(e) if retry => {
                log::warn!(
                    "Check results upload for {} failed, trying once more: {e}",
                    results.id
                );
                if stop.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(UPLOAD_RETRY_DELAY);
            }
            Err(e) => {
                log::warn!("Check results upload for {} failed: {e}", results.id);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const REQUESTS: &str =
        include_str!("../../../../packages/agent-protocol/fixtures/check-requests.json");
    const RESULTS: &str =
        include_str!("../../../../packages/agent-protocol/fixtures/check-results.json");

    /// The agent's half of `check-requests.json`: it runs exactly `runs`.
    #[test]
    fn reads_every_fixture_request_as_the_platform_expects() {
        let all: Vec<Value> = serde_json::from_str(REQUESTS).unwrap();
        for fixture in all {
            let description = fixture["description"].as_str().unwrap();
            let request = CheckRequest::from_json(&fixture["request"]);
            match fixture["runs"].as_array() {
                None => assert_eq!(request, None, "{description}"),
                Some(runs) => {
                    let ids: Vec<&str> = request
                        .as_ref()
                        .unwrap()
                        .checks
                        .iter()
                        .map(|c| c.id.as_str())
                        .collect();
                    let want: Vec<&str> = runs.iter().map(|r| r.as_str().unwrap()).collect();
                    assert_eq!(ids, want, "{description}");
                }
            }
        }
    }

    /// A network: names, echoes, ports, sites and resolvers, by address.
    #[derive(Default)]
    struct Fake {
        names: HashMap<&'static str, IpAddr>,
        echo: Option<Outcome>,
        ports: HashMap<u16, Result<Duration, Outcome>>,
        http: Option<HttpAnswer>,
        dns: Option<DnsAnswer>,
        asked: RefCell<Vec<String>>,
    }

    impl CheckHost for Fake {
        fn resolve(&self, host: &str) -> Option<IpAddr> {
            self.names.get(host).copied()
        }
        fn echo(&self, address: IpAddr) -> reachability::Probe {
            self.asked.borrow_mut().push(format!("echo {address}"));
            match self.echo.unwrap_or(Outcome::Open) {
                Outcome::Open => reachability::Probe {
                    outcome: Outcome::Open,
                    rtt_ms: Some(4),
                },
                other => reachability::Probe::of(other),
            }
        }
        fn connect(&self, address: SocketAddr) -> Result<Duration, Outcome> {
            self.asked.borrow_mut().push(format!("connect {address}"));
            *self
                .ports
                .get(&address.port())
                .unwrap_or(&Err(Outcome::Timeout))
        }
        fn http(&self, url: &reqwest::Url, address: IpAddr) -> HttpAnswer {
            self.asked
                .borrow_mut()
                .push(format!("get {url} at {address}"));
            self.http.unwrap()
        }
        fn dns(&self, resolver: IpAddr, name: &str, _: RecordType) -> Option<DnsAnswer> {
            self.asked
                .borrow_mut()
                .push(format!("dns {name} at {resolver}"));
            self.dns.clone()
        }
    }

    fn request(checks: Value) -> CheckRequest {
        CheckRequest::from_json(&serde_json::json!({ "id": "chk_1", "checks": checks })).unwrap()
    }

    fn run_once(request: &CheckRequest, allow_private: bool, host: &Fake) -> Vec<CheckResult> {
        run(
            request,
            allow_private,
            host,
            &mut HashMap::new(),
            Instant::now(),
        )
        .results
    }

    #[test]
    fn a_private_target_needs_the_passive_level_and_loopback_is_never_checked() {
        let host = Fake::default();
        let req = request(serde_json::json!([
            { "id": "nas", "kind": "ping", "target": "192.168.1.20" },
            { "id": "self", "kind": "tcp", "target": "127.0.0.1", "port": 22 },
            { "id": "resolver", "kind": "dns", "name": "example.com", "recordType": "A", "resolver": "10.0.0.53" }
        ]));
        let below = run_once(&req, false, &host);
        assert!(below
            .iter()
            .all(|r| r.outcome == "skipped" && r.reason == Some("not-allowed")));
        assert!(host.asked.borrow().is_empty(), "nothing goes on the wire");

        let passive = run_once(&req, true, &host);
        assert_eq!(passive[0].outcome, "up");
        assert_eq!(
            passive[1].reason,
            Some("not-allowed"),
            "loopback, even at passive"
        );
    }

    #[test]
    fn a_name_is_checked_against_where_it_resolves() {
        let host = Fake {
            names: HashMap::from([("intranet.example.com", "10.0.0.8".parse().unwrap())]),
            ..Fake::default()
        };
        let req = request(serde_json::json!([
            { "id": "a", "kind": "http", "url": "https://intranet.example.com/" },
            { "id": "b", "kind": "ping", "target": "nowhere.example.com" }
        ]));
        let results = run_once(&req, false, &host);
        assert_eq!(results[0].reason, Some("not-allowed"));
        assert_eq!(results[1].reason, Some("dns"));
    }

    #[test]
    fn the_same_target_is_checked_at_most_once_a_minute() {
        let host = Fake::default();
        let req = request(serde_json::json!([
            { "id": "a", "kind": "ping", "target": "203.0.113.5" },
            { "id": "b", "kind": "ping", "target": "203.0.113.5" }
        ]));
        let mut last = HashMap::new();
        let t0 = Instant::now();
        let first = run(&req, false, &host, &mut last, t0).results;
        assert_eq!(first[0].outcome, "up");
        assert_eq!(first[1].reason, Some("too-soon"));
        let later = run(&req, false, &host, &mut last, t0 + MIN_INTERVAL_PER_TARGET).results;
        assert_eq!(later[0].outcome, "up");
    }

    #[test]
    fn ping_is_three_echoes_and_says_how_many_came_back() {
        let host = Fake::default();
        let req =
            request(serde_json::json!([{ "id": "a", "kind": "ping", "target": "203.0.113.5" }]));
        let result = &run_once(&req, false, &host)[0];
        assert_eq!(
            result.ping,
            Some(PingStats {
                sent: 3,
                received: 3
            })
        );
        assert_eq!(result.ms, Some(4));
        assert_eq!(host.asked.borrow().len(), PING_COUNT as usize);

        let refused = Fake {
            echo: Some(Outcome::Skipped),
            ..Fake::default()
        };
        assert_eq!(
            run_once(&req, false, &refused)[0].reason,
            Some("unsupported")
        );
    }

    #[test]
    fn tcp_says_what_the_handshake_got() {
        let host = Fake {
            ports: HashMap::from([
                (443, Ok(Duration::from_millis(12))),
                (5432, Err(Outcome::Refused)),
            ]),
            ..Fake::default()
        };
        let req = request(serde_json::json!([
            { "id": "a", "kind": "tcp", "target": "203.0.113.5", "port": 443 },
            { "id": "b", "kind": "tcp", "target": "203.0.113.6", "port": 5432 },
            { "id": "c", "kind": "tcp", "target": "203.0.113.7", "port": 25 }
        ]));
        let results = run_once(&req, false, &host);
        assert_eq!((results[0].outcome, results[0].ms), ("up", Some(12)));
        assert_eq!(results[1].reason, Some("refused"));
        assert_eq!(results[2].reason, Some("timeout"));
    }

    #[test]
    fn http_is_pinned_to_the_resolved_address_and_reads_its_status_only() {
        let host = Fake {
            names: HashMap::from([("example.com", "93.184.215.14".parse().unwrap())]),
            http: Some(HttpAnswer {
                status: Some(503),
                first_byte: Some(Duration::from_millis(80)),
                cert_days_left: Some(61),
                tls_valid: Some(true),
                failure: None,
            }),
            ..Fake::default()
        };
        let req = request(
            serde_json::json!([{ "id": "a", "kind": "http", "url": "https://example.com/health" }]),
        );
        let result = &run_once(&req, false, &host)[0];
        assert_eq!(
            (result.outcome, result.reason, result.ms),
            ("down", Some("status"), Some(80))
        );
        assert_eq!(
            result.http,
            Some(HttpStats {
                status: Some(503),
                cert_days_left: Some(61),
                tls_valid: Some(true)
            })
        );
        assert_eq!(
            host.asked.borrow().as_slice(),
            ["get https://example.com/health at 93.184.215.14"]
        );
    }

    #[test]
    fn dns_is_up_with_an_answer_and_down_without_one() {
        let answer = |rcode, answers: Vec<IpAddr>| Fake {
            dns: Some(DnsAnswer {
                rcode,
                answers,
                took: Duration::from_millis(14),
            }),
            ..Fake::default()
        };
        let req = request(
            serde_json::json!([{ "id": "a", "kind": "dns", "name": "example.com", "recordType": "A", "resolver": "1.1.1.1" }]),
        );
        let up = &run_once(
            &req,
            false,
            &answer("noerror", vec!["93.184.215.14".parse().unwrap()]),
        )[0];
        assert_eq!((up.outcome, up.ms), ("up", Some(14)));
        let gone = &run_once(&req, false, &answer("nxdomain", vec![]))[0];
        assert_eq!((gone.outcome, gone.reason), ("down", Some("no-answer")));
        assert_eq!(
            run_once(&req, false, &Fake::default())[0].reason,
            Some("timeout")
        );
    }

    /// The agent's half of `check-results.json`: what it writes for each
    /// result is exactly the `valid` shape.
    #[test]
    fn writes_results_as_the_fixture_has_them() {
        let fixture: Value = serde_json::from_str(RESULTS).unwrap();
        let ours = CheckResults {
            version: 1,
            id: "chk_01J0A".into(),
            results: vec![
                CheckResult {
                    http: Some(HttpStats {
                        status: Some(200),
                        cert_days_left: Some(61),
                        tls_valid: Some(true),
                    }),
                    ..CheckResult::up("site", Some(182))
                },
                CheckResult {
                    ping: Some(PingStats {
                        sent: 3,
                        received: 3,
                    }),
                    ..CheckResult::up("router", Some(1))
                },
                CheckResult::up("db", Some(2)),
                CheckResult {
                    dns: Some(DnsStats {
                        rcode: "noerror",
                        answers: vec!["93.184.215.14".into()],
                    }),
                    ..CheckResult::up("resolver", Some(14))
                },
            ],
        };
        let sent: Value = serde_json::from_slice(&ours.to_json()).unwrap();
        assert_eq!(sent, fixture["valid"][0]["upload"]);
    }

    #[test]
    fn caps_are_what_the_protocol_says() {
        let protocol = include_str!("../../../../packages/agent-protocol/src/checks.ts");
        for (name, value) in [
            ("CHECK_MAX_PER_REQUEST", MAX_PER_REQUEST.to_string()),
            ("CHECK_TIMEOUT_MS", "10_000".to_string()),
            ("CHECK_PING_COUNT", PING_COUNT.to_string()),
            ("CHECK_DNS_MAX_ANSWERS", MAX_DNS_ANSWERS.to_string()),
        ] {
            assert!(
                protocol.contains(&format!("export const {name} = {value};")),
                "{name} = {value}"
            );
        }
        assert_eq!(CHECK_TIMEOUT, Duration::from_millis(10_000));
    }

    // A certificate's validity, as DER: notBefore 2026-01-01, notAfter
    // 2026-12-31 23:59:59 (UTCTime), behind a version, serial, algorithm and
    // issuer, as X.509 lays them out.
    fn certificate(not_after: &[u8], tag: u8) -> Vec<u8> {
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag, value.len() as u8];
            out.extend_from_slice(value);
            out
        }
        let validity = [tlv(0x17, b"260101000000Z"), tlv(tag, not_after)].concat();
        let tbs = [
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[1, 2, 3]),
            tlv(0x30, &tlv(0x06, &[0x2a, 0x86])),
            tlv(0x30, &tlv(0x31, &[])),
            tlv(0x30, &validity),
        ]
        .concat();
        tlv(0x30, &tlv(0x30, &tbs))
    }

    #[test]
    fn reads_a_certificates_expiry() {
        let utc = certificate(b"261231235959Z", 0x17);
        assert_eq!(cert_not_after(&utc), Some(1_798_761_599));
        let generalized = certificate(b"20261231235959Z", 0x18);
        assert_eq!(cert_not_after(&generalized), Some(1_798_761_599));
        assert_eq!(cert_not_after(&[0x30, 0x05, 0x30]), None);
        // 61 days and a bit before: 61 days left; a day after: -1.
        assert_eq!(
            days_left(1_798_761_599, 1_798_761_599 - 61 * 86_400 - 5),
            61
        );
        assert_eq!(days_left(1_798_761_599, 1_798_761_599 + 86_400), -1);
    }

    #[test]
    fn writes_a_dns_query_and_reads_its_answer() {
        let query = dns_query(0x1234, "example.com", RecordType::A).unwrap();
        assert_eq!(
            query,
            [
                &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..],
                b"\x07example\x03com\x00",
                &[0, 1, 0, 1]
            ]
            .concat()
        );
        assert_eq!(dns_query(1, "bad..name", RecordType::A), None);

        // The answer: the question echoed, one A record by a compressed name.
        let mut answer = query.clone();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[7] = 1;
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14]);
        assert_eq!(
            dns_answer(&answer, 0x1234),
            Some(("noerror", vec!["93.184.215.14".parse().unwrap()]))
        );
        assert_eq!(dns_answer(&answer, 0x9999), None, "not our query");
        let mut nx = query;
        nx[2] = 0x81;
        nx[3] = 0x83;
        assert_eq!(dns_answer(&nx, 0x1234), Some(("nxdomain", vec![])));
    }
}
