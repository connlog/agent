//! Reachability probes for the network map (docs/topology/PLAN.md,
//! guarantee 3): what an opted-in agent does with the `probe_request` a
//! heartbeat answer carries.
//!
//! The agent bounds what it will do, whatever it is told. These caps are
//! compiled in, not configuration:
//!
//! - at most 32 targets and 8 ports per target, in the order given; the rest
//!   is dropped before anything is read;
//! - at most 4 probes in flight, a 1 s timeout each;
//! - a TCP probe is a handshake and a close, never a byte of payload;
//! - an address outside the private ranges (RFC 1918, 100.64/10,
//!   169.254/16, fc00::/7, fe80::/10) is `skipped` unless the host sets
//!   `CONNLOG_PROBE_PUBLIC=true`;
//! - one request at a time (`network_map` drops a request while one runs).
//!
//! The ICMP echo uses an unprivileged ping socket (`SOCK_DGRAM` /
//! `IPPROTO_ICMP`), which the kernel allows only for the groups in
//! `net.ipv4.ping_group_range`; where it is not allowed the echo is
//! `skipped`. The agent never gains a capability for it.
//!
//! Results are `application/vnd.connlog.probes.v1+json`, pinned by
//! `probe-requests.json` and `probe-results.json`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

pub const CONTENT_TYPE: &str = "application/vnd.connlog.probes.v1+json";
pub const PROBES_PATH: &str = "/api/agents/probes";
pub const FORMAT_VERSION: u8 = 1;

/// `PROBE_MAX_TARGETS` and `PROBE_MAX_PORTS_PER_TARGET` in the protocol.
pub const MAX_TARGETS: usize = 32;
pub const MAX_PORTS_PER_TARGET: usize = 8;
pub const MAX_IN_FLIGHT: usize = 4;
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// The protocol's ceiling on `rttMs`.
const MAX_RTT_MS: u128 = 60_000;
const MAX_ID_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    pub id: String,
    pub targets: Vec<ProbeTarget>,
    /// The other opted-in hosts on this host's site (T11.1): at the peers
    /// level, the only ones whose connections may be sent. At most 1,024.
    pub peers: Vec<IpAddr>,
}

/// `PROBE_MAX_PEERS` in the protocol.
pub const MAX_PEERS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub address: IpAddr,
    pub ports: Vec<u16>,
    pub icmp: bool,
}

impl ProbeRequest {
    /// Read a heartbeat answer's `probe_request`, cut to the caps first: no
    /// more than 32 targets and 8 ports each are ever looked at. A target
    /// that is not an address, or a port that is not one, is dropped; a
    /// request without a usable id is no request (its results could not be
    /// matched).
    pub fn from_json(value: &Value) -> Option<Self> {
        let id = value.get("id")?.as_str()?;
        let id_ok = (1..=MAX_ID_LEN).contains(&id.len())
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !id_ok {
            return None;
        }
        let targets = value
            .get("targets")?
            .as_array()?
            .iter()
            .take(MAX_TARGETS)
            .filter_map(|target| {
                let address = parse_address(target.get("address")?.as_str()?)?;
                let ports = target
                    .get("ports")
                    .and_then(Value::as_array)
                    .map(|ports| {
                        ports
                            .iter()
                            .take(MAX_PORTS_PER_TARGET)
                            .filter_map(|p| p.as_u64())
                            .filter_map(|p| u16::try_from(p).ok())
                            .filter(|p| *p != 0)
                            .collect()
                    })
                    .unwrap_or_default();
                let icmp = target.get("icmp").and_then(Value::as_bool) == Some(true);
                Some(ProbeTarget {
                    address,
                    ports,
                    icmp,
                })
            })
            .collect();
        let peers = value
            .get("peers")
            .and_then(Value::as_array)
            .map(|peers| {
                peers
                    .iter()
                    .take(MAX_PEERS)
                    .filter_map(|p| parse_address(p.as_str()?))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            id: id.to_string(),
            targets,
            peers,
        })
    }
}

/// An address as the platform writes one. An IPv4-mapped IPv6 address is
/// refused: the platform does not read that form back.
fn parse_address(text: &str) -> Option<IpAddr> {
    let ip: IpAddr = text.parse().ok()?;
    (!(ip.is_ipv6() && ip.to_string().contains('.'))).then_some(ip)
}

/// The ranges an agent probes without `CONNLOG_PROBE_PUBLIC`: `isPrivateAddress`
/// in `packages/agent-protocol/src/network.ts`, pinned by the fixture's
/// `privateAddresses` and `publicAddresses`.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let n = u32::from(*v4);
            [
                (0x0a00_0000u32, 8u32), // 10/8
                (0xac10_0000, 12),      // 172.16/12
                (0xc0a8_0000, 16),      // 192.168/16
                (0x6440_0000, 10),      // 100.64/10 (CGNAT, Tailscale)
                (0xa9fe_0000, 16),      // 169.254/16 link-local
            ]
            .iter()
            .any(|(base, bits)| n & (u32::MAX << (32 - bits)) == *base)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Open,
    Refused,
    Timeout,
    Unreachable,
    Skipped,
}

/// One probe's answer: `rtt_ms` only with `Open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub outcome: Outcome,
    pub rtt_ms: Option<u32>,
}

impl Probe {
    pub const fn of(outcome: Outcome) -> Self {
        Self {
            outcome,
            rtt_ms: None,
        }
    }

    pub fn open(elapsed: Duration) -> Self {
        Self {
            outcome: Outcome::Open,
            rtt_ms: Some(elapsed.as_millis().min(MAX_RTT_MS) as u32),
        }
    }
}

/// One line of the plan: an address and a port, or the echo (`None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job {
    pub address: IpAddr,
    pub port: Option<u16>,
    /// False when the guard refused it: reported `skipped`, never opened.
    pub tried: bool,
}

/// What a request comes to: each target's ports in the order given, then its
/// echo when asked for; outside the private ranges, all of it skipped unless
/// the host allows public targets.
pub fn plan(request: &ProbeRequest, allow_public: bool) -> Vec<Job> {
    request
        .targets
        .iter()
        .flat_map(|target| {
            let tried = allow_public || is_private(&target.address);
            target
                .ports
                .iter()
                .map(|port| Some(*port))
                .chain(target.icmp.then_some(None))
                .map(move |port| Job {
                    address: target.address,
                    port,
                    tried,
                })
        })
        .collect()
}

/// How a probe is carried out; `SystemProber` on a host, a stand-in in tests.
pub trait Prober: Send + Sync {
    fn tcp(&self, address: SocketAddr, timeout: Duration) -> Probe;
    fn echo(&self, address: IpAddr, timeout: Duration) -> Probe;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub address: String,
    pub port: Option<u16>,
    pub outcome: Outcome,
    pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeResults {
    pub version: u8,
    pub id: String,
    pub results: Vec<ProbeResult>,
}

impl ProbeResults {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Run a request: the plan, at most `MAX_IN_FLIGHT` probes at a time, each
/// with `PROBE_TIMEOUT`. Results come back in the plan's order.
pub fn run(request: &ProbeRequest, allow_public: bool, prober: &dyn Prober) -> ProbeResults {
    let jobs = plan(request, allow_public);
    let answers: Vec<Mutex<Option<Probe>>> = jobs.iter().map(|_| Mutex::new(None)).collect();
    let tried: Vec<usize> = (0..jobs.len()).filter(|i| jobs[*i].tried).collect();
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..MAX_IN_FLIGHT.min(tried.len()) {
            scope.spawn(|| {
                while let Some(&index) = tried.get(next.fetch_add(1, Ordering::SeqCst)) {
                    let job = jobs[index];
                    let probe = match job.port {
                        Some(port) => prober.tcp(SocketAddr::new(job.address, port), PROBE_TIMEOUT),
                        None => prober.echo(job.address, PROBE_TIMEOUT),
                    };
                    *answers[index].lock().unwrap_or_else(|p| p.into_inner()) = Some(probe);
                }
            });
        }
    });
    let results = jobs
        .iter()
        .zip(answers)
        .map(|(job, answer)| {
            let probe = answer
                .into_inner()
                .unwrap_or_else(|p| p.into_inner())
                // A job no thread answered (a panicking prober) is reported
                // as skipped rather than guessed.
                .unwrap_or(Probe::of(Outcome::Skipped));
            ProbeResult {
                address: job.address.to_string(),
                port: job.port,
                outcome: probe.outcome,
                rtt_ms: if probe.outcome == Outcome::Open {
                    probe.rtt_ms
                } else {
                    None
                },
            }
        })
        .collect();
    ProbeResults {
        version: FORMAT_VERSION,
        id: request.id.clone(),
        results,
    }
}

/// Probes with the host's own sockets.
pub struct SystemProber;

impl Prober for SystemProber {
    /// A handshake, then the socket is closed: not a byte is written.
    fn tcp(&self, address: SocketAddr, timeout: Duration) -> Probe {
        let started = Instant::now();
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                let elapsed = started.elapsed();
                drop(stream);
                Probe::open(elapsed)
            }
            Err(e) => Probe::of(connect_error_outcome(&e)),
        }
    }

    fn echo(&self, address: IpAddr, timeout: Duration) -> Probe {
        icmp_echo(address, timeout)
    }
}

/// `refused` for a reset, `timeout` for silence, `unreachable` for anything
/// that says there is no way there.
pub fn connect_error_outcome(e: &io::Error) -> Outcome {
    match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => Outcome::Refused,
        Some(libc::ETIMEDOUT) => Outcome::Timeout,
        Some(_) => Outcome::Unreachable,
        None => match e.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Outcome::Timeout,
            io::ErrorKind::ConnectionRefused => Outcome::Refused,
            _ => Outcome::Unreachable,
        },
    }
}

/// The ICMP header checksum (RFC 1071). The kernel fills it in for a ping
/// socket anyway; it is set so the packet is right as written.
fn icmp_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// One echo request on an unprivileged ping socket, and its reply.
/// `skipped` when this host does not let the agent's group open one.
pub fn icmp_echo(address: IpAddr, timeout: Duration) -> Probe {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let (domain, protocol, request_type, reply_type) = match address {
        IpAddr::V4(_) => (libc::AF_INET, libc::IPPROTO_ICMP, 8u8, 0u8),
        IpAddr::V6(_) => (libc::AF_INET6, libc::IPPROTO_ICMPV6, 128u8, 129u8),
    };
    // SAFETY: plain socket(2); the descriptor is owned below.
    let raw = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, protocol) };
    if raw < 0 {
        // EACCES / EPERM (ping_group_range), or no such protocol (FreeBSD
        // has no ping socket): a raw socket, which only an agent its host's
        // root chose to run as root can open (T13.5c); else not a probe
        // this host allows.
        return match address {
            IpAddr::V4(v4) => raw_echo_v4(v4, timeout).unwrap_or(Probe::of(Outcome::Skipped)),
            IpAddr::V6(_) => Probe::of(Outcome::Skipped),
        };
    }
    // SAFETY: `raw` is a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = socket.as_raw_fd();

    // Type, code, checksum, identifier (the kernel sets it), sequence 1. No
    // payload.
    let mut packet = [request_type, 0, 0, 0, 0, 0, 0, 1];
    if address.is_ipv4() {
        let sum = icmp_checksum(&packet).to_be_bytes();
        packet[2..4].copy_from_slice(&sum);
    }

    let started = Instant::now();
    let sent = match address {
        IpAddr::V4(v4) => {
            let to = sockaddr_v4(v4);
            // SAFETY: `to` is a valid sockaddr_in for its stated length.
            unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&to as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        IpAddr::V6(v6) => {
            let to = sockaddr_v6(v6);
            // SAFETY: `to` is a valid sockaddr_in6 for its stated length.
            unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&to as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if sent < 0 {
        return Probe::of(Outcome::Unreachable);
    }

    let mut reply = [0u8; 128];
    loop {
        let Some(left) = timeout.checked_sub(started.elapsed()) else {
            return Probe::of(Outcome::Timeout);
        };
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: one pollfd, valid for the call.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready == 0 {
            return Probe::of(Outcome::Timeout);
        }
        if ready < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            return Probe::of(Outcome::Unreachable);
        }
        // SAFETY: `reply` is writable for its length.
        let n = unsafe {
            libc::recv(
                fd,
                reply.as_mut_ptr().cast(),
                reply.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            match last_errno() {
                libc::EAGAIN | libc::EINTR => continue,
                _ => return Probe::of(Outcome::Unreachable),
            }
        }
        // A ping socket hands back the ICMP message, without the IP header,
        // and only replies to its own identifier.
        if n > 0 && reply[0] == reply_type {
            return Probe::open(started.elapsed());
        }
    }
}

/// Whether a raw socket's IPv4 packet is the echo reply to `id`, sequence 1:
/// a raw socket hands back the IP header and every ICMP message the host
/// gets, so the identifier is what tells ours apart.
pub fn is_echo_reply(packet: &[u8], id: u16) -> bool {
    let Some(first) = packet.first() else {
        return false;
    };
    let header = usize::from(first & 0x0f) * 4;
    matches!(
        packet.get(header..header + 8),
        Some(icmp) if icmp[0] == 0 && icmp[4..6] == id.to_be_bytes() && icmp[6..8] == [0, 1]
    )
}

/// One echo on a raw ICMP socket, for a host without a ping socket whose
/// root runs the agent as root (a firewall, T13.5c). `None` when the socket
/// cannot be opened: without privilege, that is every time.
pub fn raw_echo_v4(address: Ipv4Addr, timeout: Duration) -> Option<Probe> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU16, Ordering};

    static NEXT: AtomicU16 = AtomicU16::new(0);
    // SAFETY: plain socket(2); the descriptor is owned below.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` is a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = socket.as_raw_fd();
    let id = (std::process::id() as u16) ^ NEXT.fetch_add(1, Ordering::Relaxed).rotate_left(8);
    let mut packet = [8u8, 0, 0, 0, 0, 0, 0, 1];
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    let sum = icmp_checksum(&packet).to_be_bytes();
    packet[2..4].copy_from_slice(&sum);
    let to = sockaddr_v4(address);
    let started = Instant::now();
    // SAFETY: `to` is a valid sockaddr_in for its stated length.
    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&to as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Some(Probe::of(Outcome::Unreachable));
    }
    let mut reply = [0u8; 256];
    loop {
        let Some(left) = timeout.checked_sub(started.elapsed()) else {
            return Some(Probe::of(Outcome::Timeout));
        };
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: one pollfd, valid for the call.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready == 0 {
            return Some(Probe::of(Outcome::Timeout));
        }
        if ready < 0 {
            if last_errno() == libc::EINTR {
                continue;
            }
            return Some(Probe::of(Outcome::Unreachable));
        }
        // SAFETY: all-zero is a valid sockaddr_in; recvfrom writes within
        // `reply` and `from`.
        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd,
                reply.as_mut_ptr().cast(),
                reply.len(),
                libc::MSG_DONTWAIT,
                (&mut from as *mut libc::sockaddr_in).cast(),
                &mut from_len,
            )
        };
        if n < 0 {
            match last_errno() {
                libc::EAGAIN | libc::EINTR => continue,
                _ => return Some(Probe::of(Outcome::Unreachable)),
            }
        }
        let source = Ipv4Addr::from(from.sin_addr.s_addr.to_ne_bytes());
        if source == address && is_echo_reply(&reply[..n as usize], id) {
            return Some(Probe::open(started.elapsed()));
        }
    }
}

fn sockaddr_v4(ip: Ipv4Addr) -> libc::sockaddr_in {
    // SAFETY: all-zero is a valid sockaddr_in.
    let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    to.sin_family = libc::AF_INET as libc::sa_family_t;
    to.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    to
}

fn sockaddr_v6(ip: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: all-zero is a valid sockaddr_in6.
    let mut to: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    to.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    to.sin6_addr.s6_addr = ip.octets();
    to
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;

    const REQUESTS: &str = protocol_fixture!("probe-requests.json");
    const RESULTS: &str = protocol_fixture!("probe-results.json");

    fn pairs(value: &Value) -> Vec<(String, Option<u16>)> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_string(),
                    pair[1].as_u64().map(|p| p as u16),
                )
            })
            .collect()
    }

    #[test]
    fn tells_its_own_echo_reply_from_any_other_icmp() {
        // An IPv4 header (20 bytes), then an echo reply to id 0x1234, sequence 1.
        let mut packet = vec![0x45u8];
        packet.resize(20, 0);
        packet.extend([0, 0, 0, 0, 0x12, 0x34, 0, 1]);
        assert!(is_echo_reply(&packet, 0x1234));
        assert!(!is_echo_reply(&packet, 0x4321), "another process's ping");
        packet[20] = 8;
        assert!(!is_echo_reply(&packet, 0x1234), "a request, not a reply");
        assert!(!is_echo_reply(&packet[..24], 0x1234), "cut short");
        assert!(!is_echo_reply(&[], 0x1234));
    }

    /// Only as root (the FreeBSD VM in CI, a root agent on a firewall):
    /// unprivileged, the raw socket cannot be opened and nothing is sent.
    #[test]
    fn a_raw_echo_reaches_loopback_as_root_and_nothing_opens_otherwise() {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let probe = raw_echo_v4(Ipv4Addr::LOCALHOST, Duration::from_secs(2));
        if root {
            assert_eq!(probe.map(|p| p.outcome), Some(Outcome::Open));
        } else {
            assert!(probe.is_none());
        }
    }

    /// The agent's half of `probe-requests.json`: the same addresses are
    /// private on both sides.
    #[test]
    fn agrees_on_which_addresses_are_private() {
        let fixture: Value = serde_json::from_str(REQUESTS).unwrap();
        for (key, private) in [("privateAddresses", true), ("publicAddresses", false)] {
            let list = fixture[key].as_array().unwrap();
            assert!(!list.is_empty());
            for address in list {
                let ip: IpAddr = address.as_str().unwrap().parse().unwrap();
                assert_eq!(is_private(&ip), private, "{address}");
            }
        }
    }

    /// Every case of `probe-requests.json`: what is tried and what is
    /// reported skipped, in order.
    #[test]
    fn reproduces_every_fixture_case() {
        let fixture: Value = serde_json::from_str(REQUESTS).unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let description = case["description"].as_str().unwrap();
            let request = ProbeRequest::from_json(&case["request"]).expect(description);
            let jobs = plan(&request, case["allowPublic"].as_bool().unwrap());
            let of = |tried: bool| -> Vec<(String, Option<u16>)> {
                jobs.iter()
                    .filter(|j| j.tried == tried)
                    .map(|j| (j.address.to_string(), j.port))
                    .collect()
            };
            assert_eq!(of(true), pairs(&case["tried"]), "{description}: tried");
            assert_eq!(of(false), pairs(&case["skipped"]), "{description}: skipped");
        }
    }

    /// A stand-in that answers from a table and records what it was asked.
    #[derive(Default)]
    struct Table {
        answers: HashMap<(IpAddr, Option<u16>), Probe>,
        asked: Mutex<Vec<(IpAddr, Option<u16>)>>,
        in_flight: AtomicUsize,
        most_in_flight: AtomicUsize,
        delay: Duration,
    }

    impl Table {
        fn answer(&self, key: (IpAddr, Option<u16>)) -> Probe {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.most_in_flight.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.asked.lock().unwrap().push(key);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            self.answers
                .get(&key)
                .copied()
                .unwrap_or(Probe::of(Outcome::Timeout))
        }
    }

    impl Prober for Table {
        fn tcp(&self, address: SocketAddr, timeout: Duration) -> Probe {
            assert_eq!(timeout, PROBE_TIMEOUT);
            self.answer((address.ip(), Some(address.port())))
        }
        fn echo(&self, address: IpAddr, timeout: Duration) -> Probe {
            assert_eq!(timeout, PROBE_TIMEOUT);
            self.answer((address, None))
        }
    }

    /// The agent's half of `probe-results.json`: the request behind the
    /// fixture, run against a network that answers as it says, produces
    /// exactly that upload; the public address is skipped without a probe.
    #[test]
    fn produces_every_fixture_result_exactly() {
        let fixture: Value = serde_json::from_str(RESULTS).unwrap();
        for case in fixture["valid"].as_array().unwrap() {
            let description = case["description"].as_str().unwrap();
            let upload = &case["upload"];
            let mut table = Table::default();
            let mut targets: Vec<Value> = Vec::new();
            for result in upload["results"].as_array().unwrap() {
                let address = result["address"].as_str().unwrap();
                let ip: IpAddr = address.parse().unwrap();
                let port = result["port"].as_u64().map(|p| p as u16);
                let outcome: Outcome = serde_json::from_value(result["outcome"].clone()).unwrap();
                table.answers.insert(
                    (ip, port),
                    Probe {
                        outcome,
                        rtt_ms: result["rttMs"].as_u64().map(|v| v as u32),
                    },
                );
                if !targets.iter().any(|t| t["address"] == address) {
                    targets.push(
                        serde_json::json!({ "address": address, "ports": [], "icmp": false }),
                    );
                }
                let target = targets
                    .iter_mut()
                    .find(|t| t["address"] == address)
                    .unwrap();
                match port {
                    Some(p) => target["ports"].as_array_mut().unwrap().push(p.into()),
                    None => target["icmp"] = true.into(),
                }
            }
            let request = ProbeRequest::from_json(&serde_json::json!({
                "id": upload["id"],
                "targets": targets,
            }))
            .unwrap();
            let results = run(&request, false, &table);
            let sent: Value = serde_json::from_slice(&results.to_json()).unwrap();
            assert_eq!(&sent, upload, "{description}");
            assert!(
                table
                    .asked
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(ip, _)| is_private(ip)),
                "{description}: a public address was probed"
            );
        }
    }

    #[test]
    fn requests_are_cut_to_the_caps_before_anything_runs() {
        let targets: Vec<Value> = (0..40)
            .map(|i| {
                serde_json::json!({
                    "address": format!("10.0.0.{i}"),
                    "ports": (1..=20).collect::<Vec<u16>>(),
                    "icmp": true
                })
            })
            .collect();
        let request =
            ProbeRequest::from_json(&serde_json::json!({ "id": "prb_big", "targets": targets }))
                .unwrap();
        assert_eq!(request.targets.len(), MAX_TARGETS);
        assert!(request
            .targets
            .iter()
            .all(|t| t.ports == (1..=8).collect::<Vec<u16>>()));
        assert_eq!(request.targets[31].address.to_string(), "10.0.0.31");

        let table = Table::default();
        let results = run(&request, false, &table);
        assert_eq!(
            results.results.len(),
            MAX_TARGETS * (MAX_PORTS_PER_TARGET + 1)
        );
        assert_eq!(
            table.asked.lock().unwrap().len(),
            MAX_TARGETS * (MAX_PORTS_PER_TARGET + 1)
        );
    }

    #[test]
    fn at_most_four_probes_are_in_flight_and_results_keep_their_order() {
        let table = Table {
            delay: Duration::from_millis(20),
            ..Table::default()
        };
        let request = ProbeRequest::from_json(&serde_json::json!({
            "id": "prb_order",
            "targets": [
                { "address": "10.0.0.1", "ports": [1, 2, 3, 4, 5, 6, 7, 8], "icmp": true },
                { "address": "10.0.0.2", "ports": [9, 10], "icmp": false }
            ]
        }))
        .unwrap();
        let results = run(&request, false, &table);
        assert_eq!(table.most_in_flight.load(Ordering::SeqCst), MAX_IN_FLIGHT);
        let order: Vec<(String, Option<u16>)> = results
            .results
            .iter()
            .map(|r| (r.address.clone(), r.port))
            .collect();
        let mut expected: Vec<(String, Option<u16>)> =
            (1..=8).map(|p| ("10.0.0.1".to_string(), Some(p))).collect();
        expected.push(("10.0.0.1".to_string(), None));
        expected.push(("10.0.0.2".to_string(), Some(9)));
        expected.push(("10.0.0.2".to_string(), Some(10)));
        assert_eq!(order, expected);
    }

    #[test]
    fn what_cannot_be_read_is_dropped() {
        for bad_id in [
            serde_json::json!({ "id": "prb/1", "targets": [] }),
            serde_json::json!({ "id": "", "targets": [] }),
            serde_json::json!({ "id": "a".repeat(65), "targets": [] }),
            serde_json::json!({ "id": 7, "targets": [] }),
            serde_json::json!({ "targets": [] }),
            serde_json::json!({ "id": "prb_1" }),
            serde_json::json!("prb_1"),
        ] {
            assert_eq!(ProbeRequest::from_json(&bad_id), None, "{bad_id}");
        }
        let request = ProbeRequest::from_json(&serde_json::json!({
            "id": "prb_1",
            "targets": [
                { "address": "10.0.0.256", "ports": [22] },
                { "address": "::ffff:10.0.0.1", "ports": [22] },
                { "address": "db-1", "ports": [22] },
                { "address": "10.0.0.1", "ports": [0, 22, 70000, -1, "443", 5432] },
                { "address": "fd00:10::7" }
            ]
        }))
        .unwrap();
        assert_eq!(
            request.targets,
            vec![
                ProbeTarget {
                    address: "10.0.0.1".parse().unwrap(),
                    ports: vec![22, 5432],
                    icmp: false
                },
                ProbeTarget {
                    address: "fd00:10::7".parse().unwrap(),
                    ports: vec![],
                    icmp: false
                },
            ]
        );
    }

    #[test]
    fn rtt_is_reported_only_for_open() {
        struct Odd;
        impl Prober for Odd {
            fn tcp(&self, _: SocketAddr, _: Duration) -> Probe {
                Probe {
                    outcome: Outcome::Refused,
                    rtt_ms: Some(5),
                }
            }
            fn echo(&self, _: IpAddr, _: Duration) -> Probe {
                Probe::open(Duration::from_secs(120))
            }
        }
        let request = ProbeRequest::from_json(&serde_json::json!({
            "id": "prb_1",
            "targets": [{ "address": "10.0.0.1", "ports": [22], "icmp": true }]
        }))
        .unwrap();
        let results = run(&request, false, &Odd);
        assert_eq!(results.results[0].rtt_ms, None);
        assert_eq!(
            results.results[1].rtt_ms,
            Some(60_000),
            "capped at a minute"
        );
    }

    #[test]
    fn connect_errors_map_to_outcomes() {
        let os = io::Error::from_raw_os_error;
        assert_eq!(
            connect_error_outcome(&os(libc::ECONNREFUSED)),
            Outcome::Refused
        );
        assert_eq!(
            connect_error_outcome(&os(libc::ETIMEDOUT)),
            Outcome::Timeout
        );
        assert_eq!(
            connect_error_outcome(&os(libc::EHOSTUNREACH)),
            Outcome::Unreachable
        );
        assert_eq!(
            connect_error_outcome(&os(libc::ENETUNREACH)),
            Outcome::Unreachable
        );
        assert_eq!(
            connect_error_outcome(&io::Error::from(io::ErrorKind::TimedOut)),
            Outcome::Timeout
        );
    }

    #[test]
    fn icmp_checksum_matches_a_known_echo_request() {
        // Type 8, id 0, seq 1: 0xffff - 0x0801 = 0xf7fe.
        assert_eq!(icmp_checksum(&[8, 0, 0, 0, 0, 0, 0, 1]), 0xf7fe);
    }

    /// The real prober against this machine: a listener is open, a closed
    /// port refuses, and the echo is either answered or not allowed here.
    #[test]
    fn the_system_prober_handshakes_and_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap();
        let probe = SystemProber.tcp(open, PROBE_TIMEOUT);
        assert_eq!(probe.outcome, Outcome::Open);
        assert!(probe.rtt_ms.is_some());
        // The handshake completed and the agent closed without a byte.
        let (mut accepted, _) = listener.accept().unwrap();
        let mut buf = [0u8; 16];
        accepted
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(
            io::Read::read(&mut accepted, &mut buf).unwrap(),
            0,
            "no payload, then EOF"
        );

        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        assert_eq!(
            SystemProber.tcp(closed, PROBE_TIMEOUT).outcome,
            Outcome::Refused
        );

        let echo = SystemProber.echo("127.0.0.1".parse().unwrap(), PROBE_TIMEOUT);
        assert!(
            matches!(echo.outcome, Outcome::Open | Outcome::Skipped),
            "{echo:?}"
        );
    }
}
