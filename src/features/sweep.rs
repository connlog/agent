//! Subnet sweeps (docs/topology/PLAN.md, T12.1, the `active` level): what a
//! host does with the `sweep_request` a heartbeat answer carries. Only at
//! `active`, the lower of the host's own ceiling and what the console
//! allows; below it a request is answered `not-active` and nothing is sent
//! on the network.
//!
//! The agent bounds what it does, whatever it is told. Compiled in, not
//! configuration:
//!
//! - an IPv4 subnet this host has an address in, at most a /22 (1,022
//!   addresses); IPv6 is never swept;
//! - at most 64 addresses started a second, at most 32 in flight;
//! - per address, an ICMP echo (an unprivileged ping socket, skipped where
//!   the kernel does not allow one) and TCP handshakes to at most 8 ports,
//!   each one of `WELL_KNOWN`; a handshake is closed at once, never a byte
//!   of payload;
//! - one mDNS question (`_services._dns-sd._udp.local`, asked as a legacy
//!   unicast query, so no multicast group is joined) and one SSDP
//!   M-SEARCH, each answered for 3 seconds, out of the swept subnet's
//!   interface with a TTL of 1;
//! - one sweep at a time (`network_map` drops a request while one runs).
//!
//! What is sent back is what the legal text names: the addresses that
//! answered, their open well-known ports, and what they announce over mDNS
//! (service types, never instance names) and SSDP (the `SERVER` line and the
//! device types, never a UUID). Results are
//! `application/vnd.connlog.sweeps.v1+json`, pinned by `sweep-requests.json`
//! and `sweep-results.json`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use crate::features::discovery::DiscoveryLevel;
use crate::features::reachability::{Outcome, Prober};

pub const CONTENT_TYPE: &str = "application/vnd.connlog.sweeps.v1+json";
pub const SWEEPS_PATH: &str = "/api/agents/sweeps";
pub const FORMAT_VERSION: u8 = 1;

/// `SWEEP_MIN_PREFIX` in the protocol: a /22 at most.
pub const MIN_PREFIX: u8 = 22;
pub const ADDRESSES_PER_SECOND: u32 = 64;
pub const MAX_IN_FLIGHT: usize = 32;
/// `SWEEP_MAX_PORTS` in the protocol.
pub const MAX_PORTS: usize = 8;
/// `SWEEP_PORTS` in the protocol: the only ports a sweep opens.
pub const WELL_KNOWN: [u16; 16] = [
    21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1883, 3389, 5000, 8080, 8443, 9100,
];
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);
const LISTEN: Duration = Duration::from_secs(3);
const MAX_ID_LEN: usize = 64;
const MAX_SERVICES: usize = 16;
const MAX_TYPES: usize = 8;
const TEXT_MAX: usize = 128;

const MDNS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
const SSDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepRequest {
    pub id: String,
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub ports: Vec<u16>,
    pub mdns: bool,
    pub ssdp: bool,
}

impl SweepRequest {
    /// A request as the platform sends it; anything malformed is none. Ports
    /// outside `WELL_KNOWN` are dropped, then all past the eighth.
    pub fn from_json(value: &Value) -> Option<Self> {
        let id = value.get("id")?.as_str()?;
        if id.is_empty() || id.len() > MAX_ID_LEN || id.chars().any(char::is_control) {
            return None;
        }
        let (network, prefix) = value.get("subnet")?.as_str()?.split_once('/')?;
        let network: Ipv4Addr = network.parse().ok()?;
        let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32)?;
        let mut ports: Vec<u16> = Vec::new();
        for port in value.get("ports")?.as_array()? {
            let port = u16::try_from(port.as_u64()?).ok()?;
            if WELL_KNOWN.contains(&port) && !ports.contains(&port) && ports.len() < MAX_PORTS {
                ports.push(port);
            }
        }
        Some(Self {
            id: id.to_string(),
            network,
            prefix,
            ports,
            mdns: value.get("mdns").and_then(Value::as_bool) == Some(true),
            ssdp: value.get("ssdp").and_then(Value::as_bool) == Some(true),
        })
    }

    pub fn subnet(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }
}

/// Why a host swept nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    /// The host is not at `active`, by its own ceiling or the console's.
    NotActive,
    /// The host has no address in the subnet.
    NotOnSubnet,
    /// Larger than a /22.
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ssdp {
    pub server: Option<String>,
    pub types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Found {
    pub address: String,
    pub icmp: bool,
    pub ports: Vec<u16>,
    pub mdns: Vec<String>,
    pub ssdp: Option<Ssdp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SweepResults {
    pub version: u8,
    pub id: String,
    pub subnet: String,
    pub refused: Option<Refusal>,
    pub found: Vec<Found>,
}

impl SweepResults {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

/// The host's own address in the subnet, and every other address to try:
/// the network and broadcast addresses left out (but for a /31 or /32).
pub fn targets(
    request: &SweepRequest,
    own: &[(Ipv4Addr, u8)],
) -> Result<(Ipv4Addr, Vec<Ipv4Addr>), Refusal> {
    if request.prefix < MIN_PREFIX {
        return Err(Refusal::TooLarge);
    }
    let m = mask(request.prefix);
    let base = u32::from(request.network) & m;
    let local = own
        .iter()
        .find(|(ip, _)| u32::from(*ip) & m == base)
        .map(|(ip, _)| *ip)
        .ok_or(Refusal::NotOnSubnet)?;
    let last = base | !m;
    let (first, end) = if request.prefix >= 31 {
        (base, last)
    } else {
        (base + 1, last - 1)
    };
    let addresses = (first..=end)
        .map(Ipv4Addr::from)
        .filter(|ip| *ip != local)
        .collect();
    Ok((local, addresses))
}

/// What the sweep asks of the host's network beyond the handshakes: a
/// multicast question out of one interface and the datagrams that answer
/// it, and the addresses the kernel now holds a MAC for. `SystemAsker` on a
/// host, a stand-in in tests.
pub trait Asker: Sync {
    fn ask(
        &self,
        local: Ipv4Addr,
        group: SocketAddrV4,
        query: &[u8],
        wait: Duration,
    ) -> Vec<(Ipv4Addr, Vec<u8>)>;

    /// The IPv4 addresses in the host's ARP table with a MAC, after the
    /// handshakes (T13.5c): every one made the kernel ask, so a device that
    /// answered ARP is there even when it drops the echo and every port.
    /// What a host without ping (an unprivileged agent on a firewall) finds
    /// devices by.
    fn answered_arp(&self) -> Vec<Ipv4Addr>;
}

/// What one address said to the echo and the handshakes.
fn probe_address(prober: &dyn Prober, address: Ipv4Addr, ports: &[u16]) -> Option<Found> {
    let ip = IpAddr::V4(address);
    let icmp = prober.echo(ip, PROBE_TIMEOUT).outcome == Outcome::Open;
    let mut alive = icmp;
    let mut open = Vec::new();
    for port in ports {
        match prober
            .tcp(SocketAddr::new(ip, *port), PROBE_TIMEOUT)
            .outcome
        {
            Outcome::Open => {
                alive = true;
                open.push(*port);
            }
            // A reset is a host that is there.
            Outcome::Refused => alive = true,
            _ => {}
        }
    }
    alive.then(|| Found {
        address: address.to_string(),
        icmp,
        ports: open,
        mdns: Vec::new(),
        ssdp: None,
    })
}

/// Every address, started at most `ADDRESSES_PER_SECOND` a second, at most
/// `MAX_IN_FLIGHT` at once; the ones that answered.
fn sweep_addresses(prober: &dyn Prober, addresses: &[Ipv4Addr], ports: &[u16]) -> Vec<Found> {
    let started = Instant::now();
    let next = AtomicUsize::new(0);
    let found = Mutex::new(Vec::new());
    let gap = Duration::from_secs(1) / ADDRESSES_PER_SECOND;
    std::thread::scope(|scope| {
        for _ in 0..MAX_IN_FLIGHT.min(addresses.len()) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::SeqCst);
                let Some(address) = addresses.get(index) else {
                    return;
                };
                let due = started + gap * u32::try_from(index).unwrap_or(u32::MAX);
                if let Some(wait) = due.checked_duration_since(Instant::now()) {
                    std::thread::sleep(wait);
                }
                if let Some(answer) = probe_address(prober, *address, ports) {
                    found.lock().unwrap_or_else(|p| p.into_inner()).push(answer);
                }
            });
        }
    });
    found.into_inner().unwrap_or_else(|p| p.into_inner())
}

// ── mDNS ─────────────────────────────────────────────────────────────────

const SERVICES: &str = "_services._dns-sd._udp.local";

/// The DNS question for every service type on the link (RFC 6763 9).
pub fn mdns_query() -> Vec<u8> {
    // A non-zero id and a source port other than 5353: a legacy unicast
    // query, answered to the asker alone (RFC 6762 6.7).
    let mut packet = vec![0x43, 0x4c, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in SERVICES.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 12, 0, 1]);
    packet
}

/// A name at `at`, following compression pointers a bounded number of times.
fn dns_name(packet: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..32 {
        let len = *packet.get(at)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(at + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let pointer = ((len & 0x3f) << 8) | *packet.get(at + 1)? as usize;
            end.get_or_insert(at + 2);
            at = pointer;
            continue;
        }
        let label = packet.get(at + 1..at + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        at += 1 + len;
    }
    None
}

/// The service types an mDNS answer lists: `_ipp._tcp`, `_airplay._tcp`.
pub fn mdns_services(packet: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut read = || -> Option<()> {
        let count = |i: usize| usize::from(u16::from_be_bytes([packet[i], packet[i + 1]]));
        if packet.len() < 12 {
            return None;
        }
        let (questions, records) = (count(4), count(6) + count(8) + count(10));
        let mut at = 12;
        for _ in 0..questions {
            at = dns_name(packet, at)?.1 + 4;
        }
        for _ in 0..records.min(64) {
            let (owner, next) = dns_name(packet, at)?;
            let kind = u16::from_be_bytes([*packet.get(next)?, *packet.get(next + 1)?]);
            let len = usize::from(u16::from_be_bytes([
                *packet.get(next + 8)?,
                *packet.get(next + 9)?,
            ]));
            let data = next + 10;
            if kind == 12 && owner.eq_ignore_ascii_case(SERVICES) {
                let (service, _) = dns_name(packet, data)?;
                let service = service.trim_end_matches(".local").to_string();
                let ok = service.len() <= 64
                    && service.starts_with('_')
                    && service
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
                if ok && !out.contains(&service) && out.len() < MAX_SERVICES {
                    out.push(service);
                }
            }
            at = data + len;
        }
        Some(())
    };
    let _ = read();
    out
}

// ── SSDP ─────────────────────────────────────────────────────────────────

pub fn ssdp_query() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        .to_vec()
}

fn header_text(value: &str) -> Option<String> {
    let value = value.trim();
    let ok = !value.is_empty() && value.chars().all(|c| !c.is_control());
    ok.then(|| value.chars().take(TEXT_MAX).collect())
}

/// An SSDP answer's `SERVER` line and its device or service type (`ST`);
/// a UUID, which identifies the one device, is not kept.
pub fn ssdp_answer(packet: &[u8]) -> (Option<String>, Option<String>) {
    let text = String::from_utf8_lossy(packet);
    let mut lines = text.split("\r\n");
    if !lines.next().is_some_and(|l| l.starts_with("HTTP/1.1 200")) {
        return (None, None);
    }
    let (mut server, mut kind) = (None, None);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "server" => server = header_text(value),
            "st" => kind = header_text(value).filter(|v| !v.starts_with("uuid:")),
            _ => {}
        }
    }
    (server, kind)
}

// ── A sweep ──────────────────────────────────────────────────────────────

/// The answer for `ip`, made empty for an address only an announcement found.
fn found_at(found: &mut BTreeMap<Ipv4Addr, Found>, ip: Ipv4Addr) -> &mut Found {
    found.entry(ip).or_insert_with(|| Found {
        address: ip.to_string(),
        icmp: false,
        ports: Vec::new(),
        mdns: Vec::new(),
        ssdp: None,
    })
}

/// Run a request at `level`, from a host with the IPv4 addresses `own`.
pub fn run(
    request: &SweepRequest,
    level: DiscoveryLevel,
    own: &[(Ipv4Addr, u8)],
    prober: &dyn Prober,
    asker: &dyn Asker,
) -> SweepResults {
    let mut results = SweepResults {
        version: FORMAT_VERSION,
        id: request.id.clone(),
        subnet: request.subnet(),
        refused: None,
        found: Vec::new(),
    };
    if level < DiscoveryLevel::Active {
        results.refused = Some(Refusal::NotActive);
        return results;
    }
    let (local, addresses) = match targets(request, own) {
        Ok(planned) => planned,
        Err(refusal) => {
            results.refused = Some(refusal);
            return results;
        }
    };
    let inside = |ip: &Ipv4Addr| *ip != local && addresses.binary_search(ip).is_ok();

    let mut found: BTreeMap<Ipv4Addr, Found> = sweep_addresses(prober, &addresses, &request.ports)
        .into_iter()
        .filter_map(|f| Some((f.address.parse().ok()?, f)))
        .collect();
    for ip in asker.answered_arp() {
        if inside(&ip) {
            found_at(&mut found, ip);
        }
    }
    if request.mdns {
        for (ip, packet) in asker.ask(local, MDNS, &mdns_query(), LISTEN) {
            let services = mdns_services(&packet);
            if inside(&ip) && !services.is_empty() {
                let answer = found_at(&mut found, ip);
                for service in services {
                    if !answer.mdns.contains(&service) && answer.mdns.len() < MAX_SERVICES {
                        answer.mdns.push(service);
                    }
                }
            }
        }
    }
    if request.ssdp {
        for (ip, packet) in asker.ask(local, SSDP, &ssdp_query(), LISTEN) {
            let (server, kind) = ssdp_answer(&packet);
            if inside(&ip) && (server.is_some() || kind.is_some()) {
                let ssdp = found_at(&mut found, ip).ssdp.get_or_insert(Ssdp {
                    server: None,
                    types: Vec::new(),
                });
                if ssdp.server.is_none() {
                    ssdp.server = server;
                }
                if let Some(kind) = kind {
                    if !ssdp.types.contains(&kind) && ssdp.types.len() < MAX_TYPES {
                        ssdp.types.push(kind);
                    }
                }
            }
        }
    }
    results.found = found.into_values().collect();
    results
}

/// The host's own IPv4 addresses with their prefix lengths, loopback aside.
pub fn own_addresses() -> Vec<(Ipv4Addr, u8)> {
    crate::features::network_inventory::interface_addresses()
        .into_iter()
        .filter(|a| a.up && !a.loopback)
        .filter_map(|a| match a.ip {
            IpAddr::V4(v4) => Some((v4, a.prefix_length)),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// Asks with the host's own UDP sockets.
pub struct SystemAsker;

impl Asker for SystemAsker {
    fn ask(
        &self,
        local: Ipv4Addr,
        group: SocketAddrV4,
        query: &[u8],
        wait: Duration,
    ) -> Vec<(Ipv4Addr, Vec<u8>)> {
        let Ok(socket) = UdpSocket::bind(SocketAddrV4::new(local, 0)) else {
            return Vec::new();
        };
        let _ = socket.set_multicast_ttl_v4(1);
        set_multicast_interface(&socket, local);
        if socket.send_to(query, group).is_err() {
            return Vec::new();
        }
        let deadline = Instant::now() + wait;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 9000];
        while out.len() < 1024 {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if socket
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .is_err()
            {
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((n, SocketAddr::V4(from))) => out.push((*from.ip(), buf[..n].to_vec())),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        out
    }

    fn answered_arp(&self) -> Vec<Ipv4Addr> {
        crate::features::neighbours::neighbours()
            .into_iter()
            .filter_map(|n| n.address.parse().ok())
            .collect()
    }
}

/// Multicast out of the swept subnet's interface, not the default route's.
fn set_multicast_interface(socket: &UdpSocket, local: Ipv4Addr) {
    use std::os::fd::AsRawFd;
    let address = libc::in_addr {
        s_addr: u32::from_ne_bytes(local.octets()),
    };
    // SAFETY: a valid socket descriptor and an in_addr of the size given.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::in_addr>() as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::reachability::Probe;
    use serde_json::json;
    use std::collections::HashMap;

    fn request(subnet: &str, ports: Value) -> SweepRequest {
        SweepRequest::from_json(
            &json!({ "id": "swp_1", "subnet": subnet, "ports": ports, "mdns": true, "ssdp": true }),
        )
        .unwrap()
    }

    const OWN: [(Ipv4Addr, u8); 1] = [(Ipv4Addr::new(10, 0, 20, 2), 24)];

    #[test]
    fn reads_a_request_keeping_only_well_known_ports_and_eight_of_them() {
        let r = request(
            "10.0.20.0/24",
            json!([22, 22, 31337, 80, 443, 445, 3389, 8080, 9100, 21, 23]),
        );
        assert_eq!(r.ports, [22, 80, 443, 445, 3389, 8080, 9100, 21]);
        assert!(r.mdns && r.ssdp);
        assert_eq!(r.subnet(), "10.0.20.0/24");
        for bad in [
            json!({ "id": "", "subnet": "10.0.0.0/24", "ports": [] }),
            json!({ "id": "x", "subnet": "fd00::/64", "ports": [] }),
            json!({ "id": "x", "subnet": "10.0.0.0/33", "ports": [] }),
            json!({ "id": "x", "subnet": "10.0.0.0/24" }),
        ] {
            assert_eq!(SweepRequest::from_json(&bad), None, "{bad}");
        }
    }

    #[test]
    fn sweeps_only_a_subnet_the_host_is_on_and_no_larger_than_a_22() {
        let (local, addresses) = targets(&request("10.0.20.0/24", json!([])), &OWN).unwrap();
        assert_eq!(local, Ipv4Addr::new(10, 0, 20, 2));
        assert_eq!(addresses.len(), 253, "no network, broadcast or own address");
        assert!(!addresses.contains(&local));
        assert_eq!(
            targets(&request("10.0.30.0/24", json!([])), &OWN),
            Err(Refusal::NotOnSubnet)
        );
        assert_eq!(
            targets(
                &request("10.0.0.0/21", json!([])),
                &[(Ipv4Addr::new(10, 0, 0, 2), 21)]
            ),
            Err(Refusal::TooLarge)
        );
        let own = [(Ipv4Addr::new(10, 0, 0, 2), 22)];
        assert_eq!(
            targets(&request("10.0.0.0/22", json!([])), &own)
                .unwrap()
                .1
                .len(),
            1021
        );
    }

    struct Hosts(HashMap<Ipv4Addr, (bool, Vec<u16>, Vec<u16>)>);

    impl Prober for Hosts {
        fn tcp(&self, address: SocketAddr, _: Duration) -> Probe {
            let IpAddr::V4(ip) = address.ip() else {
                return Probe::of(Outcome::Unreachable);
            };
            match self.0.get(&ip) {
                Some((_, open, _)) if open.contains(&address.port()) => {
                    Probe::open(Duration::from_millis(1))
                }
                Some((_, _, refused)) if refused.contains(&address.port()) => {
                    Probe::of(Outcome::Refused)
                }
                _ => Probe::of(Outcome::Timeout),
            }
        }

        fn echo(&self, address: IpAddr, _: Duration) -> Probe {
            match address {
                IpAddr::V4(ip) if self.0.get(&ip).is_some_and(|h| h.0) => {
                    Probe::open(Duration::from_millis(1))
                }
                _ => Probe::of(Outcome::Timeout),
            }
        }
    }

    /// A printer answering mDNS and a TV answering SSDP; a stranger off the subnet.
    struct Link;

    pub fn mdns_answer(services: &[&str]) -> Vec<u8> {
        // Written from RFC 6762/6763: the question echoed, PTR answers, the
        // owner a pointer back to the question's name.
        let mut packet = vec![0x43, 0x4c, 0x84, 0, 0, 1];
        packet.extend_from_slice(&(services.len() as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&mdns_query()[12..]);
        for service in services {
            let mut data = Vec::new();
            for label in service.split('.') {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
            data.push(0);
            packet.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0x11, 0x94]);
            packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
            packet.extend_from_slice(&data);
        }
        packet
    }

    impl Asker for Link {
        fn ask(
            &self,
            local: Ipv4Addr,
            group: SocketAddrV4,
            _query: &[u8],
            _wait: Duration,
        ) -> Vec<(Ipv4Addr, Vec<u8>)> {
            assert_eq!(local, Ipv4Addr::new(10, 0, 20, 2));
            if group == MDNS {
                vec![
                    (
                        Ipv4Addr::new(10, 0, 20, 40),
                        mdns_answer(&["_ipp._tcp.local", "_printer._tcp.local"]),
                    ),
                    (
                        Ipv4Addr::new(192, 168, 1, 9),
                        mdns_answer(&["_x._tcp.local"]),
                    ),
                ]
            } else {
                let answer = |st: &str| {
                    format!("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: Linux/4.9 UPnP/1.0 Bravia/1.0\r\nST: {st}\r\nUSN: uuid:1234::{st}\r\n\r\n")
                        .into_bytes()
                };
                vec![
                    (Ipv4Addr::new(10, 0, 20, 50), answer("upnp:rootdevice")),
                    (Ipv4Addr::new(10, 0, 20, 50), answer("uuid:1234")),
                    (
                        Ipv4Addr::new(10, 0, 20, 50),
                        answer("urn:schemas-upnp-org:device:MediaRenderer:1"),
                    ),
                ]
            }
        }

        fn answered_arp(&self) -> Vec<Ipv4Addr> {
            Vec::new()
        }
    }

    /// `Link`, and a camera that drops the echo and every port but answered
    /// ARP; one off the subnet, and the sweeping host itself, are left out.
    struct LinkWithArp;

    impl Asker for LinkWithArp {
        fn ask(
            &self,
            local: Ipv4Addr,
            group: SocketAddrV4,
            query: &[u8],
            wait: Duration,
        ) -> Vec<(Ipv4Addr, Vec<u8>)> {
            Link.ask(local, group, query, wait)
        }

        fn answered_arp(&self) -> Vec<Ipv4Addr> {
            vec![
                Ipv4Addr::new(10, 0, 20, 60),
                Ipv4Addr::new(10, 0, 20, 1),
                Ipv4Addr::new(10, 0, 20, 2),
                Ipv4Addr::new(192, 168, 1, 9),
            ]
        }
    }

    #[test]
    fn reports_what_answered_its_open_ports_and_what_it_announces() {
        let hosts = Hosts(HashMap::from([
            (Ipv4Addr::new(10, 0, 20, 1), (true, vec![53, 443], vec![])),
            (Ipv4Addr::new(10, 0, 20, 9), (false, vec![], vec![22])),
            (Ipv4Addr::new(10, 0, 20, 40), (true, vec![631], vec![])),
        ]));
        let results = run(
            &request("10.0.20.0/24", json!([22, 53, 443, 631])),
            DiscoveryLevel::Active,
            &OWN,
            &hosts,
            &LinkWithArp,
        );
        assert_eq!(results.refused, None);
        let found: Vec<(&str, bool, &[u16])> = results
            .found
            .iter()
            .map(|f| (f.address.as_str(), f.icmp, f.ports.as_slice()))
            .collect();
        assert_eq!(
            found,
            [
                ("10.0.20.1", true, &[53, 443][..]),
                ("10.0.20.9", false, &[][..]),
                ("10.0.20.40", true, &[631][..]),
                ("10.0.20.50", false, &[][..]),
                ("10.0.20.60", false, &[][..]),
            ],
            "a refused handshake is a host there; an SSDP answer is one too, and an ARP answer"
        );
        assert_eq!(results.found[2].mdns, ["_ipp._tcp", "_printer._tcp"]);
        assert_eq!(
            results.found[3].ssdp,
            Some(Ssdp {
                server: Some("Linux/4.9 UPnP/1.0 Bravia/1.0".into()),
                types: vec![
                    "upnp:rootdevice".into(),
                    "urn:schemas-upnp-org:device:MediaRenderer:1".into()
                ],
            }),
            "never a UUID"
        );
        assert!(
            !results.found.iter().any(|f| f.address == "192.168.1.9"),
            "an answer from off the subnet is left out"
        );
    }

    #[test]
    fn below_active_sends_nothing_at_all() {
        struct Nothing;
        impl Prober for Nothing {
            fn tcp(&self, _: SocketAddr, _: Duration) -> Probe {
                panic!("no handshake below active")
            }
            fn echo(&self, _: IpAddr, _: Duration) -> Probe {
                panic!("no echo below active")
            }
        }
        impl Asker for Nothing {
            fn ask(
                &self,
                _: Ipv4Addr,
                _: SocketAddrV4,
                _: &[u8],
                _: Duration,
            ) -> Vec<(Ipv4Addr, Vec<u8>)> {
                panic!("no multicast below active")
            }
            fn answered_arp(&self) -> Vec<Ipv4Addr> {
                panic!("nothing read below active")
            }
        }
        let results = run(
            &request("10.0.20.0/24", json!([22])),
            DiscoveryLevel::Passive,
            &OWN,
            &Nothing,
            &Nothing,
        );
        assert_eq!(results.refused, Some(Refusal::NotActive));
        let refused = run(
            &request("10.0.30.0/24", json!([22])),
            DiscoveryLevel::Active,
            &OWN,
            &Nothing,
            &Nothing,
        );
        assert_eq!(refused.refused, Some(Refusal::NotOnSubnet));
    }

    #[test]
    fn paces_a_sweep_at_64_addresses_a_second() {
        let hosts = Hosts(HashMap::new());
        let own = [(Ipv4Addr::new(10, 0, 0, 2), 26)];
        let started = Instant::now();
        let quiet = SweepRequest::from_json(
            &json!({ "id": "swp_2", "subnet": "10.0.0.0/26", "ports": [] }),
        )
        .unwrap();
        let results = run(&quiet, DiscoveryLevel::Active, &own, &hosts, &Link);
        // 61 addresses: the last starts 60/64 of a second in.
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert!(results.found.is_empty());
    }

    fn fixture(name: &str) -> Value {
        let text = match name {
            "requests" => {
                include_str!("../../../../packages/agent-protocol/fixtures/sweep-requests.json")
            }
            _ => include_str!("../../../../packages/agent-protocol/fixtures/sweep-results.json"),
        };
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn reads_every_shared_request_as_the_platform_writes_it() {
        let requests = fixture("requests");
        for case in requests["valid"].as_array().unwrap() {
            let read = SweepRequest::from_json(&case["request"]).expect("a valid request");
            let want = &case["read"];
            assert_eq!(read.id, want["id"].as_str().unwrap());
            assert_eq!(read.subnet(), want["subnet"].as_str().unwrap());
            let ports: Vec<u64> = read.ports.iter().map(|p| u64::from(*p)).collect();
            let want_ports: Vec<u64> = want["ports"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_u64().unwrap())
                .collect();
            assert_eq!(ports, want_ports, "{}", case["description"]);
            assert_eq!(read.mdns, want["mdns"].as_bool().unwrap());
            assert_eq!(read.ssdp, want["ssdp"].as_bool().unwrap());
        }
        for case in requests["invalid"].as_array().unwrap() {
            assert_eq!(
                SweepRequest::from_json(&case["request"]),
                None,
                "{}",
                case["description"]
            );
        }
    }

    #[test]
    fn writes_the_results_the_shared_fixture_holds() {
        let results = fixture("results");
        let hosts = Hosts(HashMap::from([
            (Ipv4Addr::new(10, 0, 20, 1), (true, vec![53, 443], vec![])),
            (Ipv4Addr::new(10, 0, 20, 9), (false, vec![], vec![22])),
            (Ipv4Addr::new(10, 0, 20, 40), (true, vec![631], vec![])),
        ]));
        let ran = run(
            &request("10.0.20.0/24", json!([22, 53, 443, 631])),
            DiscoveryLevel::Active,
            &OWN,
            &hosts,
            &Link,
        );
        assert_eq!(
            serde_json::to_value(&ran).unwrap(),
            results["valid"][0]["upload"]
        );
        let mut elsewhere = request("10.0.30.0/24", json!([]));
        elsewhere.id = "swp_6".into();
        let refused = run(&elsewhere, DiscoveryLevel::Active, &OWN, &hosts, &Link);
        assert_eq!(
            serde_json::to_value(&refused).unwrap(),
            results["valid"][1]["upload"]
        );
    }

    #[test]
    fn sweeps_for_real_over_loopback() {
        // The host's own sockets: a listener on a well-known port at
        // 127.0.0.2, swept from 127.0.0.1 in 127.0.0.0/30.
        let Some((listener, port)) = [8080u16, 8443, 5000, 1883].into_iter().find_map(|port| {
            std::net::TcpListener::bind(("127.0.0.2", port))
                .ok()
                .map(|l| (l, port))
        }) else {
            return; // every candidate port is taken on this host
        };
        let quiet = SweepRequest::from_json(
            &json!({ "id": "swp_lo", "subnet": "127.0.0.0/30", "ports": [port] }),
        )
        .unwrap();
        let own = [(Ipv4Addr::new(127, 0, 0, 1), 8)];
        let results = run(
            &quiet,
            DiscoveryLevel::Active,
            &own,
            &crate::features::reachability::SystemProber,
            &SystemAsker,
        );
        drop(listener);
        let found = results
            .found
            .iter()
            .find(|f| f.address == "127.0.0.2")
            .expect("127.0.0.2 answered");
        assert_eq!(found.ports, [port]);
    }
}
