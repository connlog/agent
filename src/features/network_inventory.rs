//! The network map's inventory (docs/topology/PLAN.md, guarantee 4): this
//! host's interface addresses with their prefix length, the TCP port numbers
//! listening on a non-loopback address, the default gateway and its MAC, plus
//! the site name and extra ports from agent.conf; at the `passive` level, the
//! VLAN id of an address on a VLAN interface (T8.2, `features::vlan`) and
//! the private neighbours the kernel already knows (T8.3,
//! `features::neighbours`).
//! Nothing else: no process names, users, interface names, UDP or remote
//! peers.
//!
//! Read with `getifaddrs` and from `/proc/net/{tcp,tcp6,route,arp}`, no new
//! crate. Every parser here takes the text it reads, so the tests drive them
//! with captured files. The JSON is `application/vnd.connlog.inventory.v1+json`
//! as `packages/agent-protocol/src/network.ts` decodes it, pinned by
//! `inventory-uploads.json`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::features::discovery::DiscoveryLevel;

pub const CONTENT_TYPE: &str = "application/vnd.connlog.inventory.v1+json";
pub const FORMAT_VERSION: u8 = 1;

/// `INVENTORY_MAX_ADDRESSES` and `INVENTORY_MAX_LISTENERS` in the protocol.
pub const MAX_ADDRESSES: usize = 256;
pub const MAX_LISTENERS: usize = 1024;

/// Interfaces left out by name: container and virtual bridges and their
/// veth ends, whose addresses mean nothing to another host. Real bridges
/// (`vmbr*` on Proxmox, `br0`) and VPNs (`wg*`, `tailscale*`, `tun*`) stay.
const VIRTUAL_INTERFACE_PREFIXES: [&str; 13] = [
    "docker", "br-", "veth", "cni", "flannel", "cali", "vxlan", "kube-", "podman", "virbr",
    "lxcbr", "cilium", "weave",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub version: u8,
    pub addresses: Vec<InventoryAddress>,
    pub tcp_listeners: Vec<Listener>,
    pub gateway: Option<Gateway>,
    pub site: Option<String>,
    pub extra_ports: Vec<u16>,
    /// Only at `passive`; left out of the upload when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub neighbours: Vec<crate::features::neighbours::Neighbour>,
    /// The path out (T8.4): only at `passive`, and only where the host
    /// allows the ping socket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<crate::features::trace::Path>,
    /// Observed connections (T11.1): only when the platform asks for them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<crate::features::connections::Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryAddress {
    pub address: String,
    pub prefix_length: u8,
    /// The 802.1Q id of the VLAN interface it is on; only at `passive`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Listener {
    pub port: u16,
    /// Bound to 0.0.0.0 or ::, not to one address.
    pub wildcard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gateway {
    pub address: String,
    /// From the neighbour table, lowercase; `None` while it is not known.
    pub mac: Option<String>,
}

/// One address of one interface, as `getifaddrs` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub interface: String,
    pub up: bool,
    pub loopback: bool,
    pub ip: IpAddr,
    pub prefix_length: u8,
    /// The interface's VLAN id, when it is a VLAN and the level allows it.
    pub vlan: Option<u16>,
}

impl Inventory {
    /// Assemble an inventory: filtered, de-duplicated, sorted and capped, so
    /// the same host state always gives the same bytes.
    pub fn build(
        interfaces: &[InterfaceAddress],
        sockets: &[(IpAddr, u16)],
        gateway: Option<(Ipv4Addr, Option<String>)>,
        site: Option<String>,
        extra_ports: &[u16],
    ) -> Self {
        let mut extra_ports = extra_ports.to_vec();
        extra_ports.sort_unstable();
        extra_ports.dedup();
        extra_ports.truncate(crate::features::network_map::MAX_EXTRA_PORTS);
        Self {
            version: FORMAT_VERSION,
            addresses: select_addresses(interfaces),
            tcp_listeners: select_listeners(sockets),
            gateway: gateway.map(|(ip, mac)| Gateway {
                address: ip.to_string(),
                mac,
            }),
            site,
            extra_ports,
            neighbours: Vec::new(),
            path: None,
            connections: Vec::new(),
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        // A struct of strings, numbers and options: serialising cannot fail.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// What the passive level adds to the inventory: the path out, traced when
/// due, towards the gateway and the platform.
pub struct PathSource<'a> {
    pub cache: &'a mut crate::features::trace::TraceCache,
    pub internet: &'a dyn Fn() -> Option<Ipv4Addr>,
}

/// Read this host's inventory now, at `level` (the lower of the host's
/// ceiling and what the console allows). Every source degrades to
/// "nothing": an unreadable file is an empty list, never an error.
pub fn collect(
    site: Option<String>,
    extra_ports: &[u16],
    level: DiscoveryLevel,
    path: Option<PathSource<'_>>,
    connections: Option<&std::collections::HashSet<IpAddr>>,
) -> Inventory {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let mut sockets = parse_tcp_listeners(&read("/proc/net/tcp"));
    sockets.extend(parse_tcp_listeners(&read("/proc/net/tcp6")));
    let gateway = default_gateway();
    let gateway_ip = gateway.as_ref().map(|(ip, _)| *ip);
    let mut interfaces = interface_addresses();
    if level >= DiscoveryLevel::Passive {
        let vlans = crate::features::vlan::link_vlans();
        for address in &mut interfaces {
            address.vlan = vlans.get(&address.interface).copied();
        }
    }
    let mut inventory = Inventory::build(&interfaces, &sockets, gateway, site, extra_ports);
    // Only when the platform asked; `named` is all the peers level allows.
    if let Some(named) = connections {
        let listening = inventory.tcp_listeners.iter().map(|l| l.port).collect();
        inventory.connections = crate::features::connections::collect(&listening, level, named);
    }
    if level >= DiscoveryLevel::Passive {
        inventory.neighbours = crate::features::neighbours::neighbours();
        if let Some(source) = path {
            inventory.path = source.cache.path(
                gateway_ip,
                source.internet,
                &crate::features::trace::SystemHopper,
                std::time::Instant::now(),
            );
        }
    }
    inventory
}

pub fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// An IPv6 address the platform reads as one (`isIpv6` in the protocol): its
/// RFC 5952 text, which for a v4-mapped address has dots and does not count.
fn is_plain_ipv6_text(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(_)) && !ip.to_string().contains('.')
}

/// The addresses another host could reach this one on.
pub fn select_addresses(interfaces: &[InterfaceAddress]) -> Vec<InventoryAddress> {
    let mut kept: Vec<(IpAddr, u8, Option<u16>)> = interfaces
        .iter()
        .filter(|a| a.up && !a.loopback && !is_virtual_interface(&a.interface))
        .filter(|a| match a.ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified() && a.prefix_length <= 32,
            IpAddr::V6(v6) => {
                !v6.is_loopback()
                    && !v6.is_unspecified()
                    && !is_ipv6_link_local(&v6)
                    && is_plain_ipv6_text(&a.ip)
                    && a.prefix_length <= 128
            }
        })
        .map(|a| (a.ip, a.prefix_length, a.vlan))
        .collect();
    // IPv4 before IPv6 (`IpAddr`'s order), then numerically.
    kept.sort_unstable();
    kept.dedup_by_key(|(ip, _, _)| *ip);
    kept.truncate(MAX_ADDRESSES);
    kept.into_iter()
        .map(|(ip, prefix_length, vlan)| InventoryAddress {
            address: ip.to_string(),
            prefix_length,
            vlan,
        })
        .collect()
}

fn is_loopback_bind(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn is_wildcard_bind(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified())
        }
    }
}

/// One entry per port, loopback binds left out; a port bound to a wildcard
/// anywhere is a wildcard listener.
pub fn select_listeners(sockets: &[(IpAddr, u16)]) -> Vec<Listener> {
    let mut ports: BTreeMap<u16, bool> = BTreeMap::new();
    for (ip, port) in sockets {
        if *port == 0 || is_loopback_bind(ip) {
            continue;
        }
        *ports.entry(*port).or_insert(false) |= is_wildcard_bind(ip);
    }
    ports
        .into_iter()
        .take(MAX_LISTENERS)
        .map(|(port, wildcard)| Listener { port, wildcard })
        .collect()
}

/// `/proc/net/tcp` and `/proc/net/tcp6` hex addresses: the address's bytes
/// in network order, printed as host-order 32-bit words.
pub fn parse_proc_ip(hex: &str) -> Option<IpAddr> {
    let word = |chunk: &str| u32::from_str_radix(chunk, 16).ok().map(u32::to_ne_bytes);
    match hex.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word(hex)?))),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word(hex.get(i * 8..i * 8 + 8)?)?);
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// The sockets in state `0A` (LISTEN) of a `/proc/net/tcp` or `tcp6` file:
/// (local address, port).
pub fn parse_tcp_listeners(text: &str) -> Vec<(IpAddr, u16)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _slot = fields.next()?;
            let local = fields.next()?;
            let _remote = fields.next()?;
            let state = fields.next()?;
            if !state.eq_ignore_ascii_case("0A") {
                return None;
            }
            let (ip, port) = local.split_once(':')?;
            Some((parse_proc_ip(ip)?, u16::from_str_radix(port, 16).ok()?))
        })
        .collect()
}

#[cfg_attr(target_os = "freebsd", allow(dead_code))] // FreeBSD reads the routing table
const RTF_UP: u32 = 0x0001;
#[cfg_attr(target_os = "freebsd", allow(dead_code))] // FreeBSD reads the routing table
const RTF_GATEWAY: u32 = 0x0002;

/// The IPv4 default route's next hop from `/proc/net/route`, lowest metric
/// first, and its interface. Routes through container bridges are left out.
#[cfg_attr(target_os = "freebsd", allow(dead_code))] // FreeBSD reads the routing table
pub fn parse_default_gateway(text: &str) -> Option<(Ipv4Addr, String)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                return None;
            }
            let (iface, destination, gateway, flags, metric, mask) = (
                fields[0], fields[1], fields[2], fields[3], fields[6], fields[7],
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            if destination != "00000000"
                || mask != "00000000"
                || flags & (RTF_UP | RTF_GATEWAY) != (RTF_UP | RTF_GATEWAY)
                || is_virtual_interface(iface)
            {
                return None;
            }
            let IpAddr::V4(ip) = parse_proc_ip(gateway)? else {
                return None;
            };
            if ip.is_unspecified() {
                return None;
            }
            Some((metric.parse::<u32>().ok()?, ip, iface.to_string()))
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, ip, iface)| (ip, iface))
}

/// `ip`'s MAC from `/proc/net/arp`, lowercase; `None` when it is not there,
/// not complete yet (all zeros) or not a MAC.
#[cfg_attr(target_os = "freebsd", allow(dead_code))] // FreeBSD reads the routing table
pub fn parse_arp_mac(text: &str, ip: Ipv4Addr) -> Option<String> {
    let wanted = ip.to_string();
    text.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[0] != wanted {
            return None;
        }
        let mac = fields[3].to_ascii_lowercase();
        let well_formed = mac.len() == 17
            && mac.split(':').count() == 6
            && mac
                .split(':')
                .all(|pair| pair.len() == 2 && pair.chars().all(|c| c.is_ascii_hexdigit()));
        (well_formed && mac != "00:00:00:00:00:00").then_some(mac)
    })
}

fn prefix_of(mask: &[u8]) -> u8 {
    mask.iter().map(|b| b.count_ones() as u8).sum()
}

/// The IPv4 default gateway and its MAC, where the ARP table has it.
#[cfg(not(target_os = "freebsd"))]
fn default_gateway() -> Option<(Ipv4Addr, Option<String>)> {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    parse_default_gateway(&read("/proc/net/route")).map(|(ip, _iface)| {
        let mac = parse_arp_mac(&read("/proc/net/arp"), ip);
        (ip, mac)
    })
}

/// The IPv4 default gateway and its MAC: on FreeBSD (a firewall, T13.5b)
/// from the routing table and the ARP table.
#[cfg(target_os = "freebsd")]
fn default_gateway() -> Option<(Ipv4Addr, Option<String>)> {
    let ip = crate::features::routing::default_route()?;
    let mac = crate::features::routing::neighbour_entries()
        .into_iter()
        .find(|(address, _, _)| *address == IpAddr::V4(ip))
        .map(|(_, mac, _)| {
            mac.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        });
    Some((ip, mac))
}

/// Every interface address with its netmask, from `getifaddrs`.
pub fn interface_addresses() -> Vec<InterfaceAddress> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list it owns into `head`; it is read only
    // while alive and released with freeifaddrs below, on every path.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node of the list getifaddrs returned.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_netmask.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a NUL-terminated name owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: ifa_addr and ifa_netmask point at sockaddrs of the family
        // `sa_family` says; each is read as that family's struct only.
        let parsed = unsafe {
            match i32::from((*entry.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let addr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    let mask = &*(entry.ifa_netmask as *const libc::sockaddr_in);
                    Some((
                        IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                        prefix_of(&mask.sin_addr.s_addr.to_ne_bytes()),
                    ))
                }
                libc::AF_INET6 => {
                    let addr = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                    let mask = &*(entry.ifa_netmask as *const libc::sockaddr_in6);
                    Some((
                        IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                        prefix_of(&mask.sin6_addr.s6_addr),
                    ))
                }
                _ => None,
            }
        };
        if let Some((ip, prefix_length)) = parsed {
            let flags = entry.ifa_flags;
            out.push(InterfaceAddress {
                interface: name,
                up: flags & libc::IFF_UP as u32 != 0,
                loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
                ip,
                prefix_length,
                vlan: None,
            });
        }
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Captured from a host with sshd on every address, postgres on one
    /// address, a loopback-only service, an established connection and a
    /// docker-proxy port.
    const PROC_NET_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21051 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 23120 1 0000000000000000 100 0 0 10 0
   2: 050A000A:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 24987 1 0000000000000000 100 0 0 10 0
   3: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 19817 1 0000000000000000 100 0 0 10 5
   4: 050A000A:0016 0B0A000A:D2F0 01 00000000:00000000 02:0009A1B2 00000000     0        0 31337 2 0000000000000000 20 4 30 10 -1
   5: 010011AC:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40001 1 0000000000000000 100 0 0 10 0
";

    /// The same host's tcp6: sshd on ::, a ::1-only service, a v4-mapped
    /// loopback bind, nginx on one ULA address and an established socket.
    const PROC_NET_TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21053 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22001 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22002 1 0000000000000000 100 0 0 10 0
   3: 100000FD000000000000000005000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 22003 1 0000000000000000 100 0 0 10 0
   4: 100000FD000000000000000005000000:01BB 100000FD000000000000000009000000:C350 01 00000000:00000000 00:00000000 00000000    33        0 22004 1 0000000000000000 20 4 30 10 -1
";

    const PROC_NET_ROUTE: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t010A000A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t000A000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
docker0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";

    const PROC_NET_ARP: &str =
        "IP address       HW type     Flags       HW address            Mask     Device
10.0.10.1        0x1         0x2         52:54:00:AB:CD:EF     *        eth0
10.0.10.9        0x1         0x0         00:00:00:00:00:00     *        eth0
172.17.0.2       0x1         0x2         02:42:ac:11:00:02     *        docker0
";

    fn iface(name: &str, ip: &str, prefix: u8) -> InterfaceAddress {
        InterfaceAddress {
            interface: name.to_string(),
            up: true,
            loopback: name == "lo",
            ip: ip.parse().unwrap(),
            prefix_length: prefix,
            vlan: None,
        }
    }

    #[test]
    fn tcp_listeners_parse_from_proc() {
        let v4 = parse_tcp_listeners(PROC_NET_TCP);
        assert_eq!(
            v4,
            vec![
                ("0.0.0.0".parse().unwrap(), 22),
                ("127.0.0.1".parse().unwrap(), 3306),
                ("10.0.10.5".parse().unwrap(), 5432),
                ("127.0.0.53".parse().unwrap(), 53),
                ("172.17.0.1".parse().unwrap(), 8080),
            ],
            "LISTEN only; the established socket is not one"
        );
        let v6 = parse_tcp_listeners(PROC_NET_TCP6);
        assert_eq!(
            v6,
            vec![
                ("::".parse().unwrap(), 22),
                ("::1".parse().unwrap(), 631),
                ("::ffff:127.0.0.1".parse().unwrap(), 8081),
                ("fd00:10::5".parse().unwrap(), 443),
            ]
        );
        assert!(parse_tcp_listeners("").is_empty());
        assert!(parse_tcp_listeners("header\n   0: zz:0016 0:0 0A\n").is_empty());
    }

    #[test]
    fn loopback_binds_never_leave_the_host_and_wildcards_win() {
        let mut sockets = parse_tcp_listeners(PROC_NET_TCP);
        sockets.extend(parse_tcp_listeners(PROC_NET_TCP6));
        // 22 is on 0.0.0.0 and on ::; 443 on one address; 5432 on another.
        sockets.push(("10.0.10.5".parse().unwrap(), 22));
        assert_eq!(
            select_listeners(&sockets),
            vec![
                Listener {
                    port: 22,
                    wildcard: true
                },
                Listener {
                    port: 443,
                    wildcard: false
                },
                Listener {
                    port: 5432,
                    wildcard: false
                },
                Listener {
                    port: 8080,
                    wildcard: false
                },
            ],
            "3306, 53, 631 and 8081 listen on loopback only"
        );
    }

    #[test]
    fn listeners_are_capped() {
        let sockets: Vec<(IpAddr, u16)> = (1..=2000u16)
            .map(|p| ("0.0.0.0".parse().unwrap(), p))
            .collect();
        let listeners = select_listeners(&sockets);
        assert_eq!(listeners.len(), MAX_LISTENERS);
        assert_eq!(listeners[0].port, 1);
        assert_eq!(listeners.last().unwrap().port, 1024);
    }

    #[test]
    fn the_default_gateway_is_the_lowest_metric_default_route() {
        assert_eq!(
            parse_default_gateway(PROC_NET_ROUTE),
            Some(("10.0.10.1".parse().unwrap(), "eth0".to_string())),
            "docker0's metric-0 route is a container bridge, wlan0's metric is higher"
        );
        assert_eq!(parse_default_gateway(""), None);
        let only_links = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t000A000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_default_gateway(only_links), None);
    }

    #[test]
    fn the_gateway_mac_comes_from_the_neighbour_table() {
        assert_eq!(
            parse_arp_mac(PROC_NET_ARP, "10.0.10.1".parse().unwrap()).as_deref(),
            Some("52:54:00:ab:cd:ef"),
            "lowercase"
        );
        assert_eq!(
            parse_arp_mac(PROC_NET_ARP, "10.0.10.9".parse().unwrap()),
            None,
            "incomplete entry"
        );
        assert_eq!(
            parse_arp_mac(PROC_NET_ARP, "10.0.10.2".parse().unwrap()),
            None
        );
        assert_eq!(parse_arp_mac("", "10.0.10.1".parse().unwrap()), None);
    }

    #[test]
    fn addresses_leave_out_loopback_link_local_and_container_bridges() {
        let interfaces = vec![
            iface("lo", "127.0.0.1", 8),
            iface("lo", "::1", 128),
            iface("eth0", "fd00:10::5", 64),
            iface("eth0", "10.0.10.5", 24),
            iface("eth0", "fe80::5054:ff:feab:cdef", 64),
            iface("docker0", "172.17.0.1", 16),
            iface("br-3f2a9c", "172.18.0.1", 16),
            iface("veth12ab", "fe80::1", 64),
            iface("cni0", "10.244.0.1", 24),
            iface("flannel.1", "10.244.0.0", 32),
            iface("cali7e1", "192.168.50.1", 32),
            iface("vxlan.calico", "192.168.50.2", 32),
            iface("kube-ipvs0", "10.96.0.1", 32),
            iface("podman0", "10.88.0.1", 16),
            iface("virbr0", "192.168.122.1", 24),
            iface("lxcbr0", "10.0.3.1", 24),
            iface("cilium_host", "10.0.0.200", 32),
            iface("weave", "10.32.0.1", 12),
            iface("vmbr0", "192.168.1.20", 24),
            iface("wg0", "10.8.0.2", 24),
            iface("tailscale0", "100.101.102.103", 32),
            iface("tun0", "10.9.0.6", 24),
            InterfaceAddress {
                up: false,
                ..iface("eth1", "10.0.20.5", 24)
            },
        ];
        let kept: Vec<(String, u8)> = select_addresses(&interfaces)
            .into_iter()
            .map(|a| (a.address, a.prefix_length))
            .collect();
        assert_eq!(
            kept,
            vec![
                ("10.0.10.5".to_string(), 24),
                ("10.8.0.2".to_string(), 24),
                ("10.9.0.6".to_string(), 24),
                ("100.101.102.103".to_string(), 32),
                ("192.168.1.20".to_string(), 24),
                ("fd00:10::5".to_string(), 64),
            ]
        );
    }

    #[test]
    fn virtual_interface_names() {
        for name in [
            "docker0",
            "br-0a1b",
            "veth9",
            "cni0",
            "kube-bridge",
            "virbr1",
        ] {
            assert!(is_virtual_interface(name), "{name}");
        }
        for name in [
            "eth0",
            "ens18",
            "vmbr0",
            "br0",
            "bond0",
            "wg0",
            "tailscale0",
            "tun0",
        ] {
            assert!(!is_virtual_interface(name), "{name}");
        }
    }

    /// The fixture's inputs, as the host would report them.
    fn from_fixture(upload: &Value) -> Inventory {
        let interfaces: Vec<InterfaceAddress> = upload["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                // An address with a VLAN id is on that VLAN's interface.
                let vlan = a["vlan"].as_u64().map(|v| v as u16);
                let name = vlan.map_or("eth0".to_string(), |v| format!("eth0.{v}"));
                InterfaceAddress {
                    vlan,
                    ..iface(
                        &name,
                        a["address"].as_str().unwrap(),
                        a["prefixLength"].as_u64().unwrap() as u8,
                    )
                }
            })
            // Reversed, plus what must be dropped: the result does not depend
            // on the order the kernel lists them in.
            .rev()
            .chain([
                iface("lo", "127.0.0.1", 8),
                iface("docker0", "172.17.0.1", 16),
            ])
            .collect();
        let sockets: Vec<(IpAddr, u16)> = upload["tcpListeners"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                let ip = if l["wildcard"].as_bool().unwrap() {
                    "0.0.0.0"
                } else {
                    upload["addresses"][0]["address"].as_str().unwrap()
                };
                (ip.parse().unwrap(), l["port"].as_u64().unwrap() as u16)
            })
            .rev()
            .chain([("127.0.0.1".parse().unwrap(), 3306)])
            .collect();
        let gateway = upload["gateway"].as_object().map(|g| {
            (
                g["address"].as_str().unwrap().parse().unwrap(),
                g["mac"].as_str().map(str::to_string),
            )
        });
        let site = upload["site"].as_str().map(str::to_string);
        let ports: Vec<u16> = upload["extraPorts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_u64().unwrap() as u16)
            .collect();
        let mut inventory = Inventory::build(&interfaces, &sockets, gateway, site, &ports);
        inventory.neighbours = upload["neighbours"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|n| crate::features::neighbours::Neighbour {
                        address: n["address"].as_str().unwrap().to_string(),
                        mac: n["mac"].as_str().unwrap().to_string(),
                        state: match n["state"].as_str().unwrap() {
                            "reachable" => "reachable",
                            "permanent" => "permanent",
                            _ => "stale",
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();
        let trace = |t: &Value| {
            t.as_object().map(|t| crate::features::trace::Trace {
                hops: t["hops"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| h.as_str().map(str::to_string))
                    .collect(),
                reached: t["reached"].as_bool().unwrap(),
            })
        };
        inventory.connections = upload["connections"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|c| crate::features::connections::Connection {
                        peer: c["peer"].as_str().unwrap().to_string(),
                        port: c["port"].as_u64().unwrap() as u16,
                        direction: if c["direction"] == "in" { "in" } else { "out" },
                    })
                    .collect()
            })
            .unwrap_or_default();
        inventory.path = upload["path"]
            .as_object()
            .map(|p| crate::features::trace::Path {
                gateway: trace(&p["gateway"]),
                internet: trace(&p["internet"]),
            });
        inventory
    }

    /// The agent's half of `inventory-uploads.json`: from the inputs each
    /// valid upload describes, the agent sends exactly that upload.
    #[test]
    fn serialises_every_fixture_upload_exactly() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../packages/agent-protocol/fixtures/inventory-uploads.json"
        ))
        .unwrap();
        let valid = fixture["valid"].as_array().unwrap();
        assert!(!valid.is_empty());
        for case in valid {
            let description = case["description"].as_str().unwrap();
            let inventory = from_fixture(&case["upload"]);
            let sent: Value = serde_json::from_slice(&inventory.to_json()).unwrap();
            assert_eq!(sent, case["upload"], "{description}");
        }
    }

    #[test]
    fn this_host_collects_without_error() {
        let inventory = collect(
            Some("hq".into()),
            &[8443],
            DiscoveryLevel::Passive,
            None,
            None,
        );
        assert_eq!(inventory.version, 1);
        assert!(inventory.addresses.len() <= MAX_ADDRESSES);
        assert!(inventory
            .addresses
            .iter()
            .all(|a| a.address != "127.0.0.1" && a.address != "::1"));
        let json: Value = serde_json::from_slice(&inventory.to_json()).unwrap();
        assert_eq!(json["site"], "hq");
        assert_eq!(json["extraPorts"], serde_json::json!([8443]));
    }
}
