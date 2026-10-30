//! FreeBSD's routing tables, for what the passive discovery level reads on a
//! firewall (docs/topology/PLAN.md, T13.5b): OPNsense and pfSense run on
//! FreeBSD, which has no netlink and no `/proc/net`.
//!
//! One `sysctl` each, unprivileged and read-only, the calls `arp -an`,
//! `ndp -an` and `netstat -rn` make: `NET_RT_FLAGS` with `RTF_LLINFO` for the
//! ARP and NDP tables, `NET_RT_DUMP` for the default route. What comes back
//! is a run of routing messages, each a `rt_msghdr` and the socket addresses
//! its `rtm_addrs` names; the parser is plain bytes in, so it is tested
//! everywhere, and the FreeBSD VM in CI checks it against a real kernel.
//!
//! VLAN ids come from the `SIOCGETVLAN` ioctl on each interface, as
//! `ifconfig` reads them: the names OPNsense and pfSense give VLAN
//! interfaces (`vlan01`, `igb0.20`) do not always carry the tag.

// The readers are FreeBSD's; the parser builds and is tested everywhere.
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `sizeof(struct rt_msghdr)` on 64-bit FreeBSD (`net/route.h`): 40 bytes
/// of header, then `struct rt_metrics`, fourteen `u_long`s.
pub const RT_MSGHDR: usize = 152;
/// `rtm_rmx.rmx_expire`: 0 for an entry set by hand.
const RMX_EXPIRE: usize = 40 + 3 * 8;
const RTM_VERSION: u8 = 5;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
/// The address kinds, in the order their bits come in `rtm_addrs`.
const RTAX_MAX: u32 = 8;
const RTF_GATEWAY: i32 = 0x2;
const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
const AF_INET6: u8 = 28;

/// One routing message, as far as the readers need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMessage {
    pub flags: i32,
    /// `rmx_expire`: 0 when the entry never expires (set by hand).
    pub expire: u64,
    pub destination: Option<IpAddr>,
    /// A next hop's address, for a route.
    pub gateway_ip: Option<IpAddr>,
    /// A link-layer address, for an ARP or NDP entry; empty while unresolved.
    pub gateway_mac: Option<Vec<u8>>,
    /// The netmask's bytes, for a route; `Some(vec![])` for a zero-length one.
    pub netmask: Option<Vec<u8>>,
}

/// `SA_SIZE`: a socket address padded to a `long`, a zero-length one a whole `long`.
fn sa_size(len: u8) -> usize {
    if len == 0 {
        8
    } else {
        (usize::from(len) + 7) & !7
    }
}

fn ip_of(sa: &[u8]) -> Option<IpAddr> {
    match *sa.get(1)? {
        AF_INET => {
            let b: [u8; 4] = sa.get(4..8)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        AF_INET6 => {
            let b: [u8; 16] = sa.get(8..24)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// A `sockaddr_dl`'s link-layer address: after the 8-byte header and the
/// interface's name.
fn mac_of(sa: &[u8]) -> Option<Vec<u8>> {
    if *sa.get(1)? != AF_LINK {
        return None;
    }
    let (nlen, alen) = (usize::from(*sa.get(5)?), usize::from(*sa.get(6)?));
    sa.get(8 + nlen..8 + nlen + alen).map(<[u8]>::to_vec)
}

/// Every routing message in a sysctl's answer; a malformed one ends the run.
pub fn parse_messages(mut bytes: &[u8]) -> Vec<RouteMessage> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if len < RT_MSGHDR || len > bytes.len() || bytes[2] != RTM_VERSION {
            break;
        }
        if let Some(message) = parse_message(&bytes[..len]) {
            out.push(message);
        }
        bytes = &bytes[len..];
    }
    out
}

fn int_at(bytes: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn parse_message(bytes: &[u8]) -> Option<RouteMessage> {
    let flags = int_at(bytes, 8)?;
    let addrs = int_at(bytes, 12)?;
    let expire = u64::from_ne_bytes(bytes.get(RMX_EXPIRE..RMX_EXPIRE + 8)?.try_into().ok()?);
    let mut message = RouteMessage {
        flags,
        expire,
        destination: None,
        gateway_ip: None,
        gateway_mac: None,
        netmask: None,
    };
    let mut at = RT_MSGHDR;
    for bit in 0..RTAX_MAX {
        let kind = 1 << bit;
        if addrs & kind == 0 {
            continue;
        }
        let len = *bytes.get(at)?;
        let sa = bytes.get(at..at + usize::from(len).max(2)).unwrap_or(&[]);
        match kind {
            RTA_DST => message.destination = ip_of(sa),
            RTA_GATEWAY => {
                message.gateway_ip = ip_of(sa);
                message.gateway_mac = mac_of(sa);
            }
            // A netmask's family may be unset; its bytes start where an
            // address's would.
            RTA_NETMASK => {
                let start = if sa.get(1) == Some(&AF_INET6) { 8 } else { 4 };
                message.netmask = Some(sa.get(start..).unwrap_or(&[]).to_vec());
            }
            _ => {}
        }
        at += sa_size(len);
    }
    Some(message)
}

/// The ARP or NDP entries of an `RTF_LLINFO` dump that have a MAC, as
/// `(address, mac, permanent)`.
pub fn link_entries(messages: &[RouteMessage]) -> Vec<(IpAddr, [u8; 6], bool)> {
    messages
        .iter()
        .filter_map(|m| {
            let mac: [u8; 6] = m.gateway_mac.as_deref()?.try_into().ok()?;
            Some((m.destination?, mac, m.expire == 0))
        })
        .collect()
}

/// The IPv4 default route's next hop in a `NET_RT_DUMP`: destination
/// 0.0.0.0, an all-zero (or absent) netmask, through a gateway.
pub fn default_gateway(messages: &[RouteMessage]) -> Option<Ipv4Addr> {
    messages.iter().find_map(|m| {
        let default = m.destination == Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            && m.netmask
                .as_deref()
                .is_none_or(|mask| mask.iter().all(|b| *b == 0))
            && m.flags & RTF_GATEWAY != 0;
        match (default, m.gateway_ip) {
            (true, Some(IpAddr::V4(gateway))) => Some(gateway),
            _ => None,
        }
    })
}

#[cfg(target_os = "freebsd")]
mod system {
    /// One routing sysctl's answer: `CTL_NET, PF_ROUTE, 0, family, op, arg`.
    pub fn sysctl(family: libc::c_int, op: libc::c_int, arg: libc::c_int) -> Option<Vec<u8>> {
        let mib = [libc::CTL_NET, libc::PF_ROUTE, 0, family, op, arg];
        // The table can grow between the two calls: a few tries, with room.
        for _ in 0..3 {
            let mut len = 0usize;
            // SAFETY: a size query; the kernel writes only `len`.
            let sized = unsafe {
                libc::sysctl(
                    mib.as_ptr(),
                    mib.len() as libc::c_uint,
                    std::ptr::null_mut(),
                    &mut len,
                    std::ptr::null(),
                    0,
                )
            };
            if sized != 0 {
                return None;
            }
            let mut buf = vec![0u8; len + len / 4 + 1024];
            let mut got = buf.len();
            // SAFETY: the kernel writes at most `got` bytes into `buf`.
            let read = unsafe {
                libc::sysctl(
                    mib.as_ptr(),
                    mib.len() as libc::c_uint,
                    buf.as_mut_ptr().cast(),
                    &mut got,
                    std::ptr::null(),
                    0,
                )
            };
            if read == 0 {
                buf.truncate(got);
                return Some(buf);
            }
        }
        None
    }

    /// `SIOCGETVLAN` (`SIOCGIFGENERIC`, `_IOWR('i', 58, struct ifreq)`).
    const SIOCGETVLAN: libc::c_ulong = 0xc020_693a;

    #[repr(C)]
    struct VlanReq {
        parent: [libc::c_char; libc::IFNAMSIZ],
        tag: u16,
        proto: u16,
    }

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: *mut VlanReq,
        _rest: [u8; 8],
    }

    /// A VLAN interface's tag; `None` for any other interface.
    pub fn vlan_tag(name: &str) -> Option<u16> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
            return None;
        }
        // SAFETY: plain socket(2), closed below.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return None;
        }
        let mut vlan = VlanReq {
            parent: [0; libc::IFNAMSIZ],
            tag: 0,
            proto: 0,
        };
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            data: &mut vlan,
            _rest: [0; 8],
        };
        for (to, from) in req.name.iter_mut().zip(bytes) {
            *to = *from as libc::c_char;
        }
        // SAFETY: the ioctl reads `req` and writes `vlan`, both live here.
        let ok = unsafe { libc::ioctl(fd, SIOCGETVLAN, &mut req) } == 0;
        // SAFETY: `fd` is ours.
        unsafe { libc::close(fd) };
        (ok && (1..=4094).contains(&vlan.tag)).then_some(vlan.tag)
    }
}

/// This host's ARP and NDP entries with a MAC, as `(address, mac, permanent)`.
#[cfg(target_os = "freebsd")]
pub fn neighbour_entries() -> Vec<(IpAddr, [u8; 6], bool)> {
    let mut out = Vec::new();
    for family in [libc::AF_INET, libc::AF_INET6] {
        if let Some(bytes) = system::sysctl(family, libc::NET_RT_FLAGS, libc::RTF_LLINFO) {
            out.extend(link_entries(&parse_messages(&bytes)));
        }
    }
    out
}

/// The IPv4 default route's next hop.
#[cfg(target_os = "freebsd")]
pub fn default_route() -> Option<Ipv4Addr> {
    let bytes = system::sysctl(libc::AF_INET, libc::NET_RT_DUMP, 0)?;
    default_gateway(&parse_messages(&bytes))
}

#[cfg(target_os = "freebsd")]
pub use system::vlan_tag;

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A routing message as the kernel writes it: the header, then each
    /// socket address padded to a `long`.
    pub fn message(flags: i32, expire: u64, addrs: &[(i32, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0u8; RT_MSGHDR];
        out[2] = RTM_VERSION;
        out[8..12].copy_from_slice(&flags.to_ne_bytes());
        let mask = addrs.iter().fold(0, |m, (kind, _)| m | kind);
        out[12..16].copy_from_slice(&mask.to_ne_bytes());
        out[RMX_EXPIRE..RMX_EXPIRE + 8].copy_from_slice(&expire.to_ne_bytes());
        for (_, sa) in addrs {
            let mut padded = sa.clone();
            padded.resize(sa_size(sa.first().copied().unwrap_or(0)), 0);
            out.extend(padded);
        }
        let len = out.len() as u16;
        out[0..2].copy_from_slice(&len.to_ne_bytes());
        out
    }

    pub fn inet(ip: [u8; 4]) -> Vec<u8> {
        let mut sa = vec![16, AF_INET, 0, 0];
        sa.extend(ip);
        sa.resize(16, 0);
        sa
    }

    fn inet6(ip: Ipv6Addr) -> Vec<u8> {
        let mut sa = vec![28, AF_INET6, 0, 0, 0, 0, 0, 0];
        sa.extend(ip.octets());
        sa.resize(28, 0);
        sa
    }

    pub fn link(name: &str, mac: &[u8]) -> Vec<u8> {
        let mut sa = vec![0, AF_LINK, 1, 0, 6, name.len() as u8, mac.len() as u8, 0];
        sa.extend(name.as_bytes());
        sa.extend(mac);
        sa[0] = sa.len().max(20) as u8;
        sa.resize(usize::from(sa[0]), 0);
        sa
    }

    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x07];

    #[test]
    fn reads_arp_and_ndp_entries_with_a_mac() {
        let mut dump = message(
            0,
            0,
            &[
                (RTA_DST, inet([10, 99, 20, 7])),
                (RTA_GATEWAY, link("vlan0", &MAC)),
            ],
        );
        // Expiring: learned, not set by hand.
        dump.extend(message(
            0,
            1200,
            &[
                (RTA_DST, inet([10, 99, 20, 8])),
                (RTA_GATEWAY, link("vlan0", &MAC)),
            ],
        ));
        // Unresolved: no MAC yet.
        dump.extend(message(
            0,
            5,
            &[
                (RTA_DST, inet([10, 99, 20, 9])),
                (RTA_GATEWAY, link("vlan0", &[])),
            ],
        ));
        let v6: Ipv6Addr = "fe80::1".parse().unwrap();
        dump.extend(message(
            0,
            30,
            &[(RTA_DST, inet6(v6)), (RTA_GATEWAY, link("igb0", &MAC))],
        ));

        assert_eq!(
            link_entries(&parse_messages(&dump)),
            vec![
                (IpAddr::V4(Ipv4Addr::new(10, 99, 20, 7)), MAC, true),
                (IpAddr::V4(Ipv4Addr::new(10, 99, 20, 8)), MAC, false),
                (IpAddr::V6(v6), MAC, false),
            ]
        );
    }

    #[test]
    fn finds_the_default_route_through_a_gateway() {
        let mut dump = message(
            0x1 | RTF_GATEWAY,
            0,
            &[
                (RTA_DST, inet([10, 0, 0, 0])),
                (RTA_GATEWAY, inet([10, 0, 0, 9])),
                (RTA_NETMASK, vec![8, 0, 0, 0, 255, 0, 0, 0]),
            ],
        );
        // A zero-length netmask: one whole `long` of padding.
        dump.extend(message(
            0x1 | RTF_GATEWAY,
            0,
            &[
                (RTA_DST, inet([0, 0, 0, 0])),
                (RTA_GATEWAY, inet([192, 168, 1, 1])),
                (RTA_NETMASK, vec![0]),
            ],
        ));
        assert_eq!(
            default_gateway(&parse_messages(&dump)),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        // A directly connected default is no gateway.
        let direct = message(
            0x1,
            0,
            &[
                (RTA_DST, inet([0, 0, 0, 0])),
                (RTA_GATEWAY, link("igb0", &[])),
            ],
        );
        assert_eq!(default_gateway(&parse_messages(&direct)), None);
    }

    #[test]
    fn stops_at_a_malformed_message() {
        let mut dump = message(
            0,
            0,
            &[
                (RTA_DST, inet([10, 0, 0, 1])),
                (RTA_GATEWAY, link("em0", &MAC)),
            ],
        );
        dump.extend([0xff, 0xff, RTM_VERSION, 0]);
        assert_eq!(parse_messages(&dump).len(), 1);
        assert!(parse_messages(&[1, 0, RTM_VERSION, 0]).is_empty());
    }

    /// Against a real kernel: CI's FreeBSD VM makes `vlan0` (tag 20,
    /// 10.99.20.1/24) and a static ARP entry for 10.99.20.7 first, then runs
    /// `cargo test -- --ignored freebsd_`. Checks the layout this module
    /// assumes (`RT_MSGHDR`, the ioctl) against what the kernel writes.
    #[cfg(target_os = "freebsd")]
    #[test]
    #[ignore = "needs the CI VM's vlan0 and static ARP entry"]
    fn freebsd_reads_the_hosts_tables() {
        let vlans = crate::features::vlan::link_vlans();
        assert_eq!(vlans.get("vlan0"), Some(&20), "{vlans:?}");

        let neighbours = crate::features::neighbours::neighbours();
        let static_entry = neighbours.iter().find(|n| n.address == "10.99.20.7");
        assert_eq!(
            static_entry.map(|n| (n.mac.as_str(), n.state)),
            Some(("02:00:00:00:00:07", "permanent")),
            "{neighbours:?}"
        );

        assert!(default_route().is_some(), "no default route read");
    }
}
