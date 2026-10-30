//! This host's neighbour table (docs/topology/PLAN.md, T8.3), for a host
//! whose discovery level is `passive` or above: the devices it has talked to
//! on its own networks, as the kernel already knows them. Nothing is sent on
//! the wire to learn them.
//!
//! One netlink neighbour dump (`RTM_GETNEIGH`, `features::netlink`), IPv4
//! and IPv6 alike, without privilege. Kept: an entry with a MAC, in a private
//! range as the probes and the protocol read it (`reachability::is_private`:
//! RFC 1918, 100.64/10, 169.254/16, fc00::/7, fe80::/10), not a multicast or
//! broadcast MAC; its address, MAC and state. At most 1,024, in address
//! order, so the same table always gives the same bytes. Never the
//! interface, never a name.

// FreeBSD reads these through `features::routing`; the netlink parsing
// still builds and is tested there.
#![cfg_attr(target_os = "freebsd", allow(dead_code, unused_imports))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use super::netlink::{attribute, attributes, dump, request};

/// `INVENTORY_MAX_NEIGHBOURS` in the protocol.
pub const MAX_NEIGHBOURS: usize = 1024;

/// `linux/rtnetlink.h`, `linux/neighbour.h`: stable kernel ABI.
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NDMSG: usize = 12;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Neighbour {
    pub address: String,
    /// Lowercase `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// `reachable` (confirmed lately), `stale` (known, not confirmed lately)
    /// or `permanent` (set by hand).
    pub state: &'static str,
}

/// This host's neighbours, as the inventory sends them: on FreeBSD (a
/// firewall, T13.5b) from its ARP and NDP tables, which hold no state but
/// whether an entry was set by hand.
#[cfg(target_os = "freebsd")]
pub fn neighbours() -> Vec<Neighbour> {
    tidy(
        crate::features::routing::neighbour_entries()
            .into_iter()
            .filter_map(|(ip, mac, permanent)| {
                kept(ip, mac, if permanent { "permanent" } else { "reachable" })
            })
            .collect(),
    )
}

/// This host's neighbours, as the inventory sends them.
#[cfg(not(target_os = "freebsd"))]
pub fn neighbours() -> Vec<Neighbour> {
    let mut found = Vec::new();
    let _ = dump(
        &request(RTM_GETNEIGH, 0, NDMSG),
        RTM_NEWNEIGH,
        &mut |body| {
            if let Some(neighbour) = neighbour_of(body) {
                found.push(neighbour);
            }
        },
    );
    tidy(found)
}

/// Sorted by address, one entry per address, capped.
fn tidy(mut found: Vec<Neighbour>) -> Vec<Neighbour> {
    found.sort_by_key(|n| n.address.parse::<IpAddr>().ok());
    found.dedup_by(|a, b| a.address == b.address);
    found.truncate(MAX_NEIGHBOURS);
    found
}

fn state_word(state: u16) -> Option<&'static str> {
    if state & (NUD_INCOMPLETE | NUD_FAILED | NUD_NOARP) != 0 || state == 0 {
        return None;
    }
    Some(if state & NUD_PERMANENT != 0 {
        "permanent"
    } else if state & NUD_REACHABLE != 0 {
        "reachable"
    } else {
        "stale"
    })
}

/// An `RTM_NEWNEIGH` body as a neighbour, when it is one the inventory keeps.
fn neighbour_of(body: &[u8]) -> Option<Neighbour> {
    let state = u16::from_ne_bytes([*body.get(8)?, *body.get(9)?]);
    let state = state_word(state)?;
    let attrs = attributes(body.get(NDMSG..)?);
    let ip = match attribute(&attrs, NDA_DST)? {
        dst if dst.len() == 4 => IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
        dst if dst.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(dst);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    let mac: [u8; 6] = attribute(&attrs, NDA_LLADDR)?.try_into().ok()?;
    kept(ip, mac, state)
}

/// A neighbour the inventory keeps: a private address, a unicast MAC.
fn kept(ip: IpAddr, mac: [u8; 6], state: &'static str) -> Option<Neighbour> {
    // Multicast and broadcast (the group bit), and an all-zero placeholder.
    if !crate::features::reachability::is_private(&ip) || mac[0] & 1 == 1 || mac == [0; 6] {
        return None;
    }
    Some(Neighbour {
        address: ip.to_string(),
        mac: mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::netlink::parse_messages;
    use crate::features::netlink::tests::{attr, done, message};

    fn entry(dst: &[u8], mac: Option<[u8; 6]>, state: u16) -> Vec<u8> {
        let mut body = vec![0u8; NDMSG];
        body[0] = if dst.len() == 4 { 2 } else { 10 };
        body[8..10].copy_from_slice(&state.to_ne_bytes());
        body.extend(attr(NDA_DST, dst));
        if let Some(mac) = mac {
            body.extend(attr(NDA_LLADDR, &mac));
        }
        message(RTM_NEWNEIGH, &body)
    }

    fn read(dump: &[u8]) -> Vec<Neighbour> {
        let mut found = Vec::new();
        parse_messages(dump, RTM_NEWNEIGH, &mut |body| {
            if let Some(n) = neighbour_of(body) {
                found.push(n);
            }
        });
        tidy(found)
    }

    const PHONE: [u8; 6] = [0xa4, 0x83, 0xe7, 0x01, 0x02, 0x03];
    const PRINTER: [u8; 6] = [0x00, 0x1b, 0xa9, 0x0a, 0x0b, 0x0c];

    #[test]
    fn keeps_private_neighbours_with_a_mac_and_their_state() {
        let mut dump = Vec::new();
        dump.extend(entry(&[10, 0, 40, 12], Some(PHONE), NUD_REACHABLE));
        dump.extend(entry(&[192, 168, 1, 7], Some(PRINTER), 0x04)); // STALE
        let ula = "fd00::7".parse::<Ipv6Addr>().unwrap().octets();
        dump.extend(entry(&ula, Some(PRINTER), NUD_PERMANENT));
        dump.extend(done());
        assert_eq!(
            read(&dump),
            vec![
                Neighbour {
                    address: "10.0.40.12".into(),
                    mac: "a4:83:e7:01:02:03".into(),
                    state: "reachable"
                },
                Neighbour {
                    address: "192.168.1.7".into(),
                    mac: "00:1b:a9:0a:0b:0c".into(),
                    state: "stale"
                },
                Neighbour {
                    address: "fd00::7".into(),
                    mac: "00:1b:a9:0a:0b:0c".into(),
                    state: "permanent"
                },
            ]
        );
    }

    #[test]
    fn leaves_out_public_addresses_unresolved_entries_and_group_macs() {
        let mut dump = Vec::new();
        // A public address (an upstream router seen over a public subnet).
        dump.extend(entry(&[203, 0, 113, 1], Some(PHONE), NUD_REACHABLE));
        // Still resolving, or failed: no MAC worth keeping.
        dump.extend(entry(&[10, 0, 0, 9], None, NUD_INCOMPLETE));
        dump.extend(entry(&[10, 0, 0, 8], Some(PHONE), NUD_FAILED));
        // Multicast and all-zero MACs.
        dump.extend(entry(
            &[10, 0, 0, 7],
            Some([0x01, 0x00, 0x5e, 0, 0, 1]),
            NUD_PERMANENT,
        ));
        dump.extend(entry(&[10, 0, 0, 6], Some([0; 6]), NUD_NOARP));
        assert!(read(&dump).is_empty());
    }

    #[test]
    fn reads_private_as_the_protocol_does() {
        // Carrier-grade NAT and IPv4 link-local are private there too.
        let mut dump = entry(&[100, 64, 0, 9], Some(PRINTER), NUD_REACHABLE);
        dump.extend(entry(&[169, 254, 1, 1], Some(PHONE), NUD_REACHABLE));
        let kept: Vec<String> = read(&dump).into_iter().map(|n| n.address).collect();
        assert_eq!(kept, vec!["100.64.0.9", "169.254.1.1"]);
    }

    #[test]
    fn caps_the_table_and_orders_it_by_address() {
        let mut found: Vec<Neighbour> = (0..1100u32)
            .rev()
            .map(|i| Neighbour {
                address: Ipv4Addr::from(0x0a00_0000 + i).to_string(),
                mac: "a4:83:e7:01:02:03".into(),
                state: "stale",
            })
            .collect();
        found.push(found[0].clone());
        let kept = tidy(found);
        assert_eq!(kept.len(), MAX_NEIGHBOURS);
        assert_eq!(kept[0].address, "10.0.0.0");
        assert_eq!(kept[1].address, "10.0.0.1");
    }

    #[test]
    fn this_host_reads_without_error() {
        let _ = neighbours();
    }
}
