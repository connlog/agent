//! Observed connections (docs/topology/PLAN.md, T11.1): who this host talks
//! to, from its established TCP sockets in `/proc/net/tcp{,6}`, aggregated
//! per peer address, port and direction. Sent with the inventory, and only
//! when the platform asks for them (`connections` on a heartbeat answer).
//!
//! What may leave the host is bounded here, whatever the platform asks:
//!
//! - at the peers level, only peers the platform named: the other opted-in
//!   hosts on this host's site, sent with the probe request; at passive, any
//!   private peer;
//! - never a public, loopback or unspecified peer;
//! - the direction and the port, never the process, the user or a byte
//!   count; the side with the listening port is the server;
//! - at most 512, in order, so the same sockets always give the same bytes.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;

use serde::Serialize;

use super::discovery::DiscoveryLevel;
use super::network_inventory::parse_proc_ip;
use super::reachability;

/// `INVENTORY_MAX_CONNECTIONS` in the protocol.
pub const MAX_CONNECTIONS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Connection {
    pub peer: String,
    pub port: u16,
    /// `in`: the peer opened it, to this host's `port`; `out`: this host
    /// opened it, to the peer's `port`.
    pub direction: &'static str,
}

/// An established socket: (local address, local port, remote address,
/// remote port).
pub type Socket = (IpAddr, u16, IpAddr, u16);

/// The sockets in state `01` (ESTABLISHED) of a `/proc/net/tcp` or `tcp6` file.
pub fn parse_established(text: &str) -> Vec<Socket> {
    let endpoint = |field: &str| -> Option<(IpAddr, u16)> {
        let (ip, port) = field.split_once(':')?;
        Some((parse_proc_ip(ip)?, u16::from_str_radix(port, 16).ok()?))
    };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _slot = fields.next()?;
            let (local_ip, local_port) = endpoint(fields.next()?)?;
            let (remote_ip, remote_port) = endpoint(fields.next()?)?;
            fields.next()?.eq_ignore_ascii_case("01").then_some((
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            ))
        })
        .collect()
}

/// An IPv4 peer seen through an IPv6 socket, as itself.
fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// The connections that may be sent: private peers the level allows, each
/// once, in order, at most 512. `listening` are this host's listening
/// ports; `named` the peers the platform named, which is all the peers
/// level allows.
pub fn observe(
    sockets: &[Socket],
    listening: &BTreeSet<u16>,
    level: DiscoveryLevel,
    named: &HashSet<IpAddr>,
) -> Vec<Connection> {
    let mut out = BTreeSet::new();
    for &(_, local_port, remote, remote_port) in sockets {
        let peer = plain(remote);
        if peer.is_loopback() || peer.is_unspecified() || !reachability::is_private(&peer) {
            continue;
        }
        let allowed = match level {
            DiscoveryLevel::Off => false,
            DiscoveryLevel::Peers => named.contains(&peer),
            DiscoveryLevel::Passive | DiscoveryLevel::Active => true,
        };
        if !allowed {
            continue;
        }
        let (port, direction) = if listening.contains(&local_port) {
            (local_port, "in")
        } else {
            (remote_port, "out")
        };
        out.insert(Connection {
            peer: peer.to_string(),
            port,
            direction,
        });
    }
    out.into_iter().take(MAX_CONNECTIONS).collect()
}

/// This host's connections now, as `observe` keeps them.
pub fn collect(
    listening: &BTreeSet<u16>,
    level: DiscoveryLevel,
    named: &HashSet<IpAddr>,
) -> Vec<Connection> {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let mut sockets = parse_established(&read("/proc/net/tcp"));
    sockets.extend(parse_established(&read("/proc/net/tcp6")));
    observe(&sockets, listening, level, named)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_NET_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0500000A:01BB 0700000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0500000A:D431 0900000A:1538 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0500000A:D432 0900000A:1538 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
   3: 0500000A:D433 0A7100CB:01BB 01 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
   4: 0100007F:1F90 0100007F:D434 01 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 100 0 0 10 0
   5: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 1 0000000000000000 100 0 0 10 0
   6: 0500000A:D435 0B00000A:0016 06 00000000:00000000 00:00000000 00000000     0        0 7 1 0000000000000000 100 0 0 10 0
";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn reads_established_sockets_only() {
        let sockets = parse_established(PROC_NET_TCP);
        assert_eq!(sockets.len(), 5, "LISTEN and TIME_WAIT are not connections");
        assert_eq!(sockets[0], (ip("10.0.0.5"), 443, ip("10.0.0.7"), 50000));
    }

    #[test]
    fn at_passive_keeps_private_peers_with_their_direction_once_each() {
        let listening = BTreeSet::from([443]);
        let got = observe(
            &parse_established(PROC_NET_TCP),
            &listening,
            DiscoveryLevel::Passive,
            &HashSet::new(),
        );
        assert_eq!(
            got,
            vec![
                Connection {
                    peer: "10.0.0.7".into(),
                    port: 443,
                    direction: "in"
                },
                // Two sockets to the same database: one connection.
                Connection {
                    peer: "10.0.0.9".into(),
                    port: 5432,
                    direction: "out"
                },
            ],
            "the public peer and loopback are left out"
        );
    }

    #[test]
    fn at_peers_keeps_only_the_peers_the_platform_named() {
        let named = HashSet::from([ip("10.0.0.9")]);
        let got = observe(
            &parse_established(PROC_NET_TCP),
            &BTreeSet::from([443]),
            DiscoveryLevel::Peers,
            &named,
        );
        assert_eq!(
            got.iter().map(|c| c.peer.as_str()).collect::<Vec<_>>(),
            ["10.0.0.9"]
        );
        assert!(observe(
            &parse_established(PROC_NET_TCP),
            &BTreeSet::new(),
            DiscoveryLevel::Off,
            &named
        )
        .is_empty());
    }

    #[test]
    fn reads_an_ipv4_peer_through_an_ipv6_socket_as_itself() {
        let sockets = vec![(ip("::ffff:10.0.0.5"), 40000, ip("::ffff:10.0.0.9"), 5432)];
        let got = observe(
            &sockets,
            &BTreeSet::new(),
            DiscoveryLevel::Passive,
            &HashSet::new(),
        );
        assert_eq!(got[0].peer, "10.0.0.9");
    }

    #[test]
    fn caps_the_list() {
        let sockets: Vec<Socket> = (0..600u16)
            .map(|i| (ip("10.0.0.5"), 40000 + i, ip("10.0.1.1"), 1000 + i))
            .collect();
        let got = observe(
            &sockets,
            &BTreeSet::new(),
            DiscoveryLevel::Passive,
            &HashSet::new(),
        );
        assert_eq!(got.len(), MAX_CONNECTIONS);
    }

    #[test]
    fn this_host_reads_without_error() {
        let _ = collect(&BTreeSet::new(), DiscoveryLevel::Passive, &HashSet::new());
    }
}
