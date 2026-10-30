//! VLAN ids of this host's own VLAN interfaces (docs/topology/PLAN.md, T8.2),
//! for a host whose discovery level is `passive` or above.
//!
//! Read with one netlink link dump (`RTM_GETLINK`, `features::netlink`), the
//! call `ip -d link` makes: it needs no privilege, and `/proc/net/vlan` is
//! root's. Only the interface's name and its VLAN id are kept, and only to
//! label the addresses the inventory already sends: the name itself never
//! leaves the host.
//!
//! Every failure degrades to "no VLANs": the inventory is sent without them.

// FreeBSD reads these through `features::routing`; the netlink parsing
// still builds and is tested there.
#![cfg_attr(target_os = "freebsd", allow(dead_code, unused_imports))]

use std::collections::HashMap;

use super::netlink::{attribute, attributes, dump, request};

/// `linux/rtnetlink.h`, `linux/if_link.h`: stable kernel ABI.
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const IFINFOMSG: usize = 16;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_VLAN_ID: u16 = 1;

/// Interface name to VLAN id, for every VLAN interface on this host: on
/// FreeBSD (a firewall, T13.5b), each interface asked with `SIOCGETVLAN`.
#[cfg(target_os = "freebsd")]
pub fn link_vlans() -> HashMap<String, u16> {
    let names: std::collections::HashSet<String> =
        crate::features::network_inventory::interface_addresses()
            .into_iter()
            .map(|a| a.interface)
            .collect();
    names
        .into_iter()
        .filter_map(|name| Some((crate::features::routing::vlan_tag(&name)?, name)))
        .map(|(id, name)| (name, id))
        .collect()
}

/// Interface name to VLAN id, for every VLAN interface on this host.
#[cfg(not(target_os = "freebsd"))]
pub fn link_vlans() -> HashMap<String, u16> {
    let mut vlans = HashMap::new();
    let _ = dump(
        &request(RTM_GETLINK, 0, IFINFOMSG),
        RTM_NEWLINK,
        &mut |body| {
            if let Some((name, id)) = vlan_of_link(body) {
                vlans.insert(name, id);
            }
        },
    );
    vlans
}

/// An `RTM_NEWLINK` body's name and VLAN id, when the link is a VLAN.
fn vlan_of_link(body: &[u8]) -> Option<(String, u16)> {
    let attrs = attributes(body.get(IFINFOMSG..)?);
    let info = attributes(attribute(&attrs, IFLA_LINKINFO)?);
    let kind = attribute(&info, IFLA_INFO_KIND)?;
    if kind.split(|b| *b == 0).next()? != b"vlan" {
        return None;
    }
    let data = attributes(attribute(&info, IFLA_INFO_DATA)?);
    let id = attribute(&data, IFLA_VLAN_ID)?;
    let id = u16::from_ne_bytes([*id.first()?, *id.get(1)?]);
    let name = attribute(&attrs, IFLA_IFNAME)?;
    let name = String::from_utf8_lossy(name.split(|b| *b == 0).next()?).into_owned();
    (!name.is_empty() && (1..=4094).contains(&id)).then_some((name, id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::netlink::parse_messages;
    use crate::features::netlink::tests::{attr, done, message};

    /// A link as the kernel describes it, with a kind and (for a VLAN) an id.
    fn link(name: &str, kind: Option<&str>, vlan: Option<u16>) -> Vec<u8> {
        let mut body = vec![0u8; IFINFOMSG];
        body.extend(attr(IFLA_IFNAME, format!("{name}\0").as_bytes()));
        if let Some(kind) = kind {
            let mut info = attr(IFLA_INFO_KIND, format!("{kind}\0").as_bytes());
            if let Some(id) = vlan {
                info.extend(attr(
                    IFLA_INFO_DATA | 0x8000,
                    &attr(IFLA_VLAN_ID, &id.to_ne_bytes()),
                ));
            }
            body.extend(attr(IFLA_LINKINFO | 0x8000, &info));
        }
        message(RTM_NEWLINK, &body)
    }

    fn vlans_in(dump: &[u8]) -> HashMap<String, u16> {
        let mut vlans = HashMap::new();
        parse_messages(dump, RTM_NEWLINK, &mut |body| {
            if let Some((name, id)) = vlan_of_link(body) {
                vlans.insert(name, id);
            }
        });
        vlans
    }

    #[test]
    fn finds_vlan_interfaces_and_nothing_else() {
        let mut dump = Vec::new();
        dump.extend(link("lo", None, None));
        dump.extend(link("eth0", None, None));
        dump.extend(link("eth0.20", Some("vlan"), Some(20)));
        dump.extend(link("vmbr0", Some("bridge"), None));
        dump.extend(link("guests", Some("vlan"), Some(4094)));
        dump.extend(done());
        assert_eq!(
            vlans_in(&dump),
            HashMap::from([("eth0.20".to_string(), 20), ("guests".to_string(), 4094)])
        );
    }

    #[test]
    fn a_reserved_id_is_left_out() {
        assert!(vlans_in(&link("eth0.0", Some("vlan"), Some(0))).is_empty());
    }

    #[test]
    fn this_host_reads_without_error() {
        // No VLAN in a test container is expected; it must still read cleanly.
        let _ = link_vlans();
    }
}
