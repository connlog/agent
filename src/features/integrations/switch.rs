//! A switch or router over SNMP (docs/topology/PLAN.md, T10.3): its
//! interfaces, its VLANs and which ports carry them, its LLDP neighbours,
//! and its bridge table (which port each MAC address was learned on). That
//! is what the legal text names for switches; CDP, a device's description
//! and its configuration are not read.
//!
//! Built from the standard MIBs: IF-MIB (RFC 2863), BRIDGE-MIB (RFC 4188),
//! Q-BRIDGE-MIB (RFC 4363) and LLDP-MIB (IEEE 802.1AB). The tables in the
//! tests are written from those, not walked off a switch, and are labelled
//! so.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::snmp::ber::Value;
use super::snmp::{Client, VarBind, Wire};
use super::Failure;

/// `SWITCH_MAX_*` in the protocol.
pub const MAX_INTERFACES: usize = 1024;
pub const MAX_VLANS: usize = 1024;
pub const MAX_NEIGHBOURS: usize = 512;
pub const MAX_MACS: usize = 16_384;
const MAX_TAGGED: usize = 64;
/// `SWITCH_MAX_ARP` and `SWITCH_MAX_NETWORKS` in the protocol.
pub const MAX_ARP: usize = 4096;
pub const MAX_NETWORKS: usize = 256;
const TEXT_MAX: usize = 128;
/// One read stops walking after this: what is read so far is reported.
const READ_BUDGET: Duration = Duration::from_secs(90);

const SYS_NAME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 5, 0];
const IF_DESCR: [u32; 10] = [1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
const IF_TYPE: [u32; 10] = [1, 3, 6, 1, 2, 1, 2, 2, 1, 3];
const IF_OPER_STATUS: [u32; 10] = [1, 3, 6, 1, 2, 1, 2, 2, 1, 8];
const IF_NAME: [u32; 11] = [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
const IF_HIGH_SPEED: [u32; 11] = [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15];
const IF_ALIAS: [u32; 11] = [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18];
const BASE_PORT_IF_INDEX: [u32; 11] = [1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
const TP_FDB_PORT: [u32; 11] = [1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
const Q_TP_FDB_PORT: [u32; 13] = [1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];
const Q_VLAN_EGRESS: [u32; 13] = [1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 4];
const Q_VLAN_UNTAGGED: [u32; 13] = [1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 5];
const Q_VLAN_STATIC_NAME: [u32; 13] = [1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];
const Q_PVID: [u32; 13] = [1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1];
/// ipNetToPhysicalPhysAddress (IP-MIB, RFC 4293): index (ifIndex, type, address).
const IP_NET_TO_PHYSICAL: [u32; 10] = [1, 3, 6, 1, 2, 1, 4, 35, 1, 4];
/// ipNetToMediaPhysAddress, the older table every router still has: index (ifIndex, a.b.c.d).
const IP_NET_TO_MEDIA: [u32; 10] = [1, 3, 6, 1, 2, 1, 4, 22, 1, 2];
/// ipAdEntIfIndex and ipAdEntNetMask: the device's own addresses, index a.b.c.d.
const IP_AD_ENT_IF_INDEX: [u32; 10] = [1, 3, 6, 1, 2, 1, 4, 20, 1, 2];
const IP_AD_ENT_NET_MASK: [u32; 10] = [1, 3, 6, 1, 2, 1, 4, 20, 1, 3];
const LLDP_LOC_PORT_ID: [u32; 11] = [1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 3];
const LLDP_REM: [u32; 10] = [1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
/// softwareLoopback: never a port.
const IF_TYPE_LOOPBACK: i64 = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Port {
    /// The interface's ifIndex.
    pub index: u32,
    /// ifName, else ifDescr: `ge-0/0/12`, `Gi1/0/12`, `port 12`.
    pub name: String,
    /// ifAlias: what the customer wrote on it.
    pub description: Option<String>,
    pub up: bool,
    pub speed_mbps: Option<u32>,
    /// The VLAN its untagged frames go to (the PVID).
    pub vlan: Option<u16>,
    /// The VLANs it carries tagged.
    pub tagged: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vlan {
    pub id: u16,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Neighbour {
    /// The ifIndex of the port it is on, where the switch's numbering says.
    pub port: Option<u32>,
    /// A MAC address (`aa:bb:…`) where the neighbour gives one, else its words.
    pub chassis_id: String,
    pub port_id: String,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Learned {
    pub mac: String,
    /// The ifIndex of the port it was learned on.
    pub port: u32,
    pub vlan: Option<u16>,
}

/// An address the device holds a MAC for: a row of its ARP table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArpEntry {
    pub address: String,
    pub mac: String,
}

/// A network the device has an address in: what it routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Network {
    /// Its own address there with the prefix length: `10.0.20.1/24`.
    pub cidr: String,
    /// The ifIndex of the interface the address is on.
    pub port: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// sysName.
    pub name: Option<String>,
    /// The address it was read at, where the integration names one.
    pub address: Option<String>,
    pub ports: Vec<Port>,
    pub vlans: Vec<Vlan>,
    pub neighbours: Vec<Neighbour>,
    pub macs: Vec<Learned>,
    /// A router's or layer-3 switch's ARP table, private addresses only: the
    /// address of each MAC, on every VLAN it routes. It is how a device on a
    /// network no server is on gets an address on the map. Left out when the
    /// device has none (a plain layer-2 switch holds its management
    /// neighbours at most), so such a report reads as it always did.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arp: Vec<ArpEntry>,
    /// The private networks it has an address in, each with its interface.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<Network>,
}

/// What reading a switch asks of SNMP.
pub trait Mib {
    fn get(&mut self, oid: &[u32]) -> Result<Value, Failure>;
    fn walk(&mut self, root: &[u32], max: usize) -> Result<Vec<VarBind>, Failure>;
}

impl<W: Wire> Mib for Client<W> {
    fn get(&mut self, oid: &[u32]) -> Result<Value, Failure> {
        Ok(Client::get(self, &[oid])?
            .into_iter()
            .next()
            .map_or(Value::Missing, |(_, v)| v))
    }

    fn walk(&mut self, root: &[u32], max: usize) -> Result<Vec<VarBind>, Failure> {
        Client::walk(self, root, max)
    }
}

fn text(value: &Value) -> Option<String> {
    let bytes = value.as_bytes()?;
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    let ok = !text.is_empty() && !text.chars().any(char::is_control);
    ok.then(|| text.chars().take(TEXT_MAX).collect())
}

fn mac_of(bytes: &[u8]) -> Option<String> {
    (bytes.len() == 6).then(|| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

/// An LLDP id: a MAC where the subtype says so, else its words, else hex.
fn lldp_id(subtype: Option<i64>, value: &Value, mac_subtype: i64) -> Option<String> {
    let bytes = value.as_bytes()?;
    if subtype == Some(mac_subtype) {
        if let Some(mac) = mac_of(bytes) {
            return Some(mac);
        }
    }
    text(value).or_else(|| {
        (!bytes.is_empty()).then(|| {
            bytes
                .iter()
                .take(TEXT_MAX / 2)
                .map(|b| format!("{b:02x}"))
                .collect()
        })
    })
}

/// The arcs of a row's index: the OID past its column.
fn index_of<'a>(oid: &'a [u32], column: &[u32]) -> Option<&'a [u32]> {
    oid.strip_prefix(column)
}

/// A column keyed by its single-arc index.
fn by_index(rows: &[VarBind], column: &[u32]) -> BTreeMap<u32, Value> {
    rows.iter()
        .filter_map(|(oid, v)| match index_of(oid, column)? {
            [i] => Some((*i, v.clone())),
            _ => None,
        })
        .collect()
}

fn vlan_id(n: i64) -> Option<u16> {
    u16::try_from(n).ok().filter(|v| (1..=4094).contains(v))
}

/// A PortList bitmap: bit 0 of byte 0 (the high bit) is bridge port 1.
fn ports_in(bitmap: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bitmap.iter().enumerate().flat_map(|(i, byte)| {
        (0..8)
            .filter(move |bit| byte & (0x80 >> bit) != 0)
            .map(move |bit| (i * 8 + bit + 1) as u32)
    })
}

struct Reader<'a> {
    mib: &'a mut dyn Mib,
    started: Instant,
}

impl Reader<'_> {
    /// A table, or nothing once the budget is spent or the switch has none.
    fn walk(&mut self, column: &[u32], max: usize) -> Result<Vec<VarBind>, Failure> {
        if self.started.elapsed() > READ_BUDGET {
            return Ok(Vec::new());
        }
        match self.mib.walk(column, max) {
            // A table outside the switch's view is a table it does not have.
            Err(Failure::Forbidden | Failure::Status) => Ok(Vec::new()),
            other => other,
        }
    }
}

/// The switch, read once. sysName must answer (that is where a wrong
/// community or user shows); every table after it is read where it exists.
pub fn read(mib: &mut dyn Mib) -> Result<Report, Failure> {
    let started = Instant::now();
    let name = text(&mib.get(&SYS_NAME)?);
    let mut r = Reader { mib, started };

    let types = by_index(&r.walk(&IF_TYPE, MAX_INTERFACES)?, &IF_TYPE);
    let descr = by_index(&r.walk(&IF_DESCR, MAX_INTERFACES)?, &IF_DESCR);
    let names = by_index(&r.walk(&IF_NAME, MAX_INTERFACES)?, &IF_NAME);
    let status = by_index(&r.walk(&IF_OPER_STATUS, MAX_INTERFACES)?, &IF_OPER_STATUS);
    let speed = by_index(&r.walk(&IF_HIGH_SPEED, MAX_INTERFACES)?, &IF_HIGH_SPEED);
    let alias = by_index(&r.walk(&IF_ALIAS, MAX_INTERFACES)?, &IF_ALIAS);

    // Bridge ports to interfaces: the FDB and VLAN tables speak in bridge ports.
    let base: HashMap<u32, u32> = by_index(
        &r.walk(&BASE_PORT_IF_INDEX, MAX_INTERFACES)?,
        &BASE_PORT_IF_INDEX,
    )
    .into_iter()
    .filter_map(|(port, v)| Some((port, u32::try_from(v.as_int()?).ok()?)))
    .collect();
    let if_of = |port: u32| base.get(&port).copied();

    let pvid: HashMap<u32, u16> = by_index(&r.walk(&Q_PVID, MAX_INTERFACES)?, &Q_PVID)
        .into_iter()
        .filter_map(|(port, v)| Some((if_of(port)?, vlan_id(v.as_int()?)?)))
        .collect();

    let mut vlans: BTreeMap<u16, Option<String>> = BTreeMap::new();
    for (oid, v) in r.walk(&Q_VLAN_STATIC_NAME, MAX_VLANS)? {
        if let Some([id]) = index_of(&oid, &Q_VLAN_STATIC_NAME) {
            if let Some(id) = vlan_id(i64::from(*id)) {
                vlans.insert(id, text(&v));
            }
        }
    }
    // Current membership: (timeMark, vlan) → port lists; tagged = egress − untagged.
    let untagged: HashMap<u16, Vec<u8>> = r
        .walk(&Q_VLAN_UNTAGGED, MAX_VLANS)?
        .into_iter()
        .filter_map(|(oid, v)| match index_of(&oid, &Q_VLAN_UNTAGGED)? {
            [_, id] => Some((vlan_id(i64::from(*id))?, v.as_bytes()?.to_vec())),
            _ => None,
        })
        .collect();
    let mut tagged: HashMap<u32, Vec<u16>> = HashMap::new();
    for (oid, v) in r.walk(&Q_VLAN_EGRESS, MAX_VLANS)? {
        let Some([_, id]) = index_of(&oid, &Q_VLAN_EGRESS) else {
            continue;
        };
        let (Some(id), Some(egress)) = (vlan_id(i64::from(*id)), v.as_bytes()) else {
            continue;
        };
        vlans.entry(id).or_insert(None);
        let plain: Vec<u32> = untagged
            .get(&id)
            .map(|b| ports_in(b).collect())
            .unwrap_or_default();
        for port in ports_in(egress).filter(|p| !plain.contains(p)) {
            if let Some(index) = if_of(port) {
                let list = tagged.entry(index).or_default();
                if list.len() < MAX_TAGGED {
                    list.push(id);
                }
            }
        }
    }

    let mut ports: Vec<Port> = descr
        .iter()
        .filter(|(index, _)| types.get(index).and_then(Value::as_int) != Some(IF_TYPE_LOOPBACK))
        .filter_map(|(index, d)| {
            Some(Port {
                index: *index,
                name: names.get(index).and_then(text).or_else(|| text(d))?,
                description: alias.get(index).and_then(text),
                up: status.get(index).and_then(Value::as_int) == Some(1),
                speed_mbps: speed
                    .get(index)
                    .and_then(Value::as_int)
                    .and_then(|s| u32::try_from(s).ok())
                    .filter(|s| *s > 0),
                vlan: pvid.get(index).copied(),
                tagged: tagged.remove(index).unwrap_or_default(),
            })
        })
        .collect();
    ports.truncate(MAX_INTERFACES);

    let neighbours = read_lldp(&mut r, &ports, &if_of)?;
    let macs = read_fdb(&mut r, &vlans, &if_of)?;
    let networks = read_networks(&mut r)?;
    let arp = read_arp(&mut r)?;

    Ok(Report {
        name,
        address: None,
        ports,
        vlans: vlans
            .into_iter()
            .take(MAX_VLANS)
            .map(|(id, name)| Vlan { id, name })
            .collect(),
        neighbours,
        macs,
        arp,
        networks,
    })
}

fn private_v4(arcs: &[u32]) -> Option<std::net::Ipv4Addr> {
    let [a, b, c, d] = arcs else { return None };
    let octet = |n: &u32| u8::try_from(*n).ok();
    let ip = std::net::Ipv4Addr::new(octet(a)?, octet(b)?, octet(c)?, octet(d)?);
    crate::features::reachability::is_private(&std::net::IpAddr::V4(ip)).then_some(ip)
}

/// The device's own private IPv4 addresses with their masks (ipAddrTable):
/// the networks it routes. A mask that is not a run of ones is left out.
fn read_networks(r: &mut Reader<'_>) -> Result<Vec<Network>, Failure> {
    let ports: HashMap<Vec<u32>, u32> = r
        .walk(&IP_AD_ENT_IF_INDEX, MAX_NETWORKS)?
        .into_iter()
        .filter_map(|(oid, v)| {
            let index = index_of(&oid, &IP_AD_ENT_IF_INDEX)?.to_vec();
            Some((index, u32::try_from(v.as_int()?).ok()?))
        })
        .collect();
    let mut networks: Vec<Network> = r
        .walk(&IP_AD_ENT_NET_MASK, MAX_NETWORKS)?
        .into_iter()
        .filter_map(|(oid, v)| {
            let index = index_of(&oid, &IP_AD_ENT_NET_MASK)?;
            let ip = private_v4(index)?;
            let Value::Ip(mask) = v else { return None };
            let mask = u32::from_be_bytes(mask);
            let prefix = mask.leading_ones();
            // Contiguous, and a network others share: not a /31, /32 or /0.
            (mask.count_ones() == prefix && (1..=30).contains(&prefix)).then(|| Network {
                cidr: format!("{ip}/{prefix}"),
                port: ports.get(index).copied(),
            })
        })
        .collect();
    networks.sort_by(|a, b| a.cidr.cmp(&b.cidr));
    networks.truncate(MAX_NETWORKS);
    Ok(networks)
}

/// The ARP table: ipNetToPhysicalTable's IPv4 rows, else ipNetToMediaTable.
/// Private addresses only, as the host's own neighbour table is sent; a
/// group or all-zero MAC is no device. Each address once.
fn read_arp(r: &mut Reader<'_>) -> Result<Vec<ArpEntry>, Failure> {
    fn add(seen: &mut BTreeMap<std::net::Ipv4Addr, String>, address: &[u32], v: &Value) {
        let mac = v
            .as_bytes()
            .filter(|b| b.len() == 6 && b[0] & 1 == 0 && b.iter().any(|x| *x != 0));
        if let (Some(ip), Some(mac)) = (private_v4(address), mac.and_then(mac_of)) {
            seen.entry(ip).or_insert(mac);
        }
    }
    let mut seen = BTreeMap::new();
    for (oid, v) in r.walk(&IP_NET_TO_PHYSICAL, MAX_ARP * 2)? {
        // (ifIndex, ipv4(1), length 4, a, b, c, d)
        if let Some([_, 1, 4, address @ ..]) = index_of(&oid, &IP_NET_TO_PHYSICAL) {
            add(&mut seen, address, &v);
        }
    }
    if seen.is_empty() {
        for (oid, v) in r.walk(&IP_NET_TO_MEDIA, MAX_ARP)? {
            if let Some([_, address @ ..]) = index_of(&oid, &IP_NET_TO_MEDIA) {
                add(&mut seen, address, &v);
            }
        }
    }
    Ok(seen
        .into_iter()
        .take(MAX_ARP)
        .map(|(ip, mac)| ArpEntry {
            address: ip.to_string(),
            mac,
        })
        .collect())
}

/// lldpRemTable, its rows keyed (timeMark, localPortNum, index); the local
/// port found by its lldpLocPortId (an interface name), else as a bridge
/// port, else as an ifIndex.
fn read_lldp(
    r: &mut Reader<'_>,
    ports: &[Port],
    if_of: &dyn Fn(u32) -> Option<u32>,
) -> Result<Vec<Neighbour>, Failure> {
    let local_ids: HashMap<u32, String> = by_index(
        &r.walk(&LLDP_LOC_PORT_ID, MAX_INTERFACES)?,
        &LLDP_LOC_PORT_ID,
    )
    .into_iter()
    .filter_map(|(n, v)| Some((n, text(&v)?)))
    .collect();
    let local_port = |n: u32| {
        local_ids
            .get(&n)
            .and_then(|id| ports.iter().find(|p| &p.name == id).map(|p| p.index))
            .or_else(|| if_of(n))
            .or_else(|| ports.iter().any(|p| p.index == n).then_some(n))
    };
    let mut rows: BTreeMap<(u32, u32), HashMap<u32, Value>> = BTreeMap::new();
    for (oid, v) in r.walk(&LLDP_REM, MAX_NEIGHBOURS * 6)? {
        if let Some([column, _time, local, index]) = index_of(&oid, &LLDP_REM) {
            rows.entry((*local, *index)).or_default().insert(*column, v);
        }
    }
    Ok(rows
        .into_iter()
        .filter_map(|((local, _), row)| {
            let get = |c: u32| row.get(&c).cloned().unwrap_or(Value::Missing);
            Some(Neighbour {
                port: local_port(local),
                // Subtype 4: macAddress (chassis); 3: macAddress (port).
                chassis_id: lldp_id(get(4).as_int(), &get(5), 4)?,
                port_id: lldp_id(get(6).as_int(), &get(7), 3)?,
                port_description: text(&get(8)),
                system_name: text(&get(9)),
            })
        })
        .take(MAX_NEIGHBOURS)
        .collect())
}

/// The bridge table: Q-BRIDGE's (fdbId, MAC) → bridge port, else
/// BRIDGE-MIB's MAC → bridge port. A MAC the switch itself owns (port 0)
/// is left out. An fdbId is the VLAN where it names one the switch has.
fn read_fdb(
    r: &mut Reader<'_>,
    vlans: &BTreeMap<u16, Option<String>>,
    if_of: &dyn Fn(u32) -> Option<u32>,
) -> Result<Vec<Learned>, Failure> {
    let mut macs = Vec::new();
    let mut add = |mac: &[u32], port: &Value, vlan: Option<u16>| {
        let bytes: Option<Vec<u8>> = mac.iter().map(|a| u8::try_from(*a).ok()).collect();
        let port = port
            .as_int()
            .and_then(|p| u32::try_from(p).ok())
            .filter(|p| *p > 0);
        if let (Some(mac), Some(port)) = (bytes.as_deref().and_then(mac_of), port.and_then(if_of)) {
            macs.push(Learned { mac, port, vlan });
        }
    };
    let q = r.walk(&Q_TP_FDB_PORT, MAX_MACS)?;
    if q.is_empty() {
        for (oid, v) in r.walk(&TP_FDB_PORT, MAX_MACS)? {
            if let Some(mac @ [_, _, _, _, _, _]) = index_of(&oid, &TP_FDB_PORT) {
                add(mac, &v, None);
            }
        }
    } else {
        for (oid, v) in &q {
            if let Some([fdb, mac @ ..]) = index_of(oid, &Q_TP_FDB_PORT) {
                let vlan = vlan_id(i64::from(*fdb)).filter(|id| vlans.contains_key(id));
                if mac.len() == 6 {
                    add(mac, v, vlan);
                }
            }
        }
    }
    macs.truncate(MAX_MACS);
    Ok(macs)
}

#[cfg(test)]
mod tests {
    use super::super::snmp::tests::{mib, FakeAgent};
    use super::super::snmp::Security;
    use super::*;

    // ── Written from the MIBs, not walked off a switch ──

    fn oid(base: &[u32], index: &[u32]) -> Vec<u32> {
        [base, index].concat()
    }

    fn bytes(s: &str) -> Value {
        Value::Bytes(s.as_bytes().to_vec())
    }

    fn switch() -> Vec<(Vec<u32>, Value)> {
        let mut rows = vec![
            (SYS_NAME.to_vec(), bytes("sw-core")),
            (oid(&IF_TYPE, &[1]), Value::Integer(6)),
            (oid(&IF_TYPE, &[2]), Value::Integer(6)),
            (oid(&IF_TYPE, &[3]), Value::Integer(6)),
            (oid(&IF_TYPE, &[100]), Value::Integer(IF_TYPE_LOOPBACK)),
            (oid(&IF_DESCR, &[1]), bytes("Port 1")),
            (oid(&IF_DESCR, &[2]), bytes("Port 2")),
            (oid(&IF_DESCR, &[3]), bytes("Port 3")),
            (oid(&IF_DESCR, &[100]), bytes("lo")),
            (oid(&IF_NAME, &[1]), bytes("ge-0/0/1")),
            (oid(&IF_NAME, &[2]), bytes("ge-0/0/2")),
            (oid(&IF_OPER_STATUS, &[1]), Value::Integer(1)),
            (oid(&IF_OPER_STATUS, &[2]), Value::Integer(2)),
            (oid(&IF_OPER_STATUS, &[3]), Value::Integer(1)),
            (oid(&IF_HIGH_SPEED, &[1]), Value::Unsigned(1000)),
            (oid(&IF_HIGH_SPEED, &[2]), Value::Unsigned(0)),
            (oid(&IF_ALIAS, &[1]), bytes("uplink to fw")),
            (oid(&IF_ALIAS, &[2]), bytes("")),
            // Bridge ports 1..3 are ifIndex 1..3.
            (oid(&BASE_PORT_IF_INDEX, &[1]), Value::Integer(1)),
            (oid(&BASE_PORT_IF_INDEX, &[2]), Value::Integer(2)),
            (oid(&BASE_PORT_IF_INDEX, &[3]), Value::Integer(3)),
            (oid(&Q_PVID, &[1]), Value::Unsigned(1)),
            (oid(&Q_PVID, &[2]), Value::Unsigned(20)),
            (oid(&Q_PVID, &[3]), Value::Unsigned(1)),
            (oid(&Q_VLAN_STATIC_NAME, &[1]), bytes("default")),
            (oid(&Q_VLAN_STATIC_NAME, &[20]), bytes("IoT")),
            // VLAN 20 leaves on ports 1 (tagged) and 2 (untagged).
            (
                oid(&Q_VLAN_EGRESS, &[0, 1]),
                Value::Bytes(vec![0b1010_0000]),
            ),
            (
                oid(&Q_VLAN_UNTAGGED, &[0, 1]),
                Value::Bytes(vec![0b1010_0000]),
            ),
            (
                oid(&Q_VLAN_EGRESS, &[0, 20]),
                Value::Bytes(vec![0b1100_0000]),
            ),
            (
                oid(&Q_VLAN_UNTAGGED, &[0, 20]),
                Value::Bytes(vec![0b0100_0000]),
            ),
            // Learned: a phone on port 2 in VLAN 20, the firewall on port 1, the switch itself.
            (
                oid(&Q_TP_FDB_PORT, &[20, 0xa4, 0x83, 0xe7, 1, 2, 3]),
                Value::Integer(2),
            ),
            (
                oid(&Q_TP_FDB_PORT, &[1, 0, 0x1b, 0, 0, 0, 1]),
                Value::Integer(1),
            ),
            (
                oid(&Q_TP_FDB_PORT, &[1, 0, 0x1b, 0, 0, 0, 0xff]),
                Value::Integer(0),
            ),
            (oid(&LLDP_LOC_PORT_ID, &[1]), bytes("ge-0/0/1")),
        ];
        // An LLDP neighbour on local port 1: the firewall.
        let rem = |column: u32, v: Value| (oid(&LLDP_REM, &[column, 0, 1, 1]), v);
        rows.push(rem(4, Value::Integer(4)));
        rows.push(rem(5, Value::Bytes(vec![0, 0x1b, 0, 0, 0, 1])));
        rows.push(rem(6, Value::Integer(5)));
        rows.push(rem(7, bytes("igb1")));
        rows.push(rem(8, bytes("LAN")));
        rows.push(rem(9, bytes("fw.lan")));
        rows
    }

    fn read_switch(rows: Vec<(Vec<u32>, Value)>) -> Result<Report, Failure> {
        let entries: Vec<(&[u32], Value)> = rows
            .iter()
            .map(|(o, v)| (o.as_slice(), v.clone()))
            .collect();
        let agent = FakeAgent::v2c(mib(&entries), "public");
        let mut client = Client::new(
            agent,
            &Security::V2c {
                community: "public".into(),
            },
        );
        read(&mut client)
    }

    #[test]
    fn reads_ports_their_vlans_and_state() {
        let report = read_switch(switch()).unwrap();
        assert_eq!(report.name.as_deref(), Some("sw-core"));
        assert_eq!(
            report
                .ports
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["ge-0/0/1", "ge-0/0/2", "Port 3"],
            "ifName where there is one, the loopback left out"
        );
        let uplink = &report.ports[0];
        assert_eq!(uplink.description.as_deref(), Some("uplink to fw"));
        assert_eq!((uplink.up, uplink.speed_mbps), (true, Some(1000)));
        assert_eq!((uplink.vlan, uplink.tagged.clone()), (Some(1), vec![20]));
        let access = &report.ports[1];
        assert_eq!(
            (access.up, access.speed_mbps, access.vlan),
            (false, None, Some(20))
        );
        assert!(access.tagged.is_empty() && access.description.is_none());
        assert_eq!(
            report.vlans,
            vec![
                Vlan {
                    id: 1,
                    name: Some("default".into())
                },
                Vlan {
                    id: 20,
                    name: Some("IoT".into())
                },
            ]
        );
    }

    #[test]
    fn reads_the_bridge_table_and_lldp_neighbours() {
        let report = read_switch(switch()).unwrap();
        assert_eq!(
            report.macs,
            vec![
                Learned {
                    mac: "00:1b:00:00:00:01".into(),
                    port: 1,
                    vlan: Some(1)
                },
                Learned {
                    mac: "a4:83:e7:01:02:03".into(),
                    port: 2,
                    vlan: Some(20)
                },
            ],
            "the switch's own MAC (port 0) is left out"
        );
        assert_eq!(
            report.neighbours,
            vec![Neighbour {
                port: Some(1),
                chassis_id: "00:1b:00:00:00:01".into(),
                port_id: "igb1".into(),
                port_description: Some("LAN".into()),
                system_name: Some("fw.lan".into()),
            }]
        );
    }

    #[test]
    fn falls_back_to_the_plain_bridge_table() {
        let mut rows: Vec<_> = switch()
            .into_iter()
            .filter(|(o, _)| !o.starts_with(&Q_TP_FDB_PORT))
            .collect();
        rows.push((
            oid(&TP_FDB_PORT, &[0xa4, 0x83, 0xe7, 1, 2, 3]),
            Value::Integer(3),
        ));
        let report = read_switch(rows).unwrap();
        assert_eq!(
            report.macs,
            vec![Learned {
                mac: "a4:83:e7:01:02:03".into(),
                port: 3,
                vlan: None
            }]
        );
    }

    #[test]
    fn a_switch_with_nothing_but_its_name_reads() {
        let report = read_switch(vec![(SYS_NAME.to_vec(), bytes("tiny"))]).unwrap();
        assert!(report.ports.is_empty() && report.macs.is_empty() && report.neighbours.is_empty());
    }

    #[test]
    fn writes_the_report_as_the_protocol_reads_it() {
        let json = serde_json::to_value(read_switch(switch()).unwrap()).unwrap();
        assert_eq!(json["ports"][0]["speedMbps"], 1000);
        assert_eq!(json["neighbours"][0]["chassisId"], "00:1b:00:00:00:01");
        assert_eq!(json["neighbours"][0]["systemName"], "fw.lan");
    }

    /// `switch()` as a layer-3 switch: an address in two VLANs and an ARP table.
    fn router() -> Vec<(Vec<u32>, Value)> {
        let mut rows = switch();
        rows.extend([
            (oid(&IP_AD_ENT_IF_INDEX, &[10, 0, 20, 1]), Value::Integer(2)),
            (
                oid(&IP_AD_ENT_NET_MASK, &[10, 0, 20, 1]),
                Value::Ip([255, 255, 255, 0]),
            ),
            (oid(&IP_AD_ENT_IF_INDEX, &[10, 0, 0, 2]), Value::Integer(1)),
            (
                oid(&IP_AD_ENT_NET_MASK, &[10, 0, 0, 2]),
                Value::Ip([255, 255, 255, 0]),
            ),
            // Its loopback, a public address and a mask with a hole: none is a network.
            (
                oid(&IP_AD_ENT_NET_MASK, &[127, 0, 0, 1]),
                Value::Ip([255, 0, 0, 0]),
            ),
            (
                oid(&IP_AD_ENT_NET_MASK, &[203, 0, 113, 2]),
                Value::Ip([255, 255, 255, 248]),
            ),
            (
                oid(&IP_AD_ENT_NET_MASK, &[10, 9, 9, 1]),
                Value::Ip([255, 0, 255, 0]),
            ),
            // ARP: a phone in VLAN 20, the firewall, a public next hop, a multicast MAC.
            (
                oid(&IP_NET_TO_MEDIA, &[2, 10, 0, 20, 57]),
                Value::Bytes(vec![0xa4, 0x83, 0xe7, 1, 2, 3]),
            ),
            (
                oid(&IP_NET_TO_MEDIA, &[1, 10, 0, 0, 1]),
                Value::Bytes(vec![0, 0x1b, 0, 0, 0, 1]),
            ),
            (
                oid(&IP_NET_TO_MEDIA, &[1, 203, 0, 113, 1]),
                Value::Bytes(vec![0, 0x1b, 0, 0, 0, 9]),
            ),
            (
                oid(&IP_NET_TO_MEDIA, &[2, 10, 0, 20, 99]),
                Value::Bytes(vec![1, 0, 0x5e, 0, 0, 1]),
            ),
        ]);
        rows
    }

    #[test]
    fn reads_a_routers_networks_and_arp_table() {
        let report = read_switch(router()).unwrap();
        assert_eq!(
            report.networks,
            [
                Network {
                    cidr: "10.0.0.2/24".into(),
                    port: Some(1)
                },
                Network {
                    cidr: "10.0.20.1/24".into(),
                    port: Some(2)
                },
            ]
        );
        assert_eq!(
            report.arp,
            [
                ArpEntry {
                    address: "10.0.0.1".into(),
                    mac: "00:1b:00:00:00:01".into()
                },
                ArpEntry {
                    address: "10.0.20.57".into(),
                    mac: "a4:83:e7:01:02:03".into()
                },
            ],
            "private addresses and real MACs only"
        );
    }

    #[test]
    fn prefers_the_newer_arp_table_and_reads_only_its_ipv4_rows() {
        let mut rows = router();
        rows.extend([
            (
                oid(&IP_NET_TO_PHYSICAL, &[2, 1, 4, 10, 0, 20, 58]),
                Value::Bytes(vec![0, 0x17, 0x88, 1, 2, 3]),
            ),
            // An IPv6 row: (ifIndex, ipv6(2), length 16, …).
            (
                oid(
                    &IP_NET_TO_PHYSICAL,
                    &[
                        2, 2, 16, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ],
                ),
                Value::Bytes(vec![0, 0x17, 0x88, 1, 2, 4]),
            ),
        ]);
        let report = read_switch(rows).unwrap();
        assert_eq!(
            report.arp,
            [ArpEntry {
                address: "10.0.20.58".into(),
                mac: "00:17:88:01:02:03".into()
            }]
        );
    }

    #[test]
    fn a_plain_switch_reports_neither() {
        let json = serde_json::to_value(read_switch(switch()).unwrap()).unwrap();
        assert!(json.get("arp").is_none() && json.get("networks").is_none());
    }

    #[test]
    fn writes_a_routers_report_as_the_shared_fixture_holds_it() {
        let fixtures: serde_json::Value =
            serde_json::from_str(protocol_fixture!("integration-reports.json")).unwrap();
        let expected = fixtures["valid"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["upload"]["integrations"][0]["switch"]["arp"].is_array())
            .map(|f| f["upload"]["integrations"][0]["switch"].clone())
            .expect("a fixture with an ARP table");
        let mut report = read_switch(router()).unwrap();
        report.address = Some("10.0.0.2".into());
        assert_eq!(serde_json::to_value(report).unwrap(), expected);
    }

    #[test]
    fn writes_the_report_the_shared_fixture_holds() {
        let fixtures: serde_json::Value =
            serde_json::from_str(protocol_fixture!("integration-reports.json")).unwrap();
        let expected = fixtures["valid"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["upload"]["integrations"][0]["kind"] == "snmp")
            .map(|f| f["upload"]["integrations"][0]["switch"].clone())
            .unwrap();
        let mut report = read_switch(switch()).unwrap();
        report.address = Some("10.0.0.2".into());
        assert_eq!(serde_json::to_value(report).unwrap(), expected);
    }
}
