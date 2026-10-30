//! Proxmox VE (docs/topology/PLAN.md, T10.1): nodes, guests, bridges and
//! VLAN tags, read through its REST API with an API token whose role only
//! reads (`PVEAuditor`). Read-only: the agent only ever sends GET.
//!
//! Built from Proxmox's published API (`/api2/json`): `cluster/status`,
//! `cluster/resources?type=vm`, each node's `network`, each guest's
//! `config`. The responses in the tests are written from that
//! documentation, not taken from a real cluster, and are labelled so.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use super::values::{cidr, flag, iface, ip, lower_mac, name_of};
use super::{https, pinning, Failure};

/// `PROXMOX_MAX_*` and `PROXMOX_NAME_MAX` in the protocol.
pub const MAX_NODES: usize = 64;
pub const MAX_BRIDGES: usize = 512;
pub const MAX_GUESTS: usize = 4000;
pub const MAX_NICS: usize = 16;
/// One read of a whole cluster stops asking for guests' configs after this:
/// the rest are reported without their interfaces, next time with them.
const READ_BUDGET: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    pub name: String,
    pub online: bool,
    pub address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bridge {
    pub node: String,
    pub name: String,
    pub ports: Vec<String>,
    pub vlan_aware: bool,
    pub cidr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Nic {
    pub mac: String,
    pub bridge: Option<String>,
    pub vlan: Option<u16>,
    pub address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Guest {
    pub vmid: u32,
    pub kind: &'static str,
    pub name: String,
    pub node: String,
    pub running: bool,
    pub nics: Vec<Nic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub cluster: Option<String>,
    pub nodes: Vec<Node>,
    pub bridges: Vec<Bridge>,
    pub guests: Vec<Guest>,
}

/// A GET under `/api2/json`, answered with the response's `data`.
pub trait Api {
    fn get(&self, path: &str) -> Result<Value, Failure>;
}

/// `cluster/status`: the cluster's name, and its nodes with their state
/// and address. A node on its own lists only itself.
pub fn parse_status(data: &Value) -> (Option<String>, Vec<Node>) {
    let entries = data.as_array().map(Vec::as_slice).unwrap_or_default();
    let cluster = entries
        .iter()
        .find(|e| e["type"] == "cluster")
        .and_then(|e| name_of(&e["name"]));
    let mut nodes: Vec<Node> = entries
        .iter()
        .filter(|e| e["type"] == "node")
        .filter_map(|e| {
            Some(Node {
                name: name_of(&e["name"])?,
                online: flag(&e["online"]),
                address: ip(&e["ip"]),
            })
        })
        .collect();
    nodes.sort_by(|a, b| a.name.cmp(&b.name));
    nodes.truncate(MAX_NODES);
    (cluster, nodes)
}

/// A node's `network`: its bridges (Linux and Open vSwitch), with the
/// interfaces they bridge and whether they are VLAN aware.
pub fn parse_network(node: &str, data: &Value) -> Vec<Bridge> {
    let entries = data.as_array().map(Vec::as_slice).unwrap_or_default();
    entries
        .iter()
        .filter(|e| e["type"] == "bridge" || e["type"] == "OVSBridge")
        .filter_map(|e| {
            let ports = e["bridge_ports"]
                .as_str()
                .or_else(|| e["ovs_ports"].as_str())
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(iface)
                .take(16)
                .collect();
            Some(Bridge {
                node: node.to_string(),
                name: iface(e["iface"].as_str()?)?,
                ports,
                vlan_aware: flag(&e["bridge_vlan_aware"]),
                cidr: cidr(&e["cidr"]),
            })
        })
        .collect()
}

/// One `netN` value of a guest's config: a VM's
/// `virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20`, a container's
/// `name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=10.0.20.53/24`.
pub fn parse_nic(value: &str) -> Option<Nic> {
    let mut mac = None;
    let mut bridge = None;
    let mut vlan = None;
    let mut address = None;
    for part in value.split(',') {
        let Some((key, val)) = part.split_once('=') else {
            continue;
        };
        match key.trim() {
            "bridge" => bridge = iface(val.trim()),
            "tag" => {
                vlan = val
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|v| (1..=4094).contains(v))
            }
            // A container's static address; `dhcp` and `manual` say nothing.
            "ip" => {
                address = val
                    .split('/')
                    .next()
                    .and_then(|a| a.trim().parse::<IpAddr>().ok())
                    .map(|a| a.to_string())
            }
            // A container's MAC is `hwaddr`; a VM's is the model's value
            // (`virtio=`, `e1000=`), or `macaddr` in older configs.
            _ if mac.is_none() => mac = lower_mac(val),
            _ => {}
        }
    }
    Some(Nic {
        mac: mac?,
        bridge,
        vlan,
        address,
    })
}

/// A guest's `config`: its interfaces, `net0` to `netN`, in order.
pub fn parse_config(data: &Value) -> Vec<Nic> {
    let Some(map) = data.as_object() else {
        return Vec::new();
    };
    let mut keyed: Vec<(u32, Nic)> = map
        .iter()
        .filter_map(|(key, value)| {
            let index = key.strip_prefix("net")?.parse::<u32>().ok()?;
            Some((index, parse_nic(value.as_str()?)?))
        })
        .collect();
    keyed.sort_by_key(|(index, _)| *index);
    keyed
        .into_iter()
        .map(|(_, nic)| nic)
        .take(MAX_NICS)
        .collect()
}

/// `cluster/resources?type=vm`: every VM and container, templates left out.
pub fn parse_resources(data: &Value) -> Vec<Guest> {
    let entries = data.as_array().map(Vec::as_slice).unwrap_or_default();
    let mut guests: Vec<Guest> = entries
        .iter()
        .filter(|e| !flag(&e["template"]))
        .filter_map(|e| {
            let kind = match e["type"].as_str()? {
                "qemu" => "qemu",
                "lxc" => "lxc",
                _ => return None,
            };
            let vmid = u32::try_from(e["vmid"].as_u64()?)
                .ok()
                .filter(|v| *v >= 100)?;
            Some(Guest {
                vmid,
                kind,
                name: name_of(&e["name"]).unwrap_or_else(|| format!("{kind} {vmid}")),
                node: name_of(&e["node"])?,
                running: e["status"] == "running",
                nics: Vec::new(),
            })
        })
        .collect();
    guests.sort_by_key(|g| g.vmid);
    guests.truncate(MAX_GUESTS);
    guests
}

/// The whole cluster, read once. The status and the guest list must read;
/// a node's network or a guest's config that does not is left out.
pub fn read(api: &dyn Api) -> Result<Report, Failure> {
    let started = Instant::now();
    let (cluster, nodes) = parse_status(&api.get("/cluster/status")?);
    let online: Vec<&Node> = nodes.iter().filter(|n| n.online).collect();
    let mut bridges = Vec::new();
    for node in &online {
        if let Ok(data) = api.get(&format!("/nodes/{}/network", node.name)) {
            bridges.extend(parse_network(&node.name, &data));
        }
    }
    bridges.truncate(MAX_BRIDGES);
    let mut guests = parse_resources(&api.get("/cluster/resources?type=vm")?);
    for guest in &mut guests {
        if started.elapsed() > READ_BUDGET {
            break;
        }
        if !online.iter().any(|n| n.name == guest.node) {
            continue;
        }
        let path = format!("/nodes/{}/{}/{}/config", guest.node, guest.kind, guest.vmid);
        if let Ok(data) = api.get(&path) {
            guest.nics = parse_config(&data);
        }
    }
    Ok(Report {
        cluster,
        nodes,
        bridges,
        guests,
    })
}

/// The API over HTTPS, with the token in its header.
pub struct HttpApi {
    base: String,
    auth: https::Auth,
    https: https::Client,
}

impl HttpApi {
    pub fn new(
        url: &str,
        token_id: &str,
        token_secret: &str,
        fingerprint: Option<pinning::Fingerprint>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            base: format!("{}/api2/json", url.trim_end_matches('/')),
            auth: https::Auth::Header(format!("PVEAPIToken={token_id}={token_secret}")),
            https: https::Client::new("proxmox", fingerprint)?,
        })
    }
}

impl Api for HttpApi {
    fn get(&self, path: &str) -> Result<Value, Failure> {
        let body = self
            .https
            .get(&format!("{}{path}", self.base), &self.auth)?;
        Ok(body["data"].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    // ── Written from Proxmox's API documentation, not taken from a cluster ──

    fn status() -> Value {
        json!([
            {"type": "cluster", "name": "lab", "nodes": 2, "quorate": 1, "version": 4},
            {"type": "node", "name": "pve-2", "id": "node/pve-2", "nodeid": 2, "online": 0, "ip": "10.0.20.3", "local": 0},
            {"type": "node", "name": "pve-1", "id": "node/pve-1", "nodeid": 1, "online": 1, "ip": "10.0.20.2", "local": 1}
        ])
    }

    fn network() -> Value {
        json!([
            {"iface": "enp3s0", "type": "eth", "active": 1},
            {"iface": "vmbr0", "type": "bridge", "bridge_ports": "enp3s0", "bridge_vlan_aware": 1, "cidr": "10.0.20.2/24", "address": "10.0.20.2", "active": 1},
            {"iface": "vmbr1", "type": "OVSBridge", "ovs_ports": "bond0 vlan30", "active": 1},
            {"iface": "vmbr0.20", "type": "vlan", "active": 1}
        ])
    }

    fn resources() -> Value {
        json!([
            {"id": "qemu/100", "type": "qemu", "vmid": 100, "name": "web-1", "node": "pve-1", "status": "running"},
            {"id": "lxc/101", "type": "lxc", "vmid": 101, "name": "dns", "node": "pve-1", "status": "running"},
            {"id": "qemu/102", "type": "qemu", "vmid": 102, "name": "old-build", "node": "pve-2", "status": "stopped"},
            {"id": "qemu/9000", "type": "qemu", "vmid": 9000, "name": "debian-template", "node": "pve-1", "status": "stopped", "template": 1}
        ])
    }

    struct Fake(HashMap<String, Result<Value, Failure>>);

    impl Api for Fake {
        fn get(&self, path: &str) -> Result<Value, Failure> {
            self.0.get(path).cloned().unwrap_or(Err(Failure::Status))
        }
    }

    #[test]
    fn reads_the_cluster_its_nodes_by_name_and_their_state() {
        let (cluster, nodes) = parse_status(&status());
        assert_eq!(cluster.as_deref(), Some("lab"));
        assert_eq!(
            nodes,
            vec![
                Node {
                    name: "pve-1".into(),
                    online: true,
                    address: Some("10.0.20.2".into())
                },
                Node {
                    name: "pve-2".into(),
                    online: false,
                    address: Some("10.0.20.3".into())
                },
            ]
        );
        // A node on its own: no cluster entry.
        let (cluster, nodes) = parse_status(&json!([{"type": "node", "name": "pve", "online": 1}]));
        assert_eq!((cluster, nodes.len()), (None, 1));
    }

    #[test]
    fn reads_linux_and_open_vswitch_bridges_and_nothing_else() {
        let bridges = parse_network("pve-1", &network());
        assert_eq!(
            bridges,
            vec![
                Bridge {
                    node: "pve-1".into(),
                    name: "vmbr0".into(),
                    ports: vec!["enp3s0".into()],
                    vlan_aware: true,
                    cidr: Some("10.0.20.2/24".into())
                },
                Bridge {
                    node: "pve-1".into(),
                    name: "vmbr1".into(),
                    ports: vec!["bond0".into(), "vlan30".into()],
                    vlan_aware: false,
                    cidr: None
                },
            ]
        );
    }

    #[test]
    fn reads_a_vm_and_a_container_interface() {
        assert_eq!(
            parse_nic("virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1,tag=20"),
            Some(Nic {
                mac: "bc:24:11:00:00:01".into(),
                bridge: Some("vmbr0".into()),
                vlan: Some(20),
                address: None
            })
        );
        assert_eq!(
            parse_nic(
                "name=eth0,bridge=vmbr0,firewall=1,gw=10.0.20.1,hwaddr=BC:24:11:00:00:02,ip=10.0.20.53/24,type=veth"
            ),
            Some(Nic {
                mac: "bc:24:11:00:00:02".into(),
                bridge: Some("vmbr0".into()),
                vlan: None,
                address: Some("10.0.20.53".into())
            })
        );
        // DHCP says nothing about the address; a tag out of range is none.
        let nic =
            parse_nic("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:03,ip=dhcp,tag=4095").unwrap();
        assert_eq!((nic.address, nic.vlan), (None, None));
        assert_eq!(parse_nic("bridge=vmbr0"), None);
    }

    #[test]
    fn reads_a_guests_interfaces_in_order_and_leaves_out_templates() {
        let nics = parse_config(&json!({
            "name": "web-1",
            "net1": "virtio=BC:24:11:00:00:0B,bridge=vmbr1",
            "net0": "virtio=BC:24:11:00:00:0A,bridge=vmbr0,tag=20",
            "memory": "4096"
        }));
        assert_eq!(
            nics.iter().map(|n| n.mac.as_str()).collect::<Vec<_>>(),
            ["bc:24:11:00:00:0a", "bc:24:11:00:00:0b"]
        );
        let guests = parse_resources(&resources());
        assert_eq!(
            guests.iter().map(|g| g.vmid).collect::<Vec<_>>(),
            [100, 101, 102]
        );
        assert_eq!((guests[1].kind, guests[2].running), ("lxc", false));
    }

    #[test]
    fn reads_the_whole_cluster_asking_offline_nodes_nothing() {
        let mut answers = HashMap::new();
        answers.insert("/cluster/status".to_string(), Ok(status()));
        answers.insert("/nodes/pve-1/network".to_string(), Ok(network()));
        answers.insert("/cluster/resources?type=vm".to_string(), Ok(resources()));
        answers.insert(
            "/nodes/pve-1/qemu/100/config".to_string(),
            Ok(json!({"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20"})),
        );
        // A config that does not read: that guest goes without interfaces.
        answers.insert(
            "/nodes/pve-1/lxc/101/config".to_string(),
            Err(Failure::Forbidden),
        );
        let report = read(&Fake(answers)).unwrap();
        assert_eq!(report.cluster.as_deref(), Some("lab"));
        assert_eq!(report.bridges.len(), 2);
        assert_eq!(report.guests[0].nics[0].vlan, Some(20));
        assert!(report.guests[1].nics.is_empty());
        assert!(report.guests[2].nics.is_empty(), "pve-2 is offline");
    }

    #[test]
    fn says_why_when_the_cluster_does_not_read() {
        let mut answers = HashMap::new();
        answers.insert("/cluster/status".to_string(), Err(Failure::Auth));
        assert_eq!(read(&Fake(answers)), Err(Failure::Auth));
    }

    #[test]
    fn writes_the_report_as_the_protocol_reads_it() {
        let report = Report {
            cluster: None,
            nodes: vec![],
            bridges: vec![Bridge {
                node: "pve".into(),
                name: "vmbr0".into(),
                ports: vec![],
                vlan_aware: true,
                cidr: None,
            }],
            guests: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["bridges"][0]["vlanAware"], true);
    }
}
