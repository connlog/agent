//! OPNsense (docs/topology/PLAN.md, T10.2): its interfaces and VLANs, its
//! gateways and their state, and its DHCP leases, read through its REST API
//! with an API key whose user only has the pages read here. Read-only: the
//! agent only ever sends GET.
//!
//! Built from OPNsense's own source (`opnsense/core`):
//! `interfaces/overview/interfacesInfo` (`OverviewController::parseIfInfo`),
//! `routes/gateway/status` (`scripts/routes/gateway_status.php`) and the
//! lease searches of Kea, Dnsmasq and the ISC plugin. The responses in the
//! tests are written from that source, not taken from a firewall, and are
//! labelled so.
//!
//! A lease's hostname is a device name: personal data the legal text lets
//! ConnLog keep only while the workspace collects device names, so it is
//! read only while the platform says so (`device_names`) and otherwise
//! never leaves the host.

use serde::Serialize;
use serde_json::Value;

use super::values::{cidr, iface, ip, lower_mac, name_of};
use super::{https, pinning, Failure};

/// `OPNSENSE_MAX_*` in the protocol.
pub const MAX_INTERFACES: usize = 256;
pub const MAX_GATEWAYS: usize = 64;
pub const MAX_LEASES: usize = 4000;
const MAX_ADDRESSES: usize = 16;
const HOSTNAME_MAX: usize = 64;

/// The lease searches tried, each read where it answers: Kea and Dnsmasq
/// are built in, the ISC server is a plugin since 24.7.
const LEASE_PATHS: [&str; 3] = [
    "/api/kea/leases4/search?current=1&rowCount=4000",
    "/api/dnsmasq/leases/search?current=1&rowCount=4000",
    "/api/dhcpv4/leases/searchLease?current=1&rowCount=4000",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interface {
    /// OPNsense's own name for it: `lan`, `wan`, `opt1`.
    pub name: String,
    /// What the customer called it: `LAN`, `IoT`.
    pub description: String,
    /// The device under it: `igb1`, `vlan0.20`.
    pub device: Option<String>,
    pub up: bool,
    /// Its IPv4 addresses with their prefix lengths.
    pub cidrs: Vec<String>,
    pub vlan: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayState {
    Up,
    /// Up, but over its latency or loss thresholds.
    Degraded,
    Down,
    /// Not monitored yet.
    Pending,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gateway {
    pub name: String,
    pub address: Option<String>,
    pub state: GatewayState,
    pub rtt_ms: Option<f64>,
    pub loss_pct: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lease {
    pub address: String,
    pub mac: String,
    /// Only while the workspace collects device names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The interface's description, where the server says.
    pub interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub interfaces: Vec<Interface>,
    pub gateways: Vec<Gateway>,
    /// None when no DHCP server's leases could be read.
    pub leases: Option<Vec<Lease>>,
}

/// A GET under the firewall's URL, answered with the JSON body.
pub trait Api {
    fn get(&self, path: &str) -> Result<Value, Failure>;
}

fn rows(body: &Value) -> &[Value] {
    body["rows"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn vlan_of(value: &Value) -> Option<u16> {
    let tag = value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse().ok())?;
    u16::try_from(tag).ok().filter(|t| (1..=4094).contains(t))
}

/// `interfaces/overview/interfacesInfo`: every assigned interface, with
/// its IPv4 addresses and VLAN tag.
pub fn parse_interfaces(body: &Value) -> Vec<Interface> {
    let mut out: Vec<Interface> = rows(body)
        .iter()
        .filter_map(|row| {
            let name = iface(row["identifier"].as_str()?)?;
            let cidrs = row["ipv4"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .filter_map(|entry| cidr(&entry["ipaddr"]))
                .take(MAX_ADDRESSES)
                .collect();
            Some(Interface {
                description: name_of(&row["description"]).unwrap_or_else(|| name.to_uppercase()),
                device: row["device"].as_str().and_then(iface),
                up: row["status"] == "up",
                cidrs,
                vlan: vlan_of(&row["vlan_tag"]),
                name,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.truncate(MAX_INTERFACES);
    out
}

/// dpinger's `12.3 ms` or `0.0 %`; `~` (not monitored) is none.
fn measure(value: &Value) -> Option<f64> {
    let text = value.as_str()?.trim();
    let number = text.trim_end_matches(|c: char| !c.is_ascii_digit()).trim();
    number
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite() && *n >= 0.0)
}

/// `routes/gateway/status`: each gateway and dpinger's word on it.
pub fn parse_gateways(body: &Value) -> Vec<Gateway> {
    let items = body["items"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut out: Vec<Gateway> = items
        .iter()
        .filter_map(|item| {
            let state = match item["status"].as_str()?.to_ascii_lowercase().as_str() {
                "none" => GatewayState::Up,
                "delay" | "loss" | "delay+loss" => GatewayState::Degraded,
                "down" | "force_down" => GatewayState::Down,
                _ => GatewayState::Pending,
            };
            Some(Gateway {
                name: name_of(&item["name"])?,
                address: ip(&item["address"]),
                state,
                rtt_ms: measure(&item["delay"]),
                loss_pct: measure(&item["loss"]),
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.truncate(MAX_GATEWAYS);
    out
}

/// A hostname as a device gives it, one printable line; none for `*` or empty.
fn hostname_of(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim();
    let ok = !text.is_empty() && text != "*" && !text.chars().any(char::is_control);
    ok.then(|| text.chars().take(HOSTNAME_MAX).collect())
}

/// A lease search's rows: Kea's `hwaddr`, the ISC plugin's `mac`. A lease
/// Kea marks declined or reclaimed (`state` other than 0), or ISC as not
/// active, is left out.
pub fn parse_leases(body: &Value, names: bool) -> Vec<Lease> {
    rows(body)
        .iter()
        .filter(|row| match &row["state"] {
            Value::Null => true,
            Value::Number(n) => n.as_u64() == Some(0),
            Value::String(s) => matches!(s.as_str(), "0" | "active"),
            _ => false,
        })
        .filter_map(|row| {
            let mac = row["hwaddr"]
                .as_str()
                .or_else(|| row["mac"].as_str())
                .and_then(lower_mac)?;
            let address = ip(&row["address"])?;
            Some(Lease {
                address,
                mac,
                hostname: names.then(|| hostname_of(&row["hostname"])).flatten(),
                interface: name_of(&row["if_descr"]),
            })
        })
        .collect()
}

/// The firewall, read once. Its interfaces and gateways must read; the
/// leases are read from whichever DHCP servers answer, and are none when
/// none does. `names`: whether the platform takes device names now.
pub fn read(api: &dyn Api, names: bool) -> Result<Report, Failure> {
    let interfaces = parse_interfaces(&api.get("/api/interfaces/overview/interfacesInfo")?);
    let gateways = parse_gateways(&api.get("/api/routes/gateway/status")?);
    let mut leases: Option<Vec<Lease>> = None;
    for path in LEASE_PATHS {
        if let Ok(body) = api.get(path) {
            let found = leases.get_or_insert_with(Vec::new);
            for lease in parse_leases(&body, names) {
                if !found
                    .iter()
                    .any(|l| l.mac == lease.mac && l.address == lease.address)
                {
                    found.push(lease);
                }
            }
        }
    }
    if let Some(found) = &mut leases {
        found.sort_by(|a, b| a.address.cmp(&b.address).then(a.mac.cmp(&b.mac)));
        found.truncate(MAX_LEASES);
    }
    Ok(Report {
        interfaces,
        gateways,
        leases,
    })
}

/// The API over HTTPS, the key and secret as HTTP basic credentials.
pub struct HttpApi {
    base: String,
    auth: https::Auth,
    https: https::Client,
}

impl HttpApi {
    pub fn new(
        url: &str,
        key: &str,
        secret: &str,
        fingerprint: Option<pinning::Fingerprint>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            base: url.trim_end_matches('/').to_string(),
            auth: https::Auth::Basic {
                user: key.to_string(),
                password: secret.to_string(),
            },
            https: https::Client::new("opnsense", fingerprint)?,
        })
    }
}

impl Api for HttpApi {
    fn get(&self, path: &str) -> Result<Value, Failure> {
        self.https.get(&format!("{}{path}", self.base), &self.auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    // ── Written from OPNsense's source, not taken from a firewall ──

    fn interfaces() -> Value {
        json!({"total": 3, "rowCount": 3, "current": 1, "rows": [
            {"identifier": "wan", "description": "WAN", "device": "igb0", "status": "up", "enabled": true,
             "ipv4": [{"ipaddr": "203.0.113.2/29"}], "vlan_tag": null, "gateways": ["203.0.113.1"]},
            {"identifier": "opt1", "description": "IoT", "device": "vlan0.20", "status": "up", "enabled": true,
             "ipv4": [{"ipaddr": "10.0.20.1/24"}], "vlan_tag": "20"},
            {"identifier": "lan", "description": "", "device": "igb1", "status": "down", "enabled": true,
             "ipv4": [{"ipaddr": "10.0.10.1/24"}, {"ipaddr": "nope"}]}
        ]})
    }

    fn gateways() -> Value {
        json!({"status": "ok", "items": [
            {"name": "WAN_DHCP", "address": "203.0.113.1", "status": "none", "status_translated": "Online",
             "loss": "0.0 %", "delay": "4.2 ms", "stddev": "0.3 ms", "monitor": "203.0.113.1"},
            {"name": "BACKUP_GW", "address": "~", "status": "down", "status_translated": "Offline",
             "loss": "100.0 %", "delay": "~", "stddev": "~", "monitor": "~"},
            {"name": "LTE", "address": "192.0.2.1", "status": "delay+loss", "loss": "12.0 %", "delay": "380.1 ms"}
        ]})
    }

    fn kea() -> Value {
        json!({"total": 3, "rows": [
            {"if_descr": "IoT", "address": "10.0.20.40", "hwaddr": "A4:83:E7:01:02:03", "hostname": "Johns-iPhone", "state": "0"},
            {"if_descr": "IoT", "address": "10.0.20.41", "hwaddr": "a4:83:e7:01:02:04", "hostname": "", "state": 0},
            {"if_descr": "IoT", "address": "10.0.20.42", "hwaddr": "a4:83:e7:01:02:05", "hostname": "old", "state": "2"}
        ]})
    }

    struct Fake(HashMap<&'static str, Result<Value, Failure>>);

    impl Api for Fake {
        fn get(&self, path: &str) -> Result<Value, Failure> {
            let key = path.split('?').next().unwrap_or(path);
            self.0.get(key).cloned().unwrap_or(Err(Failure::Status))
        }
    }

    #[test]
    fn reads_interfaces_their_addresses_and_vlans() {
        let read = parse_interfaces(&interfaces());
        assert_eq!(
            read.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            ["lan", "opt1", "wan"]
        );
        assert_eq!(
            read[0].description, "LAN",
            "an empty description is the name"
        );
        assert_eq!(
            read[0].cidrs,
            ["10.0.10.1/24"],
            "an address that is not one is left out"
        );
        assert!(!read[0].up);
        assert_eq!(
            (read[1].vlan, read[1].device.as_deref()),
            (Some(20), Some("vlan0.20"))
        );
        assert_eq!(read[2].vlan, None);
    }

    #[test]
    fn reads_each_gateways_state_and_measures() {
        let read = parse_gateways(&gateways());
        assert_eq!(
            read.iter()
                .map(|g| (g.name.as_str(), g.state))
                .collect::<Vec<_>>(),
            [
                ("BACKUP_GW", GatewayState::Down),
                ("LTE", GatewayState::Degraded),
                ("WAN_DHCP", GatewayState::Up),
            ]
        );
        assert_eq!(read[0].address, None, "`~` is no address");
        assert_eq!((read[2].rtt_ms, read[2].loss_pct), (Some(4.2), Some(0.0)));
        assert_eq!(read[0].rtt_ms, None);
    }

    #[test]
    fn reads_active_leases_and_their_names_only_when_asked() {
        let named = parse_leases(&kea(), true);
        assert_eq!(named.len(), 2, "a reclaimed lease is left out");
        assert_eq!(named[0].mac, "a4:83:e7:01:02:03");
        assert_eq!(named[0].hostname.as_deref(), Some("Johns-iPhone"));
        assert_eq!(named[1].hostname, None);
        let unnamed = parse_leases(&kea(), false);
        assert!(unnamed.iter().all(|l| l.hostname.is_none()));
        let json = serde_json::to_value(&unnamed[0]).unwrap();
        assert!(json.get("hostname").is_none(), "no name is sent at all");
        // The ISC plugin's rows: `mac`, and a word for the state.
        let isc = json!({"rows": [
            {"address": "10.0.10.9", "mac": "00:11:22:33:44:55", "hostname": "printer", "if_descr": "LAN", "state": "active"},
            {"address": "10.0.10.8", "mac": "00:11:22:33:44:56", "state": "expired"}
        ]});
        assert_eq!(parse_leases(&isc, true).len(), 1);
    }

    #[test]
    fn reads_the_firewall_with_the_leases_of_whichever_server_answers() {
        let mut answers = HashMap::new();
        answers.insert("/api/interfaces/overview/interfacesInfo", Ok(interfaces()));
        answers.insert("/api/routes/gateway/status", Ok(gateways()));
        answers.insert("/api/kea/leases4/search", Ok(kea()));
        answers.insert("/api/dnsmasq/leases/search", Err(Failure::Forbidden));
        let report = read(&Fake(answers.clone()), true).unwrap();
        assert_eq!(report.interfaces.len(), 3);
        assert_eq!(report.leases.as_ref().map(Vec::len), Some(2));

        // No lease search reads: no leases, not an empty list.
        answers.remove("/api/kea/leases4/search");
        assert_eq!(read(&Fake(answers.clone()), true).unwrap().leases, None);

        // The interfaces do not read: the integration did not.
        answers.insert(
            "/api/interfaces/overview/interfacesInfo",
            Err(Failure::Auth),
        );
        assert_eq!(read(&Fake(answers), true), Err(Failure::Auth));
    }

    #[test]
    fn writes_the_report_the_shared_fixture_holds() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../../../packages/agent-protocol/fixtures/integration-reports.json"
        ))
        .unwrap();
        let expected = fixtures["valid"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["upload"]["integrations"][0]["kind"] == "opnsense")
            .map(|f| f["upload"]["integrations"][0]["opnsense"].clone())
            .unwrap();
        let interface = |name: &str, description: &str, device: &str, cidr: &str, vlan| Interface {
            name: name.into(),
            description: description.into(),
            device: Some(device.into()),
            up: true,
            cidrs: vec![cidr.into()],
            vlan,
        };
        let report = Report {
            interfaces: vec![
                interface("lan", "LAN", "igb1", "10.0.10.1/24", None),
                interface("opt1", "IoT", "vlan0.20", "10.0.20.1/24", Some(20)),
                interface("wan", "WAN", "igb0", "203.0.113.2/29", None),
            ],
            gateways: vec![
                Gateway {
                    name: "BACKUP_GW".into(),
                    address: None,
                    state: GatewayState::Down,
                    rtt_ms: None,
                    loss_pct: Some(100.0),
                },
                Gateway {
                    name: "WAN_DHCP".into(),
                    address: Some("203.0.113.1".into()),
                    state: GatewayState::Up,
                    rtt_ms: Some(4.2),
                    loss_pct: Some(0.0),
                },
            ],
            leases: Some(vec![
                Lease {
                    address: "10.0.20.40".into(),
                    mac: "a4:83:e7:01:02:03".into(),
                    hostname: Some("Johns-iPhone".into()),
                    interface: Some("IoT".into()),
                },
                Lease {
                    address: "10.0.20.41".into(),
                    mac: "a4:83:e7:01:02:04".into(),
                    hostname: None,
                    interface: Some("IoT".into()),
                },
            ]),
        };
        assert_eq!(serde_json::to_value(&report).unwrap(), expected);
    }
}
