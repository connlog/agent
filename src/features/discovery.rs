//! The host's discovery ceiling (docs/topology/PLAN.md, "Discovery levels"):
//! how much this host may find out about its network, set by its root in
//! `/etc/connlog/agent.conf` and never by the platform. The console chooses a
//! level at or below it per host; the platform cannot raise it.
//!
//! `CONNLOG_DISCOVERY` is the setting. A host whose agent.conf predates it
//! and says `CONNLOG_NETWORK_MAP=true` reads as `peers`, so nothing installed
//! changes level on upgrade. The daemon reports the ceiling in `X-Discovery`
//! on every heartbeat, beside `X-Network-Map` (which released consoles keep
//! reading).
//!
//! `peers` is the network map; `passive` adds what the host already knows
//! about its network (its VLAN ids, `features::vlan`; its neighbour table,
//! `features::neighbours`; its path out, `features::trace`); `active` adds
//! sweeps of its own subnets (`features::sweep`). A host runs at the lower of this ceiling and
//! what the console allows (`Granted`, from each heartbeat answer).

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// `X-Discovery` on every heartbeat the daemon sends.
pub const DISCOVERY_HEADER: &str = "X-Discovery";

/// The agent.conf key, as `install` and `config set-discovery` write it.
pub const CONF_DISCOVERY: &str = "CONNLOG_DISCOVERY";

/// `DISCOVERY_LEVELS` in `packages/agent-protocol/src/network.ts`, lowest
/// first: each level includes the ones before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, clap::ValueEnum)]
pub enum DiscoveryLevel {
    /// Nothing: no inventory, no probes.
    #[default]
    Off,
    /// The network map: the host's addresses, listening ports and gateway,
    /// and probes to other opted-in hosts on its site.
    Peers,
    /// Peers, and what the host already knows about its network: the VLAN
    /// id of each address on a VLAN interface, its private neighbours
    /// (address, MAC, state), and a trace towards its gateway and ConnLog.
    Passive,
    /// Passive, and sweeps of the host's own subnets the console lists
    /// (`features::sweep`, T12.1), within the agent's compiled-in caps.
    Active,
}

impl DiscoveryLevel {
    pub const ALL: [Self; 4] = [Self::Off, Self::Peers, Self::Passive, Self::Active];

    /// The level as the header and agent.conf spell it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Peers => "peers",
            Self::Passive => "passive",
            Self::Active => "active",
        }
    }

    /// A level as written, ignoring case and surrounding space.
    pub fn parse(raw: &str) -> Option<Self> {
        let value = raw.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|level| level.as_str() == value)
    }

    /// What a CONNLOG_NETWORK_MAP flag alone means: `true` is `peers`.
    pub fn from_network_map(flag: Option<bool>) -> Self {
        if flag == Some(true) {
            Self::Peers
        } else {
            Self::Off
        }
    }

    /// Whether the host takes part in the network map at this level.
    pub fn network_map(self) -> bool {
        self >= Self::Peers
    }
}

/// The level the console allows this host, as the latest heartbeat answer
/// said (`discovery`); `peers` until one says, and whenever one does not (an
/// older platform). Shared between the heartbeat loop, which sets it, and the
/// inventory thread, which reads it.
#[derive(Debug, Clone)]
pub struct Granted(Arc<AtomicU8>);

impl Default for Granted {
    fn default() -> Self {
        Self(Arc::new(AtomicU8::new(DiscoveryLevel::Peers as u8)))
    }
}

impl Granted {
    pub fn get(&self) -> DiscoveryLevel {
        let n = self.0.load(Ordering::SeqCst);
        DiscoveryLevel::ALL
            .into_iter()
            .find(|level| *level as u8 == n)
            .unwrap_or(DiscoveryLevel::Peers)
    }

    /// Record what a heartbeat answer allows; whether that changed it.
    pub fn set(&self, level: Option<DiscoveryLevel>) -> bool {
        let level = level.unwrap_or(DiscoveryLevel::Peers) as u8;
        self.0.swap(level, Ordering::SeqCst) != level
    }
}

/// CONNLOG_DISCOVERY as written: unset or empty is no choice, anything that
/// is not a level is an error.
pub fn parse_discovery(raw: Option<&str>) -> Result<Option<DiscoveryLevel>, String> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(value) => DiscoveryLevel::parse(value)
            .map(Some)
            .ok_or_else(|| format!("{value:?} is not one of off, peers, passive, active")),
    }
}

/// The ceiling an agent.conf body sets, as the daemon reads it: a readable
/// CONNLOG_DISCOVERY, else CONNLOG_NETWORK_MAP alone.
pub fn conf_ceiling(conf: &str) -> DiscoveryLevel {
    parse_discovery(crate::install::conf_value(conf, CONF_DISCOVERY).as_deref())
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            DiscoveryLevel::from_network_map(crate::install::conf_bool(
                conf,
                super::network_map::CONF_NETWORK_MAP,
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_ordered_and_spelled_as_the_platform_reads_them() {
        assert!(DiscoveryLevel::Off < DiscoveryLevel::Peers);
        assert!(DiscoveryLevel::Peers < DiscoveryLevel::Passive);
        assert!(DiscoveryLevel::Passive < DiscoveryLevel::Active);
        for level in DiscoveryLevel::ALL {
            assert_eq!(DiscoveryLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(
            DiscoveryLevel::parse(" Peers "),
            Some(DiscoveryLevel::Peers)
        );
        assert_eq!(DiscoveryLevel::parse("enabled"), None);
    }

    #[test]
    fn the_console_allows_peers_until_an_answer_says_otherwise() {
        let granted = Granted::default();
        assert_eq!(granted.get(), DiscoveryLevel::Peers);
        assert!(granted.set(Some(DiscoveryLevel::Passive)));
        assert_eq!(granted.get(), DiscoveryLevel::Passive);
        assert!(!granted.set(Some(DiscoveryLevel::Passive)));
        // An answer without it (an older platform) is peers again.
        assert!(granted.set(None));
        assert_eq!(granted.get(), DiscoveryLevel::Peers);
    }

    #[test]
    fn only_peers_and_above_take_part_in_the_map() {
        assert!(!DiscoveryLevel::Off.network_map());
        assert!(DiscoveryLevel::Peers.network_map());
        assert!(DiscoveryLevel::Active.network_map());
    }

    #[test]
    fn an_unreadable_level_is_an_error_and_an_empty_one_no_choice() {
        assert_eq!(parse_discovery(None), Ok(None));
        assert_eq!(parse_discovery(Some("  ")), Ok(None));
        assert_eq!(
            parse_discovery(Some("passive")),
            Ok(Some(DiscoveryLevel::Passive))
        );
        assert!(parse_discovery(Some("everything")).is_err());
    }

    #[test]
    fn an_existing_network_map_line_reads_as_peers() {
        let cases = [
            ("", DiscoveryLevel::Off),
            ("CONNLOG_NETWORK_MAP=\"true\"\n", DiscoveryLevel::Peers),
            ("CONNLOG_NETWORK_MAP=\"false\"\n", DiscoveryLevel::Off),
            (
                "CONNLOG_NETWORK_MAP=\"true\"\nCONNLOG_DISCOVERY=\"off\"\n",
                DiscoveryLevel::Off,
            ),
            (
                "CONNLOG_NETWORK_MAP=\"false\"\nCONNLOG_DISCOVERY=\"passive\"\n",
                DiscoveryLevel::Passive,
            ),
            // A level that does not read falls back to the map's flag.
            (
                "CONNLOG_NETWORK_MAP=\"true\"\nCONNLOG_DISCOVERY=\"lots\"\n",
                DiscoveryLevel::Peers,
            ),
        ];
        for (conf, want) in cases {
            assert_eq!(conf_ceiling(conf), want, "{conf:?}");
        }
    }
}
