//! Optional, bolt-on agent capabilities layered on top of the core
//! heartbeat/transport plumbing at the crate root (`config`, `defaults`,
//! `identity`, `http`, `heartbeat`, `endpoint_assignment`).
//!
//! Nothing here is required for the agent to heartbeat, and each module
//! degrades independently without taking the heartbeat loop down with it —
//! see each module's own doc comment for its specific isolation guarantee
//! (e.g. metrics collection is panic-isolated, telemetry recording is
//! best-effort, the BMC poller runs on its own thread).

pub mod action_cli;
pub mod bmc;
pub mod checks;
pub mod connections;
pub mod discovery;
pub mod flight_recorder;
pub mod heartbeat_telemetry;
pub mod integrations;
pub mod menu;
pub mod metrics;
pub mod neighbours;
pub mod netlink;
pub mod network_inventory;
pub mod network_map;
pub mod postmortem;
pub mod quick_actions;
pub mod reachability;
pub mod remote_reboot;
pub mod routing;
pub mod settings;
pub mod sweep;
pub mod trace;
pub mod vlan;
