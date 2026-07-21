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
pub mod heartbeat_telemetry;
pub mod metrics;
pub mod quick_actions;
