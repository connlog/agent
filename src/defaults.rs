//! Centralised runtime defaults for the agent.
//!
//! Constants here used to be scattered across `main.rs`, `install/linux.rs`,
//! `install/windows.rs`, and `service/windows.rs`. Each duplicate was a tiny
//! drift hazard — bumping the disabled-state backoff in one place but not the
//! others, or pointing one install path at the wrong platform host.
//!
//! Everything here is `pub(crate)`. If a value should be configurable, expose
//! it via `Config` (CLI/env) instead of growing this file into a config layer.

/// Production platform endpoint. Used as the fallback when the operator has
/// not set `CONNLOG_PLATFORM_URL`. Every install path and the service entry
/// point on Windows resolve their endpoint through this constant.
pub(crate) const DEFAULT_ENDPOINT: &str = "https://connlog.com";

/// Backoff after a `423 Locked` (`AGENT_DISABLED`) heartbeat response.
///
/// Disabled is *reversible* — the agent must keep itself alive but not spam
/// the platform. Five minutes is long enough that a disabled fleet doesn't
/// generate visible load, short enough that re-enabling restores normal
/// operation in roughly one beat.
pub(crate) const DISABLED_BACKOFF_SECS: u64 = 300;

/// Delay between failed `GET /api/agents/config` attempts during startup.
/// Three retries × this delay is the worst-case wait before the agent falls
/// back to `AgentConfig::safe_fallback()` and continues with the heartbeat
/// loop (which will retry the config fetch on the next `config_outdated`).
pub(crate) const CONFIG_FETCH_RETRY_DELAY_SECS: u64 = 5;
