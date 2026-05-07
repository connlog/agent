//! Centralised runtime defaults for the agent.
//!
//! Everything here is `pub(crate)`. If a value should be configurable, expose
//! it via `Config` (CLI/env) instead of growing this file into a config layer.

/// Production platform endpoint. Used as the fallback when the operator has
/// not set `CONNLOG_PLATFORM_URL`.
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
