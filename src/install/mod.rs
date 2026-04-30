//! Cross-platform install / uninstall / status façade.
//!
//! Each platform implements the same three entry points; `main.rs` dispatches
//! through this module without a single `cfg!` of its own.

#[cfg(unix)]
mod linux;
#[cfg(unix)]
pub use linux::{install, status, uninstall, SYSTEMD_SERVICE};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{install, status, uninstall};

/// Stub kept so callers that print the systemd unit on `--emit-service` still
/// compile on Windows; on Windows the flag is a no-op (returns empty string).
#[cfg(windows)]
pub const SYSTEMD_SERVICE: &str = "";
