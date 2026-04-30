//! Platform-gated path constants and OS shims used by the rest of the agent.
//!
//! Anywhere the code has to know "where does the staged update binary go?" or
//! "where does the uninstall marker live?" it asks this module instead of
//! hardcoding a Linux path. That keeps the update / uninstall logic in
//! `update.rs` and `service::*` cross-platform with zero `cfg` gates of its
//! own.

#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::*;
