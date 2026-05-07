//! Install / uninstall / status façade.

mod linux;
pub use linux::{install, status, uninstall, SYSTEMD_SERVICE};
