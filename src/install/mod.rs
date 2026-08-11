//! Install / uninstall / status façade.

mod linux;
pub use linux::{
    install, print_service_diagnostics, refresh_service, status, uninstall,
    warn_if_installed_service_stale_once, SYSTEMD_SERVICE, SYSTEMD_SERVICE_PATH,
};
