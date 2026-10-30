//! Install / uninstall / status façade.

pub mod freebsd;
mod linux;
pub use linux::{
    conf_allows_remote_reboot, conf_bool, conf_value, install, print_service_diagnostics,
    read_agent_conf, refresh_service, set_checks, set_collector, set_hostname_sharing,
    set_network_map, set_postmortem_sharing, set_remote_reboot, status, uninstall,
    warn_if_installed_service_stale_once, write_integration_file, SYSTEMD_SERVICE,
    SYSTEMD_SERVICE_PATH,
};
