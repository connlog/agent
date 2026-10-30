//! Where the FreeBSD package (OPNsense, pfSense; docs/topology/PLAN.md,
//! T13.5d) keeps things. Nothing here installs: `pkg add` and install.sh do,
//! with `packaging/freebsd/` (the rc.d script, the package and its install
//! script). The agent only needs to know the paths, to name them.

/// The settings, the token among them: root:connlog 0640, read by the rc.d
/// script, never run.
pub const CONF: &str = "/usr/local/etc/connlog/agent.conf";

/// The integrations (`connlog-agent integration add`): root:connlog 0640 files
/// in a root:connlog 0750 directory, as `/etc/connlog/integrations.d` on Linux.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub const INTEGRATIONS_DIR: &str = "/usr/local/etc/connlog/integrations.d";

/// The agent's own account, which the package's install script makes.
pub const SERVICE_GROUP: &str = "connlog";

/// The rc.d script the package installs, held to the paths above.
#[cfg(test)]
const RC_SCRIPT: &str = include_str!("../../packaging/freebsd/connlog_agent");
#[cfg(test)]
const POST_INSTALL: &str = include_str!("../../packaging/freebsd/post-install.sh");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_package_and_the_agent_name_the_same_places() {
        assert!(RC_SCRIPT.contains(&format!("connlog_agent_conf:=\"{CONF}\"")));
        assert!(RC_SCRIPT.contains("CONNLOG_PACKAGING=freebsd"));
        assert!(RC_SCRIPT.contains(": ${connlog_agent_user:=\"connlog\"}"));
        assert!(POST_INSTALL.contains(&format!("-m 0750 {INTEGRATIONS_DIR}")));
        assert!(POST_INSTALL.contains(&format!("pw useradd {SERVICE_GROUP}")));
    }

    /// The rc.d script takes `CONNLOG_` lines only and evaluates nothing:
    /// no `.` or `eval` of the settings file.
    #[test]
    fn the_rc_script_reads_the_settings_without_running_them() {
        let commands: Vec<&str> = RC_SCRIPT
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .collect();
        assert!(!commands.iter().any(|l| l.starts_with("eval ")));
        assert!(!commands
            .iter()
            .any(|l| l.starts_with(". ") && l.contains("conf")));
        assert!(RC_SCRIPT.contains("CONNLOG_[A-Z0-9_]*) export \"${key}=${value}\""));
    }
}
