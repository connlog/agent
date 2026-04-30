//! Unix (Linux) paths and primitives.

/// Where the live binary lives. Owned by root; agent runs as `connlog-agent`.
pub const INSTALLED_BINARY: &str = "/usr/local/bin/connlog-agent";

/// Where a downloaded-but-not-yet-installed binary is staged.
/// systemd `ExecStopPost` looks for this and atomically swaps the live binary.
pub const STAGED_BINARY: &str = "/run/connlog/connlog-agent-new";

/// Marker file. When present, ExecStopPost knows to apply the staged binary.
pub const UPDATE_MARKER: &str = "/run/connlog/.update_requested";

/// Marker file. When present, ExecStopPost performs full self-uninstall.
pub const UNINSTALL_MARKER: &str = "/run/connlog/.uninstall_requested";

/// Config directory, mode 0700, root-only.
#[allow(dead_code)]
pub const CONFIG_DIR: &str = "/etc/connlog";

/// Config file (env-style, sourced by systemd EnvironmentFile), mode 0600.
#[allow(dead_code)]
pub const CONFIG_FILE: &str = "/etc/connlog/agent.conf";

/// Returns true if running with effective UID 0.
#[allow(dead_code)]
pub fn is_admin() -> bool {
    // SAFETY: geteuid() is always safe to call.
    unsafe { libc::geteuid() == 0 }
}
