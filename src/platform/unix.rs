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

/// Config directory, mode 0750 root:connlog-agent.
/// The token file stays 0600 root-only; actions.toml is group-readable so the
/// unprivileged service can publish local action metadata.
#[allow(dead_code)]
pub const CONFIG_DIR: &str = "/etc/connlog";

/// Persistent state directory, mode 0700 connlog-agent:connlog-agent.
///
/// Created and owned by systemd via `StateDirectory=connlog` (see
/// `install/linux.rs`), so it survives reboots, service restarts, and the
/// self-update binary swap — unlike `/run/connlog` (tmpfs, wiped on reboot).
/// Holds the bounded heartbeat delivery telemetry consumed by
/// `connlog-agent diagnostics heartbeats`. The service account writes it; the
/// same account runs ConnLog actions, so the diagnostics command can read it
/// back without root. systemd exports the resolved path as `$STATE_DIRECTORY`.
pub const STATE_DIR: &str = "/var/lib/connlog";

/// Config file (env-style, sourced by systemd EnvironmentFile), mode 0600.
#[allow(dead_code)]
pub const CONFIG_FILE: &str = "/etc/connlog/agent.conf";

/// Returns true if running with effective UID 0.
#[allow(dead_code)]
pub fn is_admin() -> bool {
    // SAFETY: geteuid() is always safe to call.
    unsafe { libc::geteuid() == 0 }
}
