//! Unix (Linux) paths and primitives.

/// Where the live binary lives. Owned by root; agent runs as `connlog-agent`.
pub const INSTALLED_BINARY: &str = "/usr/local/bin/connlog-agent";

/// Where a downloaded-but-not-yet-installed binary is staged.
/// systemd `ExecStopPost` looks for this and atomically swaps the live binary.
pub const STAGED_BINARY: &str = "/run/connlog/connlog-agent-new";

/// Ed25519 signature (64 raw bytes) over the SHA-256 of the staged binary,
/// written next to it so the root-side apply step can verify the staged bytes
/// with its own compiled-in key before anything reaches `/usr/local/bin`.
pub const STAGED_SIGNATURE: &str = "/run/connlog/connlog-agent-new.sig";

/// Marker file. When present, ExecStopPost knows to apply the staged binary.
pub const UPDATE_MARKER: &str = "/run/connlog/.update_requested";

/// Where the root-side apply step writes the verified binary before renaming
/// it over the live one. Same filesystem, so the rename is atomic.
pub const INSTALLED_BINARY_NEW: &str = "/usr/local/bin/connlog-agent.new";

/// Hard link to the previous binary, kept until the new one has refreshed the
/// service, so a failed refresh rolls back with one same-filesystem rename.
pub const INSTALLED_BINARY_OLD: &str = "/usr/local/bin/connlog-agent.old";

/// Written by the root-side apply step when a staged update could not be
/// applied. The agent reads it and does not download that version again for a
/// day, instead of fetching the same rejected binary on every heartbeat.
pub const UPDATE_FAILED_NOTE: &str = "/var/lib/connlog/update-failed";

/// The `PATH` every helper process gets. Fixed rather than inherited so a
/// root-run install or update never resolves `systemctl` or `useradd` through
/// a directory the caller's shell happened to put first.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Marker file. When present, ExecStopPost performs full self-uninstall.
pub const UNINSTALL_MARKER: &str = "/run/connlog/.uninstall_requested";

/// Marker file. When present, ExecStopPost runs `systemctl reboot` as root.
pub const REBOOT_MARKER: &str = "/run/connlog/.reboot_requested";

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
pub fn is_admin() -> bool {
    // SAFETY: geteuid() is always safe to call.
    unsafe { libc::geteuid() == 0 }
}
