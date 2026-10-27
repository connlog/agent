//! What became of a remote reboot request, told back to the platform.
//!
//! Before this, a request could end three ways the platform never heard
//! about: the host refused it, the agent could not hand it to the root hook,
//! or the hook ran and the host simply did not reboot. The dashboard then
//! showed "pending" for ever. Now each ends in a report, sent as
//! `X-Reboot-State` (and `X-Reboot-Message`) on heartbeats until one is
//! accepted:
//!
//! | Report | Meaning |
//! | --- | --- |
//! | `completed` | the host came back on a new boot after our attempt |
//! | `failed` | we handed the reboot to the hook and came back on the same boot, or could not hand it over |
//! | `refused-disabled` | remote reboot is off on this host (`CONNLOG_ALLOW_REMOTE_REBOOT` is not true) |
//! | `refused-unit` | the installed systemd unit has no working reboot hook |
//!
//! `completed` and `failed` need memory across the reboot, so the attempt is
//! written to `reboot-attempt` in the state directory (boot id + time) right
//! before the agent exits for it, and read back once on the next start.
//!
//! Best-effort throughout: a report that cannot be written or read costs the
//! platform an answer, never the heartbeat.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const REBOOT_STATE_HEADER: &str = "X-Reboot-State";
pub const REBOOT_MESSAGE_HEADER: &str = "X-Reboot-Message";

const ATTEMPT_FILE: &str = "reboot-attempt";

/// An attempt older than this is not ours to explain any more (the agent was
/// stopped across it, or the clock moved); it is dropped unreported.
const ATTEMPT_MAX_AGE_SECS: u64 = 24 * 60 * 60;

const MESSAGE_MAX_BYTES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootState {
    Completed,
    Failed,
    RefusedDisabled,
    RefusedUnit,
}

impl RebootState {
    /// Every state, for the shared-fixture test that pins the header values.
    #[cfg(test)]
    pub const ALL: [RebootState; 4] = [
        RebootState::Completed,
        RebootState::Failed,
        RebootState::RefusedDisabled,
        RebootState::RefusedUnit,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RebootState::Completed => "completed",
            RebootState::Failed => "failed",
            RebootState::RefusedDisabled => "refused-disabled",
            RebootState::RefusedUnit => "refused-unit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootReport {
    pub state: RebootState,
    pub message: Option<String>,
}

impl RebootReport {
    pub fn new(state: RebootState, message: impl AsRef<str>) -> Self {
        Self {
            state,
            message: sanitize_message(message.as_ref()),
        }
    }
}

/// Printable ASCII only, trimmed, at most 200 bytes; `None` when nothing is
/// left. The platform reads the header the same way
/// (`parseRebootMessageHeader` in `@connlog/agent-protocol`).
pub fn sanitize_message(raw: &str) -> Option<String> {
    let printable: String = raw
        .chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { ' ' })
        .collect();
    let mut message = printable.trim().to_string();
    message.truncate(MESSAGE_MAX_BYTES);
    let message = message.trim_end().to_string();
    (!message.is_empty()).then_some(message)
}

fn attempt_path(state_dir: &Path) -> PathBuf {
    state_dir.join(ATTEMPT_FILE)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Remember that we are about to exit for a reboot. Returns false when the
/// record could not be written (the reboot still goes ahead).
pub fn record_attempt(state_dir: &Path, boot_id: Option<&str>) -> bool {
    let body = format!("{}\n{}\n", boot_id.unwrap_or("-"), now_secs());
    std::fs::write(attempt_path(state_dir), body).is_ok()
}

/// Forget a recorded attempt that never reached systemd.
pub fn clear_attempt(state_dir: &Path) {
    let _ = std::fs::remove_file(attempt_path(state_dir));
}

/// Read and remove the attempt record left by a previous run, and say what
/// became of it. `None` when there was no (usable) record.
pub fn take_attempt_outcome(
    state_dir: &Path,
    boot_id: Option<&str>,
    uptime_secs: Option<u64>,
) -> Option<RebootReport> {
    let path = attempt_path(state_dir);
    let body = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    outcome(&body, boot_id, uptime_secs, now_secs())
}

fn outcome(
    body: &str,
    boot_id: Option<&str>,
    uptime_secs: Option<u64>,
    now: u64,
) -> Option<RebootReport> {
    let mut lines = body.lines();
    let attempted_boot = lines.next()?.trim();
    let attempted_at: u64 = lines.next()?.trim().parse().ok()?;
    let age = now.checked_sub(attempted_at)?;
    if age > ATTEMPT_MAX_AGE_SECS {
        return None;
    }

    // The boot id is exact. Without it on either side, fall back to uptime: a
    // boot that started after the attempt is a reboot.
    let rebooted = match boot_id {
        Some(current) if attempted_boot != "-" => current != attempted_boot,
        _ => uptime_secs? < age,
    };

    Some(if rebooted {
        RebootReport::new(RebootState::Completed, "host rebooted")
    } else {
        RebootReport::new(
            RebootState::Failed,
            format!(
                "host did not reboot: same boot {age}s after the request was handed to systemd; see journalctl -u connlog-agent"
            ),
        )
    })
}

/// Seconds since boot, from `/proc/uptime`.
pub fn system_uptime_secs() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = raw.split_whitespace().next()?.parse().ok()?;
    Some(secs as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_A: &str = "6f1f4b2c-0d3e-4a5b-9c8d-7e6f5a4b3c2d";
    const BOOT_B: &str = "0a1b2c3d-4e5f-4a5b-9c8d-7e6f5a4b3c2d";

    #[test]
    fn a_new_boot_is_a_completed_reboot() {
        let r = outcome(&format!("{BOOT_A}\n1000\n"), Some(BOOT_B), None, 1100).unwrap();
        assert_eq!(r.state, RebootState::Completed);
    }

    #[test]
    fn the_same_boot_is_a_failed_reboot() {
        let r = outcome(&format!("{BOOT_A}\n1000\n"), Some(BOOT_A), Some(9999), 1100).unwrap();
        assert_eq!(r.state, RebootState::Failed);
        assert!(r.message.unwrap().contains("100s"));
    }

    #[test]
    fn without_boot_ids_uptime_decides() {
        // Attempt 100 s ago; up for 30 s → rebooted since.
        let r = outcome("-\n1000\n", Some(BOOT_A), Some(30), 1100).unwrap();
        assert_eq!(r.state, RebootState::Completed);
        let r = outcome(&format!("{BOOT_A}\n1000\n"), None, Some(500), 1100).unwrap();
        assert_eq!(r.state, RebootState::Failed);
        assert_eq!(outcome("-\n1000\n", None, None, 1100), None);
    }

    #[test]
    fn stale_future_and_garbled_records_are_dropped() {
        let day = ATTEMPT_MAX_AGE_SECS;
        assert_eq!(
            outcome(&format!("{BOOT_A}\n1\n"), Some(BOOT_B), None, day + 2),
            None
        );
        assert_eq!(
            outcome(&format!("{BOOT_A}\n2000\n"), Some(BOOT_B), None, 1000),
            None
        );
        assert_eq!(outcome("", Some(BOOT_B), None, 1000), None);
        assert_eq!(
            outcome(&format!("{BOOT_A}\nsoon\n"), Some(BOOT_B), None, 1000),
            None
        );
    }

    #[test]
    fn the_record_is_read_once() {
        let dir = std::env::temp_dir().join(format!("connlog-reboot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(record_attempt(&dir, Some(BOOT_A)));
        let first = take_attempt_outcome(&dir, Some(BOOT_B), None).unwrap();
        assert_eq!(first.state, RebootState::Completed);
        assert_eq!(take_attempt_outcome(&dir, Some(BOOT_B), None), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn messages_are_printable_ascii_and_bounded() {
        assert_eq!(sanitize_message("  "), None);
        assert_eq!(sanitize_message("a\r\nb").as_deref(), Some("a  b"));
        assert_eq!(sanitize_message("é ok").as_deref(), Some("ok"));
        assert_eq!(sanitize_message(&"x".repeat(500)).unwrap().len(), 200);
    }
}
