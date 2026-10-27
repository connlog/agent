//! Last words: the previous boot's final warnings, after it ended badly.
//!
//! Opt-in (`CONNLOG_SHARE_POSTMORTEM=true`, off by default): logs can hold
//! anything, and they leave the host. When on, the systemd unit runs
//! `connlog-agent collect-postmortem` as root before each start
//! (`ExecStartPre=-+`, so a failure never stops the agent from starting). It
//! does something only when the flight recorder says the previous boot ended
//! without a clean stop; then it takes the last warnings of that boot's
//! journal and kernel log, redacts what looks like a secret, keeps the last
//! 8 KB, and leaves them in the state directory for the agent to send with
//! the outage's history.
//!
//! This runs as root over a directory the service account owns, so it trusts
//! nothing there: the ring is read only when it has exactly the ring's size
//! and is not a link, and the result is written through a directory handle
//! to a fresh file (`O_EXCL | O_NOFOLLOW`) that is then renamed into place,
//! so a planted link is replaced, never followed.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::features::flight_recorder::ring::{self, Kind, Stored, UNKNOWN_U32};

pub const POSTMORTEM_FILE: &str = "postmortem.txt";
pub const MAX_BYTES: usize = 8 * 1024;
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(5);

/// The boot tag of the previous boot, when it ended without a clean stop.
///
/// Runs before the agent's own start record, so the ring's last record is
/// the previous run's: another boot and not a stop means the host went down.
pub fn previous_boot_ended_unclean(records: &[Stored], current_tag: u32) -> Option<u32> {
    let last = records.last()?.record;
    let other_boot =
        last.boot_tag != UNKNOWN_U32 && current_tag != UNKNOWN_U32 && last.boot_tag != current_tag;
    (other_boot && last.kind != Kind::Stop).then_some(last.boot_tag)
}

/// Mask what looks like a secret, keep printable text, and keep the last
/// `MAX_BYTES` (the end of a boot is what explains it).
pub fn redact(text: &str) -> String {
    const KEYS: [&str; 7] = [
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "apikey=",
        "api_key=",
        "authorization:",
    ];
    let mut out = String::with_capacity(text.len().min(MAX_BYTES * 2));
    for line in text.lines() {
        let printable: String = line
            .chars()
            .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
            .collect();
        let mut words: Vec<String> = Vec::new();
        let mut mask_next = false;
        for word in printable.split(' ') {
            let lower = word.to_ascii_lowercase();
            // `bearer` first: in "Authorization: Bearer x" the secret is x.
            let masked = if lower == "bearer" {
                mask_next = true;
                word.to_string()
            } else if mask_next {
                mask_next = false;
                "[redacted]".to_string()
            } else if let Some(key) = KEYS.iter().find(|k| lower.contains(*k)) {
                let at = lower.find(key).unwrap_or(0) + key.len();
                if at >= word.len() {
                    mask_next = true;
                    word.to_string()
                } else {
                    format!("{}[redacted]", &word[..at])
                }
            } else if let Some(at) = lower.find("agent_") {
                let tail = &lower[at + 6..];
                if tail.len() >= 64 && tail[..64].bytes().all(|b| b.is_ascii_hexdigit()) {
                    format!("{}agent_[redacted]{}", &word[..at], &word[at + 70..])
                } else {
                    word.to_string()
                }
            } else {
                word.to_string()
            };
            words.push(masked);
        }
        out.push_str(&words.join(" "));
        out.push('\n');
    }
    if out.len() > MAX_BYTES {
        let cut = out.len() - MAX_BYTES;
        let start = out[cut..].find('\n').map(|i| cut + i + 1).unwrap_or(cut);
        out = format!("[earlier lines cut]\n{}", &out[start..]);
    }
    out
}

/// Run `journalctl` with a deadline; stdout up to 64 KB, or nothing.
fn journal(args: &[&str]) -> String {
    let Ok(mut child) = Command::new("journalctl")
        .args(args)
        .env_clear()
        .env("PATH", crate::platform::SAFE_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return String::new();
    };
    let deadline = Instant::now() + JOURNAL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return String::new();
            }
        }
    }
    let mut out = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(64 * 1024).read_to_end(&mut out);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Write `body` as `dir/name`, owned like `dir`, without following any link
/// the directory's owner may have planted.
pub fn write_owned_like_dir(dir: &Path, name: &str, body: &[u8]) -> io::Result<()> {
    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    let meta = dir_file.metadata()?;
    let dirfd = dir_file.as_raw_fd();

    let tmp = std::ffi::CString::new(format!(".{name}.{}", std::process::id()))?;
    let target = std::ffi::CString::new(Path::new(name).as_os_str().as_bytes())?;

    // SAFETY: dirfd is open for the duration; the path is a valid C string.
    let fd = unsafe {
        libc::openat(
            dirfd,
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by openat and is owned here alone.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let written = file
        .write_all(body)
        .and_then(|()| std::os::unix::fs::fchown(&file, Some(meta.uid()), Some(meta.gid())))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        // SAFETY: as above.
        unsafe { libc::unlinkat(dirfd, tmp.as_ptr(), 0) };
        return Err(e);
    }
    // SAFETY: both names are relative to the same open directory.
    if unsafe { libc::renameat(dirfd, tmp.as_ptr(), dirfd, target.as_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        // SAFETY: as above.
        unsafe { libc::unlinkat(dirfd, tmp.as_ptr(), 0) };
        return Err(e);
    }
    Ok(())
}

/// The ring, read only if it is a plain file of exactly the ring's size.
fn read_ring_carefully(path: &Path) -> Vec<Stored> {
    let expected = (ring::HEADER_BYTES + ring::DEFAULT_SLOTS as usize * ring::SLOT_BYTES) as u64;
    let Ok(mut file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    else {
        return Vec::new();
    };
    match file.metadata() {
        Ok(m) if m.is_file() && m.len() == expected => {}
        _ => return Vec::new(),
    }
    let mut bytes = Vec::with_capacity(expected as usize);
    if (&mut file).take(expected).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    ring::decode_ring(&bytes)
}

/// `connlog-agent collect-postmortem` (root, from `ExecStartPre=-+`).
pub fn run_collect(enabled: bool) -> anyhow::Result<()> {
    if !enabled {
        return Ok(());
    }
    if !crate::platform::is_admin() {
        anyhow::bail!("collect-postmortem runs as root, from the systemd unit");
    }
    let dir = crate::features::heartbeat_telemetry::default_state_dir();
    let records = read_ring_carefully(&crate::features::flight_recorder::ring_path(&dir));
    let current =
        crate::features::flight_recorder::signals::boot_tag(crate::identity::boot_id().as_deref());
    let Some(previous) = previous_boot_ended_unclean(&records, current) else {
        return Ok(());
    };

    let mut text = journal(&[
        "-b",
        "-1",
        "-p",
        "warning",
        "-n",
        "60",
        "-o",
        "short-iso",
        "--no-pager",
    ]);
    let kernel = journal(&[
        "-b",
        "-1",
        "-k",
        "-p",
        "err",
        "-n",
        "30",
        "-o",
        "short-iso",
        "--no-pager",
    ]);
    if !kernel.trim().is_empty() {
        text.push_str("\n-- kernel --\n");
        text.push_str(&kernel);
    }
    if text.trim().is_empty() {
        // No persistent journal for the previous boot: nothing to say.
        return Ok(());
    }
    let body = format!("boot:{previous:08x}\n{}", redact(&text));
    write_owned_like_dir(&dir, POSTMORTEM_FILE, body.as_bytes())?;
    println!("ConnLog: saved the previous boot's last warnings for the outage report");
    Ok(())
}

/// The collected text and the boot it is about, if there is one to send.
pub fn read_pending(dir: &Path) -> Option<(u32, String)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(POSTMORTEM_FILE))
        .ok()?;
    let mut text = String::new();
    (&mut file)
        .take(MAX_BYTES as u64 + 64)
        .read_to_string(&mut text)
        .ok()?;
    let (first, rest) = text.split_once('\n')?;
    let tag = u32::from_str_radix(first.strip_prefix("boot:")?, 16).ok()?;
    Some((tag, rest.to_string()))
}

pub fn clear_pending(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(POSTMORTEM_FILE));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::flight_recorder::ring::Record;

    fn rec(kind: Kind, boot_tag: u32) -> Stored {
        Stored {
            seq: 1,
            record: Record {
                time: 1,
                frame: [0; 32],
                boot_tag,
                oom_kills: 0,
                psi_cpu_some_x100: 0,
                psi_memory_full_x100: 0,
                psi_io_full_x100: 0,
                kind,
                flags: 0,
            },
        }
    }

    #[test]
    fn only_a_previous_boot_that_ended_without_a_stop_counts() {
        assert_eq!(
            previous_boot_ended_unclean(&[rec(Kind::Sample, 1)], 2),
            Some(1)
        );
        assert_eq!(previous_boot_ended_unclean(&[rec(Kind::Stop, 1)], 2), None);
        assert_eq!(
            previous_boot_ended_unclean(&[rec(Kind::Sample, 2)], 2),
            None
        );
        assert_eq!(
            previous_boot_ended_unclean(&[rec(Kind::Sample, UNKNOWN_U32)], 2),
            None
        );
        assert_eq!(previous_boot_ended_unclean(&[], 2), None);
    }

    #[test]
    fn secrets_are_masked() {
        let token = format!("agent_{}", "a".repeat(64));
        let text = format!(
            "curl -H Authorization: Bearer abc.def {token} password=hunter2 x\nDB_PASSWORD=s3cret ok\n"
        );
        let out = redact(&text);
        assert!(!out.contains("abc.def"), "{out}");
        assert!(!out.contains(&token), "{out}");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(!out.contains("s3cret"), "{out}");
        assert!(out.contains("password=[redacted]"), "{out}");
        assert!(out.contains("ok"));
    }

    #[test]
    fn keeps_printable_text_and_the_last_eight_kilobytes() {
        assert_eq!(redact("a\u{1b}[31mred\u{0}\n"), "a?[31mred?\n");
        let long: String = (0..2000).map(|i| format!("line {i}\n")).collect();
        let out = redact(&long);
        assert!(out.len() <= MAX_BYTES + 32);
        assert!(out.starts_with("[earlier lines cut]\n"));
        assert!(out.ends_with("line 1999\n"));
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("connlog-pm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_the_file_and_reads_it_back() {
        let dir = temp_dir("rw");
        write_owned_like_dir(
            &dir,
            POSTMORTEM_FILE,
            b"boot:1f2e3d4c\nkernel: Out of memory\n",
        )
        .unwrap();
        let mode = std::fs::metadata(dir.join(POSTMORTEM_FILE)).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            read_pending(&dir),
            Some((0x1f2e_3d4c, "kernel: Out of memory\n".to_string()))
        );
        clear_pending(&dir);
        assert_eq!(read_pending(&dir), None);
    }

    #[test]
    fn a_planted_link_is_replaced_never_followed() {
        let dir = temp_dir("link");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep me").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(POSTMORTEM_FILE)).unwrap();

        write_owned_like_dir(&dir, POSTMORTEM_FILE, b"boot:1\nx\n").unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
        assert!(!std::fs::symlink_metadata(dir.join(POSTMORTEM_FILE))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_ring_of_the_wrong_size_or_a_link_is_not_read() {
        let dir = temp_dir("ring");
        std::fs::write(dir.join("big"), vec![0u8; 10]).unwrap();
        assert!(read_ring_carefully(&dir.join("big")).is_empty());
        std::os::unix::fs::symlink("/dev/zero", dir.join("zero")).unwrap();
        assert!(read_ring_carefully(&dir.join("zero")).is_empty());
    }
}
