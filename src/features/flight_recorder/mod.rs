//! The flight recorder: the last day of this host, kept on the host.
//!
//! A heartbeat tells the platform the host is alive now. When heartbeats
//! stop, the platform cannot tell a network outage from a crash from a clean
//! reboot, and it has nothing about the minutes before. The recorder keeps
//! one small record a minute in a fixed-size ring on disk (`ring`), whether
//! or not the platform is reachable, so that history survives the outage, the
//! reboot and the agent restart, and can be read back locally
//! (`diagnostics history`) or sent to the platform afterwards.
//!
//! Same contract as the heartbeat telemetry: best-effort and isolated. A
//! recorder that cannot open or write its file records nothing; it never
//! delays or fails a heartbeat.

pub mod history;
pub mod ring;
pub mod signals;
pub mod upload;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{info, warn};

use crate::features::metrics::MetricsCollector;
use ring::{Kind, Record, Ring};

pub const RING_FILE: &str = "flight.ring";

/// One record a minute: 1440 slots hold a day.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);

pub fn ring_path(state_dir: &Path) -> PathBuf {
    state_dir.join(RING_FILE)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Inner {
    ring: Ring,
    /// The last sample, reused for event records so a stop costs no
    /// collection on the way out.
    last: Option<Record>,
}

/// A handle to the open ring. Cloned into the sampler thread; the daemon
/// keeps one to record its own exits. Every write goes through one lock, so
/// the sequence stays whole whichever thread writes.
#[derive(Clone)]
pub struct Recorder {
    inner: Arc<Mutex<Inner>>,
    boot_tag: u32,
}

impl Recorder {
    /// Open (or create) the ring in the state directory. `None` when it
    /// cannot be opened: the agent then runs without a recorder.
    pub fn open(state_dir: &Path, boot_id: Option<&str>) -> Option<Recorder> {
        let path = ring_path(state_dir);
        match Ring::open(&path, ring::DEFAULT_SLOTS, now_secs()) {
            Ok(ring) => Some(Recorder {
                inner: Arc::new(Mutex::new(Inner { ring, last: None })),
                boot_tag: signals::boot_tag(boot_id),
            }),
            Err(e) => {
                warn!(
                    "Flight recorder disabled: cannot open {}: {e}",
                    path.display()
                );
                None
            }
        }
    }

    fn write(&self, record: Record) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(e) = inner.ring.append(&record) {
            warn!("Flight recorder write failed: {e}");
        }
        if record.kind == Kind::Sample || inner.last.is_none() {
            inner.last = Some(record);
        }
    }

    /// Record a fresh sample (`kind` Sample or Start).
    pub fn record_sample(&self, kind: Kind, frame: [u8; 32], heartbeat_failing: bool) {
        let s = signals::read();
        self.write(Record {
            time: now_secs(),
            frame,
            boot_tag: self.boot_tag,
            oom_kills: s.oom_kills,
            psi_cpu_some_x100: s.psi_cpu_some_x100,
            psi_memory_full_x100: s.psi_memory_full_x100,
            psi_io_full_x100: s.psi_io_full_x100,
            kind,
            flags: if heartbeat_failing {
                ring::FLAG_HEARTBEAT_FAILING
            } else {
                0
            },
        });
    }

    /// Record a clean stop, with the last sample's readings. `flags` says why
    /// (`FLAG_EXIT_UPDATE`, `FLAG_EXIT_REBOOT`, or none for a service stop).
    pub fn record_stop(&self, flags: u8) {
        let last = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last;
        let s = signals::read();
        self.write(Record {
            time: now_secs(),
            frame: last.map(|r| r.frame).unwrap_or([0u8; 32]),
            boot_tag: self.boot_tag,
            oom_kills: s.oom_kills,
            psi_cpu_some_x100: s.psi_cpu_some_x100,
            psi_memory_full_x100: s.psi_memory_full_x100,
            psi_io_full_x100: s.psi_io_full_x100,
            kind: Kind::Stop,
            flags,
        });
    }
}

/// The v1 frame for a sample: the heartbeat's own encoding, every metric
/// included (the history is local; what leaves the host is decided when it
/// is sent).
fn frame_of(collector: &mut MetricsCollector) -> [u8; 32] {
    let m = collector
        .collect()
        .unwrap_or_else(|_| crate::features::metrics::SystemMetrics::unavailable());
    crate::http::encode_heartbeat(&crate::heartbeat::HeartbeatPayload {
        agent_version: String::new(),
        protocol_version: 1,
        config_version: 0,
        hostname: None,
        os: String::new(),
        arch: String::new(),
        uptime_seconds: m.uptime_seconds,
        metrics: crate::heartbeat::Metrics {
            cpu_percent: m.cpu_percent,
            cpu_peak_percent: m.cpu_peak_percent,
            cpu_core_count: m.cpu_core_count,
            memory_used_mb: m.memory_used_mb,
            memory_total_mb: m.memory_total_mb,
            disk_used_mb: m.disk_used_mb,
            disk_total_mb: m.disk_total_mb,
            load_1m: m.load_1m,
        },
        dev_mode: None,
    })
}

/// Start the sampler: a `start` record now, then a sample every minute until
/// `stop`, on its own thread and its own metrics collector, so it keeps
/// recording while the heartbeat loop is backing off through an outage.
/// `heartbeat_failing` is set by the daemon after each heartbeat.
pub fn spawn_sampler(
    recorder: Recorder,
    stop: Arc<AtomicBool>,
    heartbeat_failing: Arc<AtomicBool>,
) -> Option<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("flight-recorder".into())
        .spawn(move || {
            let mut collector = match MetricsCollector::new() {
                Ok(c) => c,
                Err(e) => {
                    warn!("Flight recorder disabled: metrics collector failed: {e}");
                    return;
                }
            };
            recorder.record_sample(Kind::Start, frame_of(&mut collector), false);
            info!("✓ Flight recorder writing one record a minute");

            let mut next = Instant::now() + SAMPLE_INTERVAL;
            while !stop.load(Ordering::SeqCst) {
                if Instant::now() < next {
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
                next += SAMPLE_INTERVAL;
                recorder.record_sample(
                    Kind::Sample,
                    frame_of(&mut collector),
                    heartbeat_failing.load(Ordering::SeqCst),
                );
            }
        })
        .map_err(|e| warn!("Flight recorder thread failed to start: {e}"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_a_start_then_records_a_stop_with_the_last_readings() {
        let dir = std::env::temp_dir().join(format!("connlog-recorder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let recorder = Recorder::open(&dir, Some("6f1f4b2c-0d3e-4a5b-9c8d-7e6f5a4b3c2d")).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let failing = Arc::new(AtomicBool::new(false));

        let handle = spawn_sampler(recorder.clone(), Arc::clone(&stop), failing).unwrap();
        // The start record is written before the first sleep.
        let deadline = Instant::now() + Duration::from_secs(10);
        while ring::read(&ring_path(&dir)).is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        recorder.record_stop(ring::FLAG_EXIT_UPDATE);

        let records = ring::read(&ring_path(&dir));
        let kinds: Vec<Kind> = records.iter().map(|s| s.record.kind).collect();
        assert_eq!(kinds, [Kind::Start, Kind::Stop]);
        assert_eq!(records[0].record.boot_tag, 0x6f1f_4b2c);
        assert_eq!(
            records[1].record.frame, records[0].record.frame,
            "a stop carries the last sample's readings"
        );
        assert_eq!(records[1].record.flags, ring::FLAG_EXIT_UPDATE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unwritable_directory_means_no_recorder_not_an_error() {
        assert!(Recorder::open(Path::new("/proc/definitely/not/here"), None).is_none());
    }
}
