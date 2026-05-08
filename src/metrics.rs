use anyhow::{anyhow, Context, Result};
use std::panic::{self, AssertUnwindSafe};
use sysinfo::{Disks, System};

pub struct SystemMetrics {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub uptime_seconds: u64,
    pub cpu_percent: f64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_mb: u64,
    pub disk_total_mb: u64,
    pub load_1m: f64,
}

impl SystemMetrics {
    /// Zero-valued sample used when [`MetricsCollector::collect`] fails.
    ///
    /// The heartbeat path falls back to this so the agent still reports
    /// liveness when `sysinfo` panics or returns garbage. Identity fields stay
    /// blank because the caller has the cached real values from
    /// [`MetricsCollector`] — callers that build a heartbeat payload override
    /// hostname/os/arch from the live collector.
    pub fn unavailable() -> Self {
        Self {
            hostname: String::new(),
            os: String::new(),
            arch: String::new(),
            uptime_seconds: 0,
            cpu_percent: 0.0,
            memory_used_mb: 0,
            memory_total_mb: 0,
            disk_used_mb: 0,
            disk_total_mb: 0,
            load_1m: 0.0,
        }
    }
}

// ── /proc/stat CPU counters (Linux only) ─────────────────────────────────────
//
// We read the aggregate `cpu` line directly rather than using sysinfo's
// two-refresh-with-sleep recipe. Storing counters between heartbeats gives a
// true average over the full heartbeat interval (e.g. 10 s or 60 s) instead
// of the 200 ms sysinfo window. On the first heartbeat the delta is computed
// from the reading taken at `MetricsCollector::new()`, so no fake 0 % is
// sent even on the very first beat.

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct CpuSnapshot {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

#[cfg(target_os = "linux")]
impl CpuSnapshot {
    fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    // iowait counts as "idle" from the user's perspective.
    fn idle_total(&self) -> u64 {
        self.idle + self.iowait
    }

    /// CPU usage % relative to a previous snapshot.
    fn percent_since(&self, prev: &CpuSnapshot) -> f64 {
        let delta_total = self.total().saturating_sub(prev.total());
        let delta_idle = self.idle_total().saturating_sub(prev.idle_total());
        if delta_total == 0 {
            return 0.0;
        }
        let busy = delta_total.saturating_sub(delta_idle);
        (busy as f64 / delta_total as f64 * 100.0).clamp(0.0, 100.0)
    }
}

/// Parse the aggregate `cpu` line from `/proc/stat`.
/// Returns `None` on any I/O or parse error so the caller can fall back
/// gracefully.
#[cfg(target_os = "linux")]
fn read_proc_stat_cpu() -> Option<CpuSnapshot> {
    let content = std::fs::read_to_string("/proc/stat").ok()?;
    let line = content.lines().find(|l| l.starts_with("cpu "))?;
    let mut it = line.split_whitespace().skip(1); // skip the "cpu" label
    let mut next = || it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    Some(CpuSnapshot {
        user: next(),
        nice: next(),
        system: next(),
        idle: next(),
        iowait: next(),
        irq: next(),
        softirq: next(),
        steal: next(),
    })
}

// ── MetricsCollector ──────────────────────────────────────────────────────────

/// Reusable collector that avoids re-allocating sysinfo structures.
/// Call `new()` once at startup, then `collect()` on each sample interval.
pub struct MetricsCollector {
    sys: System,
    disks: Disks,
    /// Cached identity values (never change during process lifetime)
    hostname: String,
    os: String,
    arch: String,
    /// Previous `/proc/stat` snapshot used to compute interval-based CPU %.
    /// On Linux this replaces sysinfo's two-refresh-with-sleep recipe.
    #[cfg(target_os = "linux")]
    prev_cpu: Option<CpuSnapshot>,
}

impl MetricsCollector {
    /// Cached identity values (hostname, os, arch). Populated once at
    /// construction and never mutated — safe to read on the fallback path
    /// when [`Self::collect`] fails.
    pub fn identity(&self) -> (&str, &str, &str) {
        (&self.hostname, &self.os, &self.arch)
    }

    /// Create a new collector. On Linux, reads an initial `/proc/stat` CPU
    /// snapshot so the very first `collect()` can already return an
    /// interval-based CPU value. On other platforms performs the sysinfo
    /// two-refresh baseline.
    pub fn new() -> Result<Self> {
        let mut sys = System::new_all();

        #[cfg(not(target_os = "linux"))]
        {
            // Non-Linux: sysinfo's documented two-refresh recipe is the only
            // way to get a non-zero CPU reading.
            sys.refresh_cpu_usage();
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
            sys.refresh_cpu_usage();
        }

        sys.refresh_memory();

        let disks = Disks::new_with_refreshed_list();

        let hostname = hostname::get()
            .context("Failed to get hostname")?
            .to_string_lossy()
            .to_string();

        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        #[cfg(target_os = "linux")]
        let prev_cpu = read_proc_stat_cpu();

        Ok(Self {
            sys,
            disks,
            hostname,
            os,
            arch,
            #[cfg(target_os = "linux")]
            prev_cpu,
        })
    }

    /// Collect current metrics. Only refreshes CPU, memory, and disks — NOT
    /// processes. This is ~10× cheaper than `System::new_all() + refresh_all()`.
    ///
    /// Internally calls [`Self::collect_inner`] inside `catch_unwind`. A panic
    /// from `sysinfo` (e.g. a syscall returning unexpected bytes on a quirky
    /// kernel) MUST NOT crash the daemon — the heartbeat loop is the agent's
    /// only job, and it has to keep beating even when metric collection is
    /// momentarily broken. The caller decides what to send (zeros, last-known,
    /// or skip-this-tick) based on the `Err`.
    pub fn collect(&mut self) -> Result<SystemMetrics> {
        // sysinfo's internal state isn't UnwindSafe, but a panic across the
        // boundary doesn't logically poison anything we care about (CPU/mem
        // refreshes are idempotent; the next tick re-refreshes from scratch).
        // AssertUnwindSafe is the documented escape hatch for this case.
        let result = panic::catch_unwind(AssertUnwindSafe(|| self.collect_inner()));
        match result {
            Ok(metrics) => Ok(metrics),
            Err(payload) => {
                let msg = panic_message(&payload);
                Err(anyhow!("metrics collection panicked: {msg}"))
            }
        }
    }

    fn collect_inner(&mut self) -> SystemMetrics {
        // ── CPU ───────────────────────────────────────────────────────────────
        //
        // Linux: compute CPU average over the full heartbeat interval from the
        // delta between the snapshot taken last cycle (or at `new()`) and a
        // fresh reading now. No sleep needed — the interval IS the heartbeat.
        //
        // Non-Linux: fall back to sysinfo's two-refresh-with-sleep recipe.
        #[cfg(target_os = "linux")]
        let cpu_percent = {
            let curr = read_proc_stat_cpu();
            let pct = match (&self.prev_cpu, &curr) {
                (Some(prev), Some(c)) => c.percent_since(prev),
                _ => 0.0,
            };
            self.prev_cpu = curr;
            pct
        };

        #[cfg(not(target_os = "linux"))]
        let cpu_percent = {
            self.sys.refresh_cpu_usage();
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
            self.sys.refresh_cpu_usage();
            self.sys.global_cpu_usage() as f64
        };

        // Memory + disks don't need the two-step dance.
        self.sys.refresh_memory();
        self.disks.refresh();

        let uptime_seconds = System::uptime();
        let memory_total_mb = self.sys.total_memory() / 1024 / 1024;
        let memory_used_mb = self.sys.used_memory() / 1024 / 1024;

        // Aggregate all "real" disks. Linux mounts the same physical device
        // under many paths (overlayfs, bind mounts, snap loop devices, docker
        // layers, etc.) — naive summing double/triple counts space. We
        // dedupe by device name and skip pseudo / virtual filesystems so the
        // numbers match what `df -h` shows for actual storage.
        let (disk_total_mb, disk_used_mb) = {
            use std::collections::HashSet;
            let mut total = 0u64;
            let mut used = 0u64;
            let mut seen: HashSet<String> = HashSet::new();

            for disk in self.disks.list() {
                let fs = disk.file_system().to_string_lossy().to_lowercase();
                // Skip pseudo / virtual / overlay filesystems that don't
                // represent real storage capacity.
                if matches!(
                    fs.as_str(),
                    "tmpfs"
                        | "devtmpfs"
                        | "overlay"
                        | "overlayfs"
                        | "squashfs"
                        | "proc"
                        | "sysfs"
                        | "cgroup"
                        | "cgroup2"
                        | "debugfs"
                        | "tracefs"
                        | "fusectl"
                        | "ramfs"
                        | "mqueue"
                        | "pstore"
                        | "autofs"
                        | "binfmt_misc"
                        | "configfs"
                        | "hugetlbfs"
                        | "nsfs"
                        | "rpc_pipefs"
                        | "selinuxfs"
                        | "securityfs"
                        | "bpf"
                        | "iso9660"
                        | "efivarfs"
                ) {
                    continue;
                }

                let name = disk.name().to_string_lossy().to_string();
                let mount = disk.mount_point().to_string_lossy().to_string();

                // Skip snap loop mounts on Linux — they're packaged apps, not
                // user storage, and inflate totals dramatically.
                #[cfg(target_os = "linux")]
                if mount.starts_with("/snap/") || mount.starts_with("/var/snap/") {
                    continue;
                }
                // Skip docker/overlay/container scratch dirs that occasionally
                // show up as named devices.
                #[cfg(unix)]
                if mount.starts_with("/var/lib/docker/")
                    || mount.starts_with("/var/lib/containers/")
                    || mount.starts_with("/run/")
                {
                    continue;
                }
                // Dedupe by device name (e.g. /dev/nvme0n1p2). Same physical
                // device mounted at multiple paths = count only once.
                let dedupe_key = if name.is_empty() { mount.clone() } else { name };
                if !seen.insert(dedupe_key) {
                    continue;
                }

                let dt = disk.total_space() / 1024 / 1024;
                let da = disk.available_space() / 1024 / 1024;
                total += dt;
                used += dt.saturating_sub(da);
            }

            if total == 0 {
                // Fallback: first disk only — better than reporting zero.
                if let Some(disk) = self.disks.list().first() {
                    let t = disk.total_space() / 1024 / 1024;
                    let a = disk.available_space() / 1024 / 1024;
                    (t, t.saturating_sub(a))
                } else {
                    (0, 0)
                }
            } else {
                (total, used)
            }
        };

        let load_1m = read_load_1m();

        SystemMetrics {
            hostname: self.hostname.clone(),
            os: self.os.clone(),
            arch: self.arch.clone(),
            uptime_seconds,
            cpu_percent,
            memory_used_mb,
            memory_total_mb,
            disk_used_mb,
            disk_total_mb,
            load_1m,
        }
    }
}

/// Read the 1-minute load average. On Linux we read `/proc/loadavg` directly
/// because the sysinfo wrapper has been observed to silently return 0.0 on
/// some hosts (likely a static-state caching quirk in older `procfs` parses).
/// `/proc/loadavg` is a tiny well-defined file:
///     `0.51 0.42 0.34 1/345 12345`
/// First field is the 1m load. On non-Linux we keep the sysinfo path.
fn read_load_1m() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/loadavg") {
            if let Some(first) = s.split_whitespace().next() {
                if let Ok(v) = first.parse::<f64>() {
                    return v;
                }
            }
        }
    }
    System::load_average().one
}

/// Best-effort extraction of a panic payload's message.
///
/// `catch_unwind` returns the payload as `Box<dyn Any + Send>`. The two common
/// shapes are `&'static str` (from `panic!("literal")`) and `String` (from
/// `panic!("{}", val)`); anything else collapses to `"<non-string panic>"`.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_ok_under_normal_conditions() {
        let mut c = MetricsCollector::new().expect("collector init must work in tests");
        let metrics = c
            .collect()
            .expect("collect must succeed in a healthy test env");
        // Don't pin exact values — just sanity-check shape so a regression in
        // the panic-isolation wrapper that swallowed real data would fail here.
        assert!(!metrics.hostname.is_empty());
        assert!(!metrics.os.is_empty());
        assert!(!metrics.arch.is_empty());
        assert!(
            metrics.memory_total_mb > 0,
            "test host should report memory"
        );
    }

    /// CPU % must be in [0, 100] and must not be NaN or infinite.
    #[test]
    fn collect_cpu_percent_is_valid() {
        let mut c = MetricsCollector::new().expect("collector init must work in tests");
        // Two calls: the second uses the snapshot stored after the first.
        let _ = c.collect().expect("first collect");
        let m = c.collect().expect("second collect");
        assert!(
            m.cpu_percent.is_finite() && m.cpu_percent >= 0.0 && m.cpu_percent <= 100.0,
            "cpu_percent out of range: {}",
            m.cpu_percent,
        );
    }

    /// On Linux the /proc/stat reader must parse the aggregate cpu line and
    /// return non-zero counters on any real host.
    #[cfg(target_os = "linux")]
    #[test]
    fn read_proc_stat_cpu_returns_nonzero_total() {
        let snap = read_proc_stat_cpu().expect("/proc/stat must be readable in the test env");
        assert!(
            snap.total() > 0,
            "cpu total counter must be > 0 on any running system"
        );
    }

    /// Delta calculation: hand-crafted snapshots should produce the correct %.
    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_snapshot_delta_calculation() {
        let prev = CpuSnapshot {
            user: 1000,
            nice: 0,
            system: 200,
            idle: 7800,
            iowait: 100,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        // Advance 1 000 ticks: 300 busy (user+system), 700 idle.
        let curr = CpuSnapshot {
            user: 1200,
            nice: 0,
            system: 300,
            idle: 8400,
            iowait: 200,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        // delta_total = 1 000, delta_idle = 700 (idle 600 + iowait 100)
        let pct = curr.percent_since(&prev);
        assert!((pct - 30.0).abs() < 0.001, "expected 30.0 %, got {pct}");
    }

    /// Identical snapshots (zero delta) must not panic and must return 0.0.
    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_snapshot_zero_delta_returns_zero() {
        let snap = CpuSnapshot {
            user: 5000,
            nice: 0,
            system: 1000,
            idle: 9000,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        assert_eq!(snap.percent_since(&snap.clone()), 0.0);
    }

    #[test]
    fn panic_message_extracts_static_str() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("static panic");
        assert_eq!(panic_message(&payload), "static panic");
    }

    #[test]
    fn panic_message_extracts_owned_string() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(String::from("owned panic"));
        assert_eq!(panic_message(&payload), "owned panic");
    }

    #[test]
    fn panic_message_falls_back_for_unknown_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(42_u32);
        assert_eq!(panic_message(&payload), "<non-string panic>");
    }
}
