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

/// Reusable collector that avoids re-allocating sysinfo structures.
/// Call `new()` once at startup, then `collect()` on each sample interval.
pub struct MetricsCollector {
    sys: System,
    disks: Disks,
    /// Cached identity values (never change during process lifetime)
    hostname: String,
    os: String,
    arch: String,
}

impl MetricsCollector {
    /// Cached identity values (hostname, os, arch). Populated once at
    /// construction and never mutated — safe to read on the fallback path
    /// when [`Self::collect`] fails.
    pub fn identity(&self) -> (&str, &str, &str) {
        (&self.hostname, &self.os, &self.arch)
    }

    /// Create a new collector. Performs a full initial refresh to populate CPU baseline.
    pub fn new() -> Result<Self> {
        // IMPORTANT: `System::new()` creates an EMPTY system with no CPUs
        // enumerated. `refresh_cpu_usage()` only refreshes CPUs that are
        // already in the list — so on a fresh `System::new()` it's a no-op
        // and `global_cpu_usage()` returns 0.0 forever. `new_all()` does the
        // initial enumeration of CPUs (and processes/memory). After that we
        // can use the cheap `refresh_cpu_usage()` per tick.
        let mut sys = System::new_all();
        // Initial CPU sample — sysinfo needs two refreshes with a small gap
        // to compute usage delta. The first heartbeat would otherwise read
        // 0 % even on a busy host.
        sys.refresh_cpu_usage();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        let disks = Disks::new_with_refreshed_list();

        let hostname = hostname::get()
            .context("Failed to get hostname")?
            .to_string_lossy()
            .to_string();

        // `std::env::consts::OS` returns the lowercase target OS string
        // ("linux" / "windows" / "macos" / ...) at compile time — exactly the
        // values the platform expects in the `X-OS` heartbeat header.
        let os = std::env::consts::OS.to_string();

        let arch = std::env::consts::ARCH.to_string();

        Ok(Self {
            sys,
            disks,
            hostname,
            os,
            arch,
        })
    }

    /// Collect current metrics. Only refreshes CPU, memory, and disks - NOT processes.
    /// This is ~10× cheaper than `System::new_all() + refresh_all()`.
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
        // CPU usage in sysinfo is computed from the delta between two
        // consecutive refreshes. The documented recipe is:
        //   refresh_cpu_usage() → sleep(MINIMUM_CPU_UPDATE_INTERVAL) → refresh_cpu_usage()
        // and only THEN read `global_cpu_usage()`. Skipping the inner sleep
        // (or relying on the previous sample being from 60s ago) reliably
        // reports 0% on Linux containers and CI runners — exactly what we
        // were seeing on the dashboard. The 200 ms penalty is paid once per
        // heartbeat and is invisible compared with the 60 s tick.
        self.sys.refresh_cpu_usage();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        self.sys.refresh_cpu_usage();

        // Memory + disks don't need the two-step dance.
        self.sys.refresh_memory();
        self.disks.refresh();

        let uptime_seconds = System::uptime();
        let cpu_percent = self.sys.global_cpu_usage() as f64;
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
                // Skip Windows network (UNC) shares — those are remote
                // storage, not local capacity. Local fixed drives mount as
                // letters (e.g. `C:\`).
                #[cfg(windows)]
                if mount.starts_with(r"\\") {
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

    /// Regression for v1.3.3: every `collect()` must perform the documented
    /// sysinfo recipe of `refresh_cpu_usage → sleep ≥ MINIMUM_CPU_UPDATE_INTERVAL
    /// → refresh_cpu_usage` so `global_cpu_usage()` returns a real delta.
    /// Skipping the inner sleep silently reports 0 % on several Linux kernels
    /// (notably the GitHub Actions runners), which is exactly what blanked
    /// the dashboard in v1.3.2. We can't easily assert the CPU value itself
    /// (a quiescent test host can legitimately report ~0 %), so instead we
    /// assert the *recipe* is in place by measuring wall-clock duration.
    #[test]
    fn collect_observes_minimum_cpu_update_interval() {
        let mut c = MetricsCollector::new().expect("collector init must work in tests");
        let start = std::time::Instant::now();
        let _ = c.collect().expect("collect must succeed");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= sysinfo::MINIMUM_CPU_UPDATE_INTERVAL,
            "collect() finished in {:?}, faster than MINIMUM_CPU_UPDATE_INTERVAL ({:?}) — \
             the refresh-sleep-refresh recipe is missing and CPU readings will be 0 %",
            elapsed,
            sysinfo::MINIMUM_CPU_UPDATE_INTERVAL,
        );
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
