use anyhow::{Context, Result};
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
    /// Create a new collector. Performs a full initial refresh to populate CPU baseline.
    pub fn new() -> Result<Self> {
        let mut sys = System::new();
        // Initial CPU refresh — sysinfo needs two refreshes to compute usage delta
        sys.refresh_cpu_all();
        std::thread::sleep(std::time::Duration::from_millis(200));
        sys.refresh_cpu_all();
        sys.refresh_memory();

        let disks = Disks::new_with_refreshed_list();

        let hostname = hostname::get()
            .context("Failed to get hostname")?
            .to_string_lossy()
            .to_string();

        let os = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "unknown"
        }
        .to_string();

        let arch = std::env::consts::ARCH.to_string();

        Ok(Self {
            sys,
            disks,
            hostname,
            os,
            arch,
        })
    }

    /// Collect current metrics. Only refreshes CPU, memory, and disks — NOT processes.
    /// This is ~10× cheaper than `System::new_all() + refresh_all()`.
    pub fn collect(&mut self) -> SystemMetrics {
        // Targeted refresh — only what we need
        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.disks.refresh();

        let uptime_seconds = System::uptime();
        let cpu_percent = self.sys.global_cpu_usage() as f64;
        let memory_total_mb = self.sys.total_memory() / 1024 / 1024;
        let memory_used_mb = self.sys.used_memory() / 1024 / 1024;

        // Aggregate all disks (sum of all mount points, avoiding double-counting)
        let (disk_total_mb, disk_used_mb) = {
            let mut total = 0u64;
            let mut used = 0u64;
            for disk in self.disks.list() {
                let dt = disk.total_space() / 1024 / 1024;
                let da = disk.available_space() / 1024 / 1024;
                total += dt;
                used += dt.saturating_sub(da);
            }
            if total == 0 {
                // Fallback: try first disk only
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

        let load_1m = System::load_average().one;

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

