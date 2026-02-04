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

impl SystemMetrics {
    pub fn collect() -> Result<Self> {
        let mut sys = System::new_all();
        sys.refresh_all();

        // Get hostname
        let hostname = hostname::get()
            .context("Failed to get hostname")?
            .to_string_lossy()
            .to_string();

        // Get OS
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

        // Get architecture
        let arch = std::env::consts::ARCH.to_string();

        // Get uptime
        let uptime_seconds = System::uptime();

        // Get CPU usage
        let cpu_percent = sys.global_cpu_usage() as f64;

        // Get memory usage
        let memory_total_mb = sys.total_memory() / 1024 / 1024;
        let memory_used_mb = sys.used_memory() / 1024 / 1024;

        // Get disk usage (first disk only for now)
        let disks = Disks::new_with_refreshed_list();
        let (disk_total_mb, disk_used_mb) = if let Some(disk) = disks.first() {
            let total = disk.total_space() / 1024 / 1024;
            let available = disk.available_space() / 1024 / 1024;
            let used = total.saturating_sub(available);
            (total, used)
        } else {
            (0, 0)
        };

        // Get load average (1 minute)
        let load_1m = System::load_average().one;

        Ok(Self {
            hostname,
            os,
            arch,
            uptime_seconds,
            cpu_percent,
            memory_used_mb,
            memory_total_mb,
            disk_used_mb,
            disk_total_mb,
            load_1m,
        })
    }
}
