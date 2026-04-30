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
        // Initial CPU refresh - sysinfo needs two refreshes to compute usage delta
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

    /// Collect current metrics. Only refreshes CPU, memory, and disks - NOT processes.
    /// This is ~10× cheaper than `System::new_all() + refresh_all()`.
    pub fn collect(&mut self) -> SystemMetrics {
        // Targeted refresh - only what we need
        self.sys.refresh_cpu_all();
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
