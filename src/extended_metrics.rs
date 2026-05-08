use anyhow::Result;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DISK_FLAG_MOUNTED: u32 = 1 << 0;
const DISK_FLAG_READ_ONLY: u32 = 1 << 1;
const DISK_FLAG_MISSING: u32 = 1 << 2;
const DISK_FLAG_STAT_FAILED: u32 = 1 << 3;
const DISK_FLAG_VIRTUAL_FILESYSTEM: u32 = 1 << 4;

const NET_FLAG_UP: u32 = 1 << 0;
const NET_FLAG_LOOPBACK: u32 = 1 << 1;
const NET_FLAG_VIRTUAL: u32 = 1 << 2;

const IGNORED_FILESYSTEMS: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "tmpfs",
    "cgroup",
    "cgroup2",
    "overlay",
    "overlayfs",
    "squashfs",
    "debugfs",
    "tracefs",
    "securityfs",
    "fusectl",
    "autofs",
    "nsfs",
    "ramfs",
    // Additional virtual / kernel-internal filesystems that are not real storage
    "hugetlbfs",
    "binfmt_misc",
    "mqueue",
    "pstore",
    "configfs",
    "selinuxfs",
    "bpf",
    "efivarfs",
    "rpc_pipefs",
    "iso9660",
];

const IGNORED_INTERFACES_PREFIX: &[&str] = &[
    "lo",
    "docker0",
    "br-",
    "veth",
    "virbr",
    "tun",
    "tap",
    "wg",
    "tailscale",
    "zt",
    "cni",
    "flannel",
    "kube-",
];

#[derive(Debug, Clone, Default)]
pub struct ExtendedMetricsState {
    prev_net: HashMap<String, PreviousNetCounters>,
}

#[derive(Debug, Clone)]
struct PreviousNetCounters {
    at_unix_secs: u64,
    rx_bytes_total: u64,
    tx_bytes_total: u64,
    rx_errors_total: u64,
    tx_errors_total: u64,
    rx_dropped_total: u64,
    tx_dropped_total: u64,
}

#[derive(Debug, Clone, Default)]
struct NetDeltaResult {
    rx_bytes_per_second: Option<u64>,
    tx_bytes_per_second: Option<u64>,
    rx_errors_delta: Option<u32>,
    tx_errors_delta: Option<u32>,
    rx_dropped_delta: Option<u32>,
    tx_dropped_delta: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryPayload {
    pub disks: Vec<DiskDiscovery>,
    pub network: Vec<NetworkDiscovery>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamplesPayload {
    pub sampled_at: String,
    pub disks: Vec<DiskSample>,
    pub network: Vec<NetworkSample>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskDiscovery {
    pub local_resource_id: u32,
    pub key: String,
    pub mount_point: String,
    pub source: String,
    pub filesystem: String,
    pub flags: u32,
    pub ignored_by_default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDiscovery {
    pub local_resource_id: u32,
    pub key: String,
    pub name: String,
    pub is_loopback: bool,
    pub is_virtual: bool,
    pub flags: u32,
    pub ignored_by_default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskSample {
    pub local_resource_id: u32,
    pub flags: u32,
    pub disk_used_mb: u64,
    pub disk_available_mb: u64,
    pub disk_total_mb: u64,
    pub disk_used_x100: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_inode_used_x100: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSample {
    pub local_resource_id: u32,
    pub flags: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_up: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_errors_delta: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_errors_delta: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_dropped_delta: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_dropped_delta: Option<u32>,
}

#[derive(Debug, Clone)]
struct DiskRuntime {
    local_resource_id: u32,
    key: String,
    source: String,
    filesystem: String,
    flags: u32,
    stat: Option<StatSnapshot>,
}

#[derive(Debug, Clone)]
struct StatSnapshot {
    total_bytes: u64,
    available_bytes: u64,
    used_bytes: u64,
    inode_total: Option<u64>,
    inode_available: Option<u64>,
    read_only: bool,
}

#[derive(Debug, Clone)]
struct NetRuntime {
    local_resource_id: u32,
    key: String,
    is_up: bool,
    is_loopback: bool,
    is_virtual: bool,
    rx_bytes_total: u64,
    tx_bytes_total: u64,
    rx_errors_total: u64,
    tx_errors_total: u64,
    rx_dropped_total: u64,
    tx_dropped_total: u64,
}

pub fn collect_discovery() -> DiscoveryPayload {
    let disks = discover_disks();
    let network = discover_network();
    DiscoveryPayload { disks, network }
}

pub fn collect_samples(
    state: &mut ExtendedMetricsState,
    monitored_disk_keys: &[String],
    monitored_network_keys: &[String],
) -> SamplesPayload {
    let disk_set: HashSet<&str> = monitored_disk_keys.iter().map(|s| s.as_str()).collect();
    let net_set: HashSet<&str> = monitored_network_keys.iter().map(|s| s.as_str()).collect();

    let disks = collect_disk_runtime()
        .into_iter()
        .filter(|d| disk_set.contains(d.key.as_str()))
        .filter_map(|d| {
            d.stat.map(|s| {
                let used_x100 = (s.used_bytes * 10000)
                    .checked_div(s.total_bytes)
                    .unwrap_or(0) as u32;
                let inode_used_x100 = match (s.inode_total, s.inode_available) {
                    (Some(total), Some(avail)) if total > 0 => {
                        Some((((total - avail) * 10000) / total) as u32)
                    }
                    _ => None,
                };
                DiskSample {
                    local_resource_id: d.local_resource_id,
                    flags: d.flags,
                    disk_used_mb: s.used_bytes / 1024 / 1024,
                    disk_available_mb: s.available_bytes / 1024 / 1024,
                    disk_total_mb: s.total_bytes / 1024 / 1024,
                    disk_used_x100: used_x100,
                    disk_inode_used_x100: inode_used_x100,
                }
            })
        })
        .collect();

    let now_secs = now_unix_secs();
    let network = collect_network_runtime()
        .into_iter()
        .filter(|n| net_set.contains(n.key.as_str()))
        .map(|n| {
            let prev = state.prev_net.get(&n.key).cloned();
            let mut sample = NetworkSample {
                local_resource_id: n.local_resource_id,
                flags: net_flags(&n),
                is_up: Some(n.is_up),
                rx_bytes_per_second: None,
                tx_bytes_per_second: None,
                rx_errors_delta: None,
                tx_errors_delta: None,
                rx_dropped_delta: None,
                tx_dropped_delta: None,
            };

            if let Some(p) = prev {
                let dt = now_secs.saturating_sub(p.at_unix_secs);
                let delta = compute_network_deltas(&p, &n, dt);
                sample.rx_bytes_per_second = delta.rx_bytes_per_second;
                sample.tx_bytes_per_second = delta.tx_bytes_per_second;
                sample.rx_errors_delta = delta.rx_errors_delta;
                sample.tx_errors_delta = delta.tx_errors_delta;
                sample.rx_dropped_delta = delta.rx_dropped_delta;
                sample.tx_dropped_delta = delta.tx_dropped_delta;
            }

            state.prev_net.insert(
                n.key.clone(),
                PreviousNetCounters {
                    at_unix_secs: now_secs,
                    rx_bytes_total: n.rx_bytes_total,
                    tx_bytes_total: n.tx_bytes_total,
                    rx_errors_total: n.rx_errors_total,
                    tx_errors_total: n.tx_errors_total,
                    rx_dropped_total: n.rx_dropped_total,
                    tx_dropped_total: n.tx_dropped_total,
                },
            );

            sample
        })
        .collect();

    SamplesPayload {
        sampled_at: chrono_timestamp(now_secs),
        disks,
        network,
    }
}

fn discover_disks() -> Vec<DiskDiscovery> {
    collect_disk_runtime()
        .into_iter()
        .map(|d| {
            let ignored = IGNORED_FILESYSTEMS.contains(&d.filesystem.as_str());
            DiskDiscovery {
                local_resource_id: d.local_resource_id,
                key: d.key.clone(),
                mount_point: d.key.strip_prefix("mount:").unwrap_or("").to_string(),
                source: d.source,
                filesystem: d.filesystem,
                flags: d.flags,
                ignored_by_default: ignored,
                ignore_reason: ignored.then(|| "virtual filesystem".to_string()),
            }
        })
        .collect()
}

fn discover_network() -> Vec<NetworkDiscovery> {
    collect_network_runtime()
        .into_iter()
        .map(|n| {
            let flags = net_flags(&n);
            let name = n.key.strip_prefix("net:").unwrap_or("").to_string();
            let ignored = is_ignored_interface(&name);
            NetworkDiscovery {
                local_resource_id: n.local_resource_id,
                key: n.key,
                name: name.clone(),
                is_loopback: n.is_loopback,
                is_virtual: n.is_virtual,
                flags,
                ignored_by_default: ignored,
                ignore_reason: ignored.then(|| "virtual/noisy interface".to_string()),
            }
        })
        .collect()
}

fn collect_disk_runtime() -> Vec<DiskRuntime> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    mountinfo
        .lines()
        .filter_map(parse_mountinfo_line)
        .map(|(mount_point, filesystem, source)| {
            let key = format!("mount:{}", mount_point);
            let mut flags = DISK_FLAG_MOUNTED;
            if IGNORED_FILESYSTEMS.contains(&filesystem.as_str()) {
                flags |= DISK_FLAG_VIRTUAL_FILESYSTEM;
            }

            let stat = stat_mount(&mount_point);
            if let Some(s) = &stat {
                if s.read_only {
                    flags |= DISK_FLAG_READ_ONLY;
                }
            } else {
                flags |= DISK_FLAG_STAT_FAILED | DISK_FLAG_MISSING;
            }

            DiskRuntime {
                local_resource_id: stable_resource_id(&key),
                key,
                source,
                filesystem,
                flags,
                stat,
            }
        })
        .collect()
}

fn collect_network_runtime() -> Vec<NetRuntime> {
    let mut out = Vec::new();
    let dev = fs::read_to_string("/proc/net/dev").unwrap_or_default();
    for line in dev.lines().skip(2) {
        let Some((name_raw, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name_raw.trim().to_string();
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 16 {
            continue;
        }

        let rx_bytes_total = cols[0].parse::<u64>().unwrap_or(0);
        let rx_errors_total = cols[2].parse::<u64>().unwrap_or(0);
        let rx_dropped_total = cols[3].parse::<u64>().unwrap_or(0);
        let tx_bytes_total = cols[8].parse::<u64>().unwrap_or(0);
        let tx_errors_total = cols[10].parse::<u64>().unwrap_or(0);
        let tx_dropped_total = cols[11].parse::<u64>().unwrap_or(0);

        let operstate_path = format!("/sys/class/net/{}/operstate", name);
        let is_up = fs::read_to_string(operstate_path)
            .map(|s| s.trim() == "up")
            .unwrap_or(false);

        let is_loopback = name == "lo";
        let is_virtual = fs::read_link(format!("/sys/class/net/{}", name))
            .map(|p| p.to_string_lossy().contains("/virtual/"))
            .unwrap_or(false);

        let key = format!("net:{}", name);
        out.push(NetRuntime {
            local_resource_id: stable_resource_id(&key),
            key,
            is_up,
            is_loopback,
            is_virtual,
            rx_bytes_total,
            tx_bytes_total,
            rx_errors_total,
            tx_errors_total,
            rx_dropped_total,
            tx_dropped_total,
        });
    }

    out
}

fn parse_mountinfo_line(line: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let sep = parts.iter().position(|p| *p == "-")?;
    if sep + 2 >= parts.len() || parts.len() < 5 {
        return None;
    }

    let mount_point = unescape_mount(parts[4]);
    let filesystem = parts[sep + 1].to_string();
    let source = parts[sep + 2].to_string();
    Some((mount_point, filesystem, source))
}

fn unescape_mount(input: &str) -> String {
    input
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn stat_mount(mount_point: &str) -> Option<StatSnapshot> {
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let c_path = std::ffi::CString::new(mount_point).ok()?;
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut st as *mut libc::statvfs) };
    if rc != 0 {
        return None;
    }

    let total = st.f_blocks.saturating_mul(st.f_frsize);
    let avail = st.f_bavail.saturating_mul(st.f_frsize);
    let used = total.saturating_sub(avail);
    let read_only = (st.f_flag & libc::ST_RDONLY) != 0;

    let inode_total = if st.f_files > 0 {
        Some(st.f_files)
    } else {
        None
    };
    let inode_available = if st.f_files > 0 {
        Some(st.f_favail)
    } else {
        None
    };

    Some(StatSnapshot {
        total_bytes: total,
        available_bytes: avail,
        used_bytes: used,
        inode_total,
        inode_available,
        read_only,
    })
}

fn net_flags(n: &NetRuntime) -> u32 {
    let mut flags = 0u32;
    if n.is_up {
        flags |= NET_FLAG_UP;
    }
    if n.is_loopback {
        flags |= NET_FLAG_LOOPBACK;
    }
    if n.is_virtual {
        flags |= NET_FLAG_VIRTUAL;
    }
    flags
}

fn is_ignored_interface(name: &str) -> bool {
    IGNORED_INTERFACES_PREFIX
        .iter()
        .any(|p| name.starts_with(p))
}

fn compute_network_deltas(
    prev: &PreviousNetCounters,
    now: &NetRuntime,
    dt_secs: u64,
) -> NetDeltaResult {
    if dt_secs == 0
        || now.rx_bytes_total < prev.rx_bytes_total
        || now.tx_bytes_total < prev.tx_bytes_total
        || now.rx_errors_total < prev.rx_errors_total
        || now.tx_errors_total < prev.tx_errors_total
        || now.rx_dropped_total < prev.rx_dropped_total
        || now.tx_dropped_total < prev.tx_dropped_total
    {
        return NetDeltaResult::default();
    }

    NetDeltaResult {
        rx_bytes_per_second: Some((now.rx_bytes_total - prev.rx_bytes_total) / dt_secs),
        tx_bytes_per_second: Some((now.tx_bytes_total - prev.tx_bytes_total) / dt_secs),
        rx_errors_delta: Some((now.rx_errors_total - prev.rx_errors_total) as u32),
        tx_errors_delta: Some((now.tx_errors_total - prev.tx_errors_total) as u32),
        rx_dropped_delta: Some((now.rx_dropped_total - prev.rx_dropped_total) as u32),
        tx_dropped_delta: Some((now.tx_dropped_total - prev.tx_dropped_total) as u32),
    }
}

fn stable_resource_id(key: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for b in key.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn chrono_timestamp(unix_secs: u64) -> String {
    use std::fmt::Write;
    let t = UNIX_EPOCH + std::time::Duration::from_secs(unix_secs);
    let datetime = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut s = String::with_capacity(24);
    let _ = write!(&mut s, "{}", datetime);
    s
}

pub fn should_collect(enabled: bool, disks: bool, network: bool) -> bool {
    enabled && (disks || network)
}

pub fn has_monitored(disks: &[String], network: &[String]) -> bool {
    !disks.is_empty() || !network.is_empty()
}

pub fn validate_payload_size<T: Serialize>(value: &T, max_kb: u64) -> Result<bool> {
    if max_kb == 0 {
        return Ok(true);
    }
    let size_kb = (serde_json::to_vec(value)?.len() as u64) / 1024;
    Ok(size_kb <= max_kb)
}

pub fn is_linux_runtime() -> bool {
    Path::new("/proc/self/mountinfo").exists() && Path::new("/proc/net/dev").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net_runtime(rx: u64, tx: u64, rx_e: u64, tx_e: u64, rx_d: u64, tx_d: u64) -> NetRuntime {
        NetRuntime {
            local_resource_id: 1,
            key: "net:eth0".to_string(),
            is_up: true,
            is_loopback: false,
            is_virtual: false,
            rx_bytes_total: rx,
            tx_bytes_total: tx,
            rx_errors_total: rx_e,
            tx_errors_total: tx_e,
            rx_dropped_total: rx_d,
            tx_dropped_total: tx_d,
        }
    }

    #[test]
    fn counter_reset_skips_rate_and_deltas() {
        let prev = PreviousNetCounters {
            at_unix_secs: 100,
            rx_bytes_total: 1000,
            tx_bytes_total: 1000,
            rx_errors_total: 10,
            tx_errors_total: 10,
            rx_dropped_total: 2,
            tx_dropped_total: 2,
        };
        let now = net_runtime(100, 100, 1, 1, 0, 0);

        let delta = compute_network_deltas(&prev, &now, 5);
        assert!(delta.rx_bytes_per_second.is_none());
        assert!(delta.tx_bytes_per_second.is_none());
        assert!(delta.rx_errors_delta.is_none());
        assert!(delta.tx_errors_delta.is_none());
        assert!(delta.rx_dropped_delta.is_none());
        assert!(delta.tx_dropped_delta.is_none());
    }

    #[test]
    fn computes_network_rate_and_deltas() {
        let prev = PreviousNetCounters {
            at_unix_secs: 100,
            rx_bytes_total: 1000,
            tx_bytes_total: 1500,
            rx_errors_total: 10,
            tx_errors_total: 5,
            rx_dropped_total: 2,
            tx_dropped_total: 1,
        };
        let now = net_runtime(3000, 3500, 12, 7, 3, 4);

        let delta = compute_network_deltas(&prev, &now, 10);
        assert_eq!(delta.rx_bytes_per_second, Some(200));
        assert_eq!(delta.tx_bytes_per_second, Some(200));
        assert_eq!(delta.rx_errors_delta, Some(2));
        assert_eq!(delta.tx_errors_delta, Some(2));
        assert_eq!(delta.rx_dropped_delta, Some(1));
        assert_eq!(delta.tx_dropped_delta, Some(3));
    }
}
