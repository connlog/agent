//! Binary wire format for ConnLog telemetry protocol v2.
//!
//! Frame layout (32 bytes fixed):
//!   [0]     u8    frame_type (0x01=metrics, 0x02=identity, 0x03=both)
//!   [1]     u8    protocol_version (2)
//!   [2..4]  u16le config_version
//!   [4..6]  u16le uptime_delta_secs
//!   [6]     u8    cpu_avg (0-200, divide by 2 for %)
//!   [7]     u8    cpu_max
//!   [8..12] u32le memory_used_mb
//!   [12..16] u32le disk_used_mb
//!   [16..18] u16le load_1m × 100
//!   [18..20] u16le load_1m_max × 100
//!   [20]    u8    sample_count
//!   [21]    u8    flags
//!   [22..24] u16le reserved
//!   [24..32] 8 bytes reserved/padding
//!
//! Identity frame (variable, appended when flags bit 0 = 1):
//!   [0]     u8    hostname_len
//!   [1..N]  [u8]  hostname UTF-8
//!   [N]     u8    os_id
//!   [N+1]   u8    arch_id
//!   [N+2..N+4] u16le agent_version_major
//!   [N+4..N+6] u16le agent_version_minor
//!   [N+6..N+8] u16le agent_version_patch
//!   [N+8..N+12] u32le memory_total_mb
//!   [N+12..N+16] u32le disk_total_mb
//!   [N+16..N+20] u32le uptime_absolute_secs (u32, wraps at ~136 years)
//!
//! Community frame (12 bytes, appended when flags bit 2 = 1):
//!   [0]     u8    cpu_bucket (0-9)
//!   [1]     u8    mem_percent_bucket (0-9)
//!   [2]     u8    disk_percent_bucket (0-9)
//!   [3]     u8    load_bucket (0-4)
//!   [4]     u8    os_id
//!   [5]     u8    arch_id
//!   [6..8]  u16le time_slot (minutes since midnight UTC, rounded to 15min)
//!   [8..12] u32le nonce (random)

use anyhow::Result;

/// Wire protocol version for binary frames
pub const WIRE_PROTOCOL_VERSION: u8 = 2;

/// Frame types
pub const FRAME_METRICS: u8 = 0x01;
pub const FRAME_IDENTITY: u8 = 0x02;
pub const FRAME_BOTH: u8 = 0x03;

/// Flag bits
pub const FLAG_IDENTITY_ATTACHED: u8 = 0x01;
pub const FLAG_DEV_MODE: u8 = 0x02;
pub const FLAG_COMMUNITY_ATTACHED: u8 = 0x04;

/// Fixed size of the metrics frame
pub const METRICS_FRAME_SIZE: usize = 32;
/// Fixed size of the community frame
pub const COMMUNITY_FRAME_SIZE: usize = 12;

/// Aggregated metrics from a sample window
#[derive(Debug, Clone, Default)]
pub struct MetricsSummary {
    pub cpu_avg: f64,
    pub cpu_max: f64,
    pub memory_used_mb: u64,
    pub memory_used_min_mb: u64,
    pub memory_used_max_mb: u64,
    pub disk_used_mb: u64,
    pub disk_used_min_mb: u64,
    pub disk_used_max_mb: u64,
    pub load_1m_avg: f64,
    pub load_1m_max: f64,
    pub sample_count: u8,
}

/// Identity information — sent once or on change
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    pub hostname: String,
    pub os_id: u8,
    pub arch_id: u8,
    pub agent_version: (u16, u16, u16),
    pub memory_total_mb: u32,
    pub disk_total_mb: u32,
    pub uptime_absolute_secs: u32,
}

/// Community telemetry — anonymized bucketed data
#[derive(Debug, Clone)]
pub struct CommunityFrame {
    pub cpu_bucket: u8,
    pub mem_percent_bucket: u8,
    pub disk_percent_bucket: u8,
    pub load_bucket: u8,
    pub os_id: u8,
    pub arch_id: u8,
    pub time_slot_minutes: u16,
    pub nonce: u32,
}

/// Encode OS string to numeric ID
pub fn os_to_id(os: &str) -> u8 {
    match os {
        "linux" => 0,
        "macos" => 1,
        "windows" => 2,
        _ => 3,
    }
}

/// Decode OS ID to string
pub fn id_to_os(id: u8) -> &'static str {
    match id {
        0 => "linux",
        1 => "macos",
        2 => "windows",
        _ => "unknown",
    }
}

/// Encode arch string to numeric ID
pub fn arch_to_id(arch: &str) -> u8 {
    match arch {
        "x86_64" => 0,
        "aarch64" => 1,
        "arm" => 2,
        _ => 3,
    }
}

/// Decode arch ID to string
pub fn id_to_arch(id: u8) -> &'static str {
    match id {
        0 => "x86_64",
        1 => "aarch64",
        2 => "arm",
        _ => "unknown",
    }
}

/// Parse semver "X.Y.Z" into (major, minor, patch)
pub fn parse_version(version: &str) -> (u16, u16, u16) {
    let parts: Vec<&str> = version.split('.').collect();
    let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

/// Format version tuple back to string
pub fn format_version(v: (u16, u16, u16)) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Encode a CPU percentage (0.0–100.0) to a u8 (0–200) for 0.5% resolution
fn encode_cpu(percent: f64) -> u8 {
    (percent.clamp(0.0, 100.0) * 2.0).round() as u8
}

/// Encode a load average to u16 (×100)
fn encode_load(load: f64) -> u16 {
    (load.clamp(0.0, 655.35) * 100.0).round() as u16
}

/// Bucket a percentage (0–100) into 10% buckets (0–9)
fn bucket_percent(pct: f64) -> u8 {
    ((pct.clamp(0.0, 99.99) / 10.0).floor() as u8).min(9)
}

/// Bucket a load average
fn bucket_load(load: f64) -> u8 {
    if load < 1.0 {
        0
    } else if load < 2.0 {
        1
    } else if load < 5.0 {
        2
    } else if load < 10.0 {
        3
    } else {
        4
    }
}

/// Get current time slot (minutes since midnight UTC, rounded to 15-minute boundary)
fn current_time_slot() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let minutes_since_midnight = ((secs % 86400) / 60) as u16;
    // Round to nearest 15-minute slot
    (minutes_since_midnight / 15) * 15
}

/// Build the binary wire frame for a heartbeat.
///
/// Returns a Vec<u8> containing:
/// - 32-byte metrics frame (always)
/// - Variable-length identity frame (if identity is Some)
/// - 12-byte community frame (if community is Some)
pub fn encode_frame(
    config_version: u16,
    uptime_delta_secs: u16,
    metrics: &MetricsSummary,
    identity: Option<&IdentityInfo>,
    community: Option<&CommunityFrame>,
) -> Vec<u8> {
    let mut flags: u8 = 0;
    let frame_type;

    if identity.is_some() {
        flags |= FLAG_IDENTITY_ATTACHED;
        frame_type = FRAME_BOTH;
    } else {
        frame_type = FRAME_METRICS;
    }

    if community.is_some() {
        flags |= FLAG_COMMUNITY_ATTACHED;
    }

    // Calculate total size
    let identity_size = identity.map_or(0, |id| 1 + id.hostname.len() + 16);
    let community_size = if community.is_some() { COMMUNITY_FRAME_SIZE } else { 0 };
    let total_size = METRICS_FRAME_SIZE + identity_size + community_size;

    let mut buf = Vec::with_capacity(total_size);

    // === Metrics frame (32 bytes) ===
    buf.push(frame_type); // [0]
    buf.push(WIRE_PROTOCOL_VERSION); // [1]
    buf.extend_from_slice(&config_version.to_le_bytes()); // [2..4]
    buf.extend_from_slice(&uptime_delta_secs.to_le_bytes()); // [4..6]
    buf.push(encode_cpu(metrics.cpu_avg)); // [6]
    buf.push(encode_cpu(metrics.cpu_max)); // [7]
    buf.extend_from_slice(&(metrics.memory_used_mb as u32).to_le_bytes()); // [8..12]
    buf.extend_from_slice(&(metrics.disk_used_mb as u32).to_le_bytes()); // [12..16]
    buf.extend_from_slice(&encode_load(metrics.load_1m_avg).to_le_bytes()); // [16..18]
    buf.extend_from_slice(&encode_load(metrics.load_1m_max).to_le_bytes()); // [18..20]
    buf.push(metrics.sample_count); // [20]
    buf.push(flags); // [21]
    buf.extend_from_slice(&0u16.to_le_bytes()); // [22..24] reserved
    buf.extend_from_slice(&[0u8; 8]); // [24..32] reserved

    debug_assert_eq!(buf.len(), METRICS_FRAME_SIZE);

    // === Identity frame (variable) ===
    if let Some(id) = identity {
        let hostname_bytes = id.hostname.as_bytes();
        let hostname_len = hostname_bytes.len().min(255) as u8;
        buf.push(hostname_len);
        buf.extend_from_slice(&hostname_bytes[..hostname_len as usize]);
        buf.push(id.os_id);
        buf.push(id.arch_id);
        buf.extend_from_slice(&id.agent_version.0.to_le_bytes());
        buf.extend_from_slice(&id.agent_version.1.to_le_bytes());
        buf.extend_from_slice(&id.agent_version.2.to_le_bytes());
        buf.extend_from_slice(&id.memory_total_mb.to_le_bytes());
        buf.extend_from_slice(&id.disk_total_mb.to_le_bytes());
        buf.extend_from_slice(&id.uptime_absolute_secs.to_le_bytes());
    }

    // === Community frame (12 bytes) ===
    if let Some(c) = community {
        buf.push(c.cpu_bucket);
        buf.push(c.mem_percent_bucket);
        buf.push(c.disk_percent_bucket);
        buf.push(c.load_bucket);
        buf.push(c.os_id);
        buf.push(c.arch_id);
        buf.extend_from_slice(&c.time_slot_minutes.to_le_bytes());
        buf.extend_from_slice(&c.nonce.to_le_bytes());
    }

    buf
}

/// Build a CommunityFrame from current metrics
pub fn build_community_frame(
    cpu_avg: f64,
    memory_used_mb: u64,
    memory_total_mb: u64,
    disk_used_mb: u64,
    disk_total_mb: u64,
    load_1m: f64,
    os_id: u8,
    arch_id: u8,
) -> CommunityFrame {
    let mem_pct = if memory_total_mb > 0 {
        (memory_used_mb as f64 / memory_total_mb as f64) * 100.0
    } else {
        0.0
    };
    let disk_pct = if disk_total_mb > 0 {
        (disk_used_mb as f64 / disk_total_mb as f64) * 100.0
    } else {
        0.0
    };

    // Generate random nonce
    let nonce = {
        let mut bytes = [0u8; 4];
        // Use /dev/urandom via getrandom or fallback to time-based
        if let Ok(f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let mut f = f;
            let _ = f.read_exact(&mut bytes);
        } else {
            use std::time::{SystemTime, UNIX_EPOCH};
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u32;
            bytes = t.to_le_bytes();
        }
        u32::from_le_bytes(bytes)
    };

    CommunityFrame {
        cpu_bucket: bucket_percent(cpu_avg),
        mem_percent_bucket: bucket_percent(mem_pct),
        disk_percent_bucket: bucket_percent(disk_pct),
        load_bucket: bucket_load(load_1m),
        os_id,
        arch_id,
        time_slot_minutes: current_time_slot(),
        nonce,
    }
}

/// Decode a binary frame into structured data (used for testing / debugging)
#[allow(dead_code)]
pub fn decode_metrics_frame(data: &[u8]) -> Result<DecodedMetricsFrame> {
    if data.len() < METRICS_FRAME_SIZE {
        anyhow::bail!("Frame too short: {} bytes (need {})", data.len(), METRICS_FRAME_SIZE);
    }

    let frame_type = data[0];
    let protocol_version = data[1];
    let config_version = u16::from_le_bytes([data[2], data[3]]);
    let uptime_delta_secs = u16::from_le_bytes([data[4], data[5]]);
    let cpu_avg = data[6] as f64 / 2.0;
    let cpu_max = data[7] as f64 / 2.0;
    let memory_used_mb = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let disk_used_mb = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let load_avg = u16::from_le_bytes([data[16], data[17]]) as f64 / 100.0;
    let load_max = u16::from_le_bytes([data[18], data[19]]) as f64 / 100.0;
    let sample_count = data[20];
    let flags = data[21];

    Ok(DecodedMetricsFrame {
        frame_type,
        protocol_version,
        config_version,
        uptime_delta_secs,
        cpu_avg,
        cpu_max,
        memory_used_mb,
        disk_used_mb,
        load_avg,
        load_max,
        sample_count,
        flags,
        has_identity: flags & FLAG_IDENTITY_ATTACHED != 0,
        has_community: flags & FLAG_COMMUNITY_ATTACHED != 0,
    })
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct DecodedMetricsFrame {
    pub frame_type: u8,
    pub protocol_version: u8,
    pub config_version: u16,
    pub uptime_delta_secs: u16,
    pub cpu_avg: f64,
    pub cpu_max: f64,
    pub memory_used_mb: u32,
    pub disk_used_mb: u32,
    pub load_avg: f64,
    pub load_max: f64,
    pub sample_count: u8,
    pub flags: u8,
    pub has_identity: bool,
    pub has_community: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_frame_size() {
        let metrics = MetricsSummary {
            cpu_avg: 45.5,
            cpu_max: 88.0,
            memory_used_mb: 8192,
            disk_used_mb: 50000,
            load_1m_avg: 2.35,
            load_1m_max: 5.10,
            sample_count: 6,
            ..Default::default()
        };
        let buf = encode_frame(42, 60, &metrics, None, None);
        assert_eq!(buf.len(), 32, "Metrics-only frame must be exactly 32 bytes");
    }

    #[test]
    fn test_full_frame_with_identity() {
        let metrics = MetricsSummary {
            cpu_avg: 50.0,
            cpu_max: 75.0,
            memory_used_mb: 4096,
            disk_used_mb: 100000,
            load_1m_avg: 1.0,
            load_1m_max: 3.0,
            sample_count: 12,
            ..Default::default()
        };
        let identity = IdentityInfo {
            hostname: "web-prod-01".to_string(),
            os_id: 0,
            arch_id: 0,
            agent_version: (0, 3, 0),
            memory_total_mb: 16384,
            disk_total_mb: 500000,
            uptime_absolute_secs: 86400,
        };
        let buf = encode_frame(1, 30, &metrics, Some(&identity), None);
        // 32 (metrics) + 1 (hostname_len) + 11 (hostname) + 16 (identity fields) = 60
        assert_eq!(buf.len(), 32 + 1 + 11 + 16);
    }

    #[test]
    fn test_cpu_encoding_roundtrip() {
        assert_eq!(encode_cpu(0.0), 0);
        assert_eq!(encode_cpu(50.0), 100);
        assert_eq!(encode_cpu(100.0), 200);
        assert_eq!(encode_cpu(99.5), 199);
    }

    #[test]
    fn test_decode_roundtrip() {
        let metrics = MetricsSummary {
            cpu_avg: 45.5,
            cpu_max: 88.0,
            memory_used_mb: 8192,
            disk_used_mb: 50000,
            load_1m_avg: 2.35,
            load_1m_max: 5.10,
            sample_count: 6,
            ..Default::default()
        };
        let buf = encode_frame(42, 60, &metrics, None, None);
        let decoded = decode_metrics_frame(&buf).unwrap();
        assert_eq!(decoded.config_version, 42);
        assert_eq!(decoded.uptime_delta_secs, 60);
        assert!((decoded.cpu_avg - 45.5).abs() < 0.5);
        assert_eq!(decoded.memory_used_mb, 8192);
        assert_eq!(decoded.sample_count, 6);
        assert!(!decoded.has_identity);
        assert!(!decoded.has_community);
    }

    #[test]
    fn test_bucket_percent() {
        assert_eq!(bucket_percent(0.0), 0);
        assert_eq!(bucket_percent(15.0), 1);
        assert_eq!(bucket_percent(99.9), 9);
        assert_eq!(bucket_percent(100.0), 9); // clamp
    }

    #[test]
    fn test_bucket_load() {
        assert_eq!(bucket_load(0.5), 0);
        assert_eq!(bucket_load(1.5), 1);
        assert_eq!(bucket_load(3.0), 2);
        assert_eq!(bucket_load(7.0), 3);
        assert_eq!(bucket_load(15.0), 4);
    }
}
