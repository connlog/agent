//! Local metric sample aggregation for the binary wire protocol.
//!
//! ## Purpose
//!
//! The agent is designed to collect raw metric samples at a sub-heartbeat rate
//! (every [`SAMPLE_INTERVAL_SECS`] seconds, currently 5s) and aggregate them into a
//! [`MetricsSummary`](crate::wire::MetricsSummary) before encoding them into the binary
//! wire frame via [`wire::encode_frame`](crate::wire::encode_frame).
//!
//! This gives the platform richer statistical information (min/max/avg per heartbeat
//! window) without increasing the heartbeat payload count.
//!
//! ## Integration status
//!
//! `SampleBuffer` is **not yet wired into the main agent loop**. The current main loop
//! in `main.rs` calls `MetricsCollector::collect()` once per heartbeat and sends the
//! single sample directly via `http::ApiClient`. The binary frame built in
//! `http::send_heartbeat_binary` uses a simpler inline encoding (not `wire::encode_frame`).
//!
//! To integrate: collect samples at `SAMPLE_INTERVAL_SECS` intervals between heartbeats,
//! push each into a `SampleBuffer`, then call `drain_summary()` at heartbeat time and
//! pass the result to `wire::encode_frame`. See `wire.rs` for the frame layout.

use crate::metrics::SystemMetrics;
use crate::wire::MetricsSummary;

/// Maximum number of raw samples to buffer (12 samples = 60s at 5s intervals)
const MAX_SAMPLES: usize = 16;

/// A single raw metric sample
#[derive(Debug, Clone)]
struct Sample {
    cpu_percent: f64,
    memory_used_mb: u64,
    disk_used_mb: u64,
    load_1m: f64,
}

/// Ring buffer that collects raw samples and produces aggregated summaries.
pub struct SampleBuffer {
    samples: Vec<Sample>,
}

impl SampleBuffer {
    pub fn new() -> Self {
        Self {
            samples: Vec::with_capacity(MAX_SAMPLES),
        }
    }

    /// Record a raw metric sample from sysinfo
    pub fn push(&mut self, metrics: &SystemMetrics) {
        if self.samples.len() >= MAX_SAMPLES {
            // Drop oldest sample if we exceed capacity
            self.samples.remove(0);
        }
        self.samples.push(Sample {
            cpu_percent: metrics.cpu_percent,
            memory_used_mb: metrics.memory_used_mb,
            disk_used_mb: metrics.disk_used_mb,
            load_1m: metrics.load_1m,
        });
    }

    /// How many samples are buffered
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Returns true if no samples are buffered
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Drain all samples and produce an aggregated summary.
    /// Returns None if no samples are buffered.
    pub fn drain_summary(&mut self) -> Option<MetricsSummary> {
        if self.samples.is_empty() {
            return None;
        }

        let count = self.samples.len();
        let mut cpu_sum = 0.0f64;
        let mut cpu_max = 0.0f64;
        let mut mem_sum = 0u64;
        let mut mem_min = u64::MAX;
        let mut mem_max = 0u64;
        let mut disk_sum = 0u64;
        let mut disk_min = u64::MAX;
        let mut disk_max = 0u64;
        let mut load_sum = 0.0f64;
        let mut load_max = 0.0f64;

        for s in &self.samples {
            cpu_sum += s.cpu_percent;
            if s.cpu_percent > cpu_max {
                cpu_max = s.cpu_percent;
            }

            mem_sum += s.memory_used_mb;
            if s.memory_used_mb < mem_min {
                mem_min = s.memory_used_mb;
            }
            if s.memory_used_mb > mem_max {
                mem_max = s.memory_used_mb;
            }

            disk_sum += s.disk_used_mb;
            if s.disk_used_mb < disk_min {
                disk_min = s.disk_used_mb;
            }
            if s.disk_used_mb > disk_max {
                disk_max = s.disk_used_mb;
            }

            load_sum += s.load_1m;
            if s.load_1m > load_max {
                load_max = s.load_1m;
            }
        }

        let summary = MetricsSummary {
            cpu_avg: cpu_sum / count as f64,
            cpu_max,
            memory_used_mb: mem_sum / count as u64,
            memory_used_min_mb: mem_min,
            memory_used_max_mb: mem_max,
            disk_used_mb: disk_sum / count as u64,
            disk_used_min_mb: disk_min,
            disk_used_max_mb: disk_max,
            load_1m_avg: load_sum / count as f64,
            load_1m_max: load_max,
            sample_count: count.min(255) as u8,
        };

        self.samples.clear();
        Some(summary)
    }
}

/// Internal sample interval - how often the agent collects raw metrics
/// between report intervals. This is NOT the heartbeat interval.
pub const SAMPLE_INTERVAL_SECS: u64 = 5;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::SystemMetrics;

    fn make_metrics(cpu: f64, mem: u64, disk: u64, load: f64) -> SystemMetrics {
        SystemMetrics {
            hostname: "test".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            uptime_seconds: 1000,
            cpu_percent: cpu,
            memory_used_mb: mem,
            memory_total_mb: 16384,
            disk_used_mb: disk,
            disk_total_mb: 500000,
            load_1m: load,
        }
    }

    #[test]
    fn test_single_sample() {
        let mut buf = SampleBuffer::new();
        buf.push(&make_metrics(50.0, 8192, 100000, 2.0));
        let summary = buf.drain_summary().unwrap();
        assert_eq!(summary.sample_count, 1);
        assert!((summary.cpu_avg - 50.0).abs() < 0.01);
        assert_eq!(summary.memory_used_mb, 8192);
    }

    #[test]
    fn test_multiple_samples_aggregation() {
        let mut buf = SampleBuffer::new();
        buf.push(&make_metrics(20.0, 4000, 100000, 1.0));
        buf.push(&make_metrics(80.0, 8000, 110000, 3.0));
        let summary = buf.drain_summary().unwrap();
        assert_eq!(summary.sample_count, 2);
        assert!((summary.cpu_avg - 50.0).abs() < 0.01);
        assert!((summary.cpu_max - 80.0).abs() < 0.01);
        assert_eq!(summary.memory_used_mb, 6000);
        assert_eq!(summary.memory_used_min_mb, 4000);
        assert_eq!(summary.memory_used_max_mb, 8000);
        assert!((summary.load_1m_avg - 2.0).abs() < 0.01);
        assert!((summary.load_1m_max - 3.0).abs() < 0.01);
    }

    #[test]
    fn test_drain_clears_buffer() {
        let mut buf = SampleBuffer::new();
        buf.push(&make_metrics(50.0, 8192, 100000, 2.0));
        let _ = buf.drain_summary();
        assert_eq!(buf.len(), 0);
        assert!(buf.drain_summary().is_none());
    }
}
