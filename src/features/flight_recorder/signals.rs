//! What the kernel says about trouble, beyond the heartbeat's numbers.
//!
//! All of it is readable by an unprivileged process, costs one small file
//! read, and is optional: an older kernel without pressure stall information
//! (before 4.20) or without the `oom_kill` counter (before 4.13) records the
//! unknown sentinel, never an error.
//!
//! - **OOM kills**: `/proc/vmstat` `oom_kill`, the number of processes the
//!   kernel has killed for memory since boot. A rise before a crash is the
//!   clearest "it ran out of memory" there is.
//! - **Pressure** (`/proc/pressure/*`): the share of the last 10 seconds that
//!   work was stalled. CPU `some` (anything waited for a CPU); memory and IO
//!   `full` (everything was stalled): a host thrashing itself to death reads
//!   near 100 here while load and CPU look unremarkable.

use super::ring::{UNKNOWN_U16, UNKNOWN_U32};

/// The signals for one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signals {
    pub oom_kills: u32,
    pub psi_cpu_some_x100: u16,
    pub psi_memory_full_x100: u16,
    pub psi_io_full_x100: u16,
}

pub fn read() -> Signals {
    let pressure = |resource: &str, line: &str| {
        std::fs::read_to_string(format!("/proc/pressure/{resource}"))
            .ok()
            .and_then(|text| parse_avg10_x100(&text, line))
            .unwrap_or(UNKNOWN_U16)
    };
    Signals {
        oom_kills: std::fs::read_to_string("/proc/vmstat")
            .ok()
            .and_then(|text| parse_oom_kills(&text))
            .unwrap_or(UNKNOWN_U32),
        psi_cpu_some_x100: pressure("cpu", "some"),
        psi_memory_full_x100: pressure("memory", "full"),
        psi_io_full_x100: pressure("io", "full"),
    }
}

/// `oom_kill N` from `/proc/vmstat`, saturated below the sentinel.
pub fn parse_oom_kills(vmstat: &str) -> Option<u32> {
    let count: u64 = vmstat
        .lines()
        .find_map(|line| line.strip_prefix("oom_kill "))?
        .trim()
        .parse()
        .ok()?;
    Some(count.min(u64::from(UNKNOWN_U32 - 1)) as u32)
}

/// `avg10` of the `some` or `full` line of a pressure file, × 100.
pub fn parse_avg10_x100(pressure: &str, which: &str) -> Option<u16> {
    let line = pressure
        .lines()
        .find(|line| line.split_whitespace().next() == Some(which))?;
    let avg10: f64 = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("avg10="))?
        .parse()
        .ok()?;
    (avg10.is_finite() && avg10 >= 0.0).then(|| (avg10.min(100.0) * 100.0).round() as u16)
}

/// The first 32 bits of a boot id (its first 8 hex digits): enough to tell
/// one boot from the next in a day of records, in four bytes.
pub fn boot_tag(boot_id: Option<&str>) -> u32 {
    boot_id
        .and_then(|id| id.get(0..8))
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .unwrap_or(UNKNOWN_U32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU: &str = "some avg10=0.06 avg60=0.46 avg300=1.42 total=30032769\n\
                       full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    const MEMORY: &str = "some avg10=12.50 avg60=3.10 avg300=1.00 total=99\n\
                          full avg10=97.31 avg60=40.00 avg300=12.00 total=77\n";

    #[test]
    fn reads_the_avg10_of_the_line_asked_for() {
        assert_eq!(parse_avg10_x100(CPU, "some"), Some(6));
        assert_eq!(parse_avg10_x100(MEMORY, "full"), Some(9731));
        assert_eq!(parse_avg10_x100(MEMORY, "some"), Some(1250));
    }

    #[test]
    fn an_old_kernel_file_without_the_line_is_unknown() {
        // Before 5.13 the cpu file has no `full` line.
        let old_cpu = "some avg10=1.00 avg60=0.00 avg300=0.00 total=1\n";
        assert_eq!(parse_avg10_x100(old_cpu, "full"), None);
        assert_eq!(parse_avg10_x100("", "some"), None);
        assert_eq!(parse_avg10_x100("some avg10=nan total=1", "some"), None);
    }

    #[test]
    fn reads_oom_kills() {
        let vmstat = "nr_free_pages 1\noom_kill 4\nnr_zone_active_file 2\n";
        assert_eq!(parse_oom_kills(vmstat), Some(4));
        assert_eq!(parse_oom_kills("nr_free_pages 1\n"), None);
        assert_eq!(
            parse_oom_kills("oom_kill 99999999999\n"),
            Some(UNKNOWN_U32 - 1),
            "saturates below the sentinel"
        );
    }

    #[test]
    fn boot_tag_is_the_first_eight_hex_digits() {
        assert_eq!(
            boot_tag(Some("6f1f4b2c-0d3e-4a5b-9c8d-7e6f5a4b3c2d")),
            0x6f1f_4b2c
        );
        assert_eq!(boot_tag(None), UNKNOWN_U32);
        assert_eq!(boot_tag(Some("zz")), UNKNOWN_U32);
    }

    #[test]
    fn this_host_reads_without_error() {
        // Whatever the kernel supports; the point is that nothing panics and
        // a Linux runner has at least the OOM counter.
        let signals = read();
        if cfg!(target_os = "linux") {
            assert_ne!(signals.oom_kills, UNKNOWN_U32);
        }
    }
}
