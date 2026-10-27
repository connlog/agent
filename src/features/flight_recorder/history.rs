//! Reading the ring back: what happened, in words, and the records around it.
//!
//! Behind `connlog-agent diagnostics history`. Like `diagnostics heartbeats`
//! it is strictly local: no token, no network, no root beyond reading the
//! state directory.
//!
//! What a pair of neighbouring records says:
//!
//! | Earlier record | Later record | Same boot? | Meaning |
//! | --- | --- | --- | --- |
//! | stop (reboot flag) | start | no | the remote reboot happened |
//! | stop | start | no | clean shutdown or reboot |
//! | sample or start | start | no | the host went down without a clean stop: crash, power loss, hard reset |
//! | stop (update flag) | start | yes | the agent updated itself |
//! | stop | start | yes | the agent service was restarted |
//! | sample or start | start | yes | the agent was killed or crashed; the host stayed up |
//!
//! "Same boot" is the boot tag when both records have one, otherwise the
//! uptime in the later record's frame against the time between them. Runs of
//! records flagged `heartbeat failing` are the host being up while the
//! platform could not be reached.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::ring::{
    self, Kind, Record, Stored, FLAG_EXIT_REBOOT, FLAG_EXIT_UPDATE, FLAG_HEARTBEAT_FAILING,
    UNKNOWN_U16, UNKNOWN_U32,
};
use crate::config::DiagnosticsFormat;
use crate::features::heartbeat_telemetry::format_unix_ms_utc;

/// The readings of a v1 frame (see `http::encode_heartbeat`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrameValues {
    pub uptime_seconds: u64,
    pub cpu_percent: Option<f64>,
    pub cpu_peak_percent: Option<f64>,
    pub memory_used_mb: u32,
    pub memory_total_mb: u32,
    pub disk_used_mb: u32,
    pub disk_total_mb: u32,
    pub load_1m: f64,
}

pub fn decode_frame(f: &[u8; 32]) -> FrameValues {
    let u16_at = |i: usize| u16::from_le_bytes([f[i], f[i + 1]]);
    let u32_at = |i: usize| u32::from_le_bytes([f[i], f[i + 1], f[i + 2], f[i + 3]]);
    let pct = |raw: u16| (raw != UNKNOWN_U16).then(|| f64::from(raw) / 100.0);
    FrameValues {
        uptime_seconds: u64::from_le_bytes(f[0..8].try_into().unwrap_or([0; 8])),
        cpu_percent: pct(u16_at(8)),
        cpu_peak_percent: pct(u16_at(10)),
        memory_used_mb: u32_at(12),
        memory_total_mb: u32_at(16),
        disk_used_mb: u32_at(20),
        disk_total_mb: u32_at(24),
        load_1m: f64::from(u16_at(28)) / 100.0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    RemoteReboot,
    CleanReboot,
    UncleanReboot,
    AgentUpdated,
    AgentRestarted,
    AgentKilled,
    PlatformUnreachable,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::RemoteReboot => "remote_reboot",
            EventKind::CleanReboot => "clean_reboot",
            EventKind::UncleanReboot => "unclean_reboot",
            EventKind::AgentUpdated => "agent_updated",
            EventKind::AgentRestarted => "agent_restarted",
            EventKind::AgentKilled => "agent_killed",
            EventKind::PlatformUnreachable => "platform_unreachable",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            EventKind::RemoteReboot => "Rebooted on request from ConnLog",
            EventKind::CleanReboot => "Clean shutdown or reboot",
            EventKind::UncleanReboot => {
                "Host went down without a clean stop (crash, power loss or hard reset)"
            }
            EventKind::AgentUpdated => "Agent updated itself",
            EventKind::AgentRestarted => "Agent service restarted",
            EventKind::AgentKilled => "Agent stopped without a clean stop; the host stayed up",
            EventKind::PlatformUnreachable => "Host up, but ConnLog could not be reached",
        }
    }
}

/// Something that happened between records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    /// The last record before it (the last sign of life, for a reboot).
    pub from: u64,
    /// The first record after it (the return, for a reboot).
    pub to: u64,
    /// Index into the records of the last record before it.
    pub before_index: usize,
}

fn same_boot(earlier: &Record, later: &Record) -> bool {
    if earlier.boot_tag != UNKNOWN_U32 && later.boot_tag != UNKNOWN_U32 {
        return earlier.boot_tag == later.boot_tag;
    }
    let uptime = decode_frame(&later.frame).uptime_seconds;
    uptime >= later.time.saturating_sub(earlier.time)
}

pub fn classify(records: &[Stored]) -> Vec<Event> {
    let mut events = Vec::new();
    let mut unreachable_since: Option<(u64, usize)> = None;

    for (i, pair) in records.windows(2).enumerate() {
        let (a, b) = (&pair[0].record, &pair[1].record);

        if b.kind == Kind::Start {
            let kind = match (same_boot(a, b), a.kind) {
                (false, Kind::Stop) if a.flags & FLAG_EXIT_REBOOT != 0 => EventKind::RemoteReboot,
                (false, Kind::Stop) => EventKind::CleanReboot,
                (false, _) => EventKind::UncleanReboot,
                (true, Kind::Stop) if a.flags & FLAG_EXIT_UPDATE != 0 => EventKind::AgentUpdated,
                (true, Kind::Stop) => EventKind::AgentRestarted,
                (true, _) => EventKind::AgentKilled,
            };
            events.push(Event {
                kind,
                from: a.time,
                to: b.time,
                before_index: i,
            });
        }

        let failing = b.flags & FLAG_HEARTBEAT_FAILING != 0 && b.kind == Kind::Sample;
        match (failing, unreachable_since) {
            (true, None) => unreachable_since = Some((a.time, i)),
            (false, Some((from, before_index))) => {
                events.push(Event {
                    kind: EventKind::PlatformUnreachable,
                    from,
                    to: b.time,
                    before_index,
                });
                unreachable_since = None;
            }
            _ => {}
        }
    }
    if let (Some((from, before_index)), Some(last)) = (unreachable_since, records.last()) {
        events.push(Event {
            kind: EventKind::PlatformUnreachable,
            from,
            to: last.record.time,
            before_index,
        });
    }
    events.sort_by_key(|e| (e.to, e.from));
    events
}

fn ts(secs: u64) -> String {
    format_unix_ms_utc(u128::from(secs) * 1000)
}

fn opt_u16(raw: u16) -> Option<f64> {
    (raw != UNKNOWN_U16).then(|| f64::from(raw) / 100.0)
}

fn record_json(s: &Stored) -> Value {
    let r = &s.record;
    let f = decode_frame(&r.frame);
    json!({
        "seq": s.seq,
        "time": ts(r.time),
        "kind": r.kind.as_str(),
        "heartbeat_failing": r.flags & FLAG_HEARTBEAT_FAILING != 0,
        "exit_for_update": r.flags & FLAG_EXIT_UPDATE != 0,
        "exit_for_reboot": r.flags & FLAG_EXIT_REBOOT != 0,
        "boot_tag": (r.boot_tag != UNKNOWN_U32).then(|| format!("{:08x}", r.boot_tag)),
        "uptime_seconds": f.uptime_seconds,
        "cpu_percent": f.cpu_percent,
        "cpu_peak_percent": f.cpu_peak_percent,
        "memory_used_mb": f.memory_used_mb,
        "memory_total_mb": f.memory_total_mb,
        "disk_used_mb": f.disk_used_mb,
        "disk_total_mb": f.disk_total_mb,
        "load_1m": f.load_1m,
        "oom_kills": (r.oom_kills != UNKNOWN_U32).then_some(r.oom_kills),
        "pressure_cpu_some": opt_u16(r.psi_cpu_some_x100),
        "pressure_memory_full": opt_u16(r.psi_memory_full_x100),
        "pressure_io_full": opt_u16(r.psi_io_full_x100),
    })
}

fn fmt_opt(v: Option<f64>, width: usize) -> String {
    v.map(|v| format!("{v:>width$.1}"))
        .unwrap_or_else(|| format!("{:>width$}", "-"))
}

fn record_line(s: &Stored) -> String {
    let r = &s.record;
    let f = decode_frame(&r.frame);
    let pct =
        |used: u32, total: u32| (total > 0).then(|| f64::from(used) * 100.0 / f64::from(total));
    let kind = match r.kind {
        Kind::Sample if r.flags & FLAG_HEARTBEAT_FAILING != 0 => "sample*",
        other => other.as_str(),
    };
    format!(
        "  {}  {:<8} {} {} {} {:>6.2} {:>5} {} {} {}",
        ts(r.time),
        kind,
        fmt_opt(f.cpu_percent, 5),
        fmt_opt(pct(f.memory_used_mb, f.memory_total_mb), 5),
        fmt_opt(pct(f.disk_used_mb, f.disk_total_mb), 5),
        f.load_1m,
        if r.oom_kills == UNKNOWN_U32 {
            "-".to_string()
        } else {
            r.oom_kills.to_string()
        },
        fmt_opt(opt_u16(r.psi_cpu_some_x100), 5),
        fmt_opt(opt_u16(r.psi_memory_full_x100), 5),
        fmt_opt(opt_u16(r.psi_io_full_x100), 5),
    )
}

const TABLE_HEADER: &str =
    "  time                  kind       cpu%  mem%  disk%   load   oom  p.cpu p.mem  p.io";

/// How many records to show before the most recent unclean stop.
const BEFORE_UNCLEAN: usize = 10;

pub fn render_text(path: &Path, all: &[Stored], since: u64, limit: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!("Flight recorder  {}\n", path.display()));
    let (Some(first), Some(last)) = (all.first(), all.last()) else {
        out.push_str("No records yet. The agent writes one a minute while it runs.\n");
        return out;
    };
    out.push_str(&format!(
        "Records          {} ({} to {}), one a minute, the last 24 h kept\n\n",
        all.len(),
        ts(first.record.time),
        ts(last.record.time)
    ));

    let events: Vec<Event> = classify(all)
        .into_iter()
        .filter(|e| e.to >= since)
        .collect();
    out.push_str("What happened\n");
    if events.is_empty() {
        out.push_str("  Nothing: no restarts, reboots or unreachable stretches in this window.\n");
    }
    for e in &events {
        out.push_str(&format!(
            "  {}  {} (last record {}, next {})\n",
            ts(e.to),
            e.kind.describe(),
            ts(e.from),
            ts(e.to)
        ));
    }

    if let Some(e) = events
        .iter()
        .rev()
        .find(|e| matches!(e.kind, EventKind::UncleanReboot | EventKind::AgentKilled))
    {
        let start = (e.before_index + 1).saturating_sub(BEFORE_UNCLEAN);
        out.push_str(&format!(
            "\nThe last {} records before {}\n{TABLE_HEADER}\n",
            e.before_index + 1 - start,
            ts(e.from)
        ));
        for s in &all[start..=e.before_index] {
            out.push_str(&record_line(s));
            out.push('\n');
        }
    }

    let recent: Vec<&Stored> = all.iter().filter(|s| s.record.time >= since).collect();
    let shown = &recent[recent.len().saturating_sub(limit)..];
    out.push_str(&format!(
        "\nLatest records ({} of {} in the window; * = heartbeat failing; p.* = pressure %)\n{TABLE_HEADER}\n",
        shown.len(),
        recent.len()
    ));
    for s in shown {
        out.push_str(&record_line(s));
        out.push('\n');
    }
    out
}

pub fn render_json(path: &Path, all: &[Stored], since: u64, limit: usize) -> Value {
    let events: Vec<Value> = classify(all)
        .into_iter()
        .filter(|e| e.to >= since)
        .map(|e| {
            json!({
                "kind": e.kind.as_str(),
                "description": e.kind.describe(),
                "last_record_before": ts(e.from),
                "first_record_after": ts(e.to),
            })
        })
        .collect();
    let recent: Vec<&Stored> = all.iter().filter(|s| s.record.time >= since).collect();
    let shown = &recent[recent.len().saturating_sub(limit)..];
    json!({
        "file": path.display().to_string(),
        "records_total": all.len(),
        "records_in_window": recent.len(),
        "events": events,
        "records": shown.iter().map(|s| record_json(s)).collect::<Vec<_>>(),
    })
}

pub fn run_history_cli(since: &str, limit: usize, format: DiagnosticsFormat) -> anyhow::Result<()> {
    let lookback = crate::features::heartbeat_telemetry::parse_lookback(since)?;
    let path = super::ring_path(&crate::features::heartbeat_telemetry::default_state_dir());
    let all = ring::read(&path);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let since = now.saturating_sub(lookback.as_secs());
    match format {
        DiagnosticsFormat::Text => print!("{}", render_text(&path, &all, since, limit)),
        DiagnosticsFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&render_json(&path, &all, since, limit))?
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const BOOT_A: u32 = 0xaaaa_aaaa;
    const BOOT_B: u32 = 0xbbbb_bbbb;

    fn frame(uptime: u64, mem_used: u32) -> [u8; 32] {
        let mut f = [0u8; 32];
        f[0..8].copy_from_slice(&uptime.to_le_bytes());
        f[8..10].copy_from_slice(&1250u16.to_le_bytes());
        f[10..12].copy_from_slice(&4000u16.to_le_bytes());
        f[12..16].copy_from_slice(&mem_used.to_le_bytes());
        f[16..20].copy_from_slice(&1000u32.to_le_bytes());
        f
    }

    fn rec(seq: u32, time: u64, kind: Kind, boot: u32, flags: u8) -> Stored {
        Stored {
            seq,
            record: Record {
                time,
                frame: frame(time, 500),
                boot_tag: boot,
                oom_kills: 0,
                psi_cpu_some_x100: 0,
                psi_memory_full_x100: 0,
                psi_io_full_x100: 0,
                kind,
                flags,
            },
        }
    }

    fn kinds(records: &[Stored]) -> Vec<EventKind> {
        classify(records).iter().map(|e| e.kind).collect()
    }

    #[test]
    fn decodes_the_frame_the_agent_encodes() {
        let f = decode_frame(&frame(86_400, 512));
        assert_eq!(f.uptime_seconds, 86_400);
        assert_eq!(f.cpu_percent, Some(12.5));
        assert_eq!(f.cpu_peak_percent, Some(40.0));
        assert_eq!(f.memory_used_mb, 512);
        let mut unknown = frame(1, 1);
        unknown[8..10].copy_from_slice(&UNKNOWN_U16.to_le_bytes());
        assert_eq!(decode_frame(&unknown).cpu_percent, None);
    }

    #[test]
    fn tells_every_kind_of_restart_apart() {
        let cases = [
            (
                Kind::Stop,
                FLAG_EXIT_REBOOT,
                BOOT_B,
                EventKind::RemoteReboot,
            ),
            (Kind::Stop, 0, BOOT_B, EventKind::CleanReboot),
            (Kind::Sample, 0, BOOT_B, EventKind::UncleanReboot),
            (
                Kind::Stop,
                FLAG_EXIT_UPDATE,
                BOOT_A,
                EventKind::AgentUpdated,
            ),
            (Kind::Stop, 0, BOOT_A, EventKind::AgentRestarted),
            (Kind::Sample, 0, BOOT_A, EventKind::AgentKilled),
        ];
        for (before, flags, next_boot, expected) in cases {
            let records = [
                rec(1, 100, Kind::Sample, BOOT_A, 0),
                rec(2, 160, before, BOOT_A, flags),
                rec(3, 400, Kind::Start, next_boot, 0),
            ];
            assert_eq!(
                kinds(&records),
                [expected],
                "{before:?} {flags} {next_boot:x}"
            );
        }
    }

    #[test]
    fn without_boot_tags_uptime_tells_a_reboot() {
        // 300 s between the records; up for 30 s → a new boot.
        let mut after = rec(3, 400, Kind::Start, UNKNOWN_U32, 0);
        after.record.frame = frame(30, 500);
        let records = [rec(1, 100, Kind::Sample, UNKNOWN_U32, 0), after];
        assert_eq!(kinds(&records), [EventKind::UncleanReboot]);
    }

    #[test]
    fn a_failing_stretch_is_the_platform_being_unreachable() {
        let records = [
            rec(1, 0, Kind::Sample, BOOT_A, 0),
            rec(2, 60, Kind::Sample, BOOT_A, FLAG_HEARTBEAT_FAILING),
            rec(3, 120, Kind::Sample, BOOT_A, FLAG_HEARTBEAT_FAILING),
            rec(4, 180, Kind::Sample, BOOT_A, 0),
        ];
        let events = classify(&records);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::PlatformUnreachable);
        assert_eq!((events[0].from, events[0].to), (0, 180));

        // Still failing at the end: the stretch runs to the last record.
        let events = classify(&records[..3]);
        assert_eq!((events[0].from, events[0].to), (0, 120));
    }

    #[test]
    fn text_shows_the_minutes_before_an_unclean_stop() {
        let mut records: Vec<Stored> = (0..15)
            .map(|i| rec(i + 1, u64::from(i) * 60, Kind::Sample, BOOT_A, 0))
            .collect();
        records.push(rec(16, 2_000, Kind::Start, BOOT_B, 0));
        let text = render_text(Path::new("/x/flight.ring"), &records, 0, 5);
        assert!(
            text.contains("Host went down without a clean stop"),
            "{text}"
        );
        assert!(
            text.contains("The last 10 records before 1970-01-01T00:14:00Z"),
            "{text}"
        );
        assert!(text.contains("Latest records (5 of 16"), "{text}");
    }

    #[test]
    fn json_lists_events_and_records() {
        let records = [
            rec(1, 100, Kind::Stop, BOOT_A, FLAG_EXIT_REBOOT),
            rec(2, 400, Kind::Start, BOOT_B, 0),
        ];
        let v = render_json(Path::new("/x"), &records, 0, 10);
        assert_eq!(v["events"][0]["kind"], "remote_reboot");
        assert_eq!(v["records"][0]["exit_for_reboot"], true);
        assert_eq!(v["records"][1]["boot_tag"], "bbbbbbbb");
        assert_eq!(v["records"][1]["cpu_percent"], 12.5);
    }

    #[test]
    fn an_empty_ring_says_so() {
        let text = render_text(Path::new("/x"), &[], 0, 10);
        assert!(text.contains("No records yet"));
    }

    const CLASSIFICATION: &str =
        include_str!("../../../../../packages/agent-protocol/fixtures/outage-classification.json");

    /// A record from the wire field order of `history-uploads.json`.
    fn from_fields(f: &[u64]) -> Stored {
        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&f[2].to_le_bytes());
        frame[8..10].copy_from_slice(&(f[3] as u16).to_le_bytes());
        frame[10..12].copy_from_slice(&(f[4] as u16).to_le_bytes());
        for (i, field) in [5, 6, 7, 8].into_iter().enumerate() {
            frame[12 + i * 4..16 + i * 4].copy_from_slice(&(f[field] as u32).to_le_bytes());
        }
        frame[28..30].copy_from_slice(&(f[9] as u16).to_le_bytes());
        frame[30..32].copy_from_slice(&(f[10] as u16).to_le_bytes());
        let kind = match f[16] {
            1 => Kind::Sample,
            2 => Kind::Start,
            _ => Kind::Stop,
        };
        Stored {
            seq: f[0] as u32,
            record: Record {
                time: f[1],
                frame,
                boot_tag: f[11] as u32,
                oom_kills: f[12] as u32,
                psi_cpu_some_x100: f[13] as u16,
                psi_memory_full_x100: f[14] as u16,
                psi_io_full_x100: f[15] as u16,
                kind,
                flags: f[17] as u8,
            },
        }
    }

    /// The agent's half of `outage-classification.json`: the platform's
    /// `historyEvents` must name the same events for the same records.
    #[test]
    fn classifies_every_shared_fixture_as_the_platform_does() {
        let fixtures: Vec<Value> = serde_json::from_str(CLASSIFICATION).unwrap();
        assert!(!fixtures.is_empty());
        for fixture in fixtures {
            let records: Vec<Stored> = fixture["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    let fields: Vec<u64> = r
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap())
                        .collect();
                    from_fields(&fields)
                })
                .collect();
            let got: Vec<(String, u64, u64)> = classify(&records)
                .iter()
                .map(|e| (e.kind.as_str().to_string(), e.from, e.to))
                .collect();
            let want: Vec<(String, u64, u64)> = fixture["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["kind"].as_str().unwrap().to_string(),
                        e["from"].as_u64().unwrap(),
                        e["to"].as_u64().unwrap(),
                    )
                })
                .collect();
            assert_eq!(got, want, "{}", fixture["description"]);
        }
    }
}
