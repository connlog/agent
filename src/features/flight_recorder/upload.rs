//! The flight recorder's history on the wire (`application/vnd.connlog.history.v1`).
//!
//! A day is 1440 records. Sent as ring slots that is 92 KB; most of it
//! repeats: totals do not change, time moves by the same step, uptime moves
//! with time, pressure sits at zero. So each field is sent only when it
//! differs from what the previous record predicts, as a zigzag varint of the
//! difference, behind a bit mask of which fields follow:
//!
//! ```text
//! body   = version (u8 = 1), count (varint), record × count
//! record = mask (varint), then for each set bit, in field order:
//!          zigzag varint (value − predicted)
//! ```
//!
//! | bit | field | predicted |
//! | --- | --- | --- |
//! | 0 | seq | previous + 1 |
//! | 1 | time (unix s) | previous + previous step (60 for the first) |
//! | 2 | uptime (s) | previous + (time − previous time) |
//! | 3 | cpu × 100 (0xffff unknown) | previous |
//! | 4 | cpu peak × 100 | this record's cpu |
//! | 5 | memory used (MB) | previous |
//! | 6 | memory total | previous |
//! | 7 | disk used | previous |
//! | 8 | disk total | previous |
//! | 9 | load × 100 | previous |
//! | 10 | load max × 100 | this record's load |
//! | 11 | boot tag | previous |
//! | 12 | OOM kills | previous |
//! | 13 | cpu pressure × 100 | previous |
//! | 14 | memory pressure × 100 | previous |
//! | 15 | io pressure × 100 | previous |
//! | 16 | kind | previous |
//! | 17 | flags | previous |
//!
//! Every "previous" of the first record is 0. A steady minute costs about
//! four bytes, a full day of a real host a few kilobytes. The platform's
//! decoder is `decodeHistoryUpload` in `@connlog/agent-protocol`; both are
//! held to `packages/agent-protocol/fixtures/history-uploads.json`.

use super::ring::Stored;

pub const CONTENT_TYPE: &str = "application/vnd.connlog.history.v1";
pub const FORMAT_VERSION: u8 = 1;
pub const FIELDS: usize = 18;

/// One record as the wire sees it: every field an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WireRecord {
    pub fields: [u64; FIELDS],
}

impl WireRecord {
    pub fn from_stored(s: &Stored) -> Self {
        let r = &s.record;
        let f = &r.frame;
        let u16_at = |i: usize| u64::from(u16::from_le_bytes([f[i], f[i + 1]]));
        let u32_at = |i: usize| u64::from(u32::from_le_bytes([f[i], f[i + 1], f[i + 2], f[i + 3]]));
        Self {
            fields: [
                u64::from(s.seq),
                r.time,
                u64::from_le_bytes(f[0..8].try_into().unwrap_or([0; 8])),
                u16_at(8),
                u16_at(10),
                u32_at(12),
                u32_at(16),
                u32_at(20),
                u32_at(24),
                u16_at(28),
                u16_at(30),
                u64::from(r.boot_tag),
                u64::from(r.oom_kills),
                u64::from(r.psi_cpu_some_x100),
                u64::from(r.psi_memory_full_x100),
                u64::from(r.psi_io_full_x100),
                r.kind as u64,
                u64::from(r.flags),
            ],
        }
    }
}

/// The most records one upload carries: two days, the platform's cap.
pub const MAX_RECORDS: usize = 2880;
/// How far before the silence the upload starts: the minutes that explain it.
pub const CONTEXT_BEFORE_SECS: u64 = 10 * 60;
/// How far after it: the start record of an agent that came back.
pub const CONTEXT_AFTER_SECS: u64 = 5 * 60;

/// Which metrics the platform config collects. Blanked fields go out as a
/// heartbeat would send them: CPU unknown, the rest zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricToggles {
    pub cpu: bool,
    pub memory: bool,
    pub disk: bool,
    pub load: bool,
}

/// The records an answer to `history_request { since, until }` carries,
/// oldest first.
pub fn records_for(
    all: &[Stored],
    since: u64,
    until: u64,
    toggles: MetricToggles,
) -> Vec<WireRecord> {
    let from = since.saturating_sub(CONTEXT_BEFORE_SECS);
    let to = until.saturating_add(CONTEXT_AFTER_SECS);
    let chosen: Vec<&Stored> = all
        .iter()
        .filter(|s| s.record.time >= from && s.record.time <= to)
        .collect();
    chosen[chosen.len().saturating_sub(MAX_RECORDS)..]
        .iter()
        .map(|s| {
            let mut w = WireRecord::from_stored(s);
            if !toggles.cpu {
                w.fields[CPU] = u64::from(super::ring::UNKNOWN_U16);
                w.fields[CPU_PEAK] = u64::from(super::ring::UNKNOWN_U16);
            }
            if !toggles.memory {
                w.fields[5] = 0;
                w.fields[6] = 0;
            }
            if !toggles.disk {
                w.fields[7] = 0;
                w.fields[8] = 0;
            }
            if !toggles.load {
                w.fields[LOAD] = 0;
                w.fields[LOAD_MAX] = 0;
            }
            w
        })
        .collect()
}

const SEQ: usize = 0;
const TIME: usize = 1;
const UPTIME: usize = 2;
const CPU: usize = 3;
const CPU_PEAK: usize = 4;
const LOAD: usize = 9;
const LOAD_MAX: usize = 10;
const DEFAULT_STEP: u64 = 60;

/// What the previous record predicts for each field of this one. Fields that
/// depend on this record (cpu peak, load max) are filled as it is read.
fn predicted(prev: &WireRecord, prev_step: u64, current: &[u64; FIELDS], field: usize) -> u64 {
    match field {
        SEQ => prev.fields[SEQ].wrapping_add(1),
        TIME => prev.fields[TIME].wrapping_add(prev_step),
        UPTIME => prev.fields[UPTIME].wrapping_add(current[TIME].wrapping_sub(prev.fields[TIME])),
        CPU_PEAK => current[CPU],
        LOAD_MAX => current[LOAD],
        other => prev.fields[other],
    }
}

fn push_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn zigzag(delta: i64) -> u64 {
    ((delta << 1) ^ (delta >> 63)) as u64
}

pub fn encode(records: &[WireRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + records.len() * 6);
    out.push(FORMAT_VERSION);
    push_varint(&mut out, records.len() as u64);

    let mut prev = WireRecord::default();
    let mut prev_step = DEFAULT_STEP;
    for record in records {
        let mut mask = 0u64;
        let mut deltas = [0i64; FIELDS];
        for (field, slot) in deltas.iter_mut().enumerate() {
            let expected = predicted(&prev, prev_step, &record.fields, field);
            *slot = record.fields[field].wrapping_sub(expected) as i64;
            if *slot != 0 {
                mask |= 1 << field;
            }
        }
        push_varint(&mut out, mask);
        for (field, delta) in deltas.iter().enumerate() {
            if mask & (1 << field) != 0 {
                push_varint(&mut out, zigzag(*delta));
            }
        }
        prev_step = record.fields[TIME].wrapping_sub(prev.fields[TIME]);
        if prev_step == 0 || prev.fields[TIME] == 0 {
            prev_step = DEFAULT_STEP;
        }
        prev = *record;
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;

    /// The inverse, for tests only: the platform's is the real one.
    fn read_varint(bytes: &[u8], pos: &mut usize) -> u64 {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let b = bytes[*pos];
            *pos += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b < 0x80 {
                return v;
            }
            shift += 7;
        }
    }

    fn decode(bytes: &[u8]) -> Vec<WireRecord> {
        assert_eq!(bytes[0], FORMAT_VERSION);
        let mut pos = 1;
        let count = read_varint(bytes, &mut pos);
        let mut records = Vec::new();
        let mut prev = WireRecord::default();
        let mut prev_step = DEFAULT_STEP;
        for _ in 0..count {
            let mask = read_varint(bytes, &mut pos);
            let mut fields = [0u64; FIELDS];
            for field in 0..FIELDS {
                let expected = predicted(&prev, prev_step, &fields, field);
                fields[field] = if mask & (1 << field) != 0 {
                    let z = read_varint(bytes, &mut pos);
                    let delta = ((z >> 1) as i64) ^ -((z & 1) as i64);
                    expected.wrapping_add(delta as u64)
                } else {
                    expected
                };
            }
            prev_step = fields[TIME].wrapping_sub(prev.fields[TIME]);
            if prev_step == 0 || prev.fields[TIME] == 0 {
                prev_step = DEFAULT_STEP;
            }
            prev = WireRecord { fields };
            records.push(prev);
        }
        assert_eq!(pos, bytes.len(), "no trailing bytes");
        records
    }

    /// A day of a plausible host: steady minutes, noise, one reboot.
    pub(crate) fn realistic_day() -> Vec<WireRecord> {
        let mut state: u64 = 42;
        let mut noise = move |range: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % range
        };
        (0..1440u64)
            .map(|i| {
                let rebooted = i >= 900;
                let uptime = if rebooted {
                    (i - 900) * 60 + 30
                } else {
                    86_400 + i * 60
                };
                let cpu = 800 + noise(900);
                let load = 40 + noise(60);
                WireRecord {
                    fields: [
                        i + 1,
                        1_790_000_000 + i * 60,
                        uptime,
                        cpu,
                        cpu + noise(2000),
                        6_000 + noise(300),
                        16_000,
                        200_000 + i / 10,
                        900_000,
                        load,
                        load,
                        if rebooted { 0xbbbb_bbbb } else { 0xaaaa_aaaa },
                        if i > 880 && !rebooted { 2 } else { 0 },
                        noise(3) * 5,
                        0,
                        0,
                        if i == 900 { 2 } else { 1 },
                        0,
                    ],
                }
            })
            .collect()
    }

    #[test]
    fn round_trips_every_field() {
        let day = realistic_day();
        assert_eq!(decode(&encode(&day)), day);
        assert_eq!(decode(&encode(&[])), []);
        let extremes = [
            WireRecord {
                fields: [u64::from(u32::MAX); FIELDS],
            },
            WireRecord {
                fields: [0; FIELDS],
            },
            WireRecord {
                fields: [u64::MAX; FIELDS],
            },
        ];
        assert_eq!(decode(&encode(&extremes)), extremes);
    }

    #[test]
    fn a_full_day_fits_in_sixteen_kilobytes() {
        let bytes = encode(&realistic_day());
        eprintln!("a realistic day: {} bytes", bytes.len());
        assert!(bytes.len() < 16 * 1024, "{} bytes", bytes.len());
    }

    #[test]
    fn a_steady_minute_costs_a_mask() {
        let a = WireRecord {
            fields: [
                1, 600, 6000, 100, 100, 5, 9, 5, 9, 10, 10, 7, 0, 0, 0, 0, 1, 0,
            ],
        };
        let mut b = a;
        b.fields[SEQ] = 2;
        b.fields[TIME] = 660;
        b.fields[UPTIME] = 6060;
        let bytes = encode(&[a, b]);
        // The second record: time moved by the default step and uptime with
        // it, nothing else changed, so its mask is 0.
        assert_eq!(*bytes.last().unwrap(), 0);
    }

    fn stored(seq: u32, time: u64) -> Stored {
        let mut frame = [0u8; 32];
        frame[8..10].copy_from_slice(&1250u16.to_le_bytes());
        frame[12..16].copy_from_slice(&512u32.to_le_bytes());
        Stored {
            seq,
            record: super::super::ring::Record {
                time,
                frame,
                boot_tag: 1,
                oom_kills: 0,
                psi_cpu_some_x100: 0,
                psi_memory_full_x100: 0,
                psi_io_full_x100: 0,
                kind: super::super::ring::Kind::Sample,
                flags: 0,
            },
        }
    }

    #[test]
    fn an_answer_carries_the_silence_and_its_context() {
        let all: Vec<Stored> = (0..100)
            .map(|i| stored(i + 1, 10_000 + u64::from(i) * 60))
            .collect();
        let all_on = MetricToggles {
            cpu: true,
            memory: true,
            disk: true,
            load: true,
        };
        // Silence from 12,000 to 13,000: ten minutes before, five after.
        let picked = records_for(&all, 12_000, 13_000, all_on);
        let times: Vec<u64> = picked.iter().map(|w| w.fields[TIME]).collect();
        assert_eq!(times.first(), Some(&11_440));
        assert_eq!(times.last(), Some(&13_300));
    }

    #[test]
    fn metrics_the_platform_does_not_collect_stay_home() {
        let all = [stored(1, 100)];
        let picked = records_for(
            &all,
            0,
            200,
            MetricToggles {
                cpu: false,
                memory: false,
                disk: true,
                load: true,
            },
        );
        assert_eq!(picked[0].fields[CPU], 0xffff);
        assert_eq!(picked[0].fields[5], 0, "memory used");
        let kept = records_for(
            &all,
            0,
            200,
            MetricToggles {
                cpu: true,
                memory: true,
                disk: true,
                load: true,
            },
        );
        assert_eq!(kept[0].fields[CPU], 1250);
        assert_eq!(kept[0].fields[5], 512);
    }

    const UPLOADS: &str =
        include_str!("../../../../../packages/agent-protocol/fixtures/history-uploads.json");

    /// The agent's half of `history-uploads.json`: each fixture's records
    /// encode to exactly its bytes.
    #[test]
    fn encodes_every_shared_fixture_exactly() {
        let fixtures: Vec<Value> = serde_json::from_str(UPLOADS).unwrap();
        assert!(!fixtures.is_empty());
        for fixture in fixtures {
            let records: Vec<WireRecord> = fixture["records"]
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
                    WireRecord {
                        fields: fields.try_into().unwrap(),
                    }
                })
                .collect();
            let hex: String = encode(&records)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(
                hex,
                fixture["bytes"].as_str().unwrap(),
                "{}",
                fixture["description"]
            );
        }
    }
}
