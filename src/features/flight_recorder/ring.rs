//! The ring file: a fixed-size, append-only record of the last day.
//!
//! ```text
//! header (64 bytes)
//!   0..4    magic "CLFR"
//!   4..6    format version (u16 LE) = 1
//!   6..8    slot size (u16 LE) = 64
//!   8..12   slot count (u32 LE)
//!   12..20  created at, unix seconds (u64 LE)
//!   20..60  zero
//!   60..64  CRC-32 of bytes 0..60
//! slot (64 bytes) × slot count
//!   0..4    sequence number (u32 LE), 1-based; the slot is seq % slot count
//!   4..12   wall-clock time, unix seconds (u64 LE)
//!   12..44  the v1 heartbeat frame, exactly as sent (`http::encode_heartbeat`)
//!   44..48  boot tag: the first 8 hex digits of the boot id (u32 LE)
//!   48..52  OOM kills since boot, from /proc/vmstat (u32 LE)
//!   52..54  CPU pressure, some avg10 × 100 (u16 LE)
//!   54..56  memory pressure, full avg10 × 100 (u16 LE)
//!   56..58  IO pressure, full avg10 × 100 (u16 LE)
//!   58      kind (sample, start, stop)
//!   59      flags
//!   60..64  CRC-32 of bytes 0..60
//! ```
//!
//! Unknown numeric values carry the all-ones sentinel of their width. Records
//! are placed by sequence number rather than by time, so two records in the
//! same minute never overwrite each other and a clock that jumps cannot
//! reorder the history. When the ring is full the oldest slot is simply the
//! next one written: that is the rotation. A slot torn by a crash mid-write
//! fails its CRC and is skipped when read.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;

pub const MAGIC: [u8; 4] = *b"CLFR";
pub const FORMAT_VERSION: u16 = 1;
pub const SLOT_BYTES: usize = 64;
pub const HEADER_BYTES: usize = 64;
/// 24 hours at one record a minute.
pub const DEFAULT_SLOTS: u32 = 1440;

pub const UNKNOWN_U16: u16 = u16::MAX;
pub const UNKNOWN_U32: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The periodic record.
    Sample = 1,
    /// The agent started.
    Start = 2,
    /// The agent stopped cleanly: a service stop, the host shutting down, or
    /// an exit for an update or a remote reboot (see the flags). Which one is
    /// told by what comes next: a new boot, or the same one.
    Stop = 3,
}

impl Kind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Kind::Sample),
            2 => Some(Kind::Start),
            3 => Some(Kind::Stop),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Sample => "sample",
            Kind::Start => "start",
            Kind::Stop => "stop",
        }
    }
}

/// The last heartbeat attempt before this record had failed: the host was
/// up but could not reach the platform.
pub const FLAG_HEARTBEAT_FAILING: u8 = 1 << 0;
/// A stop to apply a self-update.
pub const FLAG_EXIT_UPDATE: u8 = 1 << 1;
/// A stop to hand a remote reboot to systemd.
pub const FLAG_EXIT_REBOOT: u8 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub time: u64,
    pub frame: [u8; 32],
    pub boot_tag: u32,
    pub oom_kills: u32,
    pub psi_cpu_some_x100: u16,
    pub psi_memory_full_x100: u16,
    pub psi_io_full_x100: u16,
    pub kind: Kind,
    pub flags: u8,
}

/// A record read back from the ring, with its place in the sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    pub seq: u32,
    pub record: Record,
}

/// CRC-32 (IEEE 802.3, reflected, as zlib). Sixty bytes a minute do not need
/// a table.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn header_bytes(slots: u32, created_at: u64) -> [u8; HEADER_BYTES] {
    let mut h = [0u8; HEADER_BYTES];
    h[0..4].copy_from_slice(&MAGIC);
    h[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    h[6..8].copy_from_slice(&(SLOT_BYTES as u16).to_le_bytes());
    h[8..12].copy_from_slice(&slots.to_le_bytes());
    h[12..20].copy_from_slice(&created_at.to_le_bytes());
    let crc = crc32(&h[0..60]);
    h[60..64].copy_from_slice(&crc.to_le_bytes());
    h
}

/// The slot count a well-formed header declares, or `None`.
fn parse_header(h: &[u8]) -> Option<u32> {
    if h.len() < HEADER_BYTES || h[0..4] != MAGIC {
        return None;
    }
    let crc = u32::from_le_bytes(h[60..64].try_into().ok()?);
    if crc != crc32(&h[0..60]) {
        return None;
    }
    let version = u16::from_le_bytes(h[4..6].try_into().ok()?);
    let slot_bytes = u16::from_le_bytes(h[6..8].try_into().ok()?);
    let slots = u32::from_le_bytes(h[8..12].try_into().ok()?);
    (version == FORMAT_VERSION && usize::from(slot_bytes) == SLOT_BYTES && slots > 0)
        .then_some(slots)
}

pub fn encode_slot(seq: u32, r: &Record) -> [u8; SLOT_BYTES] {
    let mut s = [0u8; SLOT_BYTES];
    s[0..4].copy_from_slice(&seq.to_le_bytes());
    s[4..12].copy_from_slice(&r.time.to_le_bytes());
    s[12..44].copy_from_slice(&r.frame);
    s[44..48].copy_from_slice(&r.boot_tag.to_le_bytes());
    s[48..52].copy_from_slice(&r.oom_kills.to_le_bytes());
    s[52..54].copy_from_slice(&r.psi_cpu_some_x100.to_le_bytes());
    s[54..56].copy_from_slice(&r.psi_memory_full_x100.to_le_bytes());
    s[56..58].copy_from_slice(&r.psi_io_full_x100.to_le_bytes());
    s[58] = r.kind as u8;
    s[59] = r.flags;
    let crc = crc32(&s[0..60]);
    s[60..64].copy_from_slice(&crc.to_le_bytes());
    s
}

/// A slot that holds a whole record, or `None` for an empty or torn one.
pub fn decode_slot(s: &[u8]) -> Option<Stored> {
    if s.len() < SLOT_BYTES {
        return None;
    }
    let crc = u32::from_le_bytes(s[60..64].try_into().ok()?);
    if crc != crc32(&s[0..60]) {
        return None;
    }
    let seq = u32::from_le_bytes(s[0..4].try_into().ok()?);
    if seq == 0 {
        return None;
    }
    let u16_at = |i: usize| u16::from_le_bytes([s[i], s[i + 1]]);
    let u32_at = |i: usize| u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]);
    let mut frame = [0u8; 32];
    frame.copy_from_slice(&s[12..44]);
    Some(Stored {
        seq,
        record: Record {
            time: u64::from_le_bytes(s[4..12].try_into().ok()?),
            frame,
            boot_tag: u32_at(44),
            oom_kills: u32_at(48),
            psi_cpu_some_x100: u16_at(52),
            psi_memory_full_x100: u16_at(54),
            psi_io_full_x100: u16_at(56),
            kind: Kind::from_byte(s[58])?,
            flags: s[59],
        },
    })
}

/// Every whole record in a ring file's bytes, oldest first.
pub fn decode_ring(bytes: &[u8]) -> Vec<Stored> {
    let Some(slots) = parse_header(bytes) else {
        return Vec::new();
    };
    let mut records: Vec<Stored> = bytes[HEADER_BYTES..]
        .as_chunks::<SLOT_BYTES>()
        .0
        .iter()
        .take(slots as usize)
        .filter_map(|slot| decode_slot(slot))
        .collect();
    records.sort_by_key(|r| r.seq);
    records
}

/// Read a ring file; empty when it is missing or not a ring.
pub fn read(path: &Path) -> Vec<Stored> {
    std::fs::read(path)
        .map(|bytes| decode_ring(&bytes))
        .unwrap_or_default()
}

/// The writer. Holds the file open; one `write_at` + `sync_data` per record.
pub struct Ring {
    file: File,
    slots: u32,
    next_seq: u32,
}

impl Ring {
    /// Open the ring at `path`, or create it. A file that is not a ring of
    /// this format (or is damaged in its header) is replaced: the history is
    /// a diagnostic, never worth refusing to record over.
    pub fn open(path: &Path, slots: u32, now: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;

        let len = HEADER_BYTES as u64 + u64::from(slots) * SLOT_BYTES as u64;
        let mut header = [0u8; HEADER_BYTES];
        let usable = file.metadata()?.len() == len
            && file.read_exact_at(&mut header, 0).is_ok()
            && parse_header(&header) == Some(slots);

        if !usable {
            file.set_len(0)?;
            file.set_len(len)?;
            file.write_all_at(&header_bytes(slots, now), 0)?;
            file.sync_all()?;
            return Ok(Self {
                file,
                slots,
                next_seq: 1,
            });
        }

        let mut bytes = vec![0u8; len as usize];
        file.read_exact_at(&mut bytes, 0)?;
        let last = decode_ring(&bytes).last().map(|r| r.seq).unwrap_or(0);
        Ok(Self {
            file,
            slots,
            next_seq: last.wrapping_add(1).max(1),
        })
    }

    pub fn append(&mut self, record: &Record) -> io::Result<()> {
        let seq = self.next_seq;
        let offset = HEADER_BYTES as u64 + u64::from(seq % self.slots) * SLOT_BYTES as u64;
        self.file.write_all_at(&encode_slot(seq, record), offset)?;
        // Once a minute: a power cut then loses at most the record in flight,
        // which is the whole point of keeping one.
        self.file.sync_data()?;
        self.next_seq = seq.wrapping_add(1).max(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_ring() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "connlog-ring-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("flight.ring")
    }

    fn record(time: u64, kind: Kind) -> Record {
        let mut frame = [0u8; 32];
        frame[0..8].copy_from_slice(&time.to_le_bytes());
        Record {
            time,
            frame,
            boot_tag: 0x6f1f_4b2c,
            oom_kills: 3,
            psi_cpu_some_x100: 125,
            psi_memory_full_x100: UNKNOWN_U16,
            psi_io_full_x100: 0,
            kind,
            flags: FLAG_HEARTBEAT_FAILING,
        }
    }

    #[test]
    fn crc32_matches_zlib() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn a_record_survives_the_round_trip() {
        let r = record(1_700_000_000, Kind::Stop);
        let slot = encode_slot(7, &r);
        assert_eq!(decode_slot(&slot), Some(Stored { seq: 7, record: r }));
    }

    #[test]
    fn empty_and_torn_slots_are_skipped() {
        assert_eq!(decode_slot(&[0u8; SLOT_BYTES]), None);
        let mut slot = encode_slot(1, &record(1, Kind::Sample));
        slot[20] ^= 0xff;
        assert_eq!(decode_slot(&slot), None);
    }

    #[test]
    fn the_file_is_fixed_size_and_wraps_oldest_first() {
        let path = temp_ring();
        let mut ring = Ring::open(&path, 4, 100).unwrap();
        for t in 1..=10 {
            ring.append(&record(t, Kind::Sample)).unwrap();
        }
        let size = std::fs::metadata(&path).unwrap().len();
        assert_eq!(size, (HEADER_BYTES + 4 * SLOT_BYTES) as u64);

        let times: Vec<u64> = read(&path).iter().map(|s| s.record.time).collect();
        assert_eq!(times, [7, 8, 9, 10], "the last four, in order");
    }

    #[test]
    fn reopening_continues_the_sequence() {
        let path = temp_ring();
        let mut ring = Ring::open(&path, 8, 100).unwrap();
        ring.append(&record(1, Kind::Start)).unwrap();
        ring.append(&record(2, Kind::Sample)).unwrap();
        drop(ring);

        let mut ring = Ring::open(&path, 8, 200).unwrap();
        ring.append(&record(3, Kind::Stop)).unwrap();
        let seqs: Vec<u32> = read(&path).iter().map(|s| s.seq).collect();
        assert_eq!(seqs, [1, 2, 3]);
    }

    #[test]
    fn a_clock_jumping_back_does_not_reorder_the_history() {
        let path = temp_ring();
        let mut ring = Ring::open(&path, 8, 100).unwrap();
        ring.append(&record(5_000, Kind::Sample)).unwrap();
        ring.append(&record(10, Kind::Sample)).unwrap();
        let times: Vec<u64> = read(&path).iter().map(|s| s.record.time).collect();
        assert_eq!(times, [5_000, 10], "written order, not time order");
    }

    #[test]
    fn two_records_in_the_same_second_both_stay() {
        let path = temp_ring();
        let mut ring = Ring::open(&path, 8, 100).unwrap();
        ring.append(&record(60, Kind::Stop)).unwrap();
        ring.append(&record(60, Kind::Start)).unwrap();
        let kinds: Vec<Kind> = read(&path).iter().map(|s| s.record.kind).collect();
        assert_eq!(kinds, [Kind::Stop, Kind::Start]);
    }

    #[test]
    fn a_foreign_or_resized_file_is_replaced() {
        let path = temp_ring();
        std::fs::write(&path, b"not a ring").unwrap();
        let mut ring = Ring::open(&path, 4, 100).unwrap();
        ring.append(&record(1, Kind::Sample)).unwrap();
        assert_eq!(read(&path).len(), 1);

        // A different slot count is a different ring: start over.
        let mut ring = Ring::open(&path, 8, 100).unwrap();
        ring.append(&record(2, Kind::Sample)).unwrap();
        let times: Vec<u64> = read(&path).iter().map(|s| s.record.time).collect();
        assert_eq!(times, [2]);
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let path = temp_ring();
        let target = path.with_file_name("elsewhere");
        std::fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(Ring::open(&path, 4, 100).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    }

    #[test]
    fn default_ring_is_ninety_kilobytes() {
        assert_eq!(
            HEADER_BYTES + DEFAULT_SLOTS as usize * SLOT_BYTES,
            92_224,
            "the plan promises 92,224 bytes"
        );
    }
}
