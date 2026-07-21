//! Persistent, bounded, agent-owned heartbeat delivery diagnostics.
//!
//! This module records *why* a heartbeat was considered missed without needing
//! root, `journalctl`, or any privileged journal access. It is the data source
//! behind `connlog-agent diagnostics heartbeats`.
//!
//! ## Where it lives
//!
//! Events are appended as newline-delimited JSON (JSONL) to
//! `$STATE_DIRECTORY/heartbeat-telemetry.jsonl` (default `/var/lib/connlog`,
//! provisioned by the systemd `StateDirectory=connlog` directive — see
//! `install/linux.rs`). That path survives process restart, service restart,
//! and reboot, and is owned 0700 by the `connlog-agent` service account — the
//! same account ConnLog actions run as, so the diagnostics command can read it
//! back without `sudo`.
//!
//! ## Why JSONL + rotation
//!
//! A single append is the cheapest durable write that survives a crash without
//! corrupting prior records: a torn final line is simply skipped on read. We
//! bound disk by rotating to a single `.1` generation once the active file
//! exceeds [`MAX_LOG_BYTES`], so total on-disk usage is hard-capped at roughly
//! `2 × MAX_LOG_BYTES`. No database dependency, no per-event `fsync`.
//!
//! ## Safety invariants (must never be broken)
//!
//! * A telemetry write failure MUST NEVER block, delay, or fail a heartbeat —
//!   [`HeartbeatTelemetry::record`] is best-effort and never returns an error
//!   or panics.
//! * Secrets MUST NEVER be persisted. Detail strings pass through
//!   [`sanitize_detail`] (token/bearer redaction + length cap) and raw backend
//!   response bodies are never stored — only the HTTP status reason phrase.
//! * Concurrent writes are serialised behind a `Mutex`, so overlapping
//!   heartbeat retries cannot interleave or race a partial record.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::DiagnosticsFormat;

/// Schema version embedded in every record and in the JSON CLI output. Bump on
/// any breaking change to the persisted/emitted field set.
pub const TELEMETRY_SCHEMA_VERSION: u32 = 1;

/// File name of the active telemetry log inside the state directory.
const LOG_FILE_NAME: &str = "heartbeat-telemetry.jsonl";

/// Maximum bytes for the active log before it is rotated to `<name>.1`. With at
/// most one rotated generation kept, total on-disk usage is hard-capped at
/// roughly `2 × MAX_LOG_BYTES`. Each record is a few hundred bytes, so 1 MiB
/// holds several thousand events — days of normal once-a-minute heartbeats.
const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// Maximum characters kept from any sanitized detail string. Bounds both disk
/// usage and the blast radius of any accidental sensitive substring.
const MAX_DETAIL_CHARS: usize = 200;

/// Log target so lifecycle/telemetry lines surface as `component=heartbeat`
/// regardless of which module emits them (the logger derives `component=` from
/// the last `::` segment of the target).
pub const HB_LOG_TARGET: &str = "connlog_agent::heartbeat";

// ──────────────────────────────────────────────────────────────────────────
// Event model
// ──────────────────────────────────────────────────────────────────────────

/// Heartbeat lifecycle event types. These mirror the states a heartbeat
/// attempt can pass through; the agent emits the subset it can actually observe
/// through the blocking HTTP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Attempted,
    ConnectionEstablished,
    RequestSent,
    ResponseReceived,
    Accepted,
    HttpRejected,
    DnsError,
    ConnectionError,
    ConnectTimeout,
    RequestTimeout,
    TlsError,
    SerializationError,
    SignatureError,
    RateLimited,
    ServerError,
    RetryScheduled,
    RetryExhausted,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Attempted => "attempted",
            EventType::ConnectionEstablished => "connection_established",
            EventType::RequestSent => "request_sent",
            EventType::ResponseReceived => "response_received",
            EventType::Accepted => "accepted",
            EventType::HttpRejected => "http_rejected",
            EventType::DnsError => "dns_error",
            EventType::ConnectionError => "connection_error",
            EventType::ConnectTimeout => "connect_timeout",
            EventType::RequestTimeout => "request_timeout",
            EventType::TlsError => "tls_error",
            EventType::SerializationError => "serialization_error",
            EventType::SignatureError => "signature_error",
            EventType::RateLimited => "rate_limited",
            EventType::ServerError => "server_error",
            EventType::RetryScheduled => "retry_scheduled",
            EventType::RetryExhausted => "retry_exhausted",
        }
    }

    /// True for event types that represent a delivery failure (terminal or
    /// per-attempt). Used to compute the failure summary and to decide log
    /// level. `retry_scheduled` is deliberately excluded — a scheduled retry is
    /// not itself a failed cycle.
    fn is_failure(&self) -> bool {
        matches!(
            self,
            EventType::HttpRejected
                | EventType::DnsError
                | EventType::ConnectionError
                | EventType::ConnectTimeout
                | EventType::RequestTimeout
                | EventType::TlsError
                | EventType::SerializationError
                | EventType::SignatureError
                | EventType::RateLimited
                | EventType::ServerError
                | EventType::RetryExhausted
        )
    }
}

/// Coarse failure bucket used for grouping/troubleshooting. Kept separate from
/// [`EventType`] so HTTP rejections collapse onto stable, documented keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    DnsError,
    ConnectionError,
    ConnectTimeout,
    RequestTimeout,
    TlsError,
    Unauthorized,
    Forbidden,
    RateLimited,
    ServerError,
    HttpRejected,
    SerializationError,
    /// Reserved lifecycle category. Heartbeat authentication is bearer-token
    /// only (no per-request HMAC over headers/body — see requirement #3 and
    /// `http.rs`), so the current agent never produces a signature error. The
    /// category is part of the documented telemetry vocabulary and kept so a
    /// future authenticated-request format can populate it without a schema
    /// bump. `EventType::SignatureError` is already live via the read/parse path.
    #[allow(dead_code)]
    SignatureError,
    RetryExhausted,
}

impl ErrorCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCategory::DnsError => "dns_error",
            ErrorCategory::ConnectionError => "connection_error",
            ErrorCategory::ConnectTimeout => "connect_timeout",
            ErrorCategory::RequestTimeout => "request_timeout",
            ErrorCategory::TlsError => "tls_error",
            ErrorCategory::Unauthorized => "unauthorized",
            ErrorCategory::Forbidden => "forbidden",
            ErrorCategory::RateLimited => "rate_limited",
            ErrorCategory::ServerError => "server_error",
            ErrorCategory::HttpRejected => "http_rejected",
            ErrorCategory::SerializationError => "serialization_error",
            ErrorCategory::SignatureError => "signature_error",
            ErrorCategory::RetryExhausted => "retry_exhausted",
        }
    }
}

/// One persisted/emitted telemetry record.
///
/// Serialised field names are the stable, documented JSON contract consumed by
/// `diagnostics heartbeats --format json`. `schema_version` is repeated on each
/// record so a single line is self-describing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub schema_version: u32,
    /// RFC 3339 / ISO-8601 UTC timestamp (second precision), e.g.
    /// `2026-06-23T01:19:42Z`.
    pub timestamp_utc: String,
    /// Same instant as `timestamp_utc`, as Unix epoch milliseconds. Used for
    /// ordering and `--since` filtering without re-parsing the string.
    pub ts_unix_ms: u128,
    /// Opaque heartbeat/request correlation id. Stable across all attempts and
    /// retries of one heartbeat cycle.
    pub request_id: String,
    /// 1-based attempt number within the cycle.
    pub attempt: u32,
    pub event_type: String,
    /// Coarse outcome: `accepted`, `failed`, `retry`, or `pending`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_delay_ms: Option<u64>,
    /// Heartbeat endpoint host only (no scheme, port, path, or query) so no
    /// token-bearing URL is ever persisted.
    pub endpoint_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
    /// Sanitized, length-capped, secret-redacted detail. Never a raw backend
    /// response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Builder describing one event before it is stamped with a timestamp and
/// written. Construct with [`EventBuilder::new`] and the recorder fills in the
/// `schema_version`/`timestamp_utc`/`ts_unix_ms` fields at write time.
#[derive(Debug, Clone)]
pub struct EventBuilder {
    pub request_id: String,
    pub attempt: u32,
    pub event_type: EventType,
    pub http_status: Option<u16>,
    pub duration_ms: Option<u128>,
    pub retry_delay_ms: Option<u64>,
    pub endpoint_host: String,
    pub error_category: Option<ErrorCategory>,
    pub detail: Option<String>,
}

impl EventBuilder {
    pub fn new(request_id: &str, attempt: u32, event_type: EventType, endpoint_host: &str) -> Self {
        Self {
            request_id: request_id.to_string(),
            attempt,
            event_type,
            http_status: None,
            duration_ms: None,
            retry_delay_ms: None,
            endpoint_host: endpoint_host.to_string(),
            error_category: None,
            detail: None,
        }
    }

    pub fn http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    pub fn duration(mut self, dur: Duration) -> Self {
        self.duration_ms = Some(dur.as_millis());
        self
    }

    pub fn retry_delay(mut self, dur: Duration) -> Self {
        self.retry_delay_ms = Some(dur.as_millis() as u64);
        self
    }

    pub fn category(mut self, category: ErrorCategory) -> Self {
        self.error_category = Some(category);
        self
    }

    /// Attach a free-form detail string. Sanitized (secret-redacted, whitespace
    /// collapsed, length-capped) before it is stored.
    pub fn detail(mut self, raw: &str) -> Self {
        let cleaned = sanitize_detail(raw);
        if !cleaned.is_empty() {
            self.detail = Some(cleaned);
        }
        self
    }

    fn finish(self, now: SystemTime) -> TelemetryEvent {
        let ms = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let outcome = match self.event_type {
            EventType::Accepted => "accepted",
            EventType::RetryScheduled => "retry",
            EventType::Attempted
            | EventType::ConnectionEstablished
            | EventType::RequestSent
            | EventType::ResponseReceived => "pending",
            _ => "failed",
        };
        TelemetryEvent {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            timestamp_utc: format_unix_ms_utc(ms),
            ts_unix_ms: ms,
            request_id: self.request_id,
            attempt: self.attempt,
            event_type: self.event_type.as_str().to_string(),
            outcome: outcome.to_string(),
            http_status: self.http_status,
            duration_ms: self.duration_ms,
            retry_delay_ms: self.retry_delay_ms,
            endpoint_host: self.endpoint_host,
            error_category: self.error_category.map(|c| c.as_str().to_string()),
            detail: self.detail,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Recorder (write side, attached to ApiClient)
// ──────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct WriteState {
    /// Tracks whether the last write failed, so we log the failure once on the
    /// ok→failed transition (and once on recovery) instead of spamming.
    write_failed: bool,
}

/// Write handle for heartbeat telemetry. Cheap to construct; performs no I/O
/// until [`record`](Self::record) is called. All writes are serialised behind
/// `state` so overlapping heartbeat retries cannot race.
pub struct HeartbeatTelemetry {
    dir: PathBuf,
    state: Mutex<WriteState>,
}

impl HeartbeatTelemetry {
    /// Open the telemetry store at the default state directory
    /// (`$STATE_DIRECTORY`, else `$CONNLOG_STATE_DIR`, else `/var/lib/connlog`).
    /// Best-effort creates the directory; never fails — a missing/unwritable
    /// directory simply degrades into no-op writes.
    pub fn open_default() -> Self {
        Self::with_dir(default_state_dir())
    }

    /// Construct a store rooted at `dir`. Best-effort creates the directory.
    pub fn with_dir(dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&dir);
        Self {
            dir,
            state: Mutex::new(WriteState::default()),
        }
    }

    /// The active log path (for diagnostics/logging).
    pub fn log_path(&self) -> PathBuf {
        log_path(&self.dir)
    }

    /// Record one event. Best-effort and infallible by contract: a write
    /// failure is logged at most once (on transition) and otherwise swallowed
    /// so heartbeat delivery is never affected.
    pub fn record(&self, builder: EventBuilder) {
        self.record_at(builder, SystemTime::now());
    }

    /// Timestamp-injectable variant for deterministic tests.
    pub fn record_at(&self, builder: EventBuilder, now: SystemTime) {
        let event = builder.finish(now);
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match append_event(&self.dir, &event) {
            Ok(()) => {
                if guard.write_failed {
                    guard.write_failed = false;
                    log::info!(target: HB_LOG_TARGET, "heartbeat telemetry writes recovered");
                }
            }
            Err(e) => {
                if !guard.write_failed {
                    guard.write_failed = true;
                    // Single warning on the ok→failed edge. No feedback loop:
                    // this log never itself triggers a telemetry write.
                    log::warn!(
                        target: HB_LOG_TARGET,
                        "heartbeat telemetry write failed (diagnostics will be incomplete): {e}"
                    );
                }
            }
        }
    }
}

/// Append a single event line, rotating first if the active file would exceed
/// [`MAX_LOG_BYTES`]. Holds no lock itself — the caller serialises access.
fn append_event(dir: &Path, event: &TelemetryEvent) -> std::io::Result<()> {
    let mut line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    let path = log_path(dir);
    rotate_if_needed(dir, line.len() as u64)?;

    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    harden_permissions(&file);
    file.write_all(line.as_bytes())?;
    Ok(())
}

/// Rotate `heartbeat-telemetry.jsonl` → `heartbeat-telemetry.jsonl.1` when the
/// active file plus the incoming line would exceed [`MAX_LOG_BYTES`]. Keeps a
/// single rotated generation; the previous `.1` is dropped.
fn rotate_if_needed(dir: &Path, incoming_len: u64) -> std::io::Result<()> {
    let path = log_path(dir);
    let current = match fs::metadata(&path) {
        Ok(meta) => meta.len(),
        Err(_) => return Ok(()), // no file yet → nothing to rotate
    };
    if current + incoming_len <= MAX_LOG_BYTES {
        return Ok(());
    }
    let rotated = rotated_path(dir);
    let _ = fs::remove_file(&rotated);
    fs::rename(&path, &rotated)?;
    Ok(())
}

#[cfg(unix)]
fn harden_permissions(file: &fs::File) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = file.metadata() {
        let mut perms = meta.permissions();
        if perms.mode() & 0o077 != 0 {
            perms.set_mode(0o600);
            let _ = file.set_permissions(perms);
        }
    }
}

#[cfg(not(unix))]
fn harden_permissions(_file: &fs::File) {}

fn log_path(dir: &Path) -> PathBuf {
    dir.join(LOG_FILE_NAME)
}

fn rotated_path(dir: &Path) -> PathBuf {
    dir.join(format!("{LOG_FILE_NAME}.1"))
}

/// Generate an opaque, unique heartbeat/request correlation id (128 bits of
/// randomness, lowercase hex). Stable for one heartbeat cycle and shared across
/// all of its retries, the local diagnostics record, structured logs, and the
/// `X-ConnLog-Request-Id` header. Uses `ring`'s CSPRNG (already a dependency);
/// falls back to a time-derived id only if the RNG is unavailable, which never
/// happens on a supported platform.
pub fn new_request_id() -> String {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 16];
    if rng.fill(&mut bytes).is_ok() {
        let mut out = String::with_capacity(32);
        for b in bytes {
            out.push(nibble(b >> 4));
            out.push(nibble(b & 0x0f));
        }
        out
    } else {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("hb{nanos:032x}")
    }
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

/// Resolve the state directory, preferring an explicit override, then the
/// systemd-exported `$STATE_DIRECTORY`, then the compiled-in default.
pub fn default_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CONNLOG_STATE_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(dir) = std::env::var("STATE_DIRECTORY") {
        // systemd may hand back a colon-separated list; take the first entry.
        if let Some(first) = dir.split(':').find(|s| !s.is_empty()) {
            return PathBuf::from(first);
        }
    }
    PathBuf::from(crate::platform::STATE_DIR)
}

// ──────────────────────────────────────────────────────────────────────────
// Redaction
// ──────────────────────────────────────────────────────────────────────────

/// Sanitize a free-form detail string for safe persistence/display:
/// collapse whitespace, redact secret-looking substrings, then length-cap.
pub fn sanitize_detail(raw: &str) -> String {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let redacted = redact_secrets(&collapsed);
    if redacted.chars().count() > MAX_DETAIL_CHARS {
        let truncated: String = redacted.chars().take(MAX_DETAIL_CHARS).collect();
        format!("{truncated}…")
    } else {
        redacted
    }
}

/// Redact agent tokens, bearer credentials, and common secret query params.
/// Defensive: agent-side error strings rarely contain secrets, but a single
/// careless upstream change shouldn't be able to leak one into a file an action
/// can read.
fn redact_secrets(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for token in input.split_inclusive(char::is_whitespace) {
        out.push_str(&redact_word(token));
    }
    out
}

fn redact_word(word: &str) -> String {
    // Preserve any trailing whitespace captured by split_inclusive.
    let (core, trailing) = match word.char_indices().rev().find(|(_, c)| !c.is_whitespace()) {
        Some((idx, c)) => {
            let end = idx + c.len_utf8();
            (&word[..end], &word[end..])
        }
        None => return word.to_string(),
    };

    let lower = core.to_ascii_lowercase();
    let redacted = if core.contains("agent_") {
        // An agent bearer token (or anything embedding one).
        "agent_[REDACTED]".to_string()
    } else if lower.starts_with("bearer") {
        "Bearer[REDACTED]".to_string()
    } else if let Some(eq) = core.find('=') {
        let key = core[..eq].to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "token" | "access_token" | "authorization" | "api_key" | "apikey" | "secret"
        ) {
            format!("{}=[REDACTED]", &core[..eq])
        } else {
            core.to_string()
        }
    } else {
        core.to_string()
    };

    format!("{redacted}{trailing}")
}

// ──────────────────────────────────────────────────────────────────────────
// UTC timestamp formatting (dependency-free)
// ──────────────────────────────────────────────────────────────────────────

/// Format Unix epoch milliseconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC, second
/// precision). Avoids pulling in `chrono`/`time` and the binary-size budget hit.
pub fn format_unix_ms_utc(ms: u128) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert a count of days since 1970-01-01 to a `(year, month, day)` triple.
/// Howard Hinnant's well-known `civil_from_days` algorithm (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

// ──────────────────────────────────────────────────────────────────────────
// Read side: load + summarize + render (CLI)
// ──────────────────────────────────────────────────────────────────────────

/// Outcome of reading the on-disk store.
pub struct LoadOutcome {
    /// At least one telemetry file existed on disk (distinguishes "no telemetry
    /// yet" from "telemetry exists but nothing in the selected window").
    pub store_present: bool,
    /// A telemetry file existed but could not be read (e.g. permissions).
    pub unreadable: bool,
    /// Parseable records dropped because the line was corrupt/partial.
    pub corrupt_skipped: usize,
    /// Filtered (by `since`) + limited (most recent N) events, oldest first.
    pub events: Vec<TelemetryEvent>,
}

/// Load events from the store, filtered to the `since` window and limited to
/// the most recent `limit` records. `now` is injectable for deterministic
/// tests. Reads the rotated generation first so order is oldest→newest.
pub fn load_events(dir: &Path, since: Duration, limit: usize, now: SystemTime) -> LoadOutcome {
    let mut store_present = false;
    let mut unreadable = false;
    let mut corrupt_skipped = 0usize;
    let mut events: Vec<TelemetryEvent> = Vec::new();

    for path in [rotated_path(dir), log_path(dir)] {
        if !path.exists() {
            continue;
        }
        store_present = true;
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                unreadable = true;
                continue;
            }
        };
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<TelemetryEvent>(line) {
                Ok(event) => events.push(event),
                Err(_) => corrupt_skipped += 1,
            }
        }
    }

    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let cutoff = now_ms.saturating_sub(since.as_millis());
    events.retain(|e| e.ts_unix_ms >= cutoff);

    // Stable sort oldest→newest, then keep the most recent `limit`.
    events.sort_by_key(|e| e.ts_unix_ms);
    if events.len() > limit {
        let start = events.len() - limit;
        events.drain(0..start);
    }

    LoadOutcome {
        store_present,
        unreadable,
        corrupt_skipped,
        events,
    }
}

/// Per-cycle aggregation (one heartbeat cycle = one `request_id`).
struct CycleAgg {
    accepted: bool,
    attempts: u32,
    retried: bool,
    last_accepted_ms: Option<u128>,
    last_failure_ms: Option<u128>,
    last_failure_category: Option<String>,
}

/// Computed summary over a set of events.
pub struct Summary {
    pub cycles: usize,
    pub accepted: usize,
    pub failed: usize,
    pub retried: usize,
    pub last_accepted_utc: Option<String>,
    pub last_failure_utc: Option<String>,
    pub last_failure_category: Option<String>,
    /// Failure category → count, over failed cycles. `BTreeMap` for stable
    /// ordering in output.
    pub failure_categories: std::collections::BTreeMap<String, usize>,
}

/// Reduce events into a per-cycle [`Summary`].
pub fn summarize(events: &[TelemetryEvent]) -> Summary {
    let mut order: Vec<String> = Vec::new();
    let mut cycles: HashMap<String, CycleAgg> = HashMap::new();

    for event in events {
        let agg = cycles.entry(event.request_id.clone()).or_insert_with(|| {
            order.push(event.request_id.clone());
            CycleAgg {
                accepted: false,
                attempts: 0,
                retried: false,
                last_accepted_ms: None,
                last_failure_ms: None,
                last_failure_category: None,
            }
        });
        agg.attempts = agg.attempts.max(event.attempt);

        match parse_event_type(&event.event_type) {
            Some(EventType::Accepted) => {
                agg.accepted = true;
                agg.last_accepted_ms = Some(match agg.last_accepted_ms {
                    Some(prev) => prev.max(event.ts_unix_ms),
                    None => event.ts_unix_ms,
                });
            }
            Some(EventType::RetryScheduled) => agg.retried = true,
            // Latest failure wins. Events arrive oldest→newest, so `>=` keeps
            // the most recent failure's timestamp and category for this cycle.
            Some(t)
                if t.is_failure()
                    && agg
                        .last_failure_ms
                        .map(|p| event.ts_unix_ms >= p)
                        .unwrap_or(true) =>
            {
                agg.last_failure_ms = Some(event.ts_unix_ms);
                agg.last_failure_category = event
                    .error_category
                    .clone()
                    .or_else(|| Some(t.as_str().to_string()));
            }
            _ => {}
        }
    }

    let mut summary = Summary {
        cycles: order.len(),
        accepted: 0,
        failed: 0,
        retried: 0,
        last_accepted_utc: None,
        last_failure_utc: None,
        last_failure_category: None,
        failure_categories: std::collections::BTreeMap::new(),
    };

    let mut last_accepted_ms: Option<u128> = None;
    let mut last_failure_ms: Option<u128> = None;

    for id in &order {
        let agg = &cycles[id];
        if agg.attempts > 1 || agg.retried {
            summary.retried += 1;
        }
        if agg.accepted {
            summary.accepted += 1;
            if let Some(ms) = agg.last_accepted_ms {
                last_accepted_ms = Some(last_accepted_ms.map_or(ms, |p| p.max(ms)));
            }
        } else if agg.last_failure_ms.is_some() {
            summary.failed += 1;
            if let Some(category) = &agg.last_failure_category {
                *summary
                    .failure_categories
                    .entry(category.clone())
                    .or_insert(0) += 1;
            }
            if let Some(ms) = agg.last_failure_ms {
                if last_failure_ms.map(|p| ms >= p).unwrap_or(true) {
                    last_failure_ms = Some(ms);
                    summary.last_failure_category = agg.last_failure_category.clone();
                }
            }
        }
    }

    summary.last_accepted_utc = last_accepted_ms.map(format_unix_ms_utc);
    summary.last_failure_utc = last_failure_ms.map(format_unix_ms_utc);
    summary
}

fn parse_event_type(s: &str) -> Option<EventType> {
    let candidates = [
        EventType::Attempted,
        EventType::ConnectionEstablished,
        EventType::RequestSent,
        EventType::ResponseReceived,
        EventType::Accepted,
        EventType::HttpRejected,
        EventType::DnsError,
        EventType::ConnectionError,
        EventType::ConnectTimeout,
        EventType::RequestTimeout,
        EventType::TlsError,
        EventType::SerializationError,
        EventType::SignatureError,
        EventType::RateLimited,
        EventType::ServerError,
        EventType::RetryScheduled,
        EventType::RetryExhausted,
    ];
    candidates.into_iter().find(|c| c.as_str() == s)
}

/// Fully-resolved report ready for rendering.
pub struct DiagnosticsReport {
    pub generated_at_utc: String,
    pub period_label: String,
    pub period_seconds: u64,
    pub limit: usize,
    pub store_present: bool,
    pub unreadable: bool,
    pub corrupt_skipped: usize,
    pub records_inspected: usize,
    pub events: Vec<TelemetryEvent>,
    pub summary: Summary,
    pub store_path: PathBuf,
}

/// Build a report from the store. `now` injectable for tests.
pub fn build_report(
    dir: &Path,
    since: Duration,
    period_label: &str,
    limit: usize,
    now: SystemTime,
) -> DiagnosticsReport {
    let outcome = load_events(dir, since, limit, now);
    let summary = summarize(&outcome.events);
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    DiagnosticsReport {
        generated_at_utc: format_unix_ms_utc(now_ms),
        period_label: period_label.to_string(),
        period_seconds: since.as_secs(),
        limit,
        store_present: outcome.store_present,
        unreadable: outcome.unreadable,
        corrupt_skipped: outcome.corrupt_skipped,
        records_inspected: outcome.events.len(),
        events: outcome.events,
        summary,
        store_path: log_path(dir),
    }
}

/// Render the human-readable text report.
pub fn render_text(report: &DiagnosticsReport) -> String {
    let mut out = String::new();
    out.push_str("Heartbeat diagnostics\n");
    out.push_str(&format!("Period: last {}\n", report.period_label));

    if !report.store_present {
        out.push('\n');
        if report.unreadable {
            out.push_str("Heartbeat telemetry exists but could not be read by the current user.\n");
            out.push_str(&format!(
                "Run as the service account: it lives at {} (0700 connlog-agent).\n",
                report.store_path.display()
            ));
        } else {
            out.push_str("No heartbeat telemetry recorded yet.\n");
            out.push_str(&format!(
                "The agent has not written any records to {} yet.\n",
                report.store_path.display()
            ));
            out.push_str(
                "This is expected on a freshly updated agent until the next heartbeat cycle completes.\n",
            );
        }
        return out;
    }

    if report.records_inspected == 0 {
        out.push('\n');
        if report.unreadable {
            out.push_str(
                "Some heartbeat telemetry files exist but could not be read by the current user.\n",
            );
        }
        out.push_str(&format!(
            "No heartbeat events in the last {} (the store may hold older records).\n",
            report.period_label
        ));
        return out;
    }

    let s = &report.summary;
    out.push_str(&format!(
        "Records inspected: {}\n",
        report.records_inspected
    ));
    out.push_str(&format!("Heartbeat cycles: {}\n", s.cycles));
    out.push_str(&format!("Accepted: {}\n", s.accepted));
    out.push_str(&format!("Failed: {}\n", s.failed));
    out.push_str(&format!("Retried: {}\n", s.retried));
    out.push_str(&format!(
        "Last accepted heartbeat: {}\n",
        s.last_accepted_utc.as_deref().unwrap_or("none")
    ));
    match (&s.last_failure_utc, &s.last_failure_category) {
        (Some(ts), Some(cat)) => out.push_str(&format!("Last failure: {ts} ({cat})\n")),
        (Some(ts), None) => out.push_str(&format!("Last failure: {ts}\n")),
        _ => out.push_str("Last failure: none\n"),
    }

    if !s.failure_categories.is_empty() {
        out.push_str("\nFailure categories:\n");
        for (cat, count) in &s.failure_categories {
            out.push_str(&format!("- {cat}: {count}\n"));
        }
    }

    if report.corrupt_skipped > 0 {
        out.push_str(&format!(
            "\nNote: skipped {} corrupt/partial record(s) while reading.\n",
            report.corrupt_skipped
        ));
    }

    out.push_str("\nEvents (most recent last):\n");
    for event in &report.events {
        let id_short: String = event.request_id.chars().take(8).collect();
        let status = event
            .http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());
        let dur = event
            .duration_ms
            .map(|d| format!("{d}ms"))
            .unwrap_or_else(|| "-".to_string());
        let mut line = format!(
            "{}  hb={}  attempt={}  {:<16}  status={:<4}  dur={:<8}  host={}",
            event.timestamp_utc,
            id_short,
            event.attempt,
            event.event_type,
            status,
            dur,
            event.endpoint_host,
        );
        if let Some(delay) = event.retry_delay_ms {
            line.push_str(&format!("  retry_in={delay}ms"));
        }
        if let Some(detail) = &event.detail {
            line.push_str(&format!("  detail={detail}"));
        }
        out.push_str(&line);
        out.push('\n');
    }

    out
}

/// Machine-readable JSON document. Stable, documented, schema-versioned.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    generated_at_utc: &'a str,
    period: &'a str,
    period_seconds: u64,
    limit: usize,
    /// `no_telemetry` (store empty/absent) or `ok`.
    status: &'static str,
    store_present: bool,
    records_inspected: usize,
    corrupt_skipped: usize,
    summary: JsonSummary<'a>,
    events: &'a [TelemetryEvent],
}

#[derive(Serialize)]
struct JsonSummary<'a> {
    heartbeat_cycles: usize,
    accepted: usize,
    failed: usize,
    retried: usize,
    last_accepted_utc: Option<&'a str>,
    last_failure_utc: Option<&'a str>,
    last_failure_category: Option<&'a str>,
    failure_categories: &'a std::collections::BTreeMap<String, usize>,
}

/// Render the report as a pretty JSON string. Pure JSON: no human-readable
/// lines are emitted before or after.
pub fn render_json(report: &DiagnosticsReport) -> serde_json::Result<String> {
    let status = if report.records_inspected == 0 {
        "no_telemetry"
    } else {
        "ok"
    };
    let doc = JsonReport {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        generated_at_utc: &report.generated_at_utc,
        period: &report.period_label,
        period_seconds: report.period_seconds,
        limit: report.limit,
        status,
        store_present: report.store_present,
        records_inspected: report.records_inspected,
        corrupt_skipped: report.corrupt_skipped,
        summary: JsonSummary {
            heartbeat_cycles: report.summary.cycles,
            accepted: report.summary.accepted,
            failed: report.summary.failed,
            retried: report.summary.retried,
            last_accepted_utc: report.summary.last_accepted_utc.as_deref(),
            last_failure_utc: report.summary.last_failure_utc.as_deref(),
            last_failure_category: report.summary.last_failure_category.as_deref(),
            failure_categories: &report.summary.failure_categories,
        },
        events: &report.events,
    };
    serde_json::to_string_pretty(&doc)
}

// ──────────────────────────────────────────────────────────────────────────
// CLI entry point
// ──────────────────────────────────────────────────────────────────────────

/// `connlog-agent diagnostics heartbeats`. Reads the local store only — never
/// contacts the API, never mutates state, never sends a heartbeat, and requires
/// no root.
pub fn run_diagnostics_cli(
    since: &str,
    limit: usize,
    format: DiagnosticsFormat,
) -> anyhow::Result<()> {
    let period = parse_lookback(since)?;
    let dir = default_state_dir();
    let report = build_report(&dir, period, since, limit, SystemTime::now());

    match format {
        DiagnosticsFormat::Text => println!("{}", render_text(&report)),
        DiagnosticsFormat::Json => {
            let json = render_json(&report)
                .map_err(|e| anyhow::anyhow!("failed to serialise diagnostics JSON: {e}"))?;
            println!("{json}");
        }
    }
    Ok(())
}

/// Parse a lookback window such as `24h`, `72h`, `30m`, `90s`, `7d`. A bare
/// integer is interpreted as seconds.
pub fn parse_lookback(input: &str) -> anyhow::Result<Duration> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty duration");
    }
    let (value_part, unit_secs) = match trimmed.chars().last().unwrap() {
        's' => (&trimmed[..trimmed.len() - 1], 1u64),
        'm' => (&trimmed[..trimmed.len() - 1], 60),
        'h' => (&trimmed[..trimmed.len() - 1], 3600),
        'd' => (&trimmed[..trimmed.len() - 1], 86_400),
        c if c.is_ascii_digit() => (trimmed, 1),
        other => anyhow::bail!("invalid duration unit '{other}' (use s, m, h, or d)"),
    };
    let value: u64 = value_part
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration value in '{input}'"))?;
    value
        .checked_mul(unit_secs)
        .map(Duration::from_secs)
        .ok_or_else(|| anyhow::anyhow!("duration '{input}' is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("connlog-telemetry-{tag}-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn at(ms: u128) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    }

    fn builder(id: &str, attempt: u32, ev: EventType) -> EventBuilder {
        EventBuilder::new(id, attempt, ev, "connlog.com")
    }

    // ── timestamp formatting ────────────────────────────────────

    #[test]
    fn format_epoch_zero() {
        assert_eq!(format_unix_ms_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_known_timestamp() {
        // 2026-06-23T01:19:42Z = 1782177582 seconds since the Unix epoch.
        let ms = 1_782_177_582_000u128;
        assert_eq!(format_unix_ms_utc(ms), "2026-06-23T01:19:42Z");
    }

    #[test]
    fn format_leap_year_day() {
        // 2024-02-29T12:00:00Z = 1709208000.
        assert_eq!(
            format_unix_ms_utc(1_709_208_000_000),
            "2024-02-29T12:00:00Z"
        );
    }

    // ── duration parsing ────────────────────────────────────────

    #[test]
    fn parse_lookback_units() {
        assert_eq!(
            parse_lookback("72h").unwrap(),
            Duration::from_secs(72 * 3600)
        );
        assert_eq!(parse_lookback("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_lookback("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_lookback("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(
            parse_lookback("7d").unwrap(),
            Duration::from_secs(7 * 86_400)
        );
        assert_eq!(parse_lookback("120").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn parse_lookback_rejects_garbage() {
        assert!(parse_lookback("").is_err());
        assert!(parse_lookback("abc").is_err());
        assert!(parse_lookback("10x").is_err());
    }

    // ── redaction ───────────────────────────────────────────────

    #[test]
    fn redaction_strips_agent_token() {
        let raw = "auth failed for Bearer agent_supersecret_TOKEN at host";
        let cleaned = sanitize_detail(raw);
        assert!(!cleaned.contains("supersecret"), "got: {cleaned}");
        assert!(!cleaned.contains("agent_supersecret"), "got: {cleaned}");
        assert!(cleaned.contains("[REDACTED]"));
    }

    #[test]
    fn redaction_strips_token_query_param() {
        let cleaned = sanitize_detail("error url contains token=abc123def");
        assert!(!cleaned.contains("abc123def"), "got: {cleaned}");
        assert!(cleaned.contains("token=[REDACTED]"));
    }

    #[test]
    fn redaction_caps_length() {
        let raw = "x".repeat(1000);
        let cleaned = sanitize_detail(&raw);
        assert!(
            cleaned.chars().count() <= MAX_DETAIL_CHARS + 1,
            "got len {}",
            cleaned.chars().count()
        );
    }

    #[test]
    fn redaction_collapses_whitespace_and_newlines() {
        let cleaned = sanitize_detail("line one\n\tline two   line three");
        assert_eq!(cleaned, "line one line two line three");
    }

    // ── recording + load ────────────────────────────────────────

    #[test]
    fn records_and_reads_back_accepted_event() {
        let dir = tmp_dir("accepted");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        store.record_at(
            builder("req-accept-1", 1, EventType::Accepted)
                .http_status(200)
                .duration(Duration::from_millis(84)),
            at(1_000_000),
        );

        let outcome = load_events(&dir, Duration::from_secs(3600), 100, at(1_000_500));
        assert!(outcome.store_present);
        assert_eq!(outcome.events.len(), 1);
        let ev = &outcome.events[0];
        assert_eq!(ev.event_type, "accepted");
        assert_eq!(ev.http_status, Some(200));
        assert_eq!(ev.outcome, "accepted");
        assert_eq!(ev.request_id, "req-accept-1");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_store_is_distinct_from_all_succeeded() {
        let dir = tmp_dir("empty");
        // Nothing written.
        let report = build_report(&dir, Duration::from_secs(3600), "1h", 100, at(2_000_000));
        assert!(!report.store_present);
        let text = render_text(&report);
        assert!(
            text.contains("No heartbeat telemetry recorded yet"),
            "got: {text}"
        );

        // Now an all-succeeded store.
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        store.record_at(
            builder("c1", 1, EventType::Accepted).http_status(200),
            at(2_000_001),
        );
        let report = build_report(&dir, Duration::from_secs(3600), "1h", 100, at(2_000_002));
        let text = render_text(&report);
        assert!(text.contains("Accepted: 1"), "got: {text}");
        assert!(text.contains("Failed: 0"), "got: {text}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn since_filter_excludes_old_events() {
        let dir = tmp_dir("since");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        // Old event, 10h ago.
        store.record_at(
            builder("old", 1, EventType::Accepted).http_status(200),
            at(0),
        );
        // Recent event.
        let now = 10 * 3600 * 1000;
        store.record_at(
            builder("new", 1, EventType::Accepted).http_status(200),
            at(now),
        );

        let outcome = load_events(&dir, Duration::from_secs(3600), 100, at(now + 1000));
        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.events[0].request_id, "new");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn limit_keeps_most_recent() {
        let dir = tmp_dir("limit");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        for i in 0..10u128 {
            store.record_at(
                builder(&format!("c{i}"), 1, EventType::Accepted).http_status(200),
                at(1000 + i * 1000),
            );
        }
        let outcome = load_events(&dir, Duration::from_secs(86_400), 3, at(20_000));
        assert_eq!(outcome.events.len(), 3);
        // Most recent three kept, oldest-first ordering.
        assert_eq!(outcome.events[0].request_id, "c7");
        assert_eq!(outcome.events[2].request_id, "c9");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_lines_are_skipped() {
        let dir = tmp_dir("corrupt");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        store.record_at(
            builder("ok", 1, EventType::Accepted).http_status(200),
            at(1000),
        );
        // Append a torn/garbage line directly.
        let path = log_path(&dir);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{not valid json\n").unwrap();
        f.write_all(b"\n").unwrap();
        drop(f);

        let outcome = load_events(&dir, Duration::from_secs(3600), 100, at(2000));
        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.corrupt_skipped, 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotation_bounds_disk_and_preserves_recent_events() {
        let dir = tmp_dir("rotate");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        // Write enough events to force at least one rotation.
        let count = 8000u128;
        for i in 0..count {
            store.record_at(
                builder(&format!("cycle-{i}"), 1, EventType::Accepted)
                    .http_status(200)
                    .detail("ok"),
                at(1000 + i),
            );
        }
        // Total on-disk usage must be bounded (≤ ~2× MAX_LOG_BYTES).
        let mut total = 0u64;
        for p in [log_path(&dir), rotated_path(&dir)] {
            if let Ok(meta) = fs::metadata(&p) {
                total += meta.len();
            }
        }
        assert!(
            total <= 2 * MAX_LOG_BYTES + 4096,
            "telemetry exceeded bound: {total} bytes"
        );
        // The most recent event must still be present after rotation.
        let outcome = load_events(&dir, Duration::from_secs(86_400), 100_000, at(1_000_000));
        let last = outcome.events.last().expect("at least one event survives");
        assert_eq!(last.request_id, format!("cycle-{}", count - 1));
        fs::remove_dir_all(&dir).ok();
    }

    // ── summary semantics ───────────────────────────────────────

    #[test]
    fn summary_counts_retry_lifecycle() {
        let dir = tmp_dir("summary-retry");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        // Cycle that fails once (server_error), schedules a retry, then accepts.
        store.record_at(
            builder("retry-cycle", 1, EventType::ServerError)
                .http_status(503)
                .category(ErrorCategory::ServerError),
            at(1000),
        );
        store.record_at(
            builder("retry-cycle", 1, EventType::RetryScheduled)
                .retry_delay(Duration::from_millis(250)),
            at(1100),
        );
        store.record_at(
            builder("retry-cycle", 2, EventType::Accepted).http_status(200),
            at(1500),
        );
        let outcome = load_events(&dir, Duration::from_secs(3600), 100, at(2000));
        let s = summarize(&outcome.events);
        assert_eq!(s.cycles, 1);
        assert_eq!(s.accepted, 1);
        assert_eq!(
            s.failed, 0,
            "a cycle that eventually accepted is not failed"
        );
        assert_eq!(s.retried, 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn summary_groups_failures_by_category() {
        let events = vec![
            builder("a", 1, EventType::ConnectTimeout)
                .category(ErrorCategory::ConnectTimeout)
                .finish(at(1000)),
            builder("b", 1, EventType::ConnectTimeout)
                .category(ErrorCategory::ConnectTimeout)
                .finish(at(2000)),
            builder("c", 1, EventType::DnsError)
                .category(ErrorCategory::DnsError)
                .finish(at(3000)),
            builder("d", 1, EventType::Accepted)
                .http_status(200)
                .finish(at(4000)),
        ];
        let s = summarize(&events);
        assert_eq!(s.cycles, 4);
        assert_eq!(s.accepted, 1);
        assert_eq!(s.failed, 3);
        assert_eq!(s.failure_categories.get("connect_timeout"), Some(&2));
        assert_eq!(s.failure_categories.get("dns_error"), Some(&1));
        assert_eq!(s.last_failure_category.as_deref(), Some("dns_error"));
        assert_eq!(
            s.last_failure_utc.as_deref(),
            Some(format_unix_ms_utc(3000)).as_deref()
        );
    }

    // ── JSON output ─────────────────────────────────────────────

    #[test]
    fn json_output_is_valid_and_stable() {
        let dir = tmp_dir("json");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        store.record_at(
            builder("json-cycle", 1, EventType::Accepted)
                .http_status(200)
                .duration(Duration::from_millis(42)),
            at(5000),
        );
        let report = build_report(&dir, Duration::from_secs(3600), "1h", 100, at(6000));
        let json = render_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["schema_version"], TELEMETRY_SCHEMA_VERSION);
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["period"], "1h");
        assert_eq!(parsed["summary"]["accepted"], 1);
        assert_eq!(parsed["summary"]["failed"], 0);
        assert!(parsed["generated_at_utc"].is_string());
        assert_eq!(parsed["events"][0]["request_id"], "json-cycle");
        assert_eq!(parsed["events"][0]["http_status"], 200);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn json_no_telemetry_status() {
        let dir = tmp_dir("json-empty");
        let report = build_report(&dir, Duration::from_secs(3600), "1h", 100, at(6000));
        let json = render_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "no_telemetry");
        assert_eq!(parsed["records_inspected"], 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn json_does_not_leak_secrets_in_detail() {
        let dir = tmp_dir("json-secret");
        let store = HeartbeatTelemetry::with_dir(dir.clone());
        store.record_at(
            builder("s", 1, EventType::ConnectionError)
                .category(ErrorCategory::ConnectionError)
                .detail("connect failed Bearer agent_DEADBEEF_secret"),
            at(7000),
        );
        let report = build_report(&dir, Duration::from_secs(3600), "1h", 100, at(8000));
        let json = render_json(&report).unwrap();
        assert!(
            !json.contains("DEADBEEF"),
            "secret leaked into JSON: {json}"
        );
        assert!(json.contains("[REDACTED]"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_failure_is_swallowed() {
        // Point the store at a path that cannot be created (a file where a dir
        // is expected) and confirm record() never panics or blocks.
        let base = tmp_dir("writefail");
        let file_as_dir = base.join("not-a-dir");
        fs::write(&file_as_dir, b"x").unwrap();
        let store = HeartbeatTelemetry::with_dir(file_as_dir.clone());
        // Must not panic.
        store.record_at(
            builder("x", 1, EventType::Accepted).http_status(200),
            at(1000),
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn request_ids_are_unique_lowercase_hex() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b, "ids must be unique");
        assert_eq!(a.len(), 32, "id must be 32 hex chars");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "id must be lowercase hex: {a}"
        );
    }

    #[test]
    fn default_state_dir_prefers_override() {
        std::env::set_var("CONNLOG_STATE_DIR", "/tmp/connlog-test-override");
        assert_eq!(
            default_state_dir(),
            PathBuf::from("/tmp/connlog-test-override")
        );
        std::env::remove_var("CONNLOG_STATE_DIR");
    }
}
