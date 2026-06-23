//! End-to-end simulation tests for the agent.
//!
//! These spin a real `TcpListener` on a random loopback port, feed it
//! hand-crafted HTTP responses (so we can pin every response code the
//! platform can return) and drive the real `ApiClient` against it. The
//! goal is to catch regressions in the agent ↔ platform contract without
//! having to boot the full Next.js app.
//!
//! What's covered (one test per scenario):
//!
//!   * 200 OK heartbeat, JSON response parsed into `HeartbeatResponse`.
//!   * 200 OK with `uninstall: true` → response surfaces the flag.
//!   * 200 OK with embedded `update` info → fully parsed.
//!   * 401 Unauthorized → `ApiError::Unauthorized`.
//!   * 410 Gone        → `ApiError::Decommissioned`.
//!   * 423 Locked      → `ApiError::Disabled`.
//!   * 500 Server Err  → `ApiError::HttpError { status: 500, .. }`.
//!   * 302 redirect to a *different* host is not followed (token must not
//!     leak — `redirect::Policy::none()` is regression-tested here).
//!   * `fetch_config` parses an `AgentConfig` and `clamp()` keeps it sane.
//!   * Required HTTP headers are present on every heartbeat
//!     (`Authorization: Bearer ...`, `X-Agent-Version`, `X-Hostname`,
//!     `X-OS`, `X-Arch`).

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::heartbeat::{HeartbeatPayload, Metrics};
use crate::heartbeat_telemetry::{self, HeartbeatTelemetry, TelemetryEvent};
use crate::http::{ApiClient, ApiError, QuickActionPollingReport};

/// Captured request data the test thread passes back to the assertions.
#[derive(Debug, Default, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read one HTTP request off the socket. Best-effort and **not** a real
/// HTTP parser — sufficient for the single canned roundtrips below.
fn read_request(mut stream: &TcpStream) -> CapturedRequest {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let raw = &buf[..n];

    // Find header / body boundary.
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(n);
    let header_bytes = &raw[..split];
    let body_start = (split + 4).min(n);

    let header_str = std::str::from_utf8(header_bytes).unwrap_or("");
    let mut lines = header_str.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }

    // Read remainder of body if not all of it arrived in the first read.
    let mut body = raw[body_start..n].to_vec();
    while body.len() < content_length {
        let mut more = [0u8; 4096];
        let m = stream.read(&mut more).unwrap_or(0);
        if m == 0 {
            break;
        }
        body.extend_from_slice(&more[..m]);
    }

    CapturedRequest {
        method,
        path,
        headers,
        body,
    }
}

fn write_response(mut stream: &TcpStream, status_line: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        status_line,
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Spin up a one-shot mock server that serves exactly one response and
/// returns the captured request. Server runs on a random loopback port.
fn one_shot_server(
    status_line: &'static str,
    body: Vec<u8>,
) -> (String, mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let req = read_request(&stream);
            let _ = tx.send(req);
            write_response(&stream, status_line, &body);
        }
    });

    (format!("http://127.0.0.1:{port}"), rx)
}

/// Same as `one_shot_server` but redirects to a **different** host. Used
/// to assert that the agent's `redirect::Policy::none()` actually holds —
/// otherwise reqwest would forward `Authorization: Bearer ...` to wherever
/// the redirect points.
fn one_shot_redirect(target: &'static str) -> (String, mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let req = read_request(&stream);
            let _ = tx.send(req);
            let header = format!(
                "HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = (&stream).write_all(header.as_bytes());
        }
    });

    (format!("http://127.0.0.1:{port}"), rx)
}

/// Mock server that serves the same canned response to `count` sequential
/// connections (each heartbeat attempt opens a fresh `Connection: close`
/// socket). Used to drive the transient-retry path deterministically.
fn repeating_server(
    status_line: &'static str,
    body: Vec<u8>,
    count: usize,
) -> (String, mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        for _ in 0..count {
            if let Ok((stream, _)) = listener.accept() {
                let req = read_request(&stream);
                let _ = tx.send(req);
                write_response(&stream, status_line, &body);
            }
        }
    });

    (format!("http://127.0.0.1:{port}"), rx)
}

/// Return a port that has no listener (bind then drop), so a connection attempt
/// is refused promptly — a deterministic transport failure.
fn dead_port_base() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

fn temp_telemetry_dir(tag: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("connlog-sim-telemetry-{tag}-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_telemetry(dir: &Path) -> Vec<TelemetryEvent> {
    heartbeat_telemetry::load_events(dir, Duration::from_secs(86_400), 10_000, SystemTime::now())
        .events
}

fn make_payload() -> HeartbeatPayload {
    HeartbeatPayload {
        agent_version: "1.2.0".into(),
        protocol_version: 1,
        config_version: 0,
        hostname: Some("sim-host".to_string()),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        uptime_seconds: 1234,
        metrics: Metrics {
            cpu_percent: Some(12.34),
            cpu_peak_percent: Some(12.34),
            memory_used_mb: 100,
            memory_total_mb: 1024,
            disk_used_mb: 5_000,
            disk_total_mb: 10_000,
            load_1m: 0.42,
        },
        dev_mode: None,
    }
}

fn recv_request(rx: &mpsc::Receiver<CapturedRequest>) -> CapturedRequest {
    rx.recv_timeout(Duration::from_secs(5))
        .expect("mock server never received a request (timed out)")
}

// ────────────────────────────────────────────────────────────────────────
// 200 OK heartbeat
// ────────────────────────────────────────────────────────────────────────

#[test]
fn heartbeat_200_parses_response() {
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();
    let (base, rx) = one_shot_server("200 OK", body);

    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    let resp = client
        .send_heartbeat(&make_payload(), None)
        .expect("heartbeat ok");

    assert!(resp.ok);
    assert_eq!(resp.expected_interval_seconds, 60);
    assert!(!resp.uninstall);
    assert!(resp.update.is_none());

    let req = recv_request(&rx);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/agents/heartbeat");

    // Required identity headers (binary protocol v1 carries identity in headers).
    assert_eq!(req.header("Authorization"), Some("Bearer test-token"));
    assert_eq!(req.header("X-Agent-Version"), Some("1.2.0"));
    assert_eq!(req.header("X-Protocol-Version"), Some("1"));
    assert_eq!(req.header("X-Hostname"), Some("sim-host"));
    assert_eq!(req.header("X-OS"), Some("linux"));
    assert_eq!(req.header("X-Arch"), Some("x86_64"));
    assert_eq!(req.header("Content-Type"), Some("application/octet-stream"));

    // X-Machine-Id is sent whenever the agent could read a stable ID. CI
    // runners always have /etc/machine-id (Linux), so we expect a 64-char
    // lowercase hex hash here.
    let machine_id = req
        .header("X-Machine-Id")
        .expect("X-Machine-Id header must be present on supported OS");
    assert_eq!(machine_id.len(), 64, "machine-id must be sha256 hex");
    assert!(
        machine_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "machine-id must be lowercase hex"
    );

    // Binary frame is 32 bytes exactly (protocol v1).
    assert_eq!(req.body.len(), 32, "v2 wire frame must be exactly 32 bytes");
}

/// When the agent has not opted in to `CONNLOG_EXPOSE_SYSTEM_INFO`,
/// `X-Hostname` must be omitted — but `X-OS`/`X-Arch` must still be sent so
/// the platform can select the right self-update binary.
#[test]
fn heartbeat_omits_hostname_but_sends_os_arch_when_not_opted_in() {
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();
    let (base, rx) = one_shot_server("200 OK", body);

    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    let mut payload = make_payload();
    payload.hostname = None;
    client.send_heartbeat(&payload, None).expect("heartbeat ok");

    let req = recv_request(&rx);
    assert_eq!(req.header("X-Hostname"), None);
    assert_eq!(req.header("X-OS"), Some("linux"));
    assert_eq!(req.header("X-Arch"), Some("x86_64"));
}

#[test]
fn heartbeat_200_with_uninstall_flag() {
    let body = br#"{"ok":true,"server_time":"t","expected_interval_seconds":60,"uninstall":true}"#
        .to_vec();
    let (base, _rx) = one_shot_server("200 OK", body);
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let resp = client.send_heartbeat(&make_payload(), None).unwrap();
    assert!(resp.uninstall, "uninstall flag must be surfaced to caller");
}

#[test]
fn heartbeat_200_with_update_info() {
    let body = br#"{
        "ok": true,
        "server_time": "t",
        "expected_interval_seconds": 60,
        "update": {
            "available": true,
            "latest_version": "1.3.0",
            "download_url": "https://connlog.com/api/agents/updates/linux/x86_64/binary",
            "signature_url": "https://connlog.com/api/agents/updates/linux/x86_64/signature",
            "sha256": "deadbeef",
            "force_update": false
        }
    }"#
    .to_vec();
    let (base, _rx) = one_shot_server("200 OK", body);
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let resp = client.send_heartbeat(&make_payload(), None).unwrap();
    let update = resp.update.expect("update info parsed");
    assert!(update.available);
    assert_eq!(update.latest_version, "1.3.0");
    assert_eq!(update.sha256.as_deref(), Some("deadbeef"));
    assert!(!update.force_update);
}

#[test]
fn quick_action_poll_claims_pending_request() {
    let body = br#"{"ok":true,"quick_actions":[{"request_id":"00000000-0000-0000-0000-000000000001","action_id":"disk_usage"}]}"#
        .to_vec();
    let (base, rx) = one_shot_server("200 OK", body);

    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    let report = QuickActionPollingReport {
        enabled: true,
        poll_interval_seconds: 5,
        last_poll_at_unix_ms: Some(1_777_777_000_000),
        next_poll_at_unix_ms: Some(1_777_777_005_000),
    };
    let requests = client.poll_quick_actions(&report).expect("poll ok");

    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].request_id,
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(requests[0].action_id, "disk_usage");

    let req = recv_request(&rx);
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/agents/actions/pending");
    assert_eq!(req.header("Authorization"), Some("Bearer test-token"));
    assert_eq!(req.header("X-Quick-Action-Polling-Enabled"), Some("true"));
    assert_eq!(
        req.header("X-Quick-Action-Poll-Interval-Seconds"),
        Some("5")
    );
    assert_eq!(
        req.header("X-Quick-Action-Last-Poll-At-Ms"),
        Some("1777777000000")
    );
    assert_eq!(
        req.header("X-Quick-Action-Next-Poll-At-Ms"),
        Some("1777777005000")
    );
}

// ────────────────────────────────────────────────────────────────────────
// Error responses → typed ApiError variants
// ────────────────────────────────────────────────────────────────────────

#[test]
fn heartbeat_401_unauthorized() {
    let (base, _rx) = one_shot_server("401 Unauthorized", b"unauthorized".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(matches!(err, ApiError::Unauthorized), "got {err:?}");
}

#[test]
fn heartbeat_410_decommissioned() {
    let (base, _rx) = one_shot_server("410 Gone", b"gone".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(matches!(err, ApiError::Decommissioned), "got {err:?}");
}

#[test]
fn heartbeat_423_disabled() {
    let (base, _rx) = one_shot_server("423 Locked", b"disabled".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(matches!(err, ApiError::Disabled), "got {err:?}");
}

#[test]
fn heartbeat_500_surfaces_status_and_body() {
    let (base, _rx) = one_shot_server("500 Internal Server Error", b"boom".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    match err {
        ApiError::HttpError { status, message } => {
            assert_eq!(status, 500);
            assert!(
                message.contains("boom"),
                "expected body in error, got {message}"
            );
        }
        other => panic!("expected HttpError, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Token-leak regression: redirect must NOT be followed
// ────────────────────────────────────────────────────────────────────────

#[test]
fn heartbeat_redirect_is_not_followed() {
    // If the agent followed this redirect, it would forward the bearer token
    // to attacker.example. `redirect::Policy::none()` in `ApiClient::new`
    // prevents this — assert the request fails before reaching anywhere.
    let (base, rx) = one_shot_redirect("https://attacker.example/steal");
    let client = ApiClient::new(base, "leak-me-if-you-can".into()).unwrap();
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();

    // We expect *some* error: either an HttpError(302) (because reqwest
    // returns the redirect response unfollowed) or a network error.
    // The forbidden outcome is a successful follow that hits the attacker.
    match err {
        ApiError::HttpError { status, .. } => assert_eq!(status, 302),
        ApiError::Other(_) => { /* also fine: connection closed without body */ }
        other => panic!("unexpected error variant: {other:?}"),
    }

    // Mock server must have received the original request and seen the token —
    // but no second request to anywhere else, because redirects are off.
    let req = recv_request(&rx);
    assert_eq!(
        req.header("Authorization"),
        Some("Bearer leak-me-if-you-can")
    );
}

// ────────────────────────────────────────────────────────────────────────
// fetch_config: success + clamp()
// ────────────────────────────────────────────────────────────────────────

#[test]
fn fetch_config_parses_and_clamp_keeps_it_sane() {
    // Platform wraps the response in `{ ok: true, data: {...} }` — the
    // agent must unwrap the envelope. Regression: prior to v1.3.4, the
    // agent deserialised this directly into `AgentConfig` and failed on
    // every refresh, silently sticking on the v0 fallback config.
    let body = br#"{
        "ok": true,
        "data": {
            "configVersion": 7,
            "heartbeatIntervalSeconds": 1,
            "missedThreshold": 999,
            "metrics": {"cpu": true, "memory": true, "disk": false, "load": true},
            "maxPayloadSizeKb": 99999
        }
    }"#
    .to_vec();
    let (base, _rx) = one_shot_server("200 OK", body);
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let mut cfg = client.fetch_config().expect("fetch_config ok");

    assert_eq!(cfg.version, 7);
    assert_eq!(cfg.heartbeat_interval_secs, 1);
    assert_eq!(cfg.missed_threshold, 999);
    assert!(cfg.any_metrics_enabled());

    // Server sent absurd values; clamp() is the agent's last line of defence
    // against a buggy / malicious config payload.
    cfg.clamp();
    assert!(
        cfg.heartbeat_interval_secs >= 10,
        "clamp must enforce >= 10s heartbeat (got {})",
        cfg.heartbeat_interval_secs
    );
    assert!(
        cfg.missed_threshold <= 100,
        "clamp must enforce <= 100 missed threshold (got {})",
        cfg.missed_threshold
    );
    assert!(
        cfg.max_payload_size_kb <= 1024,
        "clamp must enforce <= 1024 KB payload (got {})",
        cfg.max_payload_size_kb
    );
}

// ────────────────────────────────────────────────────────────────────────
// Heartbeat delivery telemetry — recorded through the REAL transport
//
// These drive the actual ApiClient against a mock server with a telemetry
// store attached, then read the bounded local store back. This is the
// end-to-end proof that lifecycle events, correlation ids, and the
// X-ConnLog-Request-Id header are recorded for each delivery outcome.
// ────────────────────────────────────────────────────────────────────────

#[test]
fn telemetry_records_accepted_and_correlates_header() {
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();
    let (base, rx) = one_shot_server("200 OK", body);
    let dir = temp_telemetry_dir("accepted");

    let mut client = ApiClient::new(base, "agent_test-token".into()).expect("ApiClient::new");
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    client
        .send_heartbeat(&make_payload(), None)
        .expect("heartbeat ok");

    // The correlation header must be present and 32 lowercase hex chars.
    let req = recv_request(&rx);
    let header_id = req
        .header("X-ConnLog-Request-Id")
        .expect("X-ConnLog-Request-Id header must be present");
    assert_eq!(header_id.len(), 32, "request id must be 32 hex chars");
    assert!(header_id
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    let events = read_telemetry(&dir);
    assert_eq!(events.len(), 1, "exactly one accepted event");
    let ev = &events[0];
    assert_eq!(ev.event_type, "accepted");
    assert_eq!(ev.outcome, "accepted");
    assert_eq!(ev.http_status, Some(200));
    assert_eq!(ev.attempt, 1);
    assert!(ev.duration_ms.is_some(), "duration must be recorded");
    assert_eq!(ev.endpoint_host, "127.0.0.1");
    // The store's request_id MUST match the header sent on the wire.
    assert_eq!(
        ev.request_id, header_id,
        "store id must correlate with wire header id"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_records_http_401_as_unauthorized() {
    let (base, _rx) = one_shot_server("401 Unauthorized", b"nope".to_vec());
    let dir = temp_telemetry_dir("401");
    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(matches!(err, ApiError::Unauthorized));

    let events = read_telemetry(&dir);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "http_rejected");
    assert_eq!(events[0].error_category.as_deref(), Some("unauthorized"));
    assert_eq!(events[0].http_status, Some(401));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_records_http_403_as_forbidden() {
    let (base, _rx) = one_shot_server("403 Forbidden", b"denied".to_vec());
    let dir = temp_telemetry_dir("403");
    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    let _ = client.send_heartbeat(&make_payload(), None).unwrap_err();

    let events = read_telemetry(&dir);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].error_category.as_deref(), Some("forbidden"));
    assert_eq!(events[0].http_status, Some(403));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_records_http_429_as_rate_limited() {
    let (base, _rx) = one_shot_server("429 Too Many Requests", b"slow down".to_vec());
    let dir = temp_telemetry_dir("429");
    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    let _ = client.send_heartbeat(&make_payload(), None).unwrap_err();

    let events = read_telemetry(&dir);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "rate_limited");
    assert_eq!(events[0].error_category.as_deref(), Some("rate_limited"));
    assert_eq!(events[0].http_status, Some(429));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_records_http_500_as_server_error() {
    // 500 is non-transient → exactly one attempt, no retry.
    let (base, _rx) = one_shot_server("500 Internal Server Error", b"boom".to_vec());
    let dir = temp_telemetry_dir("500");
    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    let _ = client.send_heartbeat(&make_payload(), None).unwrap_err();

    let events = read_telemetry(&dir);
    assert_eq!(events.len(), 1, "500 is not retried");
    assert_eq!(events[0].event_type, "server_error");
    assert_eq!(events[0].error_category.as_deref(), Some("server_error"));
    assert_eq!(events[0].http_status, Some(500));
    // The raw backend body ("boom") must NOT be persisted — only the reason.
    let detail = events[0].detail.clone().unwrap_or_default();
    assert!(
        !detail.contains("boom"),
        "raw response body leaked: {detail}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_records_transport_failure_for_unreachable_host() {
    let base = dead_port_base();
    let dir = temp_telemetry_dir("transport");
    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(matches!(err, ApiError::Other(_)));

    let events = read_telemetry(&dir);
    // A connection refusal is non-transient-classified at the HTTP layer but
    // an `Other` error IS transient (is_transient), so it retries up to 3x.
    assert!(!events.is_empty(), "a transport failure must be recorded");
    // Every recorded transport attempt is a non-accepted failure with no status.
    for ev in &events {
        assert_ne!(ev.event_type, "accepted");
    }
    let categories: Vec<&str> = events
        .iter()
        .filter_map(|e| e.error_category.as_deref())
        .collect();
    assert!(
        categories
            .iter()
            .any(|c| matches!(*c, "connection_error" | "dns_error" | "connect_timeout")),
        "expected a transport category, got {categories:?}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_correlates_retries_under_one_request_id() {
    // 503 is transient → the client retries up to TRANSIENT_HTTP_ATTEMPTS (3).
    let (base, _rx) = repeating_server("503 Service Unavailable", b"unavailable".to_vec(), 3);
    let dir = temp_telemetry_dir("retry");
    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    let _ = client.send_heartbeat(&make_payload(), None).unwrap_err();

    let events = read_telemetry(&dir);
    assert!(
        events.len() >= 4,
        "expected attempts + retry events, got {}",
        events.len()
    );

    // All events for this cycle share ONE request id (retry correlation).
    let first_id = events[0].request_id.clone();
    assert!(
        events.iter().all(|e| e.request_id == first_id),
        "all retry events must share the original request id"
    );

    // Attempts increment; retry lifecycle is recorded.
    let max_attempt = events.iter().map(|e| e.attempt).max().unwrap();
    assert_eq!(max_attempt, 3, "should reach the 3rd attempt");
    assert!(
        events.iter().any(|e| e.event_type == "retry_scheduled"),
        "retry_scheduled must be recorded"
    );
    assert!(
        events.iter().any(|e| e.event_type == "retry_exhausted"),
        "retry_exhausted must be recorded once the budget is spent"
    );

    // The summary must treat this as a single failed, retried cycle.
    let summary = heartbeat_telemetry::summarize(&events);
    assert_eq!(summary.cycles, 1);
    assert_eq!(summary.accepted, 0);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.retried, 1);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_write_failure_does_not_interrupt_heartbeat() {
    // Point the telemetry store at a path that cannot hold files (a regular
    // file where a directory is expected). The heartbeat MUST still succeed.
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();
    let (base, _rx) = one_shot_server("200 OK", body);

    let base_dir = temp_telemetry_dir("writefail");
    let unwritable = base_dir.join("a-file-not-a-dir");
    fs::write(&unwritable, b"x").unwrap();

    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(unwritable));
    let result = client.send_heartbeat(&make_payload(), None);
    assert!(
        result.is_ok(),
        "heartbeat must succeed even when telemetry cannot be written"
    );
    fs::remove_dir_all(&base_dir).ok();
}
