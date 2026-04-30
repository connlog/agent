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

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::heartbeat::{HeartbeatPayload, Metrics};
use crate::http::{ApiClient, ApiError};

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

fn make_payload() -> HeartbeatPayload {
    HeartbeatPayload {
        agent_version: "1.2.0".into(),
        protocol_version: 2,
        config_version: 0,
        hostname: "sim-host".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        uptime_seconds: 1234,
        metrics: Metrics {
            cpu_percent: 12.34,
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
        .send_heartbeat(&make_payload())
        .expect("heartbeat ok");

    assert!(resp.ok);
    assert_eq!(resp.expected_interval_seconds, 60);
    assert!(!resp.uninstall);
    assert!(resp.update.is_none());

    let req = recv_request(&rx);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/agents/heartbeat");

    // Required identity headers (wire protocol v2 carries identity in headers).
    assert_eq!(req.header("Authorization"), Some("Bearer test-token"));
    assert_eq!(req.header("X-Agent-Version"), Some("1.2.0"));
    assert_eq!(req.header("X-Protocol-Version"), Some("2"));
    assert_eq!(req.header("X-Hostname"), Some("sim-host"));
    assert_eq!(req.header("X-OS"), Some("linux"));
    assert_eq!(req.header("X-Arch"), Some("x86_64"));
    assert_eq!(req.header("Content-Type"), Some("application/octet-stream"));

    // X-Machine-Id is sent whenever the agent could read a stable ID. CI
    // runners always have /etc/machine-id (Linux) or a MachineGuid (Windows),
    // so we expect a 64-char lowercase hex hash here. If we ever run this
    // test on a host without one we'd want to know — assert presence + shape.
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

    // Binary frame is 32 bytes exactly (protocol v2).
    assert_eq!(req.body.len(), 32, "v2 wire frame must be exactly 32 bytes");
}

#[test]
fn heartbeat_200_with_uninstall_flag() {
    let body = br#"{"ok":true,"server_time":"t","expected_interval_seconds":60,"uninstall":true}"#
        .to_vec();
    let (base, _rx) = one_shot_server("200 OK", body);
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let resp = client.send_heartbeat(&make_payload()).unwrap();
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
    let resp = client.send_heartbeat(&make_payload()).unwrap();
    let update = resp.update.expect("update info parsed");
    assert!(update.available);
    assert_eq!(update.latest_version, "1.3.0");
    assert_eq!(update.sha256.as_deref(), Some("deadbeef"));
    assert!(!update.force_update);
}

// ────────────────────────────────────────────────────────────────────────
// Error responses → typed ApiError variants
// ────────────────────────────────────────────────────────────────────────

#[test]
fn heartbeat_401_unauthorized() {
    let (base, _rx) = one_shot_server("401 Unauthorized", b"unauthorized".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload()).unwrap_err();
    assert!(matches!(err, ApiError::Unauthorized), "got {err:?}");
}

#[test]
fn heartbeat_410_decommissioned() {
    let (base, _rx) = one_shot_server("410 Gone", b"gone".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload()).unwrap_err();
    assert!(matches!(err, ApiError::Decommissioned), "got {err:?}");
}

#[test]
fn heartbeat_423_disabled() {
    let (base, _rx) = one_shot_server("423 Locked", b"disabled".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload()).unwrap_err();
    assert!(matches!(err, ApiError::Disabled), "got {err:?}");
}

#[test]
fn heartbeat_500_surfaces_status_and_body() {
    let (base, _rx) = one_shot_server("500 Internal Server Error", b"boom".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload()).unwrap_err();
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
    let err = client.send_heartbeat(&make_payload()).unwrap_err();

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
    let body = br#"{
        "configVersion": 7,
        "heartbeatIntervalSeconds": 1,
        "missedThreshold": 999,
        "metrics": {"cpu": true, "memory": true, "disk": false, "load": true},
        "maxPayloadSizeKb": 99999
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
