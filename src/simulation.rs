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
//!   * 429 Too Many    → `ApiError::RateLimited` (Retry-After parsed, no
//!     in-cycle retry).
//!   * 500 Server Err  → transient: retried in-cycle, then
//!     `ApiError::HttpError { status: 500, .. }`.
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

use crate::features::heartbeat_telemetry::{self, HeartbeatTelemetry, TelemetryEvent};
use crate::heartbeat::{HeartbeatPayload, Metrics};
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

/// Same as `one_shot_server` but injects one extra response header line
/// (e.g. `Retry-After: 45`).
fn one_shot_server_with_header(
    status_line: &'static str,
    extra_header: &'static str,
    body: Vec<u8>,
) -> (String, mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let req = read_request(&stream);
            let _ = tx.send(req);
            let header = format!(
                "HTTP/1.1 {}\r\n{}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                status_line,
                extra_header,
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
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

/// A mock control plane that answers every connection, by path, until the
/// test ends, and passes each request back. For the threads that upload on
/// their own (the network map), where the test cannot know how many
/// requests are coming.
fn routing_server(
    routes: Vec<(&'static str, &'static str, Vec<u8>)>,
) -> (String, mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let req = read_request(&stream);
            let (status, body) = routes
                .iter()
                .find(|(path, _, _)| *path == req.path)
                .map(|(_, status, body)| (*status, body.clone()))
                .unwrap_or(("404 Not Found", br#"{"ok":false}"#.to_vec()));
            if tx.send(req).is_err() {
                break;
            }
            write_response(&stream, status, &body);
        }
    });

    (format!("http://127.0.0.1:{port}"), rx)
}

/// Every request `rx` sees within `window`.
fn drain_requests(rx: &mpsc::Receiver<CapturedRequest>, window: Duration) -> Vec<CapturedRequest> {
    let deadline = std::time::Instant::now() + window;
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(req) => seen.push(req),
            Err(_) => break,
        }
    }
    seen
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
            cpu_core_count: None,
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

/// `X-Boot-Id` goes out whenever the kernel's boot id is readable (always on
/// a Linux CI runner); `X-Remote-Reboot` only once the daemon has set it, so
/// a diagnostic command never reports a setting it did not read.
#[test]
fn heartbeat_sends_boot_id_and_remote_reboot_setting() {
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();

    let (base, rx) = one_shot_server("200 OK", body.clone());
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    client.send_heartbeat(&make_payload(), None).expect("ok");
    let req = recv_request(&rx);
    let boot_id = req.header("X-Boot-Id").expect("X-Boot-Id on Linux");
    assert_eq!(
        crate::identity::parse_boot_id(boot_id).as_deref(),
        Some(boot_id)
    );
    assert_eq!(req.header("X-Remote-Reboot"), None);

    for (allowed, sent) in [(true, "allowed"), (false, "disabled")] {
        let (base, rx) = one_shot_server("200 OK", body.clone());
        let mut client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
        client.set_remote_reboot_allowed(allowed);
        client.send_heartbeat(&make_payload(), None).expect("ok");
        assert_eq!(recv_request(&rx).header("X-Remote-Reboot"), Some(sent));
    }
}

/// `X-Host-Settings` carries on/off values only, and only once the daemon
/// has set them.
#[test]
fn heartbeat_sends_host_settings_once_set() {
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();

    let (base, rx) = one_shot_server("200 OK", body.clone());
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    client.send_heartbeat(&make_payload(), None).expect("ok");
    assert_eq!(recv_request(&rx).header("X-Host-Settings"), None);

    let (base, rx) = one_shot_server("200 OK", body);
    let mut client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    client.set_host_settings(crate::http::HostSettings {
        bmc: true,
        hostname: false,
        postmortem: true,
    });
    client.send_heartbeat(&make_payload(), None).expect("ok");
    assert_eq!(
        recv_request(&rx).header("X-Host-Settings"),
        Some("bmc=on,hostname=off,postmortem=on")
    );
}

/// `X-Network-Map` carries the host's CONNLOG_NETWORK_MAP, and only once the
/// daemon has set it.
#[test]
fn heartbeat_sends_the_network_map_setting_once_set() {
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();

    let (base, rx) = one_shot_server("200 OK", body.clone());
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    client.send_heartbeat(&make_payload(), None).expect("ok");
    assert_eq!(recv_request(&rx).header("X-Network-Map"), None);

    for (enabled, sent) in [(true, "enabled"), (false, "disabled")] {
        let (base, rx) = one_shot_server("200 OK", body.clone());
        let mut client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
        client.set_network_map_enabled(enabled);
        client.send_heartbeat(&make_payload(), None).expect("ok");
        assert_eq!(recv_request(&rx).header("X-Network-Map"), Some(sent));
    }
}

#[test]
fn heartbeat_carries_the_reboot_report_until_cleared() {
    use crate::features::remote_reboot::{RebootReport, RebootState};
    let body =
        br#"{"ok":true,"server_time":"2026-04-30T00:00:00Z","expected_interval_seconds":60}"#
            .to_vec();

    let (base, rx) = one_shot_server("200 OK", body.clone());
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    client.set_reboot_report(Some(RebootReport::new(
        RebootState::Failed,
        "host did not reboot",
    )));
    client.send_heartbeat(&make_payload(), None).expect("ok");
    let req = recv_request(&rx);
    assert_eq!(req.header("X-Reboot-State"), Some("failed"));
    assert_eq!(req.header("X-Reboot-Message"), Some("host did not reboot"));

    let (base, rx) = one_shot_server("200 OK", body);
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    client.set_reboot_report(None);
    client.send_heartbeat(&make_payload(), None).expect("ok");
    let req = recv_request(&rx);
    assert_eq!(req.header("X-Reboot-State"), None);
    assert_eq!(req.header("X-Reboot-Message"), None);
}

#[test]
fn history_upload_posts_the_encoded_records_to_the_control_plane() {
    use crate::features::flight_recorder::upload::{self, WireRecord};
    let (base, rx) = one_shot_server("200 OK", br#"{"ok":true}"#.to_vec());
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    let records = [WireRecord {
        fields: [1; upload::FIELDS],
    }];
    let body = upload::encode(&records);

    client.upload_history(body.clone()).expect("upload ok");

    let req = recv_request(&rx);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/agents/history");
    assert_eq!(req.header("Content-Type"), Some(upload::CONTENT_TYPE));
    assert_eq!(req.header("Authorization"), Some("Bearer test-token"));
    assert!(req.header("X-Machine-Id").is_some());
    assert_eq!(req.body, body);
}

#[test]
fn postmortem_upload_posts_plain_text() {
    let (base, rx) = one_shot_server("200 OK", br#"{"ok":true}"#.to_vec());
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    client
        .upload_postmortem("kernel: Out of memory\n".into())
        .expect("upload ok");
    let req = recv_request(&rx);
    assert_eq!(req.path, "/api/agents/postmortem");
    assert_eq!(
        req.header("Content-Type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(req.body, b"kernel: Out of memory\n");
}

#[test]
fn heartbeat_parses_a_history_request() {
    let body = br#"{"ok":true,"server_time":"2026-09-23T00:00:00Z","expected_interval_seconds":60,"history_request":{"since":1790000000,"until":1790000600}}"#.to_vec();
    let (base, _rx) = one_shot_server("200 OK", body);
    let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
    let resp = client.send_heartbeat(&make_payload(), None).expect("ok");
    let request = resp.history_request.expect("history_request");
    assert_eq!(
        (request.since, request.until),
        (1_790_000_000, 1_790_000_600)
    );
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
    // 500 is transient → retried in-cycle up to 3 attempts before surfacing.
    let (base, _rx) = repeating_server("500 Internal Server Error", b"boom".to_vec(), 3);
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

#[test]
fn hardware_report_posts_snake_case_json_with_bearer_token() {
    let (base, rx) = one_shot_server("200 OK", br#"{"ok":true}"#.to_vec());
    let reporter = crate::features::bmc::PlatformReporter::new(&base, "agent_tok".into()).unwrap();

    let mut attributes = serde_json::Map::new();
    attributes.insert("model".into(), serde_json::Value::from("ST4000NM0023"));
    reporter
        .send(&crate::features::bmc::HardwareHealthReport {
            source: "redfish",
            collected_at_unix_ms: 1234,
            components: vec![crate::features::bmc::HardwareComponent {
                component_type: "drive",
                component_key: "Disk.Bay.0".into(),
                name: "Physical Disk 0:1:0".into(),
                health: crate::features::bmc::Health::Critical,
                state: Some("Enabled".into()),
                failure_predicted: true,
                attributes,
            }],
        })
        .expect("2xx response must be accepted");

    let req = recv_request(&rx);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/agents/hardware-health");
    assert_eq!(req.header("Authorization"), Some("Bearer agent_tok"));

    let body: serde_json::Value = serde_json::from_slice(&req.body).expect("body must be JSON");
    assert_eq!(body["source"], "redfish");
    let component = &body["components"][0];
    assert_eq!(component["component_type"], "drive");
    assert_eq!(component["component_key"], "Disk.Bay.0");
    assert_eq!(component["health"], "CRITICAL");
    assert_eq!(component["failure_predicted"], true);
    assert_eq!(component["attributes"]["model"], "ST4000NM0023");
}

#[test]
fn cycle_budget_skips_retries_that_do_not_fit() {
    // 503 is transient and would normally be retried up to 3 attempts, but a
    // budget too small for delay (250ms) + MIN_RETRY_BUDGET (1s) must stop
    // the cycle after the first attempt.
    let (base, rx) = repeating_server("503 Service Unavailable", b"unavailable".to_vec(), 3);
    let client = ApiClient::new(base, "tok".into()).unwrap();
    client.set_heartbeat_cycle_budget(Duration::from_millis(500));
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(
        matches!(err, ApiError::HttpError { status: 503, .. }),
        "got {err:?}"
    );

    // Give any (erroneous) retry a moment to arrive, then count requests.
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        rx.try_iter().count(),
        1,
        "no retry fits a 500ms cycle budget"
    );
}

#[test]
fn cycle_budget_allows_retries_that_fit() {
    let (base, rx) = repeating_server("503 Service Unavailable", b"unavailable".to_vec(), 3);
    let client = ApiClient::new(base, "tok".into()).unwrap();
    client.set_heartbeat_cycle_budget(Duration::from_secs(10));
    let _ = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert_eq!(
        rx.try_iter().count(),
        3,
        "all 3 attempts fit a 10s cycle budget"
    );
}

#[test]
fn heartbeat_429_maps_to_rate_limited_without_in_cycle_retry() {
    // One-shot on purpose: if the client retried in-cycle, the second attempt
    // would hit a closed listener and surface `ApiError::Other` instead.
    let (base, _rx) = one_shot_server("429 Too Many Requests", b"slow down".to_vec());
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(
        matches!(
            err,
            ApiError::RateLimited {
                retry_after_secs: None
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn heartbeat_429_parses_retry_after_seconds() {
    let (base, _rx) = one_shot_server_with_header(
        "429 Too Many Requests",
        "Retry-After: 45",
        b"slow down".to_vec(),
    );
    let client = ApiClient::new(base, "tok".into()).unwrap();
    let err = client.send_heartbeat(&make_payload(), None).unwrap_err();
    assert!(
        matches!(
            err,
            ApiError::RateLimited {
                retry_after_secs: Some(45)
            }
        ),
        "got {err:?}"
    );
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
        cfg.heartbeat_interval_secs >= crate::heartbeat::HEARTBEAT_MIN_INTERVAL_SECS,
        "clamp must enforce the heartbeat floor (got {})",
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
    // Rate limiting is deliberately never retried in-cycle → exactly one event.
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "rate_limited");
    assert_eq!(events[0].error_category.as_deref(), Some("rate_limited"));
    assert_eq!(events[0].http_status, Some(429));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn telemetry_records_http_500_as_server_error() {
    // 500 is transient → retried in-cycle up to 3 attempts.
    let (base, _rx) = repeating_server("500 Internal Server Error", b"boom".to_vec(), 3);
    let dir = temp_telemetry_dir("500");
    let mut client = ApiClient::new(base, "agent_tok".into()).unwrap();
    client.set_telemetry(HeartbeatTelemetry::with_dir(dir.clone()));
    let _ = client.send_heartbeat(&make_payload(), None).unwrap_err();

    let events = read_telemetry(&dir);
    let server_errors: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "server_error")
        .collect();
    assert_eq!(server_errors.len(), 3, "each in-cycle attempt is recorded");
    for ev in &server_errors {
        assert_eq!(ev.error_category.as_deref(), Some("server_error"));
        assert_eq!(ev.http_status, Some(500));
        // The raw backend body ("boom") must NOT be persisted — only the reason.
        let detail = ev.detail.clone().unwrap_or_default();
        assert!(
            !detail.contains("boom"),
            "raw response body leaked: {detail}"
        );
    }
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

// ────────────────────────────────────────────────────────────────────────
// The network map
// ────────────────────────────────────────────────────────────────────────

const ACCEPTED: &[u8] = br#"{"ok":true,"data":{"accepted":true}}"#;

/// The map's sources for a test: a fixed inventory, and real probes.
fn fixed_sources() -> crate::features::network_map::Sources {
    crate::features::network_map::Sources {
        inventory: std::sync::Arc::new(fixed_inventory),
        prober: std::sync::Arc::new(crate::features::reachability::SystemProber),
    }
}

fn fixed_inventory() -> crate::features::network_inventory::Inventory {
    use crate::features::network_inventory::{InterfaceAddress, Inventory};
    {
        Inventory::build(
            &[InterfaceAddress {
                interface: "eth0".into(),
                up: true,
                loopback: false,
                ip: "10.0.10.5".parse().unwrap(),
                prefix_length: 24,
            }],
            &[("0.0.0.0".parse().unwrap(), 22)],
            None,
            Some("hq".into()),
            &[8443],
        )
    }
}

/// With the host's flag on, the first accepted heartbeat starts the
/// inventory: one upload, the inventory content type, bearer and machine id.
#[test]
fn an_opted_in_host_sends_its_inventory_after_the_first_heartbeat() {
    use crate::features::network_map::{NetworkMap, NetworkMapSettings};
    let (base, rx) = routing_server(vec![("/api/agents/inventory", "200 OK", ACCEPTED.to_vec())]);
    let settings = NetworkMapSettings {
        enabled: true,
        ..NetworkMapSettings::default()
    };
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut map = NetworkMap::start_with(
        &settings,
        base,
        "test-token".into(),
        stop.clone(),
        fixed_sources(),
    );
    assert!(
        drain_requests(&rx, Duration::from_millis(300)).is_empty(),
        "nothing before the first accepted heartbeat"
    );

    map.on_heartbeat(false, None);
    let req = recv_request(&rx);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/agents/inventory");
    assert_eq!(
        req.header("Content-Type"),
        Some("application/vnd.connlog.inventory.v1+json")
    );
    assert_eq!(req.header("Authorization"), Some("Bearer test-token"));
    assert!(req.header("X-Machine-Id").is_some());
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "version": 1,
            "addresses": [{ "address": "10.0.10.5", "prefixLength": 24 }],
            "tcpListeners": [{ "port": 22, "wildcard": true }],
            "gateway": null,
            "site": "hq",
            "extraPorts": [8443]
        })
    );

    // Later heartbeats without a request send nothing more.
    map.on_heartbeat(false, None);
    assert!(drain_requests(&rx, Duration::from_millis(300)).is_empty());
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Guarantee 1: with the flag off, no heartbeat answer makes the agent send
/// an inventory.
#[test]
fn a_host_that_has_not_opted_in_sends_no_inventory() {
    use crate::features::network_map::{NetworkMap, NetworkMapSettings};
    let (base, rx) = routing_server(vec![("/api/agents/inventory", "200 OK", ACCEPTED.to_vec())]);
    let mut map = NetworkMap::start_with(
        &NetworkMapSettings::default(),
        base,
        "test-token".into(),
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fixed_sources(),
    );
    map.on_heartbeat(true, None);
    map.on_heartbeat(true, None);
    assert!(drain_requests(&rx, Duration::from_millis(500)).is_empty());
}

/// A malformed `inventory_request` is no request, never a failed heartbeat.
#[test]
fn heartbeat_reads_inventory_request_leniently() {
    for (field, expected) in [
        (r#","inventory_request":true"#, true),
        (r#","inventory_request":false"#, false),
        (r#","inventory_request":"yes""#, false),
        (r#","inventory_request":{"x":1}"#, false),
        ("", false),
    ] {
        let body =
            format!(r#"{{"ok":true,"server_time":"t","expected_interval_seconds":60{field}}}"#);
        let (base, _rx) = one_shot_server("200 OK", body.into_bytes());
        let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
        let resp = client.send_heartbeat(&make_payload(), None).expect("ok");
        assert_eq!(resp.inventory_request, expected, "{field}");
    }
}

/// A local listener as a probe target, and how many connections it saw.
fn probe_target() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn connections_seen(listener: &TcpListener) -> usize {
    let mut seen = 0;
    while listener.accept().is_ok() {
        seen += 1;
    }
    seen
}

/// A heartbeat answer that asks for one TCP probe of `port` on 127.0.0.1.
fn heartbeat_with_probe(id: &str, port: u16) -> Vec<u8> {
    format!(
        r#"{{"ok":true,"server_time":"2026-10-28T12:00:00.000Z","expected_interval_seconds":60,"uninstall":false,"reboot":false,"update":null,"probe_request":{{"id":"{id}","targets":[{{"address":"127.0.0.1","ports":[{port}],"icmp":false}}]}}}}"#
    )
    .into_bytes()
}

fn network_map_settings(
    enabled: bool,
    probe_public: bool,
) -> crate::features::network_map::NetworkMapSettings {
    crate::features::network_map::NetworkMapSettings {
        enabled,
        probe_public,
        ..Default::default()
    }
}

fn probe_uploads(requests: &[CapturedRequest]) -> Vec<serde_json::Value> {
    requests
        .iter()
        .filter(|r| r.path == "/api/agents/probes")
        .map(|r| {
            assert_eq!(r.method, "POST");
            assert_eq!(
                r.header("Content-Type"),
                Some("application/vnd.connlog.probes.v1+json")
            );
            assert_eq!(r.header("Authorization"), Some("Bearer test-token"));
            assert!(r.header("X-Machine-Id").is_some());
            serde_json::from_slice(&r.body).expect("results are JSON")
        })
        .collect()
}

/// T2.2's simulation: a heartbeat carrying a probe request yields exactly
/// one results upload, the probe itself a single handshake.
#[test]
fn a_heartbeat_with_a_probe_request_yields_exactly_one_results_upload() {
    use crate::features::network_map::NetworkMap;
    let (target, port) = probe_target();
    let (base, rx) = routing_server(vec![
        (
            "/api/agents/heartbeat",
            "200 OK",
            heartbeat_with_probe("prb_sim1", port),
        ),
        ("/api/agents/probes", "200 OK", ACCEPTED.to_vec()),
        ("/api/agents/inventory", "200 OK", ACCEPTED.to_vec()),
    ]);
    let client = ApiClient::new(base.clone(), "test-token".into()).expect("ApiClient::new");
    let resp = client.send_heartbeat(&make_payload(), None).expect("ok");
    assert_eq!(recv_request(&rx).path, "/api/agents/heartbeat");

    // 127.0.0.1 is not a private address: this host allows public targets.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut map = NetworkMap::start_with(
        &network_map_settings(true, true),
        base,
        "test-token".into(),
        stop.clone(),
        fixed_sources(),
    );
    map.on_heartbeat(resp.inventory_request, resp.probe_request);

    let uploads = probe_uploads(&drain_requests(&rx, Duration::from_millis(1500)));
    assert_eq!(uploads.len(), 1, "exactly one results upload");
    let results = &uploads[0];
    assert_eq!(results["version"], 1);
    assert_eq!(results["id"], "prb_sim1");
    let list = results["results"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["address"], "127.0.0.1");
    assert_eq!(list[0]["port"], port);
    assert_eq!(list[0]["outcome"], "open");
    assert!(list[0]["rttMs"].is_u64());
    assert_eq!(connections_seen(&target), 1, "one handshake");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Guarantee 3 end to end: without CONNLOG_PROBE_PUBLIC, a public target is
/// reported skipped and never touched.
#[test]
fn a_public_target_is_reported_skipped_and_never_touched() {
    use crate::features::network_map::NetworkMap;
    let (target, port) = probe_target();
    let (base, rx) = routing_server(vec![
        ("/api/agents/probes", "200 OK", ACCEPTED.to_vec()),
        ("/api/agents/inventory", "200 OK", ACCEPTED.to_vec()),
    ]);
    let request = crate::features::reachability::ProbeRequest::from_json(
        &serde_json::from_slice::<serde_json::Value>(&heartbeat_with_probe("prb_sim2", port))
            .unwrap()["probe_request"],
    );
    let mut map = NetworkMap::start_with(
        &network_map_settings(true, false),
        base,
        "test-token".into(),
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fixed_sources(),
    );
    map.on_heartbeat(false, request);

    let uploads = probe_uploads(&drain_requests(&rx, Duration::from_millis(1000)));
    assert_eq!(uploads.len(), 1);
    assert_eq!(
        uploads[0]["results"],
        serde_json::json!([{ "address": "127.0.0.1", "port": port, "outcome": "skipped", "rttMs": null }])
    );
    assert_eq!(connections_seen(&target), 0);
}

/// One request at a time: a request that arrives while one runs is dropped,
/// and the next one after it is run.
#[test]
fn a_probe_request_arriving_while_one_runs_is_dropped() {
    use crate::features::network_map::{NetworkMap, Sources};
    use crate::features::reachability::{Outcome, Probe, ProbeRequest, Prober};
    use std::net::{IpAddr, SocketAddr};

    struct Slow;
    impl Prober for Slow {
        fn tcp(&self, _: SocketAddr, _: Duration) -> Probe {
            thread::sleep(Duration::from_millis(400));
            Probe::of(Outcome::Refused)
        }
        fn echo(&self, _: IpAddr, _: Duration) -> Probe {
            Probe::of(Outcome::Timeout)
        }
    }
    let request = |id: &str| {
        ProbeRequest::from_json(&serde_json::json!({
            "id": id,
            "targets": [{ "address": "10.0.20.7", "ports": [5432], "icmp": false }]
        }))
    };
    let (base, rx) = routing_server(vec![
        ("/api/agents/probes", "200 OK", ACCEPTED.to_vec()),
        ("/api/agents/inventory", "200 OK", ACCEPTED.to_vec()),
    ]);
    let mut map = NetworkMap::start_with(
        &network_map_settings(true, false),
        base,
        "test-token".into(),
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        Sources {
            inventory: std::sync::Arc::new(fixed_inventory),
            prober: std::sync::Arc::new(Slow),
        },
    );
    map.on_heartbeat(false, request("prb_first"));
    map.on_heartbeat(false, request("prb_dropped"));
    let uploads = probe_uploads(&drain_requests(&rx, Duration::from_millis(1000)));
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0]["id"], "prb_first");

    map.on_heartbeat(false, request("prb_next"));
    let uploads = probe_uploads(&drain_requests(&rx, Duration::from_millis(1000)));
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0]["id"], "prb_next");
}

/// Guarantee 1: with the host's flag off, a heartbeat that asks for probes
/// and an inventory gets neither: nothing is uploaded, nothing is probed.
#[test]
fn with_the_flag_off_nothing_is_probed_or_uploaded() {
    use crate::features::network_map::NetworkMap;
    let (target, port) = probe_target();
    let mut body: serde_json::Value =
        serde_json::from_slice(&heartbeat_with_probe("prb_off", port)).unwrap();
    body["inventory_request"] = true.into();
    let (base, rx) = routing_server(vec![
        (
            "/api/agents/heartbeat",
            "200 OK",
            serde_json::to_vec(&body).unwrap(),
        ),
        ("/api/agents/probes", "200 OK", ACCEPTED.to_vec()),
        ("/api/agents/inventory", "200 OK", ACCEPTED.to_vec()),
    ]);
    let client = ApiClient::new(base.clone(), "test-token".into()).expect("ApiClient::new");
    let resp = client.send_heartbeat(&make_payload(), None).expect("ok");
    assert_eq!(recv_request(&rx).path, "/api/agents/heartbeat");
    assert!(resp.inventory_request);
    assert!(resp.probe_request.is_some(), "parsed, then ignored");

    // Even with public targets allowed: the map flag is what counts.
    let mut map = NetworkMap::start_with(
        &network_map_settings(false, true),
        base,
        "test-token".into(),
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        fixed_sources(),
    );
    for _ in 0..3 {
        map.on_heartbeat(resp.inventory_request, resp.probe_request.clone());
    }
    assert!(drain_requests(&rx, Duration::from_millis(1500)).is_empty());
    assert_eq!(connections_seen(&target), 0);
}

/// A probe request the agent cannot use is no request, never a failed
/// heartbeat; the shared fixture's request reads whole.
#[test]
fn heartbeat_reads_probe_request_leniently() {
    for (field, expected) in [
        (
            r#","probe_request":{"id":"prb_1","targets":[]}"#,
            Some("prb_1"),
        ),
        (r#","probe_request":{"id":"prb/1","targets":[]}"#, None),
        (r#","probe_request":{"targets":"all"}"#, None),
        (r#","probe_request":"10.0.0.0/8""#, None),
        (r#","probe_request":null"#, None),
        ("", None),
    ] {
        let body =
            format!(r#"{{"ok":true,"server_time":"t","expected_interval_seconds":60{field}}}"#);
        let (base, _rx) = one_shot_server("200 OK", body.into_bytes());
        let client = ApiClient::new(base, "test-token".into()).expect("ApiClient::new");
        let resp = client.send_heartbeat(&make_payload(), None).expect("ok");
        assert_eq!(
            resp.probe_request.as_ref().map(|p| p.id.as_str()),
            expected,
            "{field}"
        );
    }
}
