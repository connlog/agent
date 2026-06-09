//! V1 region-based heartbeat endpoint assignment.
//!
//! The agent always talks to a single **control-plane** URL (`control_url`,
//! i.e. the resolved platform endpoint) for config, quick actions, and the
//! assignment lookup itself. Heartbeats are the one thing that can be
//! repointed at a regional server (e.g. `https://eu-1.connlog.com`) without
//! touching anything else — the platform tells the agent where to send them
//! via `GET /api/agents/endpoint-assignment`, and the agent re-checks
//! periodically and on repeated heartbeat failure.
//!
//! Trust model: the agent only accepts assignments served over HTTPS by a
//! ConnLog-controlled domain (or an operator-configured allowlist). Anything
//! else — malformed URLs, other domains, localhost/private-network hosts — is
//! rejected and the agent keeps using the default platform heartbeat URL. A
//! compromised or buggy assignment response can therefore change *where*
//! heartbeats go (within the trusted set) but never *what* the agent runs.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use log::{info, warn};
use serde::Deserialize;

use crate::http::ApiClient;

/// Default refresh cadence for the endpoint assignment — 24 hours. Mirrors
/// the platform's `refreshAfterSeconds` default and requirement #3 ("the
/// agent refreshes the assignment every 24 hours").
pub(crate) const DEFAULT_REGION_CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Floor for the server-supplied `refreshAfterSeconds`. Guards against a
/// buggy or malicious platform forcing the agent into a refresh spin.
const MIN_REGION_CHECK_INTERVAL_SECS: u64 = 5 * 60;

/// Ceiling for the server-supplied `refreshAfterSeconds`. The agent must
/// eventually re-check even if the platform asks for an absurdly long wait.
const MAX_REGION_CHECK_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;

/// Consecutive heartbeat failures before the agent forces an out-of-band
/// assignment refresh — requirement #4 ("if heartbeat requests fail
/// repeatedly, immediately ask the central API for a fresh assignment").
const ENDPOINT_REASSIGNMENT_FAILURE_THRESHOLD: u32 = 3;

/// ConnLog-controlled domains an assignment is allowed to point at.
/// Subdomains match too (`eu-1.connlog.com` is allowed when `connlog.com` is
/// listed). There is intentionally no load balancer / regional infra live
/// yet — `connlog.com` is the only real entry — but the trust check is shaped
/// so adding `eu-1.connlog.com` etc. later requires no agent changes.
const TRUSTED_ENDPOINT_DOMAINS: &[&str] = &["connlog.com"];

/// Extra trusted domains for self-hosted / non-standard deployments. Comma
/// separated, e.g. `CONNLOG_ALLOWED_ENDPOINT_DOMAINS=example.internal,corp.example`.
/// Empty/unset by default — production ConnLog only ever needs `connlog.com`.
const ALLOWED_ENDPOINT_DOMAINS_ENV: &str = "CONNLOG_ALLOWED_ENDPOINT_DOMAINS";

/// Wire response from `GET /api/agents/endpoint-assignment`.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointAssignmentResponse {
    #[serde(rename = "heartbeatUrl")]
    pub heartbeat_url: String,
    #[serde(rename = "regionCode", default)]
    pub region_code: Option<String>,
    #[serde(rename = "refreshAfterSeconds")]
    pub refresh_after_seconds: u64,
}

/// Why an assigned endpoint URL was rejected. Display is log-friendly and
/// deliberately omits the raw URL for the domain/network cases — the
/// rejection itself is the actionable signal, not the attacker-controlled
/// string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EndpointValidationError {
    Malformed,
    InsecureScheme,
    UntrustedDomain(String),
    PrivateNetwork(String),
}

impl fmt::Display for EndpointValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed URL"),
            Self::InsecureScheme => write!(f, "must use https"),
            Self::UntrustedDomain(host) => write!(f, "untrusted domain '{host}'"),
            Self::PrivateNetwork(host) => {
                write!(f, "private/local host '{host}' not allowed outside dev mode")
            }
        }
    }
}

fn allowed_endpoint_domains() -> Vec<String> {
    let mut domains: Vec<String> = TRUSTED_ENDPOINT_DOMAINS.iter().map(|s| s.to_string()).collect();
    if let Ok(extra) = std::env::var(ALLOWED_ENDPOINT_DOMAINS_ENV) {
        for raw in extra.split(',') {
            let domain = raw.trim().trim_start_matches('.').to_ascii_lowercase();
            if !domain.is_empty() {
                domains.push(domain);
            }
        }
    }
    domains
}

fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// `true` for `localhost`, loopback/link-local/private/unique-local IPs.
/// Deliberately conservative — false positives just mean a dev-mode-only URL
/// gets rejected in production, which is the safe direction to err in.
fn is_private_or_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        }
        Err(_) => false,
    }
}

/// Validate an assigned heartbeat endpoint URL against the V1 trust policy:
///   - HTTPS required (outside dev mode)
///   - host must match a trusted ConnLog domain or `CONNLOG_ALLOWED_ENDPOINT_DOMAINS`
///   - localhost / private / link-local / loopback hosts are rejected (outside dev mode)
///
/// `dev_mode` is the existing debug-build escape hatch (the same gate that
/// allows `--endpoint` overrides) — it relaxes the scheme and host checks so
/// `connlog-agent register --endpoint http://127.0.0.1:PORT` keeps working
/// for local development, but can never be reached in a release binary.
pub(crate) fn validate_assigned_endpoint(
    raw: &str,
    dev_mode: bool,
) -> Result<reqwest::Url, EndpointValidationError> {
    let url = reqwest::Url::parse(raw).map_err(|_| EndpointValidationError::Malformed)?;
    let host = url
        .host_str()
        .ok_or(EndpointValidationError::Malformed)?
        .to_ascii_lowercase();

    if dev_mode {
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err(EndpointValidationError::InsecureScheme);
        }
        return Ok(url);
    }

    if url.scheme() != "https" {
        return Err(EndpointValidationError::InsecureScheme);
    }
    if is_private_or_local_host(&host) {
        return Err(EndpointValidationError::PrivateNetwork(host));
    }
    let domains = allowed_endpoint_domains();
    if !domains.iter().any(|domain| host_matches_domain(&host, domain)) {
        return Err(EndpointValidationError::UntrustedDomain(host));
    }

    Ok(url)
}

/// Tracks the agent's V1 endpoint assignment: where heartbeats currently go,
/// when that was last checked with the platform, and how often to re-check.
///
/// This is intentionally separate from `AgentConfig` — assignment changes
/// *where* heartbeats are sent, never any runtime behaviour (intervals,
/// metrics, quick actions, …). Keeping the two concerns apart means a bad
/// assignment response can only ever redirect heartbeat traffic within the
/// trusted domain set, not influence how the agent behaves.
#[derive(Debug, Clone)]
pub struct EndpointAssignmentState {
    /// Currently resolved heartbeat URL: either the validated regional
    /// assignment or `default_heartbeat_url`. Mirrored into `ApiClient` via
    /// `set_heartbeat_endpoint` so the loop never has to thread it through.
    heartbeat_url: String,
    /// Fallback heartbeat URL derived from `control_url`
    /// (`{control_url}/api/agents/heartbeat`) — requirement #5: used whenever
    /// no assignment is available or the assigned URL fails validation.
    default_heartbeat_url: String,
    /// Region code of the active assignment, if any (`None` = on fallback).
    region_code: Option<String>,
    /// How often to refresh the assignment. Server-controlled via
    /// `refreshAfterSeconds`, clamped to sane bounds — requirement #3.
    region_check_interval: Duration,
    /// Wall-clock time of the last assignment check (success *or* failure) —
    /// `assigned_endpoint_last_checked_at` from the spec.
    assigned_endpoint_last_checked_at: Option<SystemTime>,
    /// Consecutive heartbeat failures since the last success. Crossing
    /// `ENDPOINT_REASSIGNMENT_FAILURE_THRESHOLD` forces an immediate
    /// out-of-band refresh regardless of the interval — requirement #4.
    consecutive_heartbeat_failures: u32,
}

impl EndpointAssignmentState {
    /// Build the initial state for a freshly-resolved control-plane URL.
    /// Starts on the default (platform) heartbeat endpoint with no
    /// assignment — exactly what a pre-V1 agent would do, so a brand new
    /// agent behaves identically until its first successful assignment fetch.
    pub fn new(control_url: &str) -> Self {
        let default_heartbeat_url = format!(
            "{}/api/agents/heartbeat",
            control_url.trim_end_matches('/')
        );
        Self {
            heartbeat_url: default_heartbeat_url.clone(),
            default_heartbeat_url,
            region_code: None,
            region_check_interval: Duration::from_secs(DEFAULT_REGION_CHECK_INTERVAL_SECS),
            assigned_endpoint_last_checked_at: None,
            consecutive_heartbeat_failures: 0,
        }
    }

    /// `ResolveHeartbeatEndpoint` — the URL the agent should POST heartbeats
    /// to right now (assigned regional endpoint, or the default fallback).
    pub fn resolve_heartbeat_endpoint(&self) -> &str {
        &self.heartbeat_url
    }

    #[cfg(test)]
    pub(crate) fn region_code(&self) -> Option<&str> {
        self.region_code.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn default_heartbeat_endpoint(&self) -> &str {
        &self.default_heartbeat_url
    }

    /// Feed back the result of the most recent heartbeat attempt. Only
    /// *transport-level* failures (network errors, non-2xx from the
    /// heartbeat endpoint itself) should count here — account-level
    /// conditions like an invalid token or a disabled workspace mean the
    /// endpoint is fine and reassigning would not help.
    pub fn note_heartbeat_outcome(&mut self, success: bool) {
        if success {
            self.consecutive_heartbeat_failures = 0;
        } else {
            self.consecutive_heartbeat_failures =
                self.consecutive_heartbeat_failures.saturating_add(1);
        }
    }

    fn needs_refresh(&self, now: SystemTime) -> bool {
        if self.consecutive_heartbeat_failures >= ENDPOINT_REASSIGNMENT_FAILURE_THRESHOLD {
            return true;
        }
        match self.assigned_endpoint_last_checked_at {
            None => true,
            Some(last) => now
                .duration_since(last)
                .map(|elapsed| elapsed >= self.region_check_interval)
                .unwrap_or(true),
        }
    }

    /// `RefreshEndpointAssignmentIfNeeded` — checks whether a refresh is due
    /// (interval elapsed, first run, or repeated heartbeat failures) and, if
    /// so, calls `FetchEndpointAssignment` and applies the result. A no-op —
    /// and silent — otherwise, so this can be called every loop iteration
    /// without creating per-heartbeat log noise.
    pub fn refresh_if_needed(&mut self, client: &ApiClient, dev_mode: bool) {
        let now = SystemTime::now();
        if !self.needs_refresh(now) {
            return;
        }

        if self.consecutive_heartbeat_failures >= ENDPOINT_REASSIGNMENT_FAILURE_THRESHOLD {
            warn!(
                "Heartbeats failed {} times in a row — requesting a fresh endpoint assignment",
                self.consecutive_heartbeat_failures
            );
        }

        match client.fetch_endpoint_assignment() {
            Ok(assignment) => {
                info!(
                    "Endpoint assignment fetched (region={}, refresh_after={}s)",
                    assignment.region_code.as_deref().unwrap_or("default"),
                    assignment.refresh_after_seconds
                );
                self.apply(assignment, now, dev_mode, client);
                self.consecutive_heartbeat_failures = 0;
            }
            Err(e) => {
                self.assigned_endpoint_last_checked_at = Some(now);
                warn!(
                    "Endpoint assignment failed: could not reach the platform ({e}); keeping current heartbeat endpoint {}",
                    self.heartbeat_url
                );
            }
        }
    }

    /// `FetchEndpointAssignment` validates and applies a freshly-fetched
    /// assignment. An untrusted/malformed URL is logged and discarded — the
    /// agent falls back to the default rather than ever sending heartbeats
    /// (which never carry the bearer token, but do carry machine metadata) to
    /// an arbitrary endpoint.
    fn apply(
        &mut self,
        response: EndpointAssignmentResponse,
        now: SystemTime,
        dev_mode: bool,
        client: &ApiClient,
    ) {
        self.assigned_endpoint_last_checked_at = Some(now);
        self.region_check_interval = Duration::from_secs(response.refresh_after_seconds.clamp(
            MIN_REGION_CHECK_INTERVAL_SECS,
            MAX_REGION_CHECK_INTERVAL_SECS,
        ));

        let (resolved, region_code) = match validate_assigned_endpoint(&response.heartbeat_url, dev_mode) {
            Ok(url) => (url.to_string(), response.region_code.clone()),
            Err(e) => {
                warn!("Endpoint assignment failed: server returned an untrusted endpoint ({e}); ignoring it");
                warn!(
                    "Fallback endpoint in use: {} (region=none)",
                    self.default_heartbeat_url
                );
                (self.default_heartbeat_url.clone(), None)
            }
        };

        let changed = resolved != self.heartbeat_url || region_code != self.region_code;
        if changed {
            info!(
                "Endpoint assignment changed: {} (region={}) → {} (region={})",
                self.heartbeat_url,
                self.region_code.as_deref().unwrap_or("none"),
                resolved,
                region_code.as_deref().unwrap_or("none"),
            );
        }

        self.heartbeat_url = resolved.clone();
        self.region_code = region_code;
        client.set_heartbeat_endpoint(resolved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_assigned_endpoint ──────────────────────────────

    #[test]
    fn accepts_trusted_https_subdomain() {
        let url = validate_assigned_endpoint("https://eu-1.connlog.com/api/agents/heartbeat", false)
            .expect("trusted ConnLog subdomain must be accepted");
        assert_eq!(url.host_str(), Some("eu-1.connlog.com"));
    }

    #[test]
    fn accepts_trusted_apex_domain() {
        assert!(validate_assigned_endpoint("https://connlog.com/api/agents/heartbeat", false).is_ok());
    }

    #[test]
    fn rejects_http_in_production() {
        let err = validate_assigned_endpoint("http://eu-1.connlog.com/api/agents/heartbeat", false)
            .unwrap_err();
        assert_eq!(err, EndpointValidationError::InsecureScheme);
    }

    #[test]
    fn rejects_untrusted_domain() {
        let err =
            validate_assigned_endpoint("https://evil.example.com/api/agents/heartbeat", false)
                .unwrap_err();
        assert!(matches!(err, EndpointValidationError::UntrustedDomain(_)));
    }

    #[test]
    fn rejects_lookalike_domain() {
        // "notconnlog.com" must NOT match via a naive `.ends_with("connlog.com")`.
        let err =
            validate_assigned_endpoint("https://notconnlog.com/api/agents/heartbeat", false)
                .unwrap_err();
        assert!(matches!(err, EndpointValidationError::UntrustedDomain(_)));
    }

    #[test]
    fn rejects_localhost_and_private_ips_in_production() {
        for url in [
            "https://localhost/api/agents/heartbeat",
            "https://127.0.0.1/api/agents/heartbeat",
            "https://10.0.0.5/api/agents/heartbeat",
            "https://192.168.1.1/api/agents/heartbeat",
            "https://169.254.0.1/api/agents/heartbeat",
        ] {
            let err = validate_assigned_endpoint(url, false).unwrap_err();
            assert!(
                matches!(
                    err,
                    EndpointValidationError::PrivateNetwork(_) | EndpointValidationError::UntrustedDomain(_)
                ),
                "expected {url} to be rejected as private/untrusted, got {err:?}"
            );
        }
    }

    #[test]
    fn dev_mode_allows_loopback_http() {
        let url = validate_assigned_endpoint("http://127.0.0.1:9999/api/agents/heartbeat", true)
            .expect("dev mode must allow loopback http for local testing");
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn dev_mode_still_rejects_other_schemes() {
        let err = validate_assigned_endpoint("ftp://127.0.0.1/x", true).unwrap_err();
        assert_eq!(err, EndpointValidationError::InsecureScheme);
    }

    #[test]
    fn rejects_malformed_url() {
        let err = validate_assigned_endpoint("not a url", false).unwrap_err();
        assert_eq!(err, EndpointValidationError::Malformed);
    }

    #[test]
    fn configured_allowed_domains_extend_the_trust_set() {
        // SAFETY: tests in this module run single-threaded w.r.t. this var
        // (no other test reads/writes CONNLOG_ALLOWED_ENDPOINT_DOMAINS).
        unsafe {
            std::env::set_var(ALLOWED_ENDPOINT_DOMAINS_ENV, "example.internal");
        }
        let result = validate_assigned_endpoint("https://hb.example.internal/heartbeat", false);
        unsafe {
            std::env::remove_var(ALLOWED_ENDPOINT_DOMAINS_ENV);
        }
        assert!(result.is_ok(), "operator-configured domain must be trusted");
    }

    // ── EndpointAssignmentState ─────────────────────────────────

    fn state() -> EndpointAssignmentState {
        EndpointAssignmentState::new("https://connlog.com")
    }

    #[test]
    fn new_state_resolves_to_default_heartbeat_url() {
        let s = state();
        assert_eq!(
            s.resolve_heartbeat_endpoint(),
            "https://connlog.com/api/agents/heartbeat"
        );
        assert_eq!(s.region_code(), None);
    }

    #[test]
    fn first_check_is_always_due() {
        assert!(state().needs_refresh(SystemTime::now()));
    }

    #[test]
    fn refresh_not_due_immediately_after_a_check() {
        let mut s = state();
        s.assigned_endpoint_last_checked_at = Some(SystemTime::now());
        assert!(!s.needs_refresh(SystemTime::now()));
    }

    #[test]
    fn refresh_due_once_interval_elapses() {
        let mut s = state();
        let now = SystemTime::now();
        s.assigned_endpoint_last_checked_at =
            Some(now - s.region_check_interval - Duration::from_secs(1));
        assert!(s.needs_refresh(now));
    }

    #[test]
    fn repeated_heartbeat_failures_force_refresh_regardless_of_interval() {
        let mut s = state();
        s.assigned_endpoint_last_checked_at = Some(SystemTime::now());
        for _ in 0..ENDPOINT_REASSIGNMENT_FAILURE_THRESHOLD {
            s.note_heartbeat_outcome(false);
        }
        assert!(
            s.needs_refresh(SystemTime::now()),
            "3 consecutive heartbeat failures must force an immediate refresh"
        );
    }

    #[test]
    fn success_resets_the_failure_counter() {
        let mut s = state();
        s.note_heartbeat_outcome(false);
        s.note_heartbeat_outcome(false);
        s.note_heartbeat_outcome(true);
        assert_eq!(s.consecutive_heartbeat_failures, 0);
    }

    fn client() -> ApiClient {
        ApiClient::new("https://connlog.com".to_string(), "agent_test".to_string()).unwrap()
    }

    #[test]
    fn apply_accepts_a_trusted_assignment_and_switches_endpoint() {
        let mut s = state();
        let c = client();
        s.apply(
            EndpointAssignmentResponse {
                heartbeat_url: "https://eu-1.connlog.com/api/agents/heartbeat".to_string(),
                region_code: Some("eu-west".to_string()),
                refresh_after_seconds: 3600,
            },
            SystemTime::now(),
            false,
            &c,
        );
        assert_eq!(
            s.resolve_heartbeat_endpoint(),
            "https://eu-1.connlog.com/api/agents/heartbeat"
        );
        assert_eq!(s.region_code(), Some("eu-west"));
        assert_eq!(s.region_check_interval, Duration::from_secs(3600));
    }

    #[test]
    fn apply_falls_back_to_default_on_untrusted_assignment() {
        let mut s = state();
        let c = client();
        s.apply(
            EndpointAssignmentResponse {
                heartbeat_url: "https://attacker.example.com/steal".to_string(),
                region_code: Some("eu-west".to_string()),
                refresh_after_seconds: 3600,
            },
            SystemTime::now(),
            false,
            &c,
        );
        assert_eq!(
            s.resolve_heartbeat_endpoint(),
            s.default_heartbeat_endpoint()
        );
        assert_eq!(
            s.region_code(),
            None,
            "an untrusted assignment must not be partially applied"
        );
    }

    #[test]
    fn apply_clamps_refresh_interval_to_sane_bounds() {
        let mut s = state();
        let c = client();
        s.apply(
            EndpointAssignmentResponse {
                heartbeat_url: "https://connlog.com/api/agents/heartbeat".to_string(),
                region_code: None,
                refresh_after_seconds: 1,
            },
            SystemTime::now(),
            false,
            &c,
        );
        assert_eq!(
            s.region_check_interval,
            Duration::from_secs(MIN_REGION_CHECK_INTERVAL_SECS),
            "absurdly short refresh intervals must be floored"
        );

        s.apply(
            EndpointAssignmentResponse {
                heartbeat_url: "https://connlog.com/api/agents/heartbeat".to_string(),
                region_code: None,
                refresh_after_seconds: u64::MAX,
            },
            SystemTime::now(),
            false,
            &c,
        );
        assert_eq!(
            s.region_check_interval,
            Duration::from_secs(MAX_REGION_CHECK_INTERVAL_SECS),
            "absurdly long refresh intervals must be capped"
        );
    }
}
