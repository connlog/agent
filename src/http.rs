use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::endpoint_assignment::EndpointAssignmentResponse;
use crate::features::heartbeat_telemetry::{
    new_request_id, ErrorCategory, EventBuilder, EventType, HeartbeatTelemetry, HB_LOG_TARGET,
};
use crate::features::quick_actions::{
    QuickActionRequest, QuickActionResultPayload, QuickActionsManifestPayload,
};
use crate::heartbeat::{AgentConfig, HeartbeatPayload, HeartbeatResponse};

/// Header carrying the agent-generated heartbeat correlation id. Authentication
/// is bearer-token only (no HMAC over headers/body — see
/// `connlog-platform/.../heartbeat/route.ts`), and the platform ignores unknown
/// headers, so adding this is fully backward-compatible and never alters
/// authentication semantics or the 32-byte binary frame.
const REQUEST_ID_HEADER: &str = "X-ConnLog-Request-Id";
/// Logical CPU count of the host; parsed by the platform as `x-cpu-core-count`.
pub const CPU_CORE_COUNT_HEADER: &str = "X-Cpu-Core-Count";

const CPU_UNAVAILABLE_X100: u16 = u16::MAX;

/// Error types for API calls
#[derive(Debug)]
pub enum ApiError {
    /// Agent token is invalid or revoked (401)
    Unauthorized,
    /// Agent has been marked for uninstall (410 Gone)
    Decommissioned,
    /// Agent is currently disabled in ConnLog (423 Locked).
    /// Reversible: the agent should back off heartbeats and keep polling
    /// `/api/agents/config` infrequently. Do NOT self-uninstall.
    Disabled,
    /// Rate limited (429) — the platform asked us to slow down. Carries the
    /// parsed `Retry-After` header (delay-seconds form) when present.
    RateLimited { retry_after_secs: Option<u64> },
    /// Other HTTP error
    HttpError { status: u16, message: String },
    /// Network or other error
    Other(anyhow::Error),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized => write!(f, "Unauthorized (invalid token)"),
            ApiError::Decommissioned => write!(f, "Agent has been decommissioned"),
            ApiError::Disabled => write!(f, "Agent is disabled in ConnLog"),
            ApiError::RateLimited { retry_after_secs } => match retry_after_secs {
                Some(secs) => write!(f, "Rate limited (429), retry after {}s", secs),
                None => write!(f, "Rate limited (429)"),
            },
            ApiError::HttpError { status, message } => write!(f, "HTTP {} - {}", status, message),
            ApiError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Other(e)
    }
}

impl ApiError {
    /// Failures that are expected to clear on their own: transport errors,
    /// server errors during platform deploys or load-balancer blips, and
    /// rate limiting. The daemon loop keeps the retry backoff for these near
    /// the heartbeat interval — an exponential backoff on a short-interval
    /// agent would blow past the platform's offline threshold and flap it.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            ApiError::HttpError { status, .. } => is_transient_http_status(*status),
            ApiError::RateLimited { .. } => true,
            ApiError::Other(_) => true,
            _ => false,
        }
    }

    /// Whether an immediate in-cycle retry (sub-second delay) is appropriate.
    /// Rate limiting is transient for backoff purposes but must NOT be
    /// retried in-cycle: the server explicitly asked us to slow down, and
    /// hammering it again 250ms later only re-trips the limiter.
    pub(crate) fn retryable_in_cycle(&self) -> bool {
        !matches!(self, ApiError::RateLimited { .. }) && self.is_transient()
    }
}

/// HTTP statuses that usually mean "try again in a moment" rather than a
/// permanent rejection: any 5xx. Platform 500s (transient DB errors) are as
/// recoverable in practice as the 502-504 a proxy emits during a deploy.
pub(crate) fn is_transient_http_status(status: u16) -> bool {
    (500..=599).contains(&status)
}

const TRANSIENT_HTTP_ATTEMPTS: u32 = 3;

pub(crate) fn transient_retry_delay(attempt: u32) -> Duration {
    Duration::from_millis(250 * 2u64.pow(attempt.saturating_sub(1).min(2)))
}

pub struct ApiClient {
    client: Client,
    base_url: String,
    token: String,
    /// SHA-256 hash of the host's stable machine identifier. `None` when no
    /// source is available (e.g. an unsupported OS); platform falls back to
    /// hostname binding in that case.
    machine_id: Option<String>,
    /// Where `send_heartbeat` currently POSTs to. Defaults to
    /// `{base_url}/api/agents/heartbeat` and can be repointed at a regional
    /// endpoint via `set_heartbeat_endpoint` once the platform hands out an
    /// assignment (see `endpoint_assignment`). Interior mutability lets the
    /// loop hold a single shared `&ApiClient` without threading the resolved
    /// URL through every `send_heartbeat` call site (including the test
    /// harnesses in `simulation.rs`, whose signatures must stay stable).
    heartbeat_url: Mutex<String>,
    /// Optional heartbeat delivery telemetry sink. `None` by default (and in
    /// every test that does not opt in) so existing constructor/method
    /// signatures stay stable; the daemon attaches one via
    /// [`set_telemetry`](Self::set_telemetry). Recording is best-effort and
    /// never affects heartbeat delivery.
    telemetry: Option<HeartbeatTelemetry>,
    /// Wall-clock budget for one heartbeat *cycle* (all in-cycle attempts
    /// plus retry delays). The daemon sets this to the heartbeat interval
    /// whenever config loads or changes: with a short interval, three
    /// 10s-timeout attempts (~31s) would otherwise keep `lastHeartbeatAt`
    /// stale past the platform's offline threshold and flap the agent.
    /// `None` (tests, CLI paths) keeps the unbounded 3-attempt behavior.
    /// Interior mutability for the same reason as `heartbeat_url` above.
    heartbeat_cycle_budget: Mutex<Option<Duration>>,
}

/// Minimum useful time for one more in-cycle retry: the retry is skipped when
/// less than this remains in the cycle budget after the retry delay, and a
/// budget-capped attempt never gets a request timeout shorter than this.
const MIN_RETRY_BUDGET: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, Default)]
pub struct QuickActionPollingReport {
    pub enabled: bool,
    pub poll_interval_seconds: u64,
    pub last_poll_at_unix_ms: Option<u128>,
    pub next_poll_at_unix_ms: Option<u128>,
}

#[derive(Debug, serde::Deserialize)]
struct QuickActionPollResponse {
    #[serde(default)]
    quick_actions: Vec<QuickActionRequest>,
}

/// Total per-request timeout (connect + read + write). Tight on purpose: the
/// daemon must never block the heartbeat loop on a hung connection. Pinned by
/// a regression test below so a careless `Client::builder()` change can't
/// silently lift it.
pub(crate) const REQUEST_TIMEOUT_SECS: u64 = 10;

/// TCP+TLS connect timeout. Half the total budget — we want the agent to fail
/// fast on a black-holed route and reach the retry/back-off path quickly.
pub(crate) const CONNECT_TIMEOUT_SECS: u64 = 5;

impl ApiClient {
    pub fn new(base_url: String, token: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            // SECURITY: Disable redirects to prevent token leakage.
            // A compromised DNS/CDN could redirect to an attacker-controlled server;
            // reqwest would follow and forward the Authorization header.
            .redirect(reqwest::redirect::Policy::none())
            // Identify ourselves on the server side. Server-side metrics + abuse
            // dashboards can group by this; aids debugging without leaking secrets.
            .user_agent(concat!("connlog-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to create HTTP client")?;

        let heartbeat_url = format!("{}/api/agents/heartbeat", base_url.trim_end_matches('/'));

        Ok(Self {
            client,
            base_url,
            token,
            machine_id: crate::identity::machine_id(),
            heartbeat_url: Mutex::new(heartbeat_url),
            telemetry: None,
            heartbeat_cycle_budget: Mutex::new(None),
        })
    }

    /// Attach a heartbeat delivery telemetry sink. Call once, before the client
    /// is shared with the heartbeat loop. Tests and diagnostic CLI paths that
    /// never call this keep behaving exactly as before (no recording).
    pub fn set_telemetry(&mut self, telemetry: HeartbeatTelemetry) {
        self.telemetry = Some(telemetry);
    }

    fn record(&self, builder: EventBuilder) {
        if let Some(telemetry) = &self.telemetry {
            telemetry.record(builder);
        }
    }

    /// Repoint `send_heartbeat` at a new (already-validated) URL. Called by
    /// `EndpointAssignmentState` when it applies a trusted regional
    /// assignment, or reverts to the default after a failed/untrusted fetch.
    pub(crate) fn set_heartbeat_endpoint(&self, url: String) {
        let mut guard = self
            .heartbeat_url
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = url;
    }

    fn heartbeat_url(&self) -> String {
        self.heartbeat_url
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Set the wall-clock budget for one heartbeat cycle. The daemon calls
    /// this with the heartbeat interval whenever config loads or changes.
    pub fn set_heartbeat_cycle_budget(&self, budget: Duration) {
        let mut guard = self
            .heartbeat_cycle_budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(budget);
    }

    fn heartbeat_cycle_budget(&self) -> Option<Duration> {
        *self
            .heartbeat_cycle_budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Send heartbeat using the binary wire protocol (v1, 32-byte LE frame).
    /// This is the only supported transport — there is no JSON fallback.
    pub fn send_heartbeat(
        &self,
        payload: &HeartbeatPayload,
        quick_action_polling: Option<&QuickActionPollingReport>,
    ) -> Result<HeartbeatResponse, ApiError> {
        // One opaque correlation id per heartbeat *cycle*, shared by every
        // attempt so the diagnostics store can stitch retries back to the
        // original heartbeat.
        let request_id = new_request_id();
        let endpoint_host = host_from_url(&self.heartbeat_url());
        let cycle_deadline = self
            .heartbeat_cycle_budget()
            .map(|budget| Instant::now() + budget);
        let mut last_err = None;
        for attempt in 1..=TRANSIENT_HTTP_ATTEMPTS {
            match self.send_heartbeat_once(
                payload,
                quick_action_polling,
                &request_id,
                attempt,
                cycle_deadline,
            ) {
                Ok(response) => return Ok(response),
                Err(err) => {
                    let delay = transient_retry_delay(attempt);
                    // A retry must fit inside the cycle budget: skip it when
                    // less than MIN_RETRY_BUDGET would remain after the delay.
                    let fits_budget = cycle_deadline.is_none_or(|deadline| {
                        Instant::now() + delay + MIN_RETRY_BUDGET <= deadline
                    });
                    let retryable = err.retryable_in_cycle()
                        && attempt < TRANSIENT_HTTP_ATTEMPTS
                        && fits_budget;
                    if retryable {
                        self.record(
                            EventBuilder::new(
                                &request_id,
                                attempt,
                                EventType::RetryScheduled,
                                &endpoint_host,
                            )
                            .retry_delay(delay),
                        );
                        log::warn!(
                            target: HB_LOG_TARGET,
                            "heartbeat_retry hb_id={request_id} attempt={attempt} retry_delay_ms={}",
                            delay.as_millis()
                        );
                        std::thread::sleep(delay);
                        last_err = Some(err);
                        continue;
                    }
                    if err.retryable_in_cycle() {
                        // Ran out of retry budget on a transient failure.
                        // (RateLimited never enters here: it is transient but
                        // deliberately not retried in-cycle, so there is no
                        // budget to exhaust.)
                        self.record(
                            EventBuilder::new(
                                &request_id,
                                attempt,
                                EventType::RetryExhausted,
                                &endpoint_host,
                            )
                            .category(ErrorCategory::RetryExhausted),
                        );
                        log::warn!(
                            target: HB_LOG_TARGET,
                            "heartbeat_retry_exhausted hb_id={request_id} attempts={attempt}"
                        );
                    }
                    return Err(err);
                }
            }
        }
        Err(last_err.expect("TRANSIENT_HTTP_ATTEMPTS must be >= 1"))
    }

    fn send_heartbeat_once(
        &self,
        payload: &HeartbeatPayload,
        quick_action_polling: Option<&QuickActionPollingReport>,
        request_id: &str,
        attempt: u32,
        cycle_deadline: Option<Instant>,
    ) -> Result<HeartbeatResponse, ApiError> {
        let url = self.heartbeat_url();
        let endpoint_host = host_from_url(&url);

        let binary_payload = encode_heartbeat(payload);

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            "X-Agent-Version",
            HeaderValue::from_str(&payload.agent_version)
                .context("Failed to create agent version header")?,
        );
        headers.insert(
            "X-Protocol-Version",
            HeaderValue::from_str(&payload.protocol_version.to_string())
                .context("Failed to create protocol version header")?,
        );
        headers.insert(
            "X-Config-Version",
            HeaderValue::from_str(&payload.config_version.to_string())
                .context("Failed to create config version header")?,
        );
        // Hostname is opt-in. Only sent when CONNLOG_EXPOSE_SYSTEM_INFO=true.
        if let Some(hostname) = &payload.hostname {
            headers.insert(
                "X-Hostname",
                HeaderValue::from_str(hostname).context("Failed to create hostname header")?,
            );
        }
        // OS/arch are always sent so the platform can select the correct
        // self-update binary, regardless of hostname opt-in.
        headers.insert(
            "X-OS",
            HeaderValue::from_str(&payload.os).context("Failed to create OS header")?,
        );
        headers.insert(
            "X-Arch",
            HeaderValue::from_str(&payload.arch).context("Failed to create arch header")?,
        );

        if let Some(mid) = &self.machine_id {
            headers.insert(
                "X-Machine-Id",
                HeaderValue::from_str(mid).context("Failed to create machine-id header")?,
            );
        }

        // Logical CPU count, so the platform can read the load average
        // against the machine's size. A header rather than a frame field:
        // the 32-byte layout stays put and an older platform ignores it.
        if let Some(cores) = payload.metrics.cpu_core_count {
            headers.insert(
                CPU_CORE_COUNT_HEADER,
                HeaderValue::from_str(&cores.to_string())
                    .context("Failed to create cpu-core-count header")?,
            );
        }

        // Correlation id. Opaque, agent-generated, ignored by the platform
        // today; lets a future server-side correlate without touching auth.
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(request_id).context("Failed to create request-id header")?,
        );

        add_quick_action_polling_headers(&mut headers, quick_action_polling)?;

        // SECURITY: Never log the token
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).context("Failed to create authorization header")?,
        );

        let started = Instant::now();
        let mut request = self
            .client
            .post(&url)
            .headers(headers)
            .body(binary_payload.to_vec());
        if let Some(deadline) = cycle_deadline {
            // Shrink this attempt's timeout to whatever is left of the cycle
            // budget (floored at MIN_RETRY_BUDGET so an attempt is never
            // pointlessly short). Without this, a hung connection holds the
            // whole REQUEST_TIMEOUT even when the cycle budget is smaller.
            let remaining = deadline.saturating_duration_since(started);
            let attempt_timeout = remaining
                .min(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .max(MIN_RETRY_BUDGET);
            request = request.timeout(attempt_timeout);
        }
        let response = match request.send() {
            Ok(response) => response,
            Err(err) => {
                // Transport-level failure: never reached an HTTP status.
                let elapsed = started.elapsed();
                let category = classify_reqwest_error(&err);
                let event_type = category_event_type(category);
                self.record(
                    EventBuilder::new(request_id, attempt, event_type, &endpoint_host)
                        .duration(elapsed)
                        .category(category)
                        .detail(&error_chain_string(&err)),
                );
                log::warn!(
                    target: HB_LOG_TARGET,
                    "heartbeat_outcome hb_id={request_id} attempt={attempt} outcome=failed error_category={} status_code=- duration_ms={}",
                    category.as_str(),
                    elapsed.as_millis()
                );
                return Err(ApiError::Other(
                    anyhow::Error::new(err).context("Failed to send binary heartbeat request"),
                ));
            }
        };
        let elapsed = started.elapsed();
        let status = response.status();

        // Non-success: record before consuming the body. We persist only the
        // HTTP status reason phrase as detail, never the raw response body, so
        // no backend payload can leak into the telemetry store.
        if !status.is_success() {
            let category = http_status_category(status.as_u16());
            let event_type = category_event_type(category);
            self.record(
                EventBuilder::new(request_id, attempt, event_type, &endpoint_host)
                    .http_status(status.as_u16())
                    .duration(elapsed)
                    .category(category)
                    .detail(status.canonical_reason().unwrap_or("HTTP error")),
            );
            log::warn!(
                target: HB_LOG_TARGET,
                "heartbeat_outcome hb_id={request_id} attempt={attempt} outcome=failed error_category={} status_code={} duration_ms={}",
                category.as_str(),
                status.as_u16(),
                elapsed.as_millis()
            );

            // Map to the typed ApiError the daemon loop expects.
            if status == StatusCode::UNAUTHORIZED {
                return Err(ApiError::Unauthorized);
            }
            if status == StatusCode::GONE {
                return Err(ApiError::Decommissioned);
            }
            if status == StatusCode::LOCKED {
                return Err(ApiError::Disabled);
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                // Only the delay-seconds form of Retry-After is honored; the
                // HTTP-date form fails the parse and falls back to None
                // (interval-based backoff in the daemon loop).
                let retry_after_secs = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.trim().parse::<u64>().ok());
                return Err(ApiError::RateLimited { retry_after_secs });
            }
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ApiError::HttpError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let heartbeat_response: HeartbeatResponse = match response.json() {
            Ok(parsed) => parsed,
            Err(err) => {
                // Platform accepted the heartbeat (2xx) but the body did not
                // parse — an agent-side decode problem, recorded distinctly.
                self.record(
                    EventBuilder::new(
                        request_id,
                        attempt,
                        EventType::SerializationError,
                        &endpoint_host,
                    )
                    .http_status(status.as_u16())
                    .duration(elapsed)
                    .category(ErrorCategory::SerializationError)
                    .detail(&error_chain_string(&err)),
                );
                log::warn!(
                    target: HB_LOG_TARGET,
                    "heartbeat_outcome hb_id={request_id} attempt={attempt} outcome=failed error_category=serialization_error status_code={} duration_ms={}",
                    status.as_u16(),
                    elapsed.as_millis()
                );
                return Err(ApiError::Other(
                    anyhow::Error::new(err).context("Failed to parse heartbeat response"),
                ));
            }
        };

        // Fully successful round-trip.
        self.record(
            EventBuilder::new(request_id, attempt, EventType::Accepted, &endpoint_host)
                .http_status(status.as_u16())
                .duration(elapsed),
        );
        log::debug!(
            target: HB_LOG_TARGET,
            "heartbeat_outcome hb_id={request_id} attempt={attempt} outcome=accepted status_code={} duration_ms={}",
            status.as_u16(),
            elapsed.as_millis()
        );

        Ok(heartbeat_response)
    }

    pub fn fetch_config(&self) -> Result<AgentConfig> {
        let url = format!("{}/api/agents/config", self.base_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let auth_value = format!("Bearer {}", self.token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).context("Failed to create authorization header")?,
        );

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .context("Failed to fetch config")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Config fetch failed with status {}: {}", status, error_text);
        }

        // Get the response text first for better error reporting
        let response_text = response
            .text()
            .context("Failed to read config response body")?;

        // The platform wraps successful responses in an `apiResponse.ok`
        // envelope: `{"ok":true,"data":<AgentConfig>}`. Parse the envelope
        // first, then extract `data`. Direct `from_str::<AgentConfig>` would
        // (and historically did) fail with "missing field configVersion",
        // leaving the agent stuck on the v0 fallback config — which has all
        // metric toggles enabled by default but, crucially, prevented config
        // version ever advancing past 0 and broke any feature that gates on
        // `configVersion > 0`.
        #[derive(serde::Deserialize)]
        struct Envelope<T> {
            ok: bool,
            data: Option<T>,
            error: Option<String>,
        }

        let envelope: Envelope<AgentConfig> = serde_json::from_str(&response_text)
            .with_context(|| format!("Failed to parse config envelope: {}", response_text))?;

        if !envelope.ok {
            anyhow::bail!(
                "Config response not ok: {}",
                envelope.error.unwrap_or_else(|| response_text.clone())
            );
        }

        envelope.data.ok_or_else(|| {
            anyhow::anyhow!("Config envelope missing `data` field: {}", response_text)
        })
    }

    /// `FetchEndpointAssignment` — ask the control plane which heartbeat
    /// endpoint this agent should use. Authenticated the same way as every
    /// other agent endpoint (bearer token); the platform decides what to
    /// hand back, the agent decides whether to trust it
    /// (`endpoint_assignment::validate_assigned_endpoint`).
    pub(crate) fn fetch_endpoint_assignment(&self) -> Result<EndpointAssignmentResponse> {
        let url = format!("{}/api/agents/endpoint-assignment", self.base_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).context("Failed to create authorization header")?,
        );

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .context("Failed to fetch endpoint assignment")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!(
                "Endpoint assignment fetch failed with status {}: {}",
                status,
                error_text
            );
        }

        let response_text = response
            .text()
            .context("Failed to read endpoint assignment response body")?;

        #[derive(serde::Deserialize)]
        struct Envelope<T> {
            ok: bool,
            data: Option<T>,
            error: Option<String>,
        }

        let envelope: Envelope<EndpointAssignmentResponse> = serde_json::from_str(&response_text)
            .with_context(|| {
            format!("Failed to parse endpoint assignment envelope: {response_text}")
        })?;

        if !envelope.ok {
            anyhow::bail!(
                "Endpoint assignment response not ok: {}",
                envelope.error.unwrap_or_else(|| response_text.clone())
            );
        }

        envelope.data.ok_or_else(|| {
            anyhow::anyhow!("Endpoint assignment envelope missing `data` field: {response_text}")
        })
    }

    pub fn send_quick_actions_manifest(
        &self,
        payload: &QuickActionsManifestPayload,
    ) -> Result<(), ApiError> {
        let url = format!("{}/api/agents/actions/manifest", self.base_url);
        let auth_value = format!("Bearer {}", self.token);

        let response = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, auth_value)
            .json(payload)
            .send()
            .context("Failed to send quick actions manifest")?;

        if !response.status().is_success() {
            return Err(ApiError::HttpError {
                status: response.status().as_u16(),
                message: response
                    .text()
                    .unwrap_or_else(|_| "Unknown error".to_string()),
            });
        }

        Ok(())
    }

    pub fn send_quick_action_result(
        &self,
        payload: &QuickActionResultPayload,
    ) -> Result<(), ApiError> {
        let url = format!("{}/api/agents/actions/results", self.base_url);
        let auth_value = format!("Bearer {}", self.token);

        let response = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, auth_value)
            .json(payload)
            .send()
            .context("Failed to send quick action result")?;

        if !response.status().is_success() {
            return Err(ApiError::HttpError {
                status: response.status().as_u16(),
                message: response
                    .text()
                    .unwrap_or_else(|_| "Unknown error".to_string()),
            });
        }

        Ok(())
    }

    pub fn poll_quick_actions(
        &self,
        quick_action_polling: &QuickActionPollingReport,
    ) -> Result<Vec<QuickActionRequest>, ApiError> {
        let url = format!("{}/api/agents/actions/pending", self.base_url);
        let auth_value = format!("Bearer {}", self.token);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).context("Failed to create authorization header")?,
        );
        add_quick_action_polling_headers(&mut headers, Some(quick_action_polling))?;

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .context("Failed to poll quick action queue")?;

        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }

        if status == StatusCode::GONE {
            return Err(ApiError::Decommissioned);
        }

        if status == StatusCode::LOCKED {
            return Err(ApiError::Disabled);
        }

        if !status.is_success() {
            return Err(ApiError::HttpError {
                status: status.as_u16(),
                message: response
                    .text()
                    .unwrap_or_else(|_| "Unknown error".to_string()),
            });
        }

        let poll_response: QuickActionPollResponse = response
            .json()
            .context("Failed to parse quick action poll response")?;

        Ok(poll_response.quick_actions)
    }
}

fn add_quick_action_polling_headers(
    headers: &mut HeaderMap,
    report: Option<&QuickActionPollingReport>,
) -> Result<()> {
    let Some(report) = report else {
        return Ok(());
    };

    headers.insert(
        "X-Quick-Action-Polling-Enabled",
        HeaderValue::from_static(if report.enabled { "true" } else { "false" }),
    );
    headers.insert(
        "X-Quick-Action-Poll-Interval-Seconds",
        HeaderValue::from_str(&report.poll_interval_seconds.to_string())
            .context("Failed to create quick action poll interval header")?,
    );
    if let Some(value) = report.last_poll_at_unix_ms {
        headers.insert(
            "X-Quick-Action-Last-Poll-At-Ms",
            HeaderValue::from_str(&value.to_string())
                .context("Failed to create quick action last poll header")?,
        );
    }
    if let Some(value) = report.next_poll_at_unix_ms {
        headers.insert(
            "X-Quick-Action-Next-Poll-At-Ms",
            HeaderValue::from_str(&value.to_string())
                .context("Failed to create quick action next poll header")?,
        );
    }

    Ok(())
}

/// Extract just the host from a URL for telemetry — no scheme, port, path, or
/// query, so a token-bearing URL can never be persisted. `http://h:80/p?x=1`
/// becomes `h`. Falls back to the raw input only if there is no `://`.
pub(crate) fn host_from_url(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop userinfo and port.
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    host.split(':').next().unwrap_or(host).to_string()
}

/// Map an HTTP status to a telemetry [`ErrorCategory`].
pub(crate) fn http_status_category(status: u16) -> ErrorCategory {
    match status {
        401 => ErrorCategory::Unauthorized,
        403 => ErrorCategory::Forbidden,
        429 => ErrorCategory::RateLimited,
        500..=599 => ErrorCategory::ServerError,
        _ => ErrorCategory::HttpRejected,
    }
}

/// Map an [`ErrorCategory`] to the lifecycle [`EventType`] recorded for it.
pub(crate) fn category_event_type(category: ErrorCategory) -> EventType {
    match category {
        ErrorCategory::DnsError => EventType::DnsError,
        ErrorCategory::ConnectionError => EventType::ConnectionError,
        ErrorCategory::ConnectTimeout => EventType::ConnectTimeout,
        ErrorCategory::RequestTimeout => EventType::RequestTimeout,
        ErrorCategory::TlsError => EventType::TlsError,
        ErrorCategory::RateLimited => EventType::RateLimited,
        ErrorCategory::ServerError => EventType::ServerError,
        ErrorCategory::SerializationError => EventType::SerializationError,
        ErrorCategory::SignatureError => EventType::SignatureError,
        ErrorCategory::RetryExhausted => EventType::RetryExhausted,
        // Unauthorized / Forbidden / generic 4xx all surface as http_rejected.
        ErrorCategory::Unauthorized | ErrorCategory::Forbidden | ErrorCategory::HttpRejected => {
            EventType::HttpRejected
        }
    }
}

/// Best-effort classification of a transport-level `reqwest` error into a
/// telemetry category. Uses the typed predicates first, then keyword-matches
/// the error source chain for DNS/TLS, which `reqwest` does not expose as flags.
pub(crate) fn classify_reqwest_error(err: &reqwest::Error) -> ErrorCategory {
    let chain = error_chain_string(err).to_ascii_lowercase();
    classify_error_parts(err.is_timeout(), err.is_connect(), &chain)
}

/// Pure classification core, split out so every category is deterministically
/// testable without having to synthesise a real `reqwest::Error`. `chain_lower`
/// is the lowercased, flattened error source chain.
pub(crate) fn classify_error_parts(
    is_timeout: bool,
    is_connect: bool,
    chain_lower: &str,
) -> ErrorCategory {
    let looks_dns = chain_lower.contains("dns")
        || chain_lower.contains("failed to lookup")
        || chain_lower.contains("name or service not known")
        || chain_lower.contains("name resolution")
        || chain_lower.contains("nodename nor servname");
    let looks_tls = chain_lower.contains("tls")
        || chain_lower.contains("ssl")
        || chain_lower.contains("certificate")
        || chain_lower.contains("handshake");

    if is_timeout {
        return if is_connect {
            ErrorCategory::ConnectTimeout
        } else {
            ErrorCategory::RequestTimeout
        };
    }
    if looks_dns {
        return ErrorCategory::DnsError;
    }
    if looks_tls {
        return ErrorCategory::TlsError;
    }
    ErrorCategory::ConnectionError
}

/// Flatten an error and its `source()` chain into a single string for
/// classification/detail. The caller sanitizes/caps before persistence.
pub(crate) fn error_chain_string(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    let mut depth = 0;
    while let Some(inner) = source {
        parts.push(inner.to_string());
        source = inner.source();
        depth += 1;
        if depth > 8 {
            break;
        }
    }
    parts.join(": ")
}

/// Encode a heartbeat payload into the 32-byte protocol v1 binary wire frame.
///
/// Frame layout (little-endian):
/// | Offset | Size | Field                        |
/// |--------|------|------------------------------|
/// | 0      | 8    | uptime_seconds (u64 LE)      |
/// | 8      | 2    | cpu_percent × 100, or 0xffff when unavailable |
/// | 10     | 2    | cpu_max × 100, or 0xffff when unavailable     |
/// | 12     | 4    | memory_used_mb (u32 LE)      |
/// | 16     | 4    | memory_total_mb (u32 LE)     |
/// | 20     | 4    | disk_used_mb (u32 LE)        |
/// | 24     | 4    | disk_total_mb (u32 LE)       |
/// | 28     | 2    | load_1m × 100 (u16 LE)       |
/// | 30     | 2    | load_max × 100 (u16 LE)      |
///
/// Identity metadata (hostname, OS, arch, versions) is carried in HTTP headers,
/// not in this frame. cpu_max and load_max mirror cpu_avg/load_avg for now
/// (single-sample path — min/max fields mirror the average sample).
pub(crate) fn encode_heartbeat(payload: &HeartbeatPayload) -> [u8; 32] {
    let mut frame = [0u8; 32];

    // [0..8] uptime_seconds as u64 LE
    frame[0..8].copy_from_slice(&payload.uptime_seconds.to_le_bytes());

    // [8..10] cpu_percent × 100 as u16 LE. 0xffff is a
    // protocol-compatible sentinel for "CPU interval unavailable"; valid CPU
    // values are clamped to 0..=10000.
    let encode_cpu = |value: Option<f64>| {
        value
            .map(|v| (v.clamp(0.0, 100.0) * 100.0).round() as u16)
            .unwrap_or(CPU_UNAVAILABLE_X100)
    };
    let cpu_x100 = encode_cpu(payload.metrics.cpu_percent);
    frame[8..10].copy_from_slice(&cpu_x100.to_le_bytes());
    // [10..12] cpu_max is peak core over the same interval, if available.
    let cpu_max_x100 = encode_cpu(
        payload
            .metrics
            .cpu_peak_percent
            .or(payload.metrics.cpu_percent),
    );
    frame[10..12].copy_from_slice(&cpu_max_x100.to_le_bytes());

    // [12..16] memory_used_mb as u32 LE
    frame[12..16].copy_from_slice(&(payload.metrics.memory_used_mb as u32).to_le_bytes());
    // [16..20] memory_total_mb as u32 LE
    frame[16..20].copy_from_slice(&(payload.metrics.memory_total_mb as u32).to_le_bytes());
    // [20..24] disk_used_mb as u32 LE
    frame[20..24].copy_from_slice(&(payload.metrics.disk_used_mb as u32).to_le_bytes());
    // [24..28] disk_total_mb as u32 LE
    frame[24..28].copy_from_slice(&(payload.metrics.disk_total_mb as u32).to_le_bytes());

    // [28..30] load_1m × 100 as u16 LE.
    // Clamped to 65534 (u16::MAX - 1) so 0xffff remains unambiguously
    // "unavailable" (the CPU sentinel) and extreme loads never silently
    // wrap around to a small value (e.g. load 700 → 1.35 without the cap).
    let load_x100 = ((payload.metrics.load_1m * 100.0).round() as u32).min(65534) as u16;
    frame[28..30].copy_from_slice(&load_x100.to_le_bytes());
    // [30..32] load_max mirrors load_avg (no multi-sample aggregation yet)
    frame[30..32].copy_from_slice(&load_x100.to_le_bytes());

    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::{HeartbeatPayload, Metrics};

    /// REGRESSION: a careless `.timeout(Duration::from_secs(60))` would let a
    /// hung connection block the heartbeat loop for a full minute, which then
    /// stacks under back-off. Pin the budget so the next reviewer sees the
    /// intent before raising it.
    #[test]
    fn http_timeouts_are_tight_enough_for_heartbeat_loop() {
        const _: () = {
            assert!(
                REQUEST_TIMEOUT_SECS <= 15,
                "total request timeout must stay tight (<=15s) so the heartbeat loop never blocks"
            );
            assert!(
                CONNECT_TIMEOUT_SECS <= REQUEST_TIMEOUT_SECS,
                "connect timeout must not exceed total request timeout"
            );
            assert!(CONNECT_TIMEOUT_SECS >= 3);
        };
    }

    fn make_payload(
        uptime: u64,
        cpu: f64,
        mem_used: u64,
        mem_total: u64,
        disk_used: u64,
        disk_total: u64,
        load: f64,
    ) -> HeartbeatPayload {
        HeartbeatPayload {
            // SECURITY/CORRECTNESS: derive from CARGO_PKG_VERSION so this test never
            // silently rots when Cargo.toml is bumped. Hardcoding a string here was a
            // footgun: bumping the crate version would have left the test asserting an
            // outdated value if anything actually inspected agent_version.
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: 1,
            config_version: 0,
            hostname: Some("test-host".to_string()),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            uptime_seconds: uptime,
            metrics: Metrics {
                cpu_percent: Some(cpu),
                cpu_peak_percent: Some(cpu),
                cpu_core_count: None,
                memory_used_mb: mem_used,
                memory_total_mb: mem_total,
                disk_used_mb: disk_used,
                disk_total_mb: disk_total,
                load_1m: load,
            },
            dev_mode: None,
        }
    }

    /// Frame must always be exactly 32 bytes — platform validates `bytes.length !== 32`.
    #[test]
    fn test_frame_is_32_bytes() {
        let payload = make_payload(12345, 12.5, 1024, 8192, 20480, 100000, 0.42);
        let frame = encode_heartbeat(&payload);
        assert_eq!(
            frame.len(),
            32,
            "Protocol v1 frame must be exactly 32 bytes"
        );
    }

    /// Decode and verify each field at its documented byte offset.
    #[test]
    fn test_frame_field_offsets() {
        let payload = make_payload(
            0x0102030405060708u64, // uptime - distinctive value
            12.5,                  // cpu    → 1250 as u16
            1024,                  // mem_used
            8192,                  // mem_total
            20480,                 // disk_used
            100000,                // disk_total
            0.42,                  // load   → 42 as u16
        );
        let frame = encode_heartbeat(&payload);

        // [0..8] uptime_seconds little-endian u64
        let uptime = u64::from_le_bytes(frame[0..8].try_into().unwrap());
        assert_eq!(uptime, 0x0102030405060708u64);

        // [8..10] cpu_percent × 100 as u16 LE
        let cpu_x100 = u16::from_le_bytes(frame[8..10].try_into().unwrap());
        assert_eq!(cpu_x100, 1250, "12.5% × 100 = 1250");

        // [10..12] cpu_max mirrors cpu_avg in single-sample path
        let cpu_max_x100 = u16::from_le_bytes(frame[10..12].try_into().unwrap());
        assert_eq!(cpu_max_x100, cpu_x100, "cpu_max must mirror cpu_avg");

        // [12..16] memory_used_mb as u32 LE
        let mem_used = u32::from_le_bytes(frame[12..16].try_into().unwrap());
        assert_eq!(mem_used, 1024);

        // [16..20] memory_total_mb as u32 LE
        let mem_total = u32::from_le_bytes(frame[16..20].try_into().unwrap());
        assert_eq!(mem_total, 8192);

        // [20..24] disk_used_mb as u32 LE
        let disk_used = u32::from_le_bytes(frame[20..24].try_into().unwrap());
        assert_eq!(disk_used, 20480);

        // [24..28] disk_total_mb as u32 LE
        let disk_total = u32::from_le_bytes(frame[24..28].try_into().unwrap());
        assert_eq!(disk_total, 100000);

        // [28..30] load_1m × 100 as u16 LE
        let load_x100 = u16::from_le_bytes(frame[28..30].try_into().unwrap());
        assert_eq!(load_x100, 42, "0.42 × 100 = 42");

        // [30..32] load_max mirrors load_avg
        let load_max_x100 = u16::from_le_bytes(frame[30..32].try_into().unwrap());
        assert_eq!(load_max_x100, load_x100, "load_max must mirror load_avg");
    }

    /// Zero-metric payload (metrics disabled) should encode cleanly.
    #[test]
    fn test_frame_zero_metrics() {
        let payload = make_payload(0, 0.0, 0, 0, 0, 0, 0.0);
        let frame = encode_heartbeat(&payload);
        assert_eq!(
            frame, [0u8; 32],
            "All-zero metrics must produce an all-zero frame"
        );
    }

    /// Verify that high uptime values encode without truncation.
    #[test]
    fn test_frame_large_uptime() {
        let uptime = u64::MAX / 2;
        let payload = make_payload(uptime, 0.0, 0, 0, 0, 0, 0.0);
        let frame = encode_heartbeat(&payload);
        let decoded = u64::from_le_bytes(frame[0..8].try_into().unwrap());
        assert_eq!(decoded, uptime);
    }

    /// Max CPU (100%) and high load encode correctly without overflow.
    #[test]
    fn test_frame_max_cpu_load() {
        // 100.0 × 100 = 10000, well within u16 range (max 65535)
        let payload = make_payload(0, 100.0, 0, 0, 0, 0, 99.99);
        let frame = encode_heartbeat(&payload);
        let cpu_x100 = u16::from_le_bytes(frame[8..10].try_into().unwrap());
        assert_eq!(cpu_x100, 10000, "100% × 100 = 10000");
        let load_x100 = u16::from_le_bytes(frame[28..30].try_into().unwrap());
        // 99.99 × 100 = 9999.000...002 in f64, rounds to 9999
        assert_eq!(load_x100, 9999, "99.99 × 100 = 9999 (f64 rounding)");
    }

    /// Load values above 655.35 must be clamped to 65534, not wrap around.
    /// Without the clamp, load=700.0 → (700*100) as u16 = 4464, which the
    /// platform decodes as 44.64 — a silent wrap to a plausible-looking value.
    #[test]
    fn test_frame_extreme_load_clamped() {
        let payload = make_payload(0, 0.0, 0, 0, 0, 0, 700.0);
        let frame = encode_heartbeat(&payload);
        let load_x100 = u16::from_le_bytes(frame[28..30].try_into().unwrap());
        assert_eq!(load_x100, 65534, "load 700 must clamp to 65534, not wrap");
    }

    #[test]
    fn test_frame_cpu_unavailable_uses_sentinel() {
        let mut payload = make_payload(0, 0.0, 0, 0, 0, 0, 0.0);
        payload.metrics.cpu_percent = None;
        payload.metrics.cpu_peak_percent = None;
        let frame = encode_heartbeat(&payload);
        let cpu_x100 = u16::from_le_bytes(frame[8..10].try_into().unwrap());
        let cpu_max_x100 = u16::from_le_bytes(frame[10..12].try_into().unwrap());
        assert_eq!(cpu_x100, CPU_UNAVAILABLE_X100);
        assert_eq!(cpu_max_x100, CPU_UNAVAILABLE_X100);
    }

    #[test]
    fn test_transient_http_status_codes() {
        assert!(super::is_transient_http_status(502));
        assert!(super::is_transient_http_status(503));
        assert!(super::is_transient_http_status(504));
        assert!(super::is_transient_http_status(500));
        assert!(!super::is_transient_http_status(401));
        // 429 is handled by the dedicated RateLimited variant, never HttpError.
        assert!(!super::is_transient_http_status(429));
        assert!(!super::is_transient_http_status(400));
    }

    #[test]
    fn test_api_error_transient_classification() {
        use super::ApiError;

        assert!(ApiError::HttpError {
            status: 502,
            message: "bad gateway".into(),
        }
        .is_transient());
        assert!(ApiError::Other(anyhow::anyhow!("connection reset")).is_transient());
        assert!(ApiError::RateLimited {
            retry_after_secs: None
        }
        .is_transient());
        assert!(!ApiError::Unauthorized.is_transient());
        assert!(!ApiError::Disabled.is_transient());
    }

    #[test]
    fn rate_limited_is_never_retried_in_cycle() {
        use super::ApiError;

        // Transient for backoff purposes, but an immediate retry would just
        // re-trip the server's limiter.
        assert!(!ApiError::RateLimited {
            retry_after_secs: Some(30)
        }
        .retryable_in_cycle());
        assert!(ApiError::HttpError {
            status: 503,
            message: "unavailable".into(),
        }
        .retryable_in_cycle());
        assert!(ApiError::Other(anyhow::anyhow!("connection reset")).retryable_in_cycle());
        assert!(!ApiError::Unauthorized.retryable_in_cycle());
    }

    // ── telemetry helpers ───────────────────────────────────────

    #[test]
    fn host_from_url_strips_scheme_port_path_and_userinfo() {
        assert_eq!(
            super::host_from_url("https://connlog.com/api/agents/heartbeat"),
            "connlog.com"
        );
        assert_eq!(
            super::host_from_url("http://127.0.0.1:53431/api/x?y=1"),
            "127.0.0.1"
        );
        assert_eq!(
            super::host_from_url("https://eu-1.connlog.com:443/hb"),
            "eu-1.connlog.com"
        );
        assert_eq!(
            super::host_from_url("https://user:pass@host.example/p"),
            "host.example"
        );
        // No scheme: falls back to the authority portion only (no path/query).
        assert_eq!(super::host_from_url("connlog.com/x"), "connlog.com");
    }

    #[test]
    fn http_status_category_mapping() {
        use crate::features::heartbeat_telemetry::ErrorCategory;
        assert_eq!(
            super::http_status_category(401).as_str(),
            ErrorCategory::Unauthorized.as_str()
        );
        assert_eq!(
            super::http_status_category(403).as_str(),
            ErrorCategory::Forbidden.as_str()
        );
        assert_eq!(
            super::http_status_category(429).as_str(),
            ErrorCategory::RateLimited.as_str()
        );
        assert_eq!(
            super::http_status_category(500).as_str(),
            ErrorCategory::ServerError.as_str()
        );
        assert_eq!(
            super::http_status_category(503).as_str(),
            ErrorCategory::ServerError.as_str()
        );
        assert_eq!(
            super::http_status_category(418).as_str(),
            ErrorCategory::HttpRejected.as_str()
        );
    }

    /// Deterministic coverage of every transport category without needing to
    /// synthesise a real `reqwest::Error`.
    #[test]
    fn classify_error_parts_covers_all_transport_categories() {
        use super::classify_error_parts;
        use crate::features::heartbeat_telemetry::ErrorCategory;

        // connect timeout: timeout AND connect.
        assert_eq!(
            classify_error_parts(true, true, "operation timed out").as_str(),
            ErrorCategory::ConnectTimeout.as_str()
        );
        // request/read timeout: timeout, not connect.
        assert_eq!(
            classify_error_parts(true, false, "operation timed out").as_str(),
            ErrorCategory::RequestTimeout.as_str()
        );
        // DNS failure keyword.
        assert_eq!(
            classify_error_parts(
                false,
                true,
                "failed to lookup address information: name or service not known"
            )
            .as_str(),
            ErrorCategory::DnsError.as_str()
        );
        // TLS failure keyword.
        assert_eq!(
            classify_error_parts(
                false,
                true,
                "invalid peer certificate: tls handshake failed"
            )
            .as_str(),
            ErrorCategory::TlsError.as_str()
        );
        // Generic connection failure (e.g. connection refused).
        assert_eq!(
            classify_error_parts(false, true, "tcp connect error: connection refused").as_str(),
            ErrorCategory::ConnectionError.as_str()
        );
    }

    #[test]
    fn error_chain_string_includes_sources() {
        use std::fmt;
        #[derive(Debug)]
        struct Inner;
        impl fmt::Display for Inner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "inner cause")
            }
        }
        impl std::error::Error for Inner {}
        #[derive(Debug)]
        struct Outer(Inner);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let s = super::error_chain_string(&Outer(Inner));
        assert!(s.contains("outer"));
        assert!(s.contains("inner cause"));
    }

    #[test]
    fn test_frame_cpu_peak_core_encodes_separately() {
        let mut payload = make_payload(0, 12.5, 0, 0, 0, 0, 0.0);
        payload.metrics.cpu_peak_percent = Some(28.25);
        let frame = encode_heartbeat(&payload);
        let cpu_x100 = u16::from_le_bytes(frame[8..10].try_into().unwrap());
        let cpu_max_x100 = u16::from_le_bytes(frame[10..12].try_into().unwrap());
        assert_eq!(cpu_x100, 1250);
        assert_eq!(cpu_max_x100, 2825);
    }
}
