use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use std::time::Duration;

use crate::heartbeat::{AgentConfig, HeartbeatPayload, HeartbeatResponse};

/// Error types for API calls
#[derive(Debug)]
pub enum ApiError {
    /// Agent token is invalid or revoked (401)
    Unauthorized,
    /// Agent has been marked for uninstall (410 Gone)
    Decommissioned,
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

pub struct ApiClient {
    client: Client,
    base_url: String,
    token: String,
    use_binary: bool,
}

impl ApiClient {
    pub fn new(base_url: String, token: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            // SECURITY: Disable redirects to prevent token leakage.
            // A compromised DNS/CDN could redirect to an attacker-controlled server;
            // reqwest would follow and forward the Authorization header.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url,
            token,
            use_binary: true, // Protocol v2 by default
        }
    }

    /// Send heartbeat using binary wire format (protocol v2) or JSON (protocol v1 fallback)
    pub fn send_heartbeat(&self, payload: &HeartbeatPayload) -> Result<HeartbeatResponse, ApiError> {
        if self.use_binary {
            self.send_heartbeat_binary(payload)
        } else {
            self.send_heartbeat_json(payload)
        }
    }

    /// Protocol v2: Binary wire format (32 bytes)
    fn send_heartbeat_binary(&self, payload: &HeartbeatPayload) -> Result<HeartbeatResponse, ApiError> {
        let url = format!("{}/api/agents/heartbeat", self.base_url);

        // Encode to simple 32-byte binary format (metrics only, identity in headers)
        let mut binary_payload = [0u8; 32];

        // Encode uptime as u64 at offset 0
        binary_payload[0..8].copy_from_slice(&payload.uptime_seconds.to_le_bytes());

        // Encode metrics (scaled to integers for compact storage)
        let cpu_x100 = (payload.metrics.cpu_percent * 100.0) as u16;
        binary_payload[8..10].copy_from_slice(&cpu_x100.to_le_bytes());
        binary_payload[10..12].copy_from_slice(&cpu_x100.to_le_bytes()); // cpu_max (same as avg for now)

        binary_payload[12..16].copy_from_slice(&(payload.metrics.memory_used_mb as u32).to_le_bytes());
        binary_payload[16..20].copy_from_slice(&(payload.metrics.memory_total_mb as u32).to_le_bytes());
        binary_payload[20..24].copy_from_slice(&(payload.metrics.disk_used_mb as u32).to_le_bytes());
        binary_payload[24..28].copy_from_slice(&(payload.metrics.disk_total_mb as u32).to_le_bytes());

        let load_x100 = (payload.metrics.load_1m * 100.0) as u16;
        binary_payload[28..30].copy_from_slice(&load_x100.to_le_bytes());
        binary_payload[30..32].copy_from_slice(&load_x100.to_le_bytes()); // load_max (same as avg for now)

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
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
        headers.insert(
            "X-Hostname",
            HeaderValue::from_str(&payload.hostname)
                .context("Failed to create hostname header")?,
        );
        headers.insert(
            "X-OS",
            HeaderValue::from_str(&payload.os)
                .context("Failed to create OS header")?,
        );
        headers.insert(
            "X-Arch",
            HeaderValue::from_str(&payload.arch)
                .context("Failed to create arch header")?,
        );

        // SECURITY: Never log the token
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value)
                .context("Failed to create authorization header")?,
        );

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(binary_payload.to_vec())
            .send()
            .context("Failed to send binary heartbeat request")?;

        let status = response.status();

        // Check for specific error codes
        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }

        if status == StatusCode::GONE {
            return Err(ApiError::Decommissioned);
        }

        if !status.is_success() {
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ApiError::HttpError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let heartbeat_response: HeartbeatResponse = response
            .json()
            .context("Failed to parse heartbeat response")?;

        Ok(heartbeat_response)
    }

    /// Protocol v1: JSON format (fallback)
    fn send_heartbeat_json(&self, payload: &HeartbeatPayload) -> Result<HeartbeatResponse, ApiError> {
        let url = format!("{}/api/agents/heartbeat", self.base_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // SECURITY: Never log the token
        let auth_value = format!("Bearer {}", self.token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value)
                .context("Failed to create authorization header")?,
        );

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(payload)
            .send()
            .context("Failed to send heartbeat request")?;

        let status = response.status();

        // Check for specific error codes
        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }

        if status == StatusCode::GONE {
            return Err(ApiError::Decommissioned);
        }

        if !status.is_success() {
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ApiError::HttpError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let heartbeat_response: HeartbeatResponse = response
            .json()
            .context("Failed to parse heartbeat response")?;

        Ok(heartbeat_response)
    }

    pub fn fetch_config(&self) -> Result<AgentConfig> {
        let url = format!("{}/api/agents/config", self.base_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let auth_value = format!("Bearer {}", self.token);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value)
                .context("Failed to create authorization header")?,
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

        let config: AgentConfig = serde_json::from_str(&response_text)
            .with_context(|| format!("Failed to parse config response: {}", response_text))?;

        Ok(config)
    }
}
