use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use std::time::Duration;

use crate::heartbeat::{HeartbeatPayload, HeartbeatResponse};

pub struct ApiClient {
    client: Client,
    base_url: String,
    token: String,
}

impl ApiClient {
    pub fn new(base_url: String, token: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url,
            token,
        }
    }

    pub fn send_heartbeat(&self, payload: &HeartbeatPayload) -> Result<HeartbeatResponse> {
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
        if !status.is_success() {
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Heartbeat failed with status {}: {}", status, error_text);
        }

        let heartbeat_response: HeartbeatResponse = response
            .json()
            .context("Failed to parse heartbeat response")?;

        Ok(heartbeat_response)
    }
}
