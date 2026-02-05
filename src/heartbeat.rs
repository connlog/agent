use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct HeartbeatPayload {
    pub agent_version: String,
    pub protocol_version: u32,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub uptime_seconds: u64,
    pub metrics: Metrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_mode: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Metrics {
    pub cpu_percent: f64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_mb: u64,
    pub disk_total_mb: u64,
    pub load_1m: f64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub server_time: String,
    pub expected_interval_seconds: u64,
    pub update: Option<UpdateInfo>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UpdateInfo {
    pub available: bool,
    pub latest_version: String,
    pub download_url: Option<String>,
}
