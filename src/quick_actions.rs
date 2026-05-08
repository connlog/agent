use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_CONFIG_PATH: &str = "/etc/connlog/actions.toml";
const DEFAULT_TIMEOUT_SECONDS: u64 = 15;
const MAX_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 8192;
const HARD_MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputMode {
    Hidden,
    Ephemeral,
}

impl OutputMode {
    fn as_str(&self) -> &'static str {
        match self {
            OutputMode::Hidden => "hidden",
            OutputMode::Ephemeral => "ephemeral",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    fn as_str(&self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }

    fn requires_confirmation(&self) -> bool {
        matches!(self, Risk::Medium | Risk::High)
    }
}

#[derive(Debug, Clone)]
pub struct QuickAction {
    pub id: String,
    pub label: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub risk: Risk,
    pub requires_confirmation: bool,
    pub timeout_seconds: u64,
    pub output_mode: OutputMode,
    pub max_output_bytes: usize,
    pub exec: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct QuickActionsRegistry {
    pub enabled: bool,
    actions: HashMap<String, QuickAction>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct QuickActionRequest {
    pub request_id: String,
    pub action_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickActionsManifestPayload {
    pub enabled: bool,
    pub actions: Vec<QuickActionManifestItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickActionManifestItem {
    pub action_id: String,
    pub label: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub risk: String,
    pub requires_confirmation: bool,
    pub output_mode: String,
    pub max_output_bytes: usize,
    pub timeout_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickActionResultPayload {
    pub request_id: String,
    pub action_id: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

#[derive(Debug, Default)]
struct ActionBuilder {
    label: Option<String>,
    description: Option<String>,
    category: Option<String>,
    risk: Option<Risk>,
    requires_confirmation: Option<bool>,
    timeout_seconds: Option<u64>,
    output_mode: Option<OutputMode>,
    max_output_bytes: Option<usize>,
    exec: Option<Vec<String>>,
}

impl QuickActionsRegistry {
    pub fn load() -> Self {
        match Self::load_result() {
            Ok(registry) => registry,
            Err(e) => {
                log::warn!("Quick actions disabled: {e}");
                Self::disabled()
            }
        }
    }

    fn load_result() -> Result<Self> {
        let path = config_path();
        if !path.exists() {
            return Ok(Self::disabled());
        }

        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut registry = parse_config(&text)?;

        if env_quick_actions_disabled() {
            registry.enabled = false;
            registry.actions.clear();
        }

        Ok(registry)
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            actions: HashMap::new(),
        }
    }

    pub fn manifest(&self) -> QuickActionsManifestPayload {
        let mut actions = self
            .actions
            .values()
            .map(|action| QuickActionManifestItem {
                action_id: action.id.clone(),
                label: action.label.clone(),
                description: action.description.clone(),
                category: action.category.clone(),
                risk: action.risk.as_str().to_string(),
                requires_confirmation: action.requires_confirmation,
                output_mode: action.output_mode.as_str().to_string(),
                max_output_bytes: action.max_output_bytes,
                timeout_seconds: action.timeout_seconds,
            })
            .collect::<Vec<_>>();
        actions.sort_by(|a, b| a.action_id.cmp(&b.action_id));

        QuickActionsManifestPayload {
            enabled: self.enabled,
            actions,
        }
    }

    pub fn fingerprint(&self) -> String {
        serde_json::to_string(&self.manifest()).unwrap_or_else(|_| String::new())
    }

    pub fn execute(&self, request: &QuickActionRequest) -> QuickActionResultPayload {
        let Some(action) = self.actions.get(&request.action_id) else {
            return QuickActionResultPayload {
                request_id: request.request_id.clone(),
                action_id: request.action_id.clone(),
                status: "unsupported".to_string(),
                exit_code: None,
                duration_ms: 0,
                truncated: false,
                stdout: None,
                stderr: None,
            };
        };

        if !self.enabled {
            return QuickActionResultPayload {
                request_id: request.request_id.clone(),
                action_id: request.action_id.clone(),
                status: "unsupported".to_string(),
                exit_code: None,
                duration_ms: 0,
                truncated: false,
                stdout: None,
                stderr: None,
            };
        }

        run_action(request, action)
    }
}

fn config_path() -> PathBuf {
    std::env::var("CONNLOG_QUICK_ACTIONS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn env_quick_actions_disabled() -> bool {
    std::env::var("CONNLOG_QUICK_ACTIONS_ENABLED")
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "0" | "false" | "no" | "off")
        })
        .unwrap_or(false)
}

fn parse_config(text: &str) -> Result<QuickActionsRegistry> {
    let mut enabled = true;
    let mut current_action: Option<String> = None;
    let mut actions: HashMap<String, ActionBuilder> = HashMap::new();

    for (line_number, raw_line) in text.lines().enumerate() {
        let line = strip_comment(raw_line).trim().to_string();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            if section == "quick_actions" {
                current_action = None;
            } else if let Some(action_id) = section.strip_prefix("quick_actions.") {
                validate_action_id(action_id)
                    .with_context(|| format!("invalid action id on line {}", line_number + 1))?;
                current_action = Some(action_id.to_string());
                actions.entry(action_id.to_string()).or_default();
            } else {
                current_action = None;
            }
            continue;
        }

        let Some((key, value)) = split_key_value(&line) else {
            anyhow::bail!("invalid config line {}", line_number + 1);
        };

        if let Some(action_id) = &current_action {
            let builder = actions.entry(action_id.clone()).or_default();
            apply_action_value(builder, key, value)
                .with_context(|| format!("invalid value for {key} on line {}", line_number + 1))?;
        } else if key == "enabled" {
            enabled = parse_bool(value).with_context(|| {
                format!("invalid quick_actions.enabled on line {}", line_number + 1)
            })?;
        }
    }

    if !enabled {
        return Ok(QuickActionsRegistry::disabled());
    }

    let mut registry_actions = HashMap::new();
    for (id, builder) in actions {
        let Some(exec) = builder.exec else {
            log::warn!("Skipping quick action {id}: missing exec array");
            continue;
        };
        if exec.is_empty() || exec.iter().any(|part| part.trim().is_empty()) {
            log::warn!("Skipping quick action {id}: exec array must contain non-empty strings");
            continue;
        }

        let risk = builder.risk.unwrap_or(Risk::Low);
        let requires_confirmation =
            builder.requires_confirmation.unwrap_or(false) || risk.requires_confirmation();
        let max_output_bytes = builder
            .max_output_bytes
            .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES)
            .clamp(1, HARD_MAX_OUTPUT_BYTES);

        registry_actions.insert(
            id.clone(),
            QuickAction {
                id: id.clone(),
                label: builder.label.unwrap_or_else(|| id.clone()),
                description: builder.description,
                category: builder.category,
                risk,
                requires_confirmation,
                timeout_seconds: builder
                    .timeout_seconds
                    .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
                    .clamp(1, MAX_TIMEOUT_SECONDS),
                output_mode: builder.output_mode.unwrap_or(OutputMode::Hidden),
                max_output_bytes,
                exec,
            },
        );
    }

    Ok(QuickActionsRegistry {
        enabled: true,
        actions: registry_actions,
    })
}

fn apply_action_value(builder: &mut ActionBuilder, key: &str, value: &str) -> Result<()> {
    match key {
        "label" => builder.label = Some(parse_string(value)?),
        "description" => builder.description = Some(parse_string(value)?),
        "category" => builder.category = Some(parse_string(value)?),
        "risk" => {
            builder.risk = Some(match parse_string(value)?.as_str() {
                "low" => Risk::Low,
                "medium" => Risk::Medium,
                "high" => Risk::High,
                other => anyhow::bail!("unsupported risk {other}"),
            });
        }
        "requires_confirmation" => builder.requires_confirmation = Some(parse_bool(value)?),
        "timeout_seconds" => builder.timeout_seconds = Some(parse_u64(value)?),
        "output_mode" => {
            builder.output_mode = Some(match parse_string(value)?.as_str() {
                "hidden" => OutputMode::Hidden,
                "ephemeral" => OutputMode::Ephemeral,
                other => anyhow::bail!("unsupported output_mode {other}"),
            });
        }
        "max_output_bytes" => builder.max_output_bytes = Some(parse_u64(value)? as usize),
        "exec" => builder.exec = Some(parse_string_array(value)?),
        _ => {}
    }
    Ok(())
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let index = line.find('=')?;
    Some((line[..index].trim(), line[index + 1..].trim()))
}

fn strip_comment(line: &str) -> String {
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if ch == '#' && !in_string {
            return line[..index].to_string();
        }
    }
    line.to_string()
}

fn parse_string(value: &str) -> Result<String> {
    let value = value.trim();
    if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
        anyhow::bail!("expected quoted string");
    }
    let inner = &value[1..value.len() - 1];
    let mut result = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(next) = chars.next() else {
                anyhow::bail!("unterminated escape");
            };
            match next {
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                other => result.push(other),
            }
        } else {
            result.push(ch);
        }
    }
    Ok(result)
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => anyhow::bail!("expected boolean"),
    }
}

fn parse_u64(value: &str) -> Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .context("expected positive integer")
}

fn parse_string_array(value: &str) -> Result<Vec<String>> {
    let value = value.trim();
    if !(value.starts_with('[') && value.ends_with(']')) {
        anyhow::bail!("expected array");
    }
    let inner = value[1..value.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }

    let mut items = Vec::new();
    let mut start = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if ch == ',' && !in_string {
            items.push(parse_string(inner[start..index].trim())?);
            start = index + 1;
        }
    }
    items.push(parse_string(inner[start..].trim())?);
    Ok(items)
}

fn validate_action_id(action_id: &str) -> Result<()> {
    if action_id.is_empty() || action_id.len() > 80 {
        anyhow::bail!("action id length must be 1..=80");
    }
    if !action_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        anyhow::bail!("action id contains unsupported characters");
    }
    Ok(())
}

fn run_action(request: &QuickActionRequest, action: &QuickAction) -> QuickActionResultPayload {
    let start = Instant::now();
    let mut child = match Command::new(&action.exec[0])
        .args(&action.exec[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return QuickActionResultPayload {
                request_id: request.request_id.clone(),
                action_id: request.action_id.clone(),
                status: "failed".to_string(),
                exit_code: None,
                duration_ms: start.elapsed().as_millis(),
                truncated: false,
                stdout: None,
                stderr: if matches!(action.output_mode, OutputMode::Ephemeral) {
                    Some(format!("failed to start action: {e}"))
                } else {
                    None
                },
            };
        }
    };

    let stdout_handle = child
        .stdout
        .take()
        .map(|stdout| thread::spawn(move || read_limited(stdout, HARD_MAX_OUTPUT_BYTES)));
    let stderr_handle = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || read_limited(stderr, HARD_MAX_OUTPUT_BYTES)));

    let timeout = Duration::from_secs(action.timeout_seconds);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().ok();
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break None,
        }
    };

    let (stdout_bytes, stdout_reader_truncated) = stdout_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let (stderr_bytes, stderr_reader_truncated) = stderr_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();

    let exit_code = status.and_then(|s| s.code());
    let mut status_text = if timed_out {
        "timeout"
    } else if exit_code == Some(0) {
        "success"
    } else {
        "failed"
    }
    .to_string();

    if exit_code.is_none() && !timed_out {
        status_text = "failed".to_string();
    }

    let (stdout, stderr, output_truncated) = if matches!(action.output_mode, OutputMode::Ephemeral)
    {
        let (stdout, stderr, combined_truncated) =
            bound_output(stdout_bytes, stderr_bytes, action.max_output_bytes);
        (
            Some(String::from_utf8_lossy(&stdout).to_string()).filter(|s| !s.is_empty()),
            Some(String::from_utf8_lossy(&stderr).to_string()).filter(|s| !s.is_empty()),
            combined_truncated,
        )
    } else {
        (None, None, false)
    };

    QuickActionResultPayload {
        request_id: request.request_id.clone(),
        action_id: request.action_id.clone(),
        status: status_text,
        exit_code,
        duration_ms: start.elapsed().as_millis(),
        truncated: stdout_reader_truncated
            || stderr_reader_truncated
            || output_truncated
            || (timed_out && matches!(action.output_mode, OutputMode::Ephemeral)),
        stdout,
        stderr,
    }
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut truncated = false;
    let mut buffer = [0u8; 4096];

    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if output.len() < limit {
            let available = limit - output.len();
            let take = available.min(read);
            output.extend_from_slice(&buffer[..take]);
            if take < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    (output, truncated)
}

fn bound_output(
    mut stdout: Vec<u8>,
    mut stderr: Vec<u8>,
    limit: usize,
) -> (Vec<u8>, Vec<u8>, bool) {
    let limit = limit.clamp(1, HARD_MAX_OUTPUT_BYTES);
    let original_len = stdout.len() + stderr.len();

    if stdout.len() > limit {
        stdout.truncate(limit);
        stderr.clear();
    } else {
        let remaining = limit - stdout.len();
        if stderr.len() > remaining {
            stderr.truncate(remaining);
        }
    }

    let truncated = original_len > stdout.len() + stderr.len();
    (stdout, stderr, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action_id: &str) -> QuickActionRequest {
        QuickActionRequest {
            request_id: "00000000-0000-0000-0000-000000000001".to_string(),
            action_id: action_id.to_string(),
        }
    }

    #[test]
    fn parses_registered_ephemeral_action_manifest() {
        let config = r#"
[quick_actions.disk_usage]
label = "Check disk usage"
description = "Shows mounted filesystem usage"
category = "Diagnostics"
risk = "low"
requires_confirmation = false
timeout_seconds = 10
output_mode = "ephemeral"
max_output_bytes = 8192
exec = ["df", "-h"]
"#;

        let registry = parse_config(config).expect("config parses");
        let manifest = registry.manifest();

        assert!(manifest.enabled);
        assert_eq!(manifest.actions.len(), 1);
        assert_eq!(manifest.actions[0].action_id, "disk_usage");
        assert_eq!(manifest.actions[0].output_mode, "ephemeral");
        assert_eq!(manifest.actions[0].max_output_bytes, 8192);
    }

    #[test]
    fn hidden_output_returns_only_metadata() {
        let registry = parse_config(
            r#"
[quick_actions.echo]
label = "Echo"
output_mode = "hidden"
exec = ["printf", "secret"]
"#,
        )
        .expect("config parses");

        let result = registry.execute(&request("echo"));

        assert_eq!(result.status, "success");
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.is_none());
        assert!(result.stderr.is_none());
    }

    #[test]
    fn ephemeral_output_is_bounded() {
        let registry = parse_config(
            r#"
[quick_actions.echo]
label = "Echo"
output_mode = "ephemeral"
max_output_bytes = 4
exec = ["printf", "abcdef"]
"#,
        )
        .expect("config parses");

        let result = registry.execute(&request("echo"));

        assert_eq!(result.status, "success");
        assert_eq!(result.stdout.as_deref(), Some("abcd"));
        assert!(result.truncated);
    }

    #[test]
    fn timed_out_process_is_reported() {
        let registry = parse_config(
            r#"
[quick_actions.sleep]
label = "Sleep"
output_mode = "ephemeral"
timeout_seconds = 1
exec = ["sleep", "2"]
"#,
        )
        .expect("config parses");

        let result = registry.execute(&request("sleep"));

        assert_eq!(result.status, "timeout");
        assert!(result.duration_ms >= 900);
    }

    #[test]
    fn unknown_action_id_is_refused() {
        let registry = parse_config(
            r#"
[quick_actions.echo]
label = "Echo"
exec = ["printf", "ok"]
"#,
        )
        .expect("config parses");

        let result = registry.execute(&request("missing"));

        assert_eq!(result.status, "unsupported");
        assert!(result.stdout.is_none());
    }

    #[test]
    fn local_kill_switch_disables_actions() {
        let registry = parse_config(
            r#"
[quick_actions]
enabled = false

[quick_actions.echo]
label = "Echo"
exec = ["printf", "ok"]
"#,
        )
        .expect("config parses");

        assert!(!registry.enabled);
        assert!(registry.manifest().actions.is_empty());
    }
}
