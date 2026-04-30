//! Windows service implementation.
//!
//! Architecture:
//!
//!   1. The SCM launches `connlog-agent.exe --run-service`.
//!   2. `main.rs` detects the `--run-service` arg and calls `run_service()`.
//!   3. We hand control to `service_dispatcher::start` which calls
//!      `ffi_service_main` on a dedicated thread.
//!   4. `ffi_service_main` -> `service_main`:
//!        - Registers a control handler that flips an AtomicBool on STOP.
//!        - Reports SERVICE_RUNNING to the SCM.
//!        - Builds the agent Config (reading + DPAPI-decrypting the on-disk
//!          token), then calls `crate::run_agent_with_shutdown(config, flag)`
//!          which is a cooperative variant of `run_agent` that returns when
//!          the flag flips.
//!        - On exit, reports SERVICE_STOPPED and returns.
//!
//! We deliberately avoid panicking inside `service_main` — any unwind would
//! leave the SCM hanging in SERVICE_START_PENDING.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::config::Config;
use crate::install::windows as install_win;
use crate::platform::windows as paths;

/// Public entry — call from `main.rs` when `--run-service` is detected.
/// Blocks until the SCM tells us to stop.
pub fn run_service() -> Result<()> {
    service_dispatcher::start(paths::SERVICE_NAME, ffi_service_main)
        .context("service_dispatcher::start")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_main_inner() {
        // Best-effort: write to the event log via println — when running as a
        // service stdout is captured by the dispatcher and dropped, so we
        // also write to the log dir.
        let _ = std::fs::create_dir_all(paths::LOG_DIR);
        let _ = std::fs::write(
            format!(r"{}\service-fatal.log", paths::LOG_DIR),
            format!("{:#}\n", e),
        );
    }
}

fn service_main_inner() -> Result<()> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_for_handler = Arc::clone(&stop_flag);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_flag_for_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(paths::SERVICE_NAME, event_handler)
        .context("register service control handler")?;

    let report = |state, exit_code| -> Result<()> {
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code,
                checkpoint: 0,
                wait_hint: Duration::from_secs(5),
                process_id: None,
            })
            .map_err(|e| anyhow::anyhow!("set_service_status: {e}"))
    };

    report(ServiceState::StartPending, ServiceExitCode::Win32(0))?;

    // Build the agent config from the DPAPI-encrypted on-disk file.
    let config = match load_service_config() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::create_dir_all(paths::LOG_DIR);
            let _ = std::fs::write(
                format!(r"{}\service-fatal.log", paths::LOG_DIR),
                format!("config load failed: {:#}\n", e),
            );
            report(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(1))?;
            return Err(e);
        }
    };

    report(ServiceState::Running, ServiceExitCode::Win32(0))?;

    let result = crate::run_agent_with_shutdown(config, stop_flag);

    report(ServiceState::Stopped, ServiceExitCode::Win32(0))?;
    result
}

/// Load + decrypt the agent.conf file written by `install`.
fn load_service_config() -> Result<Config> {
    let body = std::fs::read_to_string(paths::CONFIG_FILE)
        .with_context(|| format!("read {}", paths::CONFIG_FILE))?;

    let mut token_b64: Option<String> = None;
    let mut platform_url: Option<String> = None;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "CONNLOG_TOKEN_DPAPI_B64" => token_b64 = Some(v.trim().to_string()),
                "CONNLOG_PLATFORM_URL" => platform_url = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }

    let token_b64 = token_b64.context("CONNLOG_TOKEN_DPAPI_B64 missing from config")?;
    let platform_url = platform_url.unwrap_or_else(|| "https://connlog.com".to_string());

    let blob = install_win::base64_decode(&token_b64).context("base64 decode token")?;
    let plain = install_win::dpapi_unprotect(&blob).context("DPAPI decrypt token")?;
    let token = String::from_utf8(plain).context("token is not valid UTF-8")?;

    Ok(Config::for_service(token, platform_url))
}
