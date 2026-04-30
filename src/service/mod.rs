//! Cross-platform "run as a service" abstraction.
//!
//! On Linux, the agent is invoked directly by systemd as a foreground
//! process — the systemd unit handles supervision and stdout/stderr capture.
//! There's nothing to do here.
//!
//! On Windows, the agent is launched by the SCM with the `--run-service`
//! flag. We hand control to `windows-service::service_dispatcher` which
//! runs our `service_main` entry-point, registers a control handler, and
//! reports SERVICE_RUNNING. The real agent loop runs on the dispatcher's
//! thread; when SCM sends SERVICE_CONTROL_STOP we flip a shared flag the
//! agent loop checks between heartbeats and shut down cleanly.

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::run_service;

/// Returns true when called from a binary launched by the Windows SCM
/// (i.e. the second argument is `--run-service`). On non-Windows always
/// returns false.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn is_service_invocation(args: &[String]) -> bool {
    #[cfg(windows)]
    {
        args.iter()
            .any(|a| a == crate::platform::windows::SERVICE_ARG)
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        false
    }
}
