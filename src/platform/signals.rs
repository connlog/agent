//! SIGTERM / SIGINT → the daemon's cooperative stop flag.
//!
//! Without a handler a `systemctl stop` (or the shutdown of the whole host)
//! kills the agent mid-whatever with the default disposition, and a stop is
//! indistinguishable from a crash. With it, the first signal sets the same
//! `stop` flag the main loop, the sleeps and the BMC poller already poll, so
//! the process finishes its current step and exits 0. A second signal exits
//! at once, for an operator pressing Ctrl-C twice on a foreground `register`.
//!
//! The handler only touches atomics: `OnceLock::get` is an acquire load once
//! the lock is set, and `AtomicBool::swap` is lock-free. Nothing allocates.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();

extern "C" fn on_stop_signal(_signal: libc::c_int) {
    if let Some(stop) = STOP.get() {
        if stop.swap(true, Ordering::SeqCst) {
            // SAFETY: `_exit` is async-signal-safe and never returns.
            unsafe { libc::_exit(1) };
        }
    }
}

/// Route SIGTERM and SIGINT to `stop`. Returns false when the handlers could
/// not be installed (or already were, for another flag); the agent then keeps
/// the default disposition and still runs.
pub fn install_stop_handlers(stop: &Arc<AtomicBool>) -> bool {
    if STOP.set(Arc::clone(stop)).is_err() {
        return false;
    }
    [libc::SIGTERM, libc::SIGINT].into_iter().all(|signal| {
        // SAFETY: a zeroed `sigaction` is a valid starting value; the handler
        // is an `extern "C" fn(c_int)` and SA_SIGINFO is not set, so the
        // kernel calls it with that signature.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_stop_signal as extern "C" fn(libc::c_int) as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut()) == 0
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test raises a real signal: the handler is process-wide, and a
    /// second raise would exit the test binary by design.
    #[test]
    fn sigterm_sets_the_stop_flag_and_does_not_kill_the_process() {
        let stop = Arc::new(AtomicBool::new(false));
        assert!(install_stop_handlers(&stop));
        assert!(
            !install_stop_handlers(&Arc::new(AtomicBool::new(false))),
            "a second install must not steal the handler"
        );

        // SAFETY: raise delivers synchronously to this thread before returning.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);

        assert!(stop.load(Ordering::SeqCst));
    }
}
