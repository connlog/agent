//! The service manager's watchdog: if the heartbeat loop stops turning, the
//! agent is ended and started again.
//!
//! Every wait in the loop has a timeout, but a host is not the test bench: a
//! syscall that never returns, a lock nobody releases. Without a watchdog a
//! stuck agent stays "active (running)" for good, and the host reads Down in
//! the console until someone logs in and restarts it.
//!
//! Armed by the agent, not by the unit. The unit only lets the agent be
//! heard (`NotifyAccess=main`, which is what makes systemd set
//! `NOTIFY_SOCKET`); the agent then asks for the watchdog itself, with
//! `WATCHDOG_USEC=` in its first message. So it is on only where the message
//! got through: where it does not (an older systemd that ignores the
//! request, a container, FreeBSD, a socket the sandbox hides), nothing is
//! armed and nothing can end a healthy agent. A `WatchdogSec=` in the unit
//! would arm it whether or not the agent can answer.

use std::os::unix::net::UnixDatagram;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long the loop may go without a sign of life before it is ended. The
/// longest honest stretch is an update download: three tries of 120 s with
/// their pauses, then a heartbeat with its own retries.
pub const TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// At most this often is systemd told; `alive` is called every half second.
const EVERY: Duration = Duration::from_secs(30);

struct Watchdog {
    socket: UnixDatagram,
    last: Instant,
}

static WATCHDOG: OnceLock<Option<Mutex<Watchdog>>> = OnceLock::new();

/// A socket connected to the service manager's, from `NOTIFY_SOCKET`: a path,
/// or `@name` for one in the abstract namespace.
fn connect(target: &str) -> Option<UnixDatagram> {
    let socket = UnixDatagram::unbound().ok()?;
    match target.strip_prefix('@') {
        #[cfg(target_os = "linux")]
        Some(name) => {
            use std::os::linux::net::SocketAddrExt;
            let address = std::os::unix::net::SocketAddr::from_abstract_name(name).ok()?;
            socket.connect_addr(&address).ok()?;
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => return None,
        None => socket.connect(target).ok()?,
    }
    Some(socket)
}

/// The first message: the watchdog asked for, and a first sign of life.
fn arming(timeout: Duration) -> String {
    format!("WATCHDOG_USEC={}\nWATCHDOG=1", timeout.as_micros())
}

/// Ask the service manager to watch this process, if there is one listening.
/// Once, from the daemon as it starts its loop; a no-op anywhere else.
pub fn arm() {
    WATCHDOG.get_or_init(|| {
        let target = std::env::var("NOTIFY_SOCKET").ok()?;
        let socket = connect(&target)?;
        socket.send(arming(TIMEOUT).as_bytes()).ok()?;
        log::info!(
            "Watchdog asked for: the service manager restarts the agent if its loop stops for {} minutes",
            TIMEOUT.as_secs() / 60
        );
        Some(Mutex::new(Watchdog {
            socket,
            last: Instant::now(),
        }))
    });
}

/// The loop is turning. Cheap: called on every tick of every wait, it sends
/// at most once every 30 seconds, and nothing where no watchdog was armed.
pub fn alive() {
    let Some(Some(watchdog)) = WATCHDOG.get() else {
        return;
    };
    let mut watchdog = watchdog.lock().unwrap_or_else(|p| p.into_inner());
    if watchdog.last.elapsed() >= EVERY {
        let _ = watchdog.socket.send(b"WATCHDOG=1");
        watchdog.last = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_for_the_watchdog_in_microseconds_with_a_first_sign_of_life() {
        assert_eq!(
            arming(Duration::from_secs(1200)),
            "WATCHDOG_USEC=1200000000\nWATCHDOG=1"
        );
    }

    #[test]
    fn reaches_a_service_manager_at_a_path() {
        let dir = std::env::temp_dir().join(format!("connlog-notify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let manager = UnixDatagram::bind(&path).unwrap();
        manager
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let socket = connect(path.to_str().unwrap()).expect("connects");
        socket.send(arming(TIMEOUT).as_bytes()).unwrap();
        let mut buf = [0u8; 128];
        let n = manager.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], arming(TIMEOUT).as_bytes());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reaches_one_in_the_abstract_namespace() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("connlog-notify-test-{}", std::process::id());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(&name).unwrap();
        let manager = UnixDatagram::bind_addr(&address).unwrap();
        manager
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let socket = connect(&format!("@{name}")).expect("connects");
        socket.send(b"WATCHDOG=1").unwrap();
        let mut buf = [0u8; 32];
        let n = manager.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }

    #[test]
    fn with_nobody_listening_there_is_no_watchdog() {
        assert!(connect("/nonexistent/connlog/notify").is_none());
        // And a sign of life with none armed sends nothing and does not panic.
        alive();
    }
}
