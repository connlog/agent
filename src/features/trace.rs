//! The path out of this host (docs/topology/PLAN.md, T8.4), for a host whose
//! discovery level is `passive` or above: a trace towards its default
//! gateway and towards the platform's own address, at most 16 hops each,
//! every 6 hours or when the gateway changes.
//!
//! Over the unprivileged ping socket the probes use (`SOCK_DGRAM` /
//! `IPPROTO_ICMP`, allowed by `net.ipv4.ping_group_range`): one echo per hop
//! with a rising TTL, the routers' "time exceeded" read from the socket's
//! error queue (`IP_RECVERR`), as `tracepath` does without privilege. Where
//! the host does not allow the socket there is no trace, as there is no
//! echo probe. One echo per hop, one hop at a time, a second each: never a
//! flood. IPv4 only, as the default gateway is.

// The hop itself is Linux's (the error queue); off Linux the trace's
// parsing and its tests still build, and `hop` answers nothing.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use serde::Serialize;

/// `TRACE_MAX_HOPS` in the protocol.
pub const MAX_HOPS: u8 = 16;
/// How long one hop's answer is waited for.
const HOP_TIMEOUT: Duration = Duration::from_secs(1);
/// After this many silent hops in a row the rest is not tried.
const SILENT_HOPS: usize = 4;
/// How often the path is traced again with the gateway unchanged.
pub const TRACE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// `linux/errqueue.h`: an error from an ICMP message, and its types.
const SO_EE_ORIGIN_ICMP: u8 = 2;
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_TIME_EXCEEDED: u8 = 11;

/// One trace: each hop's address, or none where it did not answer, and
/// whether the last one is the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Trace {
    pub hops: Vec<Option<String>>,
    pub reached: bool,
}

/// The path out: towards the gateway and towards the internet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Path {
    pub gateway: Option<Trace>,
    pub internet: Option<Trace>,
}

/// What one hop's echo got back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The target's own echo reply.
    Reached,
    /// A router on the way said time exceeded.
    Hop(Ipv4Addr),
    /// A router said there is no way on.
    Unreachable(Ipv4Addr),
    Silent,
}

/// Something that sends one echo at a TTL and says what came back: the host,
/// or a stand-in in tests. `None` when the host does not allow it at all.
pub trait Hopper {
    fn hop(&self, target: Ipv4Addr, ttl: u8) -> Option<Answer>;
}

/// The hops to `target`, until it answers, a router says there is no way on,
/// four hops in a row are silent, or 16 are tried. `None` when the host does
/// not allow the ping socket.
pub fn trace(target: Ipv4Addr, hopper: &dyn Hopper) -> Option<Trace> {
    let mut hops = Vec::new();
    let mut silent = 0;
    for ttl in 1..=MAX_HOPS {
        match hopper.hop(target, ttl)? {
            Answer::Reached => {
                hops.push(Some(target.to_string()));
                return Some(Trace {
                    hops,
                    reached: true,
                });
            }
            Answer::Hop(at) => {
                silent = 0;
                hops.push(Some(at.to_string()));
            }
            Answer::Unreachable(at) => {
                hops.push(Some(at.to_string()));
                break;
            }
            Answer::Silent => {
                silent += 1;
                hops.push(None);
                if silent >= SILENT_HOPS {
                    break;
                }
            }
        }
    }
    // Silent hops at the end say nothing.
    while hops.last() == Some(&None) {
        hops.pop();
    }
    Some(Trace {
        hops,
        reached: false,
    })
}

/// The platform's IPv4 address, from the URL the agent talks to.
pub fn platform_address(base_url: &str) -> Option<Ipv4Addr> {
    let url = reqwest::Url::parse(base_url).ok()?;
    let host = url.host_str()?;
    let port = url.port_or_known_default().unwrap_or(443);
    (host, port)
        .to_socket_addrs()
        .ok()?
        .find_map(|address| match address.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
}

/// The last path traced, and when and for which gateway, so the next reading
/// of the inventory traces again only when it is due.
#[derive(Debug, Default)]
pub struct TraceCache {
    last: Option<(Instant, Option<Ipv4Addr>, Path)>,
}

impl TraceCache {
    /// The path, traced again when the gateway changed or 6 hours passed.
    /// `internet` is asked only when a trace is due (it may resolve a name).
    pub fn path(
        &mut self,
        gateway: Option<Ipv4Addr>,
        internet: &dyn Fn() -> Option<Ipv4Addr>,
        hopper: &dyn Hopper,
        now: Instant,
    ) -> Option<Path> {
        if let Some((at, traced_for, path)) = &self.last {
            if *traced_for == gateway && now.duration_since(*at) < TRACE_INTERVAL {
                return Some(path.clone());
            }
        }
        let path = Path {
            gateway: gateway.and_then(|g| trace(g, hopper)),
            internet: internet().and_then(|i| trace(i, hopper)),
        };
        if path.gateway.is_none() && path.internet.is_none() {
            return None;
        }
        self.last = Some((now, gateway, path.clone()));
        Some(path)
    }
}

/// The host's ping socket, one echo per call.
pub struct SystemHopper;

impl Hopper for SystemHopper {
    fn hop(&self, target: Ipv4Addr, ttl: u8) -> Option<Answer> {
        hop(target, ttl)
    }
}

/// A trace reads ICMP errors from the ping socket's error queue
/// (`IP_RECVERR`), which is Linux's: elsewhere there is no trace yet.
#[cfg(not(target_os = "linux"))]
fn hop(_target: Ipv4Addr, _ttl: u8) -> Option<Answer> {
    None
}

#[cfg(target_os = "linux")]
fn hop(target: Ipv4Addr, ttl: u8) -> Option<Answer> {
    // SAFETY: plain socket(2); the descriptor is owned below.
    let raw = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        )
    };
    if raw < 0 {
        // Not allowed by ping_group_range: no trace from this host.
        return None;
    }
    // SAFETY: `raw` is a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    let ttl = libc::c_int::from(ttl);
    // SAFETY: setsockopt with an int it reads for the duration of the call.
    unsafe {
        let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            std::ptr::addr_of!(ttl).cast(),
            size,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            std::ptr::addr_of!(on).cast(),
            size,
        );
    }
    // An echo request: type 8, code 0, checksum, identifier (the kernel's),
    // sequence 1, no payload.
    let packet = [8u8, 0, 0xf7, 0xfe, 0, 0, 0, 1];
    // SAFETY: all-zero is a valid sockaddr_in.
    let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    to.sin_family = libc::AF_INET as libc::sa_family_t;
    to.sin_addr.s_addr = u32::from_ne_bytes(target.octets());
    // SAFETY: `to` is a valid sockaddr_in for its stated length.
    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            std::ptr::addr_of!(to).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Some(Answer::Silent);
    }
    let started = Instant::now();
    loop {
        let Some(left) = HOP_TIMEOUT.checked_sub(started.elapsed()) else {
            return Some(Answer::Silent);
        };
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        };
        let millis = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: one pollfd, valid for the call.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready == 0 {
            return Some(Answer::Silent);
        }
        if ready < 0 {
            continue;
        }
        if let Some(answer) = read_error(fd) {
            return Some(answer);
        }
        let mut reply = [0u8; 64];
        // SAFETY: `reply` is writable for its length.
        let n = unsafe {
            libc::recv(
                fd,
                reply.as_mut_ptr().cast(),
                reply.len(),
                libc::MSG_DONTWAIT,
            )
        };
        // A ping socket hands back only replies to its own identifier.
        if n > 0 && reply[0] == 0 {
            return Some(Answer::Reached);
        }
    }
}

/// An ICMP error from the socket's error queue, as an answer.
#[cfg(target_os = "linux")]
fn read_error(fd: libc::c_int) -> Option<Answer> {
    let mut data = [0u8; 64];
    let mut control = [0u8; 256];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    // SAFETY: all-zero is a valid msghdr; its buffers are set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;
    // SAFETY: recvmsg(2) writes within the buffers `msg` names.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
    if n < 0 {
        return None;
    }
    // SAFETY: walking the control messages recvmsg wrote, with the libc
    // macros, each read within `control`.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_RECVERR {
                let err = libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err;
                let offender = err.add(1) as *const libc::sockaddr_in;
                return Some(answer_of(
                    (*err).ee_origin,
                    (*err).ee_type,
                    Ipv4Addr::from((*offender).sin_addr.s_addr.to_ne_bytes()),
                ));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    None
}

fn answer_of(origin: u8, kind: u8, offender: Ipv4Addr) -> Answer {
    match (origin, kind) {
        (SO_EE_ORIGIN_ICMP, ICMP_TIME_EXCEEDED) => Answer::Hop(offender),
        (SO_EE_ORIGIN_ICMP, ICMP_DEST_UNREACH) => Answer::Unreachable(offender),
        _ => Answer::Silent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A network: the answer at each TTL, silent past the list.
    struct Script(Vec<Answer>, Cell<usize>);

    impl Hopper for Script {
        fn hop(&self, _target: Ipv4Addr, ttl: u8) -> Option<Answer> {
            self.1.set(self.1.get() + 1);
            Some(
                self.0
                    .get(usize::from(ttl) - 1)
                    .copied()
                    .unwrap_or(Answer::Silent),
            )
        }
    }

    fn script(answers: Vec<Answer>) -> Script {
        Script(answers, Cell::new(0))
    }

    const ROUTER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const ISP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const PLATFORM: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    #[test]
    fn follows_the_hops_to_the_target() {
        let net = script(vec![
            Answer::Hop(ROUTER),
            Answer::Silent,
            Answer::Hop(ISP),
            Answer::Reached,
        ]);
        assert_eq!(
            trace(PLATFORM, &net),
            Some(Trace {
                hops: vec![
                    Some("10.0.0.1".into()),
                    None,
                    Some("100.64.0.1".into()),
                    Some("203.0.113.10".into())
                ],
                reached: true
            })
        );
    }

    #[test]
    fn stops_at_an_unreachable_and_after_four_silent_hops() {
        let net = script(vec![Answer::Hop(ROUTER), Answer::Unreachable(ISP)]);
        let got = trace(PLATFORM, &net).unwrap();
        assert_eq!(got.hops.len(), 2);
        assert!(!got.reached);

        let quiet = script(vec![Answer::Hop(ROUTER)]);
        let got = trace(PLATFORM, &quiet).unwrap();
        assert_eq!(got.hops, vec![Some("10.0.0.1".into())]);
        // One answer, then four silent: five echoes, never sixteen.
        assert_eq!(quiet.1.get(), 5);
    }

    #[test]
    fn never_tries_more_than_sixteen_hops() {
        let far = script(vec![Answer::Hop(ROUTER); 40]);
        assert_eq!(trace(PLATFORM, &far).unwrap().hops.len(), 16);
        assert_eq!(far.1.get(), 16);
    }

    #[test]
    fn traces_again_only_when_due_or_the_gateway_changed() {
        let net = script(vec![Answer::Reached]);
        let mut cache = TraceCache::default();
        let t0 = Instant::now();
        let platform = || Some(PLATFORM);
        let first = cache.path(Some(ROUTER), &platform, &net, t0);
        assert_eq!(net.1.get(), 2);
        assert_eq!(
            cache.path(Some(ROUTER), &platform, &net, t0 + Duration::from_secs(60)),
            first
        );
        assert_eq!(net.1.get(), 2, "within 6 hours: the cached path");
        cache.path(
            Some(Ipv4Addr::new(10, 0, 0, 254)),
            &platform,
            &net,
            t0 + Duration::from_secs(120),
        );
        assert_eq!(net.1.get(), 4, "a new gateway: traced again");
        cache.path(
            Some(Ipv4Addr::new(10, 0, 0, 254)),
            &platform,
            &net,
            t0 + TRACE_INTERVAL + Duration::from_secs(180),
        );
        assert_eq!(net.1.get(), 6, "6 hours on: traced again");
    }

    #[test]
    fn a_host_without_the_ping_socket_has_no_path() {
        struct Refused;
        impl Hopper for Refused {
            fn hop(&self, _: Ipv4Addr, _: u8) -> Option<Answer> {
                None
            }
        }
        assert_eq!(trace(PLATFORM, &Refused), None);
        assert_eq!(
            TraceCache::default().path(Some(ROUTER), &|| Some(PLATFORM), &Refused, Instant::now()),
            None
        );
    }

    #[test]
    fn reads_icmp_errors_as_hops() {
        assert_eq!(
            answer_of(SO_EE_ORIGIN_ICMP, ICMP_TIME_EXCEEDED, ROUTER),
            Answer::Hop(ROUTER)
        );
        assert_eq!(
            answer_of(SO_EE_ORIGIN_ICMP, ICMP_DEST_UNREACH, ISP),
            Answer::Unreachable(ISP)
        );
        assert_eq!(answer_of(1, ICMP_TIME_EXCEEDED, ROUTER), Answer::Silent);
    }
}
