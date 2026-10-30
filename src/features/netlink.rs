//! One rtnetlink dump, for what the passive discovery level reads from the
//! kernel (docs/topology/PLAN.md, T8.2 and T8.3): the host's links (VLAN ids,
//! `features::vlan`) and its neighbour table (`features::neighbours`).
//!
//! A dump request (`RTM_GETLINK`, `RTM_GETNEIGH`) needs no privilege, which
//! matters because the daemon runs as `connlog-agent` with no capabilities;
//! the unit allows `AF_NETLINK`. Read-only: nothing here changes the kernel's
//! state. Every failure is `None`, and the caller sends nothing from it.

// Netlink is Linux's: off Linux `dump` answers nothing, and the parsers
// still build and are tested, for the readers built on them.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// Netlink's message and attribute layout (`linux/netlink.h`,
/// `linux/rtnetlink.h`): stable kernel ABI.
pub const NLMSG_HDR: usize = 16;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
/// The nested and byte-order flags on an attribute's type.
const NLA_TYPE_MASK: u16 = 0x3fff;

/// A dump of a host with thousands of links or neighbours is a few hundred
/// KB; past this it is cut short rather than read forever.
const MAX_DUMP_BYTES: usize = 4 << 20;

/// The attributes of one netlink message body, as (type, value).
pub fn attributes(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > bytes.len() {
            break;
        }
        out.push((kind, &bytes[4..len]));
        let aligned = (len + 3) & !3;
        bytes = &bytes[aligned.min(bytes.len())..];
    }
    out
}

pub fn attribute<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v)
}

/// Hand each message of type `reply` in one read of a dump to `on`, with its
/// body (the family header and its attributes); whether the dump is over
/// (`NLMSG_DONE`, an error the kernel answered with, or a message cut short).
pub fn parse_messages(mut bytes: &[u8], reply: u16, on: &mut dyn FnMut(&[u8])) -> bool {
    while bytes.len() >= NLMSG_HDR {
        let len = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        if len < NLMSG_HDR || len > bytes.len() {
            return true;
        }
        match kind {
            NLMSG_DONE | NLMSG_ERROR => return true,
            k if k == reply => on(&bytes[NLMSG_HDR..len]),
            _ => {}
        }
        let aligned = (len + 3) & !3;
        bytes = &bytes[aligned.min(bytes.len())..];
    }
    false
}

/// A dump request: the header, then a family header of `header_len` bytes
/// that is all zero but its first byte, the address family.
pub fn request(kind: u16, family: u8, header_len: usize) -> Vec<u8> {
    let len = NLMSG_HDR + header_len;
    let mut buf = vec![0u8; len];
    buf[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&kind.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes());
    buf[NLMSG_HDR] = family;
    buf
}

/// Closes the socket on every path.
struct Fd(libc::c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: a descriptor this process opened and owns, closed once.
        unsafe { libc::close(self.0) };
    }
}

/// Netlink is Linux's: elsewhere there is nothing to dump (the FreeBSD build
/// reads the same tables its own way, T13.5b), and the readers send nothing.
#[cfg(not(target_os = "linux"))]
pub fn dump(_request: &[u8], _reply: u16, _on: &mut dyn FnMut(&[u8])) -> Option<()> {
    None
}

/// Send one dump request and hand every `reply` message to `on`. `None` when
/// the socket could not be opened or the request sent.
#[cfg(target_os = "linux")]
pub fn dump(request: &[u8], reply: u16, on: &mut dyn FnMut(&[u8])) -> Option<()> {
    // SAFETY: plain socket(2); the result is checked before use.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return None;
    }
    let fd = Fd(fd);
    // A kernel that never answers costs a second, never the inventory thread.
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: setsockopt with a timeval it reads for the duration of the call.
    unsafe {
        libc::setsockopt(
            fd.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    // SAFETY: send(2) reads `request.len()` bytes from a live buffer.
    if unsafe { libc::send(fd.0, request.as_ptr().cast(), request.len(), 0) } < 0 {
        return None;
    }
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0usize;
    loop {
        // SAFETY: recv(2) writes at most `buf.len()` bytes into `buf`.
        let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        total += n;
        if parse_messages(&buf[..n], reply, on) || total > MAX_DUMP_BYTES {
            break;
        }
    }
    Some(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// One attribute, padded as the kernel pads it.
    pub fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let len = 4 + value.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize((len + 3) & !3, 0);
        out
    }

    /// One message with its header.
    pub fn message(kind: u16, body: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDR + body.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(body);
        out.resize((len + 3) & !3, 0);
        out
    }

    pub fn done() -> Vec<u8> {
        message(NLMSG_DONE, &[0; 4])
    }

    #[test]
    fn hands_over_the_asked_messages_until_done() {
        let mut dump = message(16, b"link");
        dump.extend(message(28, b"neighbour"));
        dump.extend(done());
        let mut seen = Vec::new();
        assert!(parse_messages(&dump, 28, &mut |body| seen.push(body.to_vec())));
        assert_eq!(seen, vec![b"neighbour".to_vec()]);
    }

    #[test]
    fn a_message_cut_short_ends_the_dump() {
        let whole = message(28, &[0; 20]);
        assert!(parse_messages(&whole[..whole.len() - 8], 28, &mut |_| {
            panic!("a cut message is never handed over")
        }));
    }

    #[test]
    fn this_host_answers_a_dump_without_privilege() {
        // RTM_GETLINK: every host has at least its loopback.
        let mut links = 0;
        assert!(dump(&request(18, 0, 16), 16, &mut |_| links += 1).is_some());
        assert!(links > 0);
    }
}
