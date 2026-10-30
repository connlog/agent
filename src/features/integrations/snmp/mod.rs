//! An SNMP manager, as small as reading a switch needs (T10.3): GET and
//! GETBULK walks over UDP, v2c with a community, or v3 with a user,
//! SHA-1/SHA-256 authentication and AES-128 privacy (RFC 3412, 3414, 3416,
//! 3826, 7860). Read-only: it never sends a SET.

pub mod ber;
pub mod usm;

use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use ber::{Malformed, Reader, Value};
use usm::AuthProtocol;

use super::Failure;

pub const DEFAULT_PORT: u16 = 161;
const TIMEOUT: Duration = Duration::from_secs(2);
const TRIES: usize = 3;
const MAX_REPETITIONS: i64 = 20;
const MAX_DATAGRAM: usize = 65_507;

const GET: u8 = 0xa0;
const RESPONSE: u8 = 0xa2;
const GET_BULK: u8 = 0xa5;
const REPORT: u8 = 0xa8;

/// usmStats*: what a v3 engine's Report says went wrong.
const USM_STATS: [u32; 9] = [1, 3, 6, 1, 6, 3, 15, 1, 1];
const NOT_IN_TIME_WINDOW: u32 = 2;
const UNKNOWN_ENGINE_ID: u32 = 4;

pub type VarBind = (Vec<u32>, Value);

/// Who the collector is to the switch.
#[derive(Clone, PartialEq, Eq)]
pub enum Security {
    V2c {
        community: String,
    },
    V3 {
        user: String,
        auth: AuthProtocol,
        auth_password: String,
        /// AES-128; none for authNoPriv.
        priv_password: Option<String>,
    },
}

// ── PDUs ─────────────────────────────────────────────────────────────────

struct Pdu {
    tag: u8,
    request_id: i64,
    error_status: i64,
    varbinds: Vec<VarBind>,
}

fn encode_pdu(tag: u8, request_id: i64, a: i64, b: i64, oids: &[&[u32]]) -> Vec<u8> {
    let varbinds: Vec<Vec<u8>> = oids
        .iter()
        .map(|o| ber::sequence(&[&ber::oid(o), &ber::null()]))
        .collect();
    let list: Vec<&[u8]> = varbinds.iter().map(Vec::as_slice).collect();
    ber::tlv(
        tag,
        &[
            ber::integer(request_id),
            ber::integer(a),
            ber::integer(b),
            ber::sequence(&list),
        ]
        .concat(),
    )
}

fn decode_pdu(tag: u8, content: &[u8]) -> Result<Pdu, Malformed> {
    let mut r = Reader::new(content);
    let request_id = r.integer()?;
    let error_status = r.integer()?;
    let _error_index = r.integer()?;
    let mut list = r.sequence()?;
    let mut varbinds = Vec::new();
    while !list.is_empty() {
        let mut vb = list.sequence()?;
        let oid = ber::decode_oid(vb.expect(ber::OID)?)?;
        let (vtag, vcontent) = vb.next()?;
        varbinds.push((oid, ber::decode_value(vtag, vcontent)?));
    }
    Ok(Pdu {
        tag,
        request_id,
        error_status,
        varbinds,
    })
}

// ── v2c ──────────────────────────────────────────────────────────────────

fn v2c_message(community: &str, pdu: &[u8]) -> Vec<u8> {
    ber::sequence(&[&ber::integer(1), &ber::octets(community.as_bytes()), pdu])
}

fn decode_v2c(buf: &[u8]) -> Result<Pdu, Malformed> {
    let mut msg = Reader::new(buf).sequence()?;
    if msg.integer()? != 1 {
        return Err(Malformed);
    }
    msg.octets()?;
    let (tag, content) = msg.next()?;
    decode_pdu(tag, content)
}

// ── v3 ───────────────────────────────────────────────────────────────────

const FLAG_AUTH: u8 = 0x01;
const FLAG_PRIV: u8 = 0x02;
const FLAG_REPORTABLE: u8 = 0x04;

/// What the switch's engine said of itself, and the keys localized to it.
#[derive(Clone)]
struct Engine {
    id: Vec<u8>,
    boots: u32,
    time: u32,
    at: Instant,
    auth_key: Vec<u8>,
    priv_key: Option<Vec<u8>>,
}

impl Engine {
    fn time_now(&self) -> u32 {
        self.time
            .saturating_add(u32::try_from(self.at.elapsed().as_secs()).unwrap_or(u32::MAX))
    }
}

struct V3 {
    user: String,
    auth: AuthProtocol,
    auth_master: Vec<u8>,
    priv_master: Option<Vec<u8>>,
    engine: Option<Engine>,
    salt: u64,
}

struct UsmParams<'a> {
    engine_id: &'a [u8],
    boots: u32,
    time: u32,
    auth: &'a [u8],
    salt: &'a [u8],
}

fn usm_params(user: &[u8], p: &UsmParams<'_>) -> Vec<u8> {
    ber::sequence(&[
        &ber::octets(p.engine_id),
        &ber::integer(i64::from(p.boots)),
        &ber::integer(i64::from(p.time)),
        &ber::octets(user),
        &ber::octets(p.auth),
        &ber::octets(p.salt),
    ])
}

fn v3_message(msg_id: i64, flags: u8, security: &[u8], data: &[u8]) -> Vec<u8> {
    let header = ber::sequence(&[
        &ber::integer(msg_id),
        &ber::integer(MAX_DATAGRAM as i64),
        &ber::octets(&[flags]),
        &ber::integer(3),
    ]);
    ber::sequence(&[&ber::integer(3), &header, &ber::octets(security), data])
}

fn scoped(context_engine: &[u8], pdu: &[u8]) -> Vec<u8> {
    ber::sequence(&[&ber::octets(context_engine), &ber::octets(b""), pdu])
}

/// Where `part`, a slice of `whole`, starts in it.
fn offset_in(whole: &[u8], part: &[u8]) -> usize {
    part.as_ptr() as usize - whole.as_ptr() as usize
}

struct V3Reply<'a> {
    msg_id: i64,
    engine_id: &'a [u8],
    boots: u32,
    time: u32,
    pdu: Pdu,
}

impl V3 {
    fn new(
        user: &str,
        auth: AuthProtocol,
        auth_password: &str,
        priv_password: Option<&str>,
    ) -> Self {
        Self {
            user: user.to_string(),
            auth,
            auth_master: usm::password_to_key(auth, auth_password.as_bytes()),
            priv_master: priv_password.map(|p| usm::password_to_key(auth, p.as_bytes())),
            engine: None,
            // Any start will do; it only has to change with every message.
            salt: u64::from(std::process::id()) << 32
                | u64::from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos())
                        .unwrap_or(0),
                ),
        }
    }

    fn adopt(&mut self, engine_id: &[u8], boots: u32, time: u32) {
        self.engine = Some(Engine {
            id: engine_id.to_vec(),
            boots,
            time,
            at: Instant::now(),
            auth_key: usm::localize(self.auth, &self.auth_master, engine_id),
            priv_key: self
                .priv_master
                .as_ref()
                .map(|k| usm::localize(self.auth, k, engine_id)),
        });
    }

    /// The probe that asks an engine for its id, boots and time.
    fn discovery(msg_id: i64, request_id: i64) -> Vec<u8> {
        let security = usm_params(
            b"",
            &UsmParams {
                engine_id: b"",
                boots: 0,
                time: 0,
                auth: b"",
                salt: b"",
            },
        );
        let pdu = encode_pdu(GET, request_id, 0, 0, &[]);
        v3_message(msg_id, FLAG_REPORTABLE, &security, &scoped(b"", &pdu))
    }

    /// A request, authenticated and, with a privacy password, encrypted.
    fn request(&mut self, msg_id: i64, pdu: &[u8]) -> Vec<u8> {
        let engine = self.engine.as_ref().expect("discovered before any request");
        let time = engine.time_now();
        let plain = scoped(&engine.id, pdu);
        let mut flags = FLAG_AUTH | FLAG_REPORTABLE;
        let mut salt = Vec::new();
        let data = match &engine.priv_key {
            Some(key) => {
                flags |= FLAG_PRIV;
                self.salt = self.salt.wrapping_add(1);
                let salt8 = self.salt.to_be_bytes();
                salt = salt8.to_vec();
                let mut cipher = plain;
                usm::encrypt(key, engine.boots, time, &salt8, &mut cipher);
                ber::octets(&cipher)
            }
            None => plain,
        };
        let zeros = vec![0u8; self.auth.mac_len()];
        let security = usm_params(
            self.user.as_bytes(),
            &UsmParams {
                engine_id: &engine.id,
                boots: engine.boots,
                time,
                auth: &zeros,
                salt: &salt,
            },
        );
        let mut message = v3_message(msg_id, flags, &security, &data);
        let mac = usm::sign(self.auth, &engine.auth_key, &message);
        // The zeroed MAC field is the only run of its length the parameters end with
        // before the salt: find it by re-reading what was just written.
        if let Ok(reply) = locate_auth(&message) {
            message[reply..reply + mac.len()].copy_from_slice(&mac);
        }
        message
    }

    /// A message from the switch: checked (MAC, engine), decrypted, its PDU read.
    fn reply<'a>(&self, buf: &'a [u8]) -> Result<V3Reply<'a>, Malformed> {
        let mut msg = Reader::new(buf).sequence()?;
        if msg.integer()? != 3 {
            return Err(Malformed);
        }
        let mut header = msg.sequence()?;
        let msg_id = header.integer()?;
        header.integer()?;
        let flags = *header.octets()?.first().ok_or(Malformed)?;
        let mut usm = Reader::new(msg.octets()?).sequence()?;
        let engine_id = usm.octets()?;
        let boots = u32::try_from(usm.integer()?).map_err(|_| Malformed)?;
        let time = u32::try_from(usm.integer()?).map_err(|_| Malformed)?;
        usm.octets()?;
        let mac = usm.octets()?;
        let salt = usm.octets()?;
        if flags & FLAG_AUTH != 0 {
            let engine = self.engine.as_ref().ok_or(Malformed)?;
            let mut zeroed = buf.to_vec();
            let at = offset_in(buf, mac);
            zeroed[at..at + mac.len()].fill(0);
            if mac.len() != self.auth.mac_len()
                || usm::sign(self.auth, &engine.auth_key, &zeroed) != mac
            {
                return Err(Malformed);
            }
        }
        let plain;
        let mut scoped = if flags & FLAG_PRIV != 0 {
            let key = self
                .engine
                .as_ref()
                .and_then(|e| e.priv_key.as_ref())
                .ok_or(Malformed)?;
            let salt: &[u8; 8] = salt.try_into().map_err(|_| Malformed)?;
            let mut data = msg.octets()?.to_vec();
            usm::decrypt(key, boots, time, salt, &mut data);
            plain = data;
            Reader::new(&plain).sequence()?
        } else {
            msg.sequence()?
        };
        scoped.octets()?;
        scoped.octets()?;
        let (tag, content) = scoped.next()?;
        Ok(V3Reply {
            msg_id,
            engine_id,
            boots,
            time,
            pdu: decode_pdu(tag, content)?,
        })
    }
}

/// Where the MAC's bytes sit in a message this manager wrote.
fn locate_auth(message: &[u8]) -> Result<usize, Malformed> {
    let mut msg = Reader::new(message).sequence()?;
    msg.integer()?;
    msg.sequence()?;
    let mut usm = Reader::new(msg.octets()?).sequence()?;
    usm.octets()?;
    usm.integer()?;
    usm.integer()?;
    usm.octets()?;
    Ok(offset_in(message, usm.octets()?))
}

// ── The wire ─────────────────────────────────────────────────────────────

/// One datagram out, and the datagrams that come back before a deadline.
pub trait Wire {
    fn send(&mut self, datagram: &[u8]) -> Result<(), Failure>;
    fn recv(&mut self, deadline: Instant) -> Option<Vec<u8>>;
}

pub struct Udp(UdpSocket);

impl Udp {
    pub fn connect(host: &str, port: u16) -> Result<Self, Failure> {
        let target = (host, port)
            .to_socket_addrs()
            .map_err(|_| Failure::Unreachable)?
            .next()
            .ok_or(Failure::Unreachable)?;
        let local = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local).map_err(|_| Failure::Unreachable)?;
        socket.connect(target).map_err(|_| Failure::Unreachable)?;
        Ok(Self(socket))
    }
}

impl Wire for Udp {
    fn send(&mut self, datagram: &[u8]) -> Result<(), Failure> {
        self.0
            .send(datagram)
            .map(|_| ())
            .map_err(|_| Failure::Unreachable)
    }

    fn recv(&mut self, deadline: Instant) -> Option<Vec<u8>> {
        let left = deadline.checked_duration_since(Instant::now())?;
        self.0
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .ok()?;
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let n = self.0.recv(&mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }
}

// ── The client ───────────────────────────────────────────────────────────

enum Mode {
    V2c(String),
    V3(Box<V3>),
}

pub struct Client<W: Wire> {
    wire: W,
    mode: Mode,
    next_id: i64,
}

/// An error-status the switch answered with.
fn status_failure(status: i64) -> Failure {
    match status {
        // noAccess, authorizationError: the view does not cover it.
        6 | 16 => Failure::Forbidden,
        _ => Failure::Status,
    }
}

impl<W: Wire> Client<W> {
    pub fn new(wire: W, security: &Security) -> Self {
        let mode = match security {
            Security::V2c { community } => Mode::V2c(community.clone()),
            Security::V3 {
                user,
                auth,
                auth_password,
                priv_password,
            } => Mode::V3(Box::new(V3::new(
                user,
                *auth,
                auth_password,
                priv_password.as_deref(),
            ))),
        };
        Self {
            wire,
            mode,
            next_id: i64::from(std::process::id() & 0x7fff) << 16,
        }
    }

    fn id(&mut self) -> i64 {
        self.next_id = (self.next_id + 1) & 0x7fff_ffff;
        self.next_id
    }

    /// Sends until an answer to `id` comes, or every try times out.
    fn exchange<T>(
        &mut self,
        message: &[u8],
        mut accept: impl FnMut(&Self, &[u8]) -> Option<T>,
    ) -> Result<T, Failure> {
        for _ in 0..TRIES {
            self.wire.send(message)?;
            let deadline = Instant::now() + TIMEOUT;
            while let Some(datagram) = self.wire.recv(deadline) {
                if let Some(found) = accept(self, &datagram) {
                    return Ok(found);
                }
            }
        }
        Err(Failure::Timeout)
    }

    /// v3: learn the engine's id, boots and time once.
    fn discover(&mut self) -> Result<(), Failure> {
        let Mode::V3(v3) = &self.mode else {
            return Ok(());
        };
        if v3.engine.is_some() {
            return Ok(());
        }
        let (msg_id, request_id) = (self.id(), self.id());
        let probe = V3::discovery(msg_id, request_id);
        let (id, boots, time) = self.exchange(&probe, |client, datagram| {
            let Mode::V3(v3) = &client.mode else {
                return None;
            };
            let reply = v3.reply(datagram).ok()?;
            (reply.msg_id == msg_id && !reply.engine_id.is_empty())
                .then(|| (reply.engine_id.to_vec(), reply.boots, reply.time))
        })?;
        if let Mode::V3(v3) = &mut self.mode {
            v3.adopt(&id, boots, time);
        }
        Ok(())
    }

    /// One request, its answer's PDU. v3: a Report says what went wrong;
    /// one out of the time window (or from a restarted engine) re-syncs and
    /// tries once more.
    fn request(&mut self, tag: u8, a: i64, b: i64, oids: &[&[u32]]) -> Result<Pdu, Failure> {
        self.discover()?;
        for attempt in 0..2 {
            let request_id = self.id();
            let pdu = encode_pdu(tag, request_id, a, b, oids);
            let message = match &mut self.mode {
                Mode::V2c(community) => v2c_message(community, &pdu),
                Mode::V3(v3) => v3.request(request_id, &pdu),
            };
            let (pdu, sync) = self.exchange(&message, |client, datagram| match &client.mode {
                Mode::V2c(_) => decode_v2c(datagram)
                    .ok()
                    .filter(|p| p.request_id == request_id && p.tag == RESPONSE)
                    .map(|p| (p, None)),
                Mode::V3(v3) => {
                    let reply = v3.reply(datagram).ok()?;
                    (reply.msg_id == request_id).then(|| {
                        let sync = (reply.engine_id.to_vec(), reply.boots, reply.time);
                        (reply.pdu, Some(sync))
                    })
                }
            })?;
            if pdu.tag == REPORT {
                let stat = pdu
                    .varbinds
                    .first()
                    .and_then(|(oid, _)| oid.strip_prefix(&USM_STATS[..]))
                    .and_then(|rest| rest.first().copied());
                let resync = matches!(stat, Some(NOT_IN_TIME_WINDOW | UNKNOWN_ENGINE_ID));
                if let (true, 0, Some((id, boots, time)), Mode::V3(v3)) =
                    (resync, attempt, sync, &mut self.mode)
                {
                    v3.adopt(&id, boots, time);
                    continue;
                }
                // Unknown user, wrong digest, not decrypted, level not offered.
                return Err(Failure::Auth);
            }
            if pdu.error_status != 0 {
                return Err(status_failure(pdu.error_status));
            }
            return Ok(pdu);
        }
        Err(Failure::Auth)
    }

    /// The values of these OIDs; a missing one is `Value::Missing`.
    pub fn get(&mut self, oids: &[&[u32]]) -> Result<Vec<VarBind>, Failure> {
        Ok(self.request(GET, 0, 0, oids)?.varbinds)
    }

    /// Every variable under `root`, in order, at most `max`. A switch that
    /// answers out of order is stopped rather than followed round.
    pub fn walk(&mut self, root: &[u32], max: usize) -> Result<Vec<VarBind>, Failure> {
        let mut out: Vec<VarBind> = Vec::new();
        let mut from = root.to_vec();
        while out.len() < max {
            let pdu = self.request(GET_BULK, 0, MAX_REPETITIONS, &[&from])?;
            if pdu.varbinds.is_empty() {
                break;
            }
            for (oid, value) in pdu.varbinds {
                if !oid.starts_with(root) || value == Value::EndOfMib || oid <= from {
                    return Ok(out);
                }
                from.clone_from(&oid);
                out.push((oid, value));
                if out.len() >= max {
                    break;
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};

    /// An agent in memory: a MIB, answering v2c or v3 as a switch would.
    pub struct FakeAgent {
        mib: BTreeMap<Vec<u32>, Value>,
        community: Option<String>,
        v3: Option<(Vec<u8>, V3)>,
        answers: VecDeque<Vec<u8>>,
        sent: usize,
    }

    fn encode_value(value: &Value) -> Vec<u8> {
        match value {
            Value::Integer(n) => ber::integer(*n),
            Value::Bytes(b) => ber::octets(b),
            Value::Oid(o) => ber::oid(o),
            Value::Unsigned(n) => {
                let mut v = ber::integer(i64::try_from(*n).unwrap_or(i64::MAX));
                v[0] = ber::GAUGE32;
                v
            }
            Value::EndOfMib => ber::tlv(ber::END_OF_MIB_VIEW, &[]),
            _ => ber::tlv(ber::NO_SUCH_OBJECT, &[]),
        }
    }

    impl FakeAgent {
        pub fn v2c(mib: BTreeMap<Vec<u32>, Value>, community: &str) -> Self {
            Self {
                mib,
                community: Some(community.into()),
                v3: None,
                answers: VecDeque::new(),
                sent: 0,
            }
        }

        pub fn v3(mib: BTreeMap<Vec<u32>, Value>, engine: &[u8], security: &Security) -> Self {
            let Security::V3 {
                user,
                auth,
                auth_password,
                priv_password,
            } = security
            else {
                unreachable!()
            };
            let mut agent_side = V3::new(user, *auth, auth_password, priv_password.as_deref());
            agent_side.adopt(engine, 7, 1000);
            Self {
                mib,
                community: None,
                v3: Some((engine.to_vec(), agent_side)),
                answers: VecDeque::new(),
                sent: 0,
            }
        }

        fn respond(mib: &BTreeMap<Vec<u32>, Value>, request: &Pdu) -> Vec<u8> {
            let mut binds: Vec<Vec<u8>> = Vec::new();
            let mut add = |oid: &[u32], value: &Value| {
                binds.push(ber::sequence(&[&ber::oid(oid), &encode_value(value)]));
            };
            for (oid, _) in &request.varbinds {
                if request.tag == GET_BULK {
                    let mut after = mib.range::<Vec<u32>, _>((
                        std::ops::Bound::Excluded(oid.clone()),
                        std::ops::Bound::Unbounded,
                    ));
                    for _ in 0..MAX_REPETITIONS {
                        match after.next() {
                            Some((o, v)) => add(o, v),
                            None => {
                                add(oid, &Value::EndOfMib);
                                break;
                            }
                        }
                    }
                } else {
                    add(oid, mib.get(oid).unwrap_or(&Value::Missing));
                }
            }
            let list: Vec<&[u8]> = binds.iter().map(Vec::as_slice).collect();
            ber::tlv(
                RESPONSE,
                &[
                    ber::integer(request.request_id),
                    ber::integer(0),
                    ber::integer(0),
                    ber::sequence(&list),
                ]
                .concat(),
            )
        }
    }

    impl Wire for FakeAgent {
        fn send(&mut self, datagram: &[u8]) -> Result<(), Failure> {
            self.sent += 1;
            if let Some(community) = &self.community {
                let mut msg = Reader::new(datagram).sequence().unwrap();
                msg.integer().unwrap();
                if msg.octets().unwrap() != community.as_bytes() {
                    return Ok(()); // a wrong community gets no answer
                }
                let (tag, content) = msg.next().unwrap();
                let pdu = decode_pdu(tag, content).unwrap();
                let reply = v2c_message(community, &Self::respond(&self.mib, &pdu));
                self.answers.push_back(reply);
                return Ok(());
            }
            let (engine, agent) = self.v3.as_mut().unwrap();
            let mut msg = Reader::new(datagram).sequence().unwrap();
            msg.integer().unwrap();
            let mut header = msg.sequence().unwrap();
            let msg_id = header.integer().unwrap();
            header.integer().unwrap();
            let flags = header.octets().unwrap()[0];
            let mut usm = Reader::new(msg.octets().unwrap()).sequence().unwrap();
            let their_engine = usm.octets().unwrap();
            if their_engine.is_empty() {
                // Discovery: a Report naming this engine.
                let report = ber::tlv(
                    REPORT,
                    &[
                        ber::integer(0),
                        ber::integer(0),
                        ber::integer(0),
                        ber::sequence(&[&ber::sequence(&[
                            &ber::oid(&[1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0]),
                            &ber::integer(1),
                        ])]),
                    ]
                    .concat(),
                );
                let security = usm_params(
                    b"",
                    &UsmParams {
                        engine_id: engine,
                        boots: 7,
                        time: 1000,
                        auth: b"",
                        salt: b"",
                    },
                );
                self.answers
                    .push_back(v3_message(msg_id, 0, &security, &scoped(engine, &report)));
                return Ok(());
            }
            // The request, as the engine checks it: the agent side's own reader.
            let Ok(reply) = agent.reply(datagram) else {
                // usmStatsWrongDigests, unauthenticated, as RFC 3414 3.2 answers.
                let report = ber::tlv(
                    REPORT,
                    &[
                        ber::integer(0),
                        ber::integer(0),
                        ber::integer(0),
                        ber::sequence(&[&ber::sequence(&[
                            &ber::oid(&[1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0]),
                            &ber::integer(1),
                        ])]),
                    ]
                    .concat(),
                );
                let security = usm_params(
                    b"",
                    &UsmParams {
                        engine_id: engine,
                        boots: 7,
                        time: 1000,
                        auth: b"",
                        salt: b"",
                    },
                );
                let answer = v3_message(msg_id, 0, &security, &scoped(engine, &report));
                self.answers.push_back(answer);
                return Ok(());
            };
            assert_eq!(flags & FLAG_AUTH, FLAG_AUTH);
            let response = Self::respond(&self.mib, &reply.pdu);
            let answer = agent.request(msg_id, &response);
            self.answers.push_back(answer);
            Ok(())
        }

        fn recv(&mut self, _deadline: Instant) -> Option<Vec<u8>> {
            self.answers.pop_front()
        }
    }

    pub fn mib(entries: &[(&[u32], Value)]) -> BTreeMap<Vec<u32>, Value> {
        entries
            .iter()
            .map(|(o, v)| (o.to_vec(), v.clone()))
            .collect()
    }

    const IF_DESCR: [u32; 10] = [1, 3, 6, 1, 2, 1, 2, 2, 1, 2];

    fn sample() -> BTreeMap<Vec<u32>, Value> {
        let mut entries: Vec<(Vec<u32>, Value)> = (1..=45)
            .map(|i| {
                let mut oid = IF_DESCR.to_vec();
                oid.push(i);
                (oid, Value::Bytes(format!("port{i}").into_bytes()))
            })
            .collect();
        entries.push((
            vec![1, 3, 6, 1, 2, 1, 1, 5, 0],
            Value::Bytes(b"sw-1".to_vec()),
        ));
        entries.push((vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1], Value::Integer(1)));
        entries.into_iter().collect()
    }

    #[test]
    fn walks_a_table_over_v2c_and_stops_at_its_end() {
        let agent = FakeAgent::v2c(sample(), "public");
        let mut client = Client::new(
            agent,
            &Security::V2c {
                community: "public".into(),
            },
        );
        let rows = client.walk(&IF_DESCR, 1000).unwrap();
        assert_eq!(rows.len(), 45, "three bulk answers, nothing past the table");
        assert_eq!(rows[44].1, Value::Bytes(b"port45".to_vec()));
        assert_eq!(client.walk(&IF_DESCR, 10).unwrap().len(), 10, "capped");
        let name = client.get(&[&[1, 3, 6, 1, 2, 1, 1, 5, 0]]).unwrap();
        assert_eq!(name[0].1, Value::Bytes(b"sw-1".to_vec()));
    }

    #[test]
    fn a_wrong_community_times_out() {
        let agent = FakeAgent::v2c(sample(), "public");
        let mut client = Client::new(
            agent,
            &Security::V2c {
                community: "privat".into(),
            },
        );
        assert_eq!(client.get(&[&IF_DESCR]).err(), Some(Failure::Timeout));
        assert_eq!(client.wire.sent, TRIES);
    }

    fn v3_security(privacy: bool) -> Security {
        Security::V3 {
            user: "connlog".into(),
            auth: AuthProtocol::Sha256,
            auth_password: "authpassword".into(),
            priv_password: privacy.then(|| "privpassword".into()),
        }
    }

    #[test]
    fn discovers_the_engine_then_walks_authenticated_and_encrypted() {
        for privacy in [false, true] {
            let security = v3_security(privacy);
            let agent = FakeAgent::v3(sample(), b"\x80\x00\x1f\x88engine", &security);
            let mut client = Client::new(agent, &security);
            let rows = client.walk(&IF_DESCR, 1000).unwrap();
            assert_eq!(rows.len(), 45, "privacy: {privacy}");
        }
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let security = v3_security(true);
        let agent = FakeAgent::v3(sample(), b"\x80\x00\x1f\x88engine", &security);
        let wrong = Security::V3 {
            user: "connlog".into(),
            auth: AuthProtocol::Sha256,
            auth_password: "not-the-password".into(),
            priv_password: Some("privpassword".into()),
        };
        let mut client = Client::new(agent, &wrong);
        assert_eq!(client.get(&[&IF_DESCR]).err(), Some(Failure::Auth));
    }
}
