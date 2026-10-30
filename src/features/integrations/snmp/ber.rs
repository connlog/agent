//! The slice of ASN.1 BER that SNMP speaks (RFC 3416, RFC 3417): integers,
//! octet strings, OIDs, the application types and nested sequences. A
//! decoder that reads only what it was given: every length is checked
//! against what is left, so an answer from the network cannot read past
//! itself or nest without end.

pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const IP_ADDRESS: u8 = 0x40;
pub const COUNTER32: u8 = 0x41;
pub const GAUGE32: u8 = 0x42;
pub const TIMETICKS: u8 = 0x43;
pub const COUNTER64: u8 = 0x46;
pub const NO_SUCH_OBJECT: u8 = 0x80;
pub const NO_SUCH_INSTANCE: u8 = 0x81;
pub const END_OF_MIB_VIEW: u8 = 0x82;

/// A variable's value, as far as the switch reader needs to tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Integer(i64),
    Bytes(Vec<u8>),
    Null,
    Oid(Vec<u32>),
    Ip([u8; 4]),
    /// Counter32, Gauge32, TimeTicks, Counter64.
    Unsigned(u64),
    /// noSuchObject, noSuchInstance: nothing there.
    Missing,
    EndOfMib,
    /// Anything else (Opaque, an unknown tag): read past, never used.
    Other,
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            Self::Unsigned(n) => i64::try_from(*n).ok(),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

// ── Encoding ──────────────────────────────────────────────────────────────

fn length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

/// A tag, its length and its content.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

pub fn integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    // The shortest two's complement that keeps the sign.
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    tlv(INTEGER, &bytes[start..])
}

pub fn octets(value: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, value)
}

pub fn null() -> Vec<u8> {
    tlv(NULL, &[])
}

pub fn oid(arcs: &[u32]) -> Vec<u8> {
    let mut content = Vec::with_capacity(arcs.len() + 4);
    let (first, rest) = match arcs {
        [a, b, rest @ ..] => (a * 40 + b, rest),
        [a] => (a * 40, &[][..]),
        [] => (0, &[][..]),
    };
    for arc in std::iter::once(first).chain(rest.iter().copied()) {
        let mut chunk = [0u8; 5];
        let mut n = arc;
        let mut i = chunk.len();
        loop {
            i -= 1;
            chunk[i] = (n & 0x7f) as u8 | if i == chunk.len() - 1 { 0 } else { 0x80 };
            n >>= 7;
            if n == 0 {
                break;
            }
        }
        content.extend_from_slice(&chunk[i..]);
    }
    tlv(OID, &content)
}

pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

// ── Decoding ──────────────────────────────────────────────────────────────

/// Reads TLVs off a buffer, front to back.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The next tag and its content.
    pub fn next(&mut self) -> Result<(u8, &'a [u8]), Malformed> {
        let (&tag, rest) = self.buf.split_first().ok_or(Malformed)?;
        let (&first, rest) = rest.split_first().ok_or(Malformed)?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 || rest.len() < count {
                return Err(Malformed);
            }
            let len = rest[..count]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (len, &rest[count..])
        };
        if rest.len() < len {
            return Err(Malformed);
        }
        let (content, rest) = rest.split_at(len);
        self.buf = rest;
        Ok((tag, content))
    }

    /// The next TLV, which must carry `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], Malformed> {
        match self.next()? {
            (t, content) if t == tag => Ok(content),
            _ => Err(Malformed),
        }
    }

    pub fn integer(&mut self) -> Result<i64, Malformed> {
        decode_integer(self.expect(INTEGER)?)
    }

    pub fn octets(&mut self) -> Result<&'a [u8], Malformed> {
        self.expect(OCTET_STRING)
    }

    pub fn sequence(&mut self) -> Result<Reader<'a>, Malformed> {
        Ok(Reader::new(self.expect(SEQUENCE)?))
    }
}

pub fn decode_integer(content: &[u8]) -> Result<i64, Malformed> {
    if content.is_empty() || content.len() > 8 {
        return Err(Malformed);
    }
    let negative = content[0] & 0x80 != 0;
    let start: i64 = if negative { -1 } else { 0 };
    Ok(content
        .iter()
        .fold(start, |acc, b| (acc << 8) | i64::from(*b)))
}

fn decode_unsigned(content: &[u8]) -> Result<u64, Malformed> {
    // A leading zero keeps the top bit clear: nine bytes for a Counter64.
    let content = match content {
        [0, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    };
    if content.is_empty() || content.len() > 8 {
        return Err(Malformed);
    }
    Ok(content
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

pub fn decode_oid(content: &[u8]) -> Result<Vec<u32>, Malformed> {
    if content.is_empty() || content.len() > 256 {
        return Err(Malformed);
    }
    let mut arcs = Vec::with_capacity(content.len() + 1);
    let mut value: u32 = 0;
    for (i, byte) in content.iter().enumerate() {
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add(u32::from(byte & 0x7f)))
            .ok_or(Malformed)?;
        if byte & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (value / 40).min(2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        } else if i == content.len() - 1 {
            return Err(Malformed);
        }
    }
    Ok(arcs)
}

pub fn decode_value(tag: u8, content: &[u8]) -> Result<Value, Malformed> {
    Ok(match tag {
        INTEGER => Value::Integer(decode_integer(content)?),
        OCTET_STRING => Value::Bytes(content.to_vec()),
        NULL => Value::Null,
        OID => Value::Oid(decode_oid(content)?),
        IP_ADDRESS => Value::Ip(content.try_into().map_err(|_| Malformed)?),
        COUNTER32 | GAUGE32 | TIMETICKS | COUNTER64 => Value::Unsigned(decode_unsigned(content)?),
        NO_SUCH_OBJECT | NO_SUCH_INSTANCE => Value::Missing,
        END_OF_MIB_VIEW => Value::EndOfMib,
        _ => Value::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_integers_in_their_shortest_form() {
        assert_eq!(integer(0), [0x02, 0x01, 0x00]);
        assert_eq!(integer(127), [0x02, 0x01, 0x7f]);
        assert_eq!(integer(128), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(-1), [0x02, 0x01, 0xff]);
        assert_eq!(integer(-129), [0x02, 0x02, 0xff, 0x7f]);
        assert_eq!(integer(65507), [0x02, 0x03, 0x00, 0xff, 0xe3]);
        for n in [
            0,
            1,
            -1,
            255,
            256,
            -256,
            i64::from(i32::MAX),
            i64::MIN,
            i64::MAX,
        ] {
            let encoded = integer(n);
            assert_eq!(Reader::new(&encoded).integer(), Ok(n), "{n}");
        }
    }

    #[test]
    fn writes_and_reads_oids() {
        // sysName.0, as RFC 3416's examples write it.
        let sys_name = [1, 3, 6, 1, 2, 1, 1, 5, 0];
        let encoded = oid(&sys_name);
        assert_eq!(encoded, [0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 5, 0]);
        assert_eq!(decode_oid(&encoded[2..]).unwrap(), sys_name);
        // LLDP-MIB's root, with an arc over 127.
        let lldp = [1, 0, 8802, 1, 1, 2];
        assert_eq!(decode_oid(&oid(&lldp)[2..]).unwrap(), lldp);
        assert_eq!(decode_oid(&[0x2b, 0x86]), Err(Malformed), "cut off mid-arc");
    }

    #[test]
    fn reads_long_lengths_and_refuses_what_runs_past_the_end() {
        let big = octets(&[7u8; 300]);
        assert_eq!(&big[..4], [0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(Reader::new(&big).octets().unwrap().len(), 300);
        assert_eq!(Reader::new(&[0x04, 0x05, 1, 2]).next(), Err(Malformed));
        assert_eq!(
            Reader::new(&[0x04, 0x85, 0, 0, 0, 0, 1]).next(),
            Err(Malformed)
        );
    }

    #[test]
    fn reads_the_application_types() {
        assert_eq!(
            decode_value(IP_ADDRESS, &[10, 0, 0, 1]),
            Ok(Value::Ip([10, 0, 0, 1]))
        );
        assert_eq!(
            decode_value(COUNTER32, &[0, 0xff]),
            Ok(Value::Unsigned(255))
        );
        assert_eq!(
            decode_value(
                COUNTER64,
                &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            ),
            Ok(Value::Unsigned(u64::MAX))
        );
        assert_eq!(decode_value(NO_SUCH_INSTANCE, &[]), Ok(Value::Missing));
        assert_eq!(decode_value(END_OF_MIB_VIEW, &[]), Ok(Value::EndOfMib));
    }
}
