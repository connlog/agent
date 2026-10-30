//! SNMPv3's user-based security (RFC 3414): a password made a key and
//! localized to one engine, HMAC authentication, and AES-128 privacy
//! (RFC 3826). SHA-1 (`usmHMACSHAAuthProtocol`, 96-bit MAC) and SHA-256
//! (`usmHMAC192SHA256AuthProtocol`, RFC 7860) only: MD5 and DES are broken
//! and not offered.

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use ring::{digest, hmac};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    Sha1,
    Sha256,
}

impl AuthProtocol {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "sha" | "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Self::Sha1 => "sha",
            Self::Sha256 => "sha256",
        }
    }

    fn digest(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
        }
    }

    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
        }
    }

    /// How many bytes of the MAC a message carries.
    pub fn mac_len(self) -> usize {
        match self {
            Self::Sha1 => 12,
            Self::Sha256 => 24,
        }
    }
}

/// RFC 3414 A.2: the password repeated to a megabyte, hashed.
pub fn password_to_key(protocol: AuthProtocol, password: &[u8]) -> Vec<u8> {
    const MEGABYTE: usize = 1_048_576;
    let mut context = digest::Context::new(protocol.digest());
    let mut chunk = [0u8; 64];
    let mut index = 0;
    for _ in 0..MEGABYTE / chunk.len() {
        for byte in &mut chunk {
            *byte = password[index % password.len()];
            index += 1;
        }
        context.update(&chunk);
    }
    context.finish().as_ref().to_vec()
}

/// RFC 3414 A.2: the key bound to one engine, so a key read off one switch
/// works on no other.
pub fn localize(protocol: AuthProtocol, key: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut context = digest::Context::new(protocol.digest());
    context.update(key);
    context.update(engine_id);
    context.update(key);
    context.finish().as_ref().to_vec()
}

/// The MAC a message carries: the HMAC of the whole message, its MAC field zeroed, cut short.
pub fn sign(protocol: AuthProtocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    let tag = hmac::sign(&hmac::Key::new(protocol.hmac(), key), message);
    tag.as_ref()[..protocol.mac_len()].to_vec()
}

/// RFC 3826: the IV is the engine's boots and time, then the 8-byte salt.
fn iv(boots: u32, time: u32, salt: &[u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(salt);
    iv
}

type Aes128Cfb = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

/// AES-128 in CFB-128 with the localized privacy key's first 16 bytes.
pub fn encrypt(key: &[u8], boots: u32, time: u32, salt: &[u8; 8], data: &mut [u8]) {
    let key: &[u8; 16] = key[..16]
        .try_into()
        .expect("a localized key is 20 or 32 bytes");
    Aes128Cfb::new(key.into(), &iv(boots, time, salt).into()).encrypt(data);
}

pub fn decrypt(key: &[u8], boots: u32, time: u32, salt: &[u8; 8], data: &mut [u8]) {
    let key: &[u8; 16] = key[..16]
        .try_into()
        .expect("a localized key is 20 or 32 bytes");
    Aes128CfbDec::new(key.into(), &iv(boots, time, salt).into()).decrypt(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const ENGINE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    #[test]
    fn makes_and_localizes_rfc_3414s_sha_key() {
        // RFC 3414 A.3.2.
        let key = password_to_key(AuthProtocol::Sha1, b"maplesyrup");
        assert_eq!(hex(&key), "9fb5cc0381497b3793528939ff788d5d79145211");
        assert_eq!(
            hex(&localize(AuthProtocol::Sha1, &key, &ENGINE)),
            "6695febc9288e36282235fc7151f128497b38f3f"
        );
    }

    #[test]
    fn makes_and_localizes_a_sha256_key() {
        // The same algorithm with SHA-256 (RFC 7860), worked by Python's hashlib.
        let key = password_to_key(AuthProtocol::Sha256, b"maplesyrup");
        assert_eq!(
            hex(&key),
            "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac"
        );
        assert_eq!(
            hex(&localize(AuthProtocol::Sha256, &key, &ENGINE)),
            "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"
        );
    }

    #[test]
    fn encrypts_as_openssl_does_and_back() {
        // openssl enc -aes-128-cfb -K 000102…0f -iv 00000001 00000002 a1…a8 -nopad
        let key: Vec<u8> = (0u8..20).collect();
        let salt = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];
        let mut data = b"connlog snmp cfb test vector!!".to_vec();
        encrypt(&key, 1, 2, &salt, &mut data);
        assert_eq!(
            hex(&data),
            "30725cb709ad27a762d4b96e38cebf8a8b33f5493d027bbb794b55aa00d1"
        );
        decrypt(&key, 1, 2, &salt, &mut data);
        assert_eq!(data, b"connlog snmp cfb test vector!!");
    }

    #[test]
    fn signs_with_the_macs_length() {
        assert_eq!(sign(AuthProtocol::Sha1, b"k", b"m").len(), 12);
        assert_eq!(sign(AuthProtocol::Sha256, b"k", b"m").len(), 24);
    }
}
