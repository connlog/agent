//! A TLS client that trusts exactly one certificate, by its SHA-256
//! fingerprint: a Proxmox node's self-signed one, pinned when the
//! integration was added. Checked in the handshake, so a request (and the
//! token it carries) is never sent to a server that shows anything else.
//!
//! The handshake's signatures are still verified against the certificate's
//! key: a pinned certificate proves the server holds its private key, as a
//! CA-signed one would.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// A SHA-256 fingerprint.
pub type Fingerprint = [u8; 32];

pub fn sha256(der: &[u8]) -> Fingerprint {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// `AB:CD:…`, as `openssl x509 -fingerprint -sha256` and Proxmox's own
/// certificate page print it.
pub fn format(fp: &Fingerprint) -> String {
    fp.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Reads one with or without colons, either case. None for anything else.
pub fn parse(text: &str) -> Option<Fingerprint> {
    let hex: String = text.trim().chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// What the verifier saw: whether the certificate was refused for its
/// fingerprint, and the fingerprint presented (for `integration add`).
#[derive(Debug, Default)]
pub struct Seen {
    pub mismatch: AtomicBool,
    pub presented: std::sync::Mutex<Option<Fingerprint>>,
}

#[derive(Debug)]
struct Pinned {
    /// None: accept nothing, only record what was presented.
    want: Option<Fingerprint>,
    seen: Arc<Seen>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = sha256(end_entity.as_ref());
        if let Ok(mut presented) = self.seen.presented.lock() {
            *presented = Some(got);
        }
        match self.want {
            // A certificate is public: comparing its hash leaks nothing,
            // so it needs no constant-time compare.
            Some(want) if want == got => Ok(ServerCertVerified::assertion()),
            _ => {
                self.seen.mismatch.store(true, Ordering::SeqCst);
                Err(rustls::Error::General("certificate fingerprint".into()))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS config that trusts only `want`; with None, one that refuses every
/// certificate and records the one presented, to show it before trusting it.
pub fn client_config(want: Option<Fingerprint>, seen: Arc<Seen>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Pinned {
        want,
        seen,
        provider: Arc::clone(&provider),
    };
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_a_fingerprint_with_or_without_colons() {
        let fp = sha256(b"certificate");
        let text = format(&fp);
        assert_eq!(text.len(), 32 * 3 - 1);
        assert_eq!(parse(&text), Some(fp));
        assert_eq!(parse(&text.replace(':', "").to_lowercase()), Some(fp));
        assert_eq!(parse("AB:CD"), None);
        assert_eq!(parse(&"ZZ".repeat(32)), None);
    }

    #[test]
    fn trusts_the_pinned_certificate_only_and_records_what_was_shown() {
        let seen = Arc::new(Seen::default());
        let verifier = Pinned {
            want: Some(sha256(b"ours")),
            seen: Arc::clone(&seen),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let name = ServerName::try_from("pve.lan").unwrap();
        let ours = CertificateDer::from(b"ours".to_vec());
        assert!(verifier
            .verify_server_cert(&ours, &[], &name, &[], UnixTime::now())
            .is_ok());
        assert!(!seen.mismatch.load(Ordering::SeqCst));
        let theirs = CertificateDer::from(b"theirs".to_vec());
        assert!(verifier
            .verify_server_cert(&theirs, &[], &name, &[], UnixTime::now())
            .is_err());
        assert!(seen.mismatch.load(Ordering::SeqCst));
        assert_eq!(*seen.presented.lock().unwrap(), Some(sha256(b"theirs")));
    }
}
