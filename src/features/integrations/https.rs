//! The HTTPS client every integration reads through: the device's
//! certificate pinned in the handshake (or, without a fingerprint, verified
//! as any website's), no redirects, never through a proxy, and a failure
//! said in one word of `Failure`, never an error's text.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::{pinning, Failure};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How a request proves who it is.
pub enum Auth {
    /// An `Authorization` header as is: Proxmox's `PVEAPIToken=…`.
    Header(String),
    /// HTTP basic: OPNsense's API key and secret.
    Basic { user: String, password: String },
}

pub struct Client {
    client: reqwest::blocking::Client,
    seen: Arc<pinning::Seen>,
}

impl Client {
    /// `kind` names the integration in the user agent: `proxmox`.
    pub fn new(kind: &str, fingerprint: Option<pinning::Fingerprint>) -> Result<Self, Failure> {
        let seen = Arc::new(pinning::Seen::default());
        let builder = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            // On the customer's own network: never through a proxy the
            // host's environment names, which would see the credentials.
            .no_proxy()
            .user_agent(format!(
                "connlog-agent/{} ({kind})",
                env!("CARGO_PKG_VERSION")
            ));
        let builder = match fingerprint {
            Some(fp) => {
                builder.use_preconfigured_tls(pinning::client_config(Some(fp), Arc::clone(&seen)))
            }
            None => builder,
        };
        Ok(Self {
            client: builder.build().map_err(|_| Failure::Tls)?,
            seen,
        })
    }

    fn failure_of(&self, e: &reqwest::Error) -> Failure {
        if self.seen.mismatch.load(Ordering::SeqCst) {
            return Failure::Fingerprint;
        }
        if e.is_timeout() {
            return Failure::Timeout;
        }
        let mut source = std::error::Error::source(e);
        while let Some(inner) = source {
            if inner.downcast_ref::<rustls::Error>().is_some() {
                return Failure::Tls;
            }
            source = inner.source();
        }
        Failure::Unreachable
    }

    /// A GET with these credentials, answered with the JSON body.
    pub fn get(&self, url: &str, auth: &Auth) -> Result<Value, Failure> {
        let request = self.client.get(url);
        let request = match auth {
            Auth::Header(value) => request.header(reqwest::header::AUTHORIZATION, value),
            Auth::Basic { user, password } => request.basic_auth(user, Some(password)),
        };
        let response = request.send().map_err(|e| self.failure_of(&e))?;
        match response.status().as_u16() {
            200 => {}
            401 => return Err(Failure::Auth),
            403 => return Err(Failure::Forbidden),
            _ => return Err(Failure::Status),
        }
        response.json().map_err(|_| Failure::Invalid)
    }
}

/// The certificate the device at `url` presents, without sending anything
/// to it: what `integration add` shows before it is trusted.
pub fn presented_fingerprint(url: &str) -> Option<pinning::Fingerprint> {
    let seen = Arc::new(pinning::Seen::default());
    let client = reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .no_proxy()
        .use_preconfigured_tls(pinning::client_config(None, Arc::clone(&seen)))
        .build()
        .ok()?;
    // The handshake is refused once the certificate is seen: no request is sent.
    let _ = client.get(url).send();
    let presented = *seen.presented.lock().ok()?;
    presented
}
