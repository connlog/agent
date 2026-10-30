//! What every integration reads out of a device's JSON the same way:
//! names, interface names, addresses, flags and MACs, each checked, so a
//! value that is not what it says is left out rather than reported.

use std::net::IpAddr;

use serde_json::Value;

/// `PROXMOX_NAME_MAX` in the protocol, and every integration's name limit.
pub const NAME_MAX: usize = 128;

/// A name a device gives something, trimmed, at most `NAME_MAX` characters;
/// none for an empty one.
pub fn name_of(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim();
    (!text.is_empty()).then(|| text.chars().take(NAME_MAX).collect())
}

pub fn iface(value: &str) -> Option<String> {
    let ok = !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    ok.then(|| value.to_string())
}

pub fn ip(value: &Value) -> Option<String> {
    value
        .as_str()?
        .trim()
        .parse::<IpAddr>()
        .ok()
        .map(|a| a.to_string())
}

pub fn cidr(value: &Value) -> Option<String> {
    let (address, bits) = value.as_str()?.trim().split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    (bits <= max).then(|| format!("{address}/{bits}"))
}

pub fn flag(value: &Value) -> bool {
    value.as_u64() == Some(1) || value.as_bool() == Some(true) || value.as_str() == Some("1")
}

pub fn lower_mac(text: &str) -> Option<String> {
    let mac = text.trim().to_ascii_lowercase();
    let parts: Vec<&str> = mac.split(':').collect();
    let ok = parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()));
    ok.then_some(mac)
}
