use anyhow::{Context, Result};
use log::{info, warn};
use ring::digest;
use ring::signature;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use crate::heartbeat::UpdateInfo;

/// Ed25519 public key (hex) for verifying update signatures.
///
/// Override at compile time:
///   CONNLOG_SIGNING_PUBLIC_KEY="abc123..." cargo build --release
///
/// Generate a keypair with: scripts/generate-signing-keys.py
const SIGNING_PUBLIC_KEY_HEX: &str = match option_env!("CONNLOG_SIGNING_PUBLIC_KEY") {
    Some(key) => key,
    None => "0000000000000000000000000000000000000000000000000000000000000000",
};

const PLACEHOLDER_KEY: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const STAGED_BINARY: &str = "/run/connlog/connlog-agent-new";
const UPDATE_MARKER: &str = "/run/connlog/.update_requested";

/// Returns true if a real signing key is compiled in (not the placeholder).
pub fn has_signing_key() -> bool {
    SIGNING_PUBLIC_KEY_HEX != PLACEHOLDER_KEY && SIGNING_PUBLIC_KEY_HEX.len() == 64
}

/// Attempt to apply a verified update.
///
/// Returns:
/// - `Ok(true)`  — update staged, caller should exit for systemd to apply it
/// - `Ok(false)` — update skipped (missing fields, no signing key, etc.)
/// - `Err(..)`   — update failed (download, checksum, or signature error)
pub fn try_apply_update(update: &UpdateInfo) -> Result<bool> {
    if !update.available {
        return Ok(false);
    }

    let download_url = match &update.download_url {
        Some(url) => url,
        None => {
            info!(
                "Update v{} available but no download URL provided — skipping",
                update.latest_version
            );
            return Ok(false);
        }
    };

    let signature_url = match &update.signature_url {
        Some(url) => url,
        None => {
            warn!(
                "Update v{} available but no signature URL — rejecting (unsigned updates are not accepted)",
                update.latest_version
            );
            return Ok(false);
        }
    };

    let expected_sha256 = match &update.sha256 {
        Some(hash) => hash,
        None => {
            warn!(
                "Update v{} available but no SHA-256 hash — skipping",
                update.latest_version
            );
            return Ok(false);
        }
    };

    if !has_signing_key() {
        warn!(
            "Update v{} available but no signing key compiled into this build — skipping. \
             Rebuild with CONNLOG_SIGNING_PUBLIC_KEY=<hex> to enable auto-updates.",
            update.latest_version
        );
        return Ok(false);
    }

    // Skip if we're already running this version or a newer one
    let current_version = env!("CARGO_PKG_VERSION");
    if update.latest_version == current_version {
        return Ok(false);
    }

    // Reject version downgrades (prevents rollback attacks)
    if !is_version_upgrade(current_version, &update.latest_version) {
        warn!(
            "UPDATE: Rejecting downgrade from v{} to v{} — only upgrades are allowed",
            current_version, update.latest_version
        );
        return Ok(false);
    }

    info!(
        "UPDATE: v{} → v{} available, downloading...",
        current_version, update.latest_version
    );

    perform_verified_update(
        download_url,
        signature_url,
        expected_sha256,
        &update.latest_version,
    )?;

    Ok(true)
}

/// Download, verify (SHA-256 + Ed25519), and stage a new binary.
fn perform_verified_update(
    download_url: &str,
    signature_url: &str,
    expected_sha256: &str,
    version: &str,
) -> Result<()> {
    // Separate download client: no auth headers, follows redirects (GitHub CDN),
    // longer timeout for large binary downloads.
    let download_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("Failed to create download client")?;

    // ── 1. Download binary ──────────────────────────────────────
    let binary_data = download_client
        .get(download_url)
        .send()
        .context("Failed to download update binary")?
        .error_for_status()
        .context("Update download returned HTTP error")?
        .bytes()
        .context("Failed to read update binary body")?;

    info!("UPDATE: Downloaded {} bytes", binary_data.len());

    // Basic sanity check (agent binary should be >100KB)
    if binary_data.len() < 100_000 {
        anyhow::bail!(
            "UPDATE: Downloaded file is suspiciously small ({} bytes) — aborting",
            binary_data.len()
        );
    }

    // ── 2. Verify SHA-256 checksum ──────────────────────────────
    let actual_hash = digest::digest(&digest::SHA256, &binary_data);
    let actual_sha256 = hex_encode(actual_hash.as_ref());

    if actual_sha256 != expected_sha256.to_lowercase() {
        anyhow::bail!(
            "UPDATE: SHA-256 MISMATCH\n  expected: {}\n  actual:   {}\n  Rejecting update.",
            expected_sha256,
            actual_sha256
        );
    }

    info!("UPDATE: SHA-256 checksum verified ✓");

    // ── 3. Download Ed25519 signature ───────────────────────────
    let sig_data = download_client
        .get(signature_url)
        .send()
        .context("Failed to download update signature")?
        .error_for_status()
        .context("Signature download returned HTTP error")?
        .bytes()
        .context("Failed to read signature body")?;

    if sig_data.len() != 64 {
        anyhow::bail!(
            "UPDATE: Invalid signature size ({} bytes, expected 64) — aborting",
            sig_data.len()
        );
    }

    // ── 4. Verify Ed25519 signature ─────────────────────────────
    // The signature covers the SHA-256 hash of the binary (32 bytes),
    // NOT the raw binary. This matches the release signing process.
    let public_key_bytes =
        hex_decode(SIGNING_PUBLIC_KEY_HEX).context("Invalid compiled-in public key hex")?;

    let public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);

    public_key
        .verify(actual_hash.as_ref(), &sig_data)
        .map_err(|_| {
            anyhow::anyhow!(
                "UPDATE: Ed25519 SIGNATURE VERIFICATION FAILED — rejecting update. \
                 This could indicate a tampered binary or mismatched signing key."
            )
        })?;

    info!("UPDATE: Ed25519 signature verified ✓");

    // ── 5. Stage binary to /run/connlog/ ────────────────────────
    fs::write(STAGED_BINARY, &binary_data).context("Failed to write staged binary")?;

    let mut perms = fs::metadata(STAGED_BINARY)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(STAGED_BINARY, perms)?;

    // ── 6. Write update marker ──────────────────────────────────
    let marker = format!("version={}\n", version);
    fs::write(UPDATE_MARKER, marker).context("Failed to write update marker")?;

    info!(
        "UPDATE: Binary staged at {} and marker written. \
         Exiting for systemd ExecStopPost to complete the update.",
        STAGED_BINARY
    );

    Ok(())
}

// ── Version comparison (avoids adding `semver` crate) ──────────

/// Returns true if `new` is a strictly higher semantic version than `current`.
/// Expects versions in the form "MAJOR.MINOR.PATCH" (no pre-release tags).
fn is_version_upgrade(current: &str, new: &str) -> bool {
    let parse = |v: &str| -> Option<(u64, u64, u64)> {
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
        ))
    };

    match (parse(current), parse(new)) {
        (Some(cur), Some(nxt)) => nxt > cur,
        _ => false, // Reject unparseable versions
    }
}

// ── Hex helpers (avoids adding the `hex` crate) ────────────────

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("Odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("Invalid hex character"))
        .collect()
}
