use anyhow::{Context, Result};
use log::{info, warn};
use ring::digest::{self, Digest};
use ring::signature;
use serde::Deserialize;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use crate::heartbeat::UpdateInfo;
use crate::platform::{INSTALLED_BINARY, STAGED_BINARY, UPDATE_MARKER};

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

const PLACEHOLDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const GITHUB_RELEASE_URL: &str =
    "https://api.github.com/repos/connlog/connlog-agent/releases/latest";

/// Returns true if a real signing key is compiled in (not the placeholder).
pub fn has_signing_key() -> bool {
    SIGNING_PUBLIC_KEY_HEX != PLACEHOLDER_KEY && SIGNING_PUBLIC_KEY_HEX.len() == 64
}

/// Attempt to apply a verified update from the platform heartbeat response.
///
/// `force` bypasses the `has_signing_key()` guard — use only when the platform
/// has explicitly set `force_update: true` in the heartbeat response (one-shot
/// flag gated by workspace-owner auth, so it is no less trusted than the rest
/// of the heartbeat payload).  SHA-256 integrity is always checked regardless.
///
/// Returns:
/// - `Ok(true)`  - update staged, caller should exit for systemd to apply it
/// - `Ok(false)` - update skipped (missing fields, no signing key, etc.)
/// - `Err(..)`   - update failed (download, checksum, or signature error)
pub fn try_apply_update(update: &UpdateInfo, force: bool) -> Result<bool> {
    if !update.available {
        info!("UPDATE SKIP: available=false");
        return Ok(false);
    }

    let download_url = match &update.download_url {
        Some(url) => url,
        None => {
            info!(
                "Update v{} available but no download URL provided - skipping",
                update.latest_version
            );
            return Ok(false);
        }
    };

    let signature_url = match &update.signature_url {
        Some(url) => url,
        None => {
            warn!(
                "Update v{} available but no signature URL - rejecting (unsigned updates are not accepted)",
                update.latest_version
            );
            return Ok(false);
        }
    };

    let expected_sha256 = match &update.sha256 {
        Some(hash) => hash,
        None => {
            warn!(
                "Update v{} available but no SHA-256 hash - skipping",
                update.latest_version
            );
            return Ok(false);
        }
    };

    if !has_signing_key() {
        if force {
            warn!(
                "UPDATE FORCE: No signing key compiled — skipping Ed25519 verification. \
                 SHA-256 integrity is still checked. This was explicitly authorised by \
                 the workspace owner via the platform."
            );
        } else {
            warn!(
                "UPDATE SKIP: No signing key compiled into this build (key_hex_len={}). \
                 Rebuild with CONNLOG_SIGNING_PUBLIC_KEY=<hex> to enable auto-updates.",
                SIGNING_PUBLIC_KEY_HEX.len()
            );
            return Ok(false);
        }
    }

    info!(
        "UPDATE: Signing key present (first 8 chars: {}...)",
        &SIGNING_PUBLIC_KEY_HEX[..8]
    );

    let current_version = env!("CARGO_PKG_VERSION");
    if update.latest_version == current_version {
        info!("UPDATE SKIP: already running v{}", current_version);
        return Ok(false);
    }

    // Reject version downgrades (prevents rollback attacks)
    if !is_version_upgrade(current_version, &update.latest_version) {
        warn!(
            "UPDATE: Rejecting downgrade from v{} to v{} - only upgrades are allowed",
            current_version, update.latest_version
        );
        return Ok(false);
    }

    info!(
        "UPDATE: v{} → v{} available, downloading...",
        current_version, update.latest_version
    );

    // Separate download client: no auth headers, follows redirects (GitHub CDN),
    // longer timeout for large binary downloads.
    let dl_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("Failed to create download client")?;

    stage_verified_update(
        &dl_client,
        download_url,
        signature_url,
        expected_sha256,
        &update.latest_version,
        force && !has_signing_key(),
    )?;

    Ok(true)
}

// ── Shared low-level primitives ─────────────────────────────────

/// Hard upper bound on the size of an agent binary we'll accept (50 MB).
/// Real binaries are ~5–10 MB; this bound prevents an attacker (or a broken
/// CDN) from forcing the agent to buffer arbitrary amounts of data into
/// memory before the SHA-256 / Ed25519 checks reject it.
const MAX_BINARY_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum size of a checksum file. sha256sum format is `<64 hex>  <filename>\n`,
/// so a few hundred bytes is more than enough.
const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;

/// SECURITY: Reject any non-HTTPS URL handed to us by the platform or used in
/// release metadata. The Ed25519 signature already protects integrity, but
/// requiring HTTPS prevents trivial passive observation of which version each
/// agent is downloading and rules out an entire class of MITM tampering before
/// we even start streaming bytes.
fn require_https(url: &str, what: &str) -> Result<()> {
    if !url.starts_with("https://") {
        anyhow::bail!("Refusing to fetch {} from non-HTTPS URL: {}", what, url);
    }
    Ok(())
}

/// Download binary bytes from a URL. Uses a long timeout for large binaries.
fn download_binary(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>> {
    require_https(url, "agent binary")?;

    let mut response = client
        .get(url)
        .send()
        .context("Failed to download binary")?
        .error_for_status()
        .context("Binary download returned HTTP error")?;

    // Reject up-front when the server tells us the body is too big. This is
    // advisory (Content-Length can be missing or lie) — the streaming read
    // below is the actual enforcement.
    if let Some(len) = response.content_length() {
        if len > MAX_BINARY_BYTES {
            anyhow::bail!(
                "Binary download too large: server reported {} bytes (max {})",
                len,
                MAX_BINARY_BYTES
            );
        }
    }

    let mut data = Vec::with_capacity(8 * 1024 * 1024);
    let mut limited = std::io::Read::take(&mut response, MAX_BINARY_BYTES + 1);
    std::io::Read::read_to_end(&mut limited, &mut data).context("Failed to read binary body")?;

    if data.len() as u64 > MAX_BINARY_BYTES {
        anyhow::bail!(
            "Binary download exceeded {} byte cap before EOF - aborting",
            MAX_BINARY_BYTES
        );
    }

    if data.len() < 100_000 {
        anyhow::bail!(
            "Downloaded file is suspiciously small ({} bytes) - aborting",
            data.len()
        );
    }

    Ok(data)
}

/// Download the Ed25519 signature file (must be exactly 64 bytes).
fn download_signature(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>> {
    require_https(url, "update signature")?;

    let sig = client
        .get(url)
        .send()
        .context("Failed to download update signature")?
        .error_for_status()
        .context("Signature download returned HTTP error")?
        .bytes()
        .context("Failed to read signature body")?
        .to_vec();

    if sig.len() != 64 {
        anyhow::bail!(
            "Invalid signature size ({} bytes, expected 64) - aborting",
            sig.len()
        );
    }

    Ok(sig)
}

/// Download and extract the leading hex digest from a `.sha256` checksum file.
/// Expected format: `"<hex>  <filename>\n"` (sha256sum-compatible).
fn download_sha256(client: &reqwest::blocking::Client, url: &str) -> Result<String> {
    require_https(url, "checksum file")?;

    let mut response = client
        .get(url)
        .send()
        .context("Failed to download checksum file")?
        .error_for_status()
        .context("Checksum download returned HTTP error")?;

    // Bound the read so a malformed/oversized checksum file can't blow up RAM.
    let mut buf = Vec::new();
    let mut limited = std::io::Read::take(&mut response, MAX_CHECKSUM_BYTES + 1);
    std::io::Read::read_to_end(&mut limited, &mut buf).context("Failed to read checksum body")?;

    if buf.len() as u64 > MAX_CHECKSUM_BYTES {
        anyhow::bail!(
            "Checksum file exceeded {} byte cap - aborting",
            MAX_CHECKSUM_BYTES
        );
    }

    let text = String::from_utf8(buf).context("Checksum file is not valid UTF-8")?;

    let hex = text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty checksum file"))?
        .to_string();

    if hex.len() != 64 {
        anyhow::bail!("Invalid checksum format (length {}): {}", hex.len(), hex);
    }

    Ok(hex)
}

/// Compute the SHA-256 digest of `data` and verify it matches `expected_hex`.
/// Returns the `Digest` on success (needed to verify the Ed25519 signature).
fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<Digest> {
    let actual = digest::digest(&digest::SHA256, data);
    let actual_hex = hex_encode(actual.as_ref());

    if actual_hex != expected_hex.to_lowercase() {
        anyhow::bail!(
            "SHA-256 MISMATCH\n  expected: {}\n  actual:   {}\n  Rejecting update.",
            expected_hex,
            actual_hex
        );
    }

    Ok(actual)
}

/// Verify the Ed25519 signature over the SHA-256 hash of the binary.
///
/// The signature covers `hash.as_ref()` (the 32-byte digest), NOT the raw binary.
/// This matches the release signing process.
fn verify_ed25519(hash: &Digest, sig_bytes: &[u8]) -> Result<()> {
    let public_key_bytes =
        hex_decode(SIGNING_PUBLIC_KEY_HEX).context("Invalid compiled-in public key hex")?;

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);

    public_key.verify(hash.as_ref(), sig_bytes).map_err(|_| {
        anyhow::anyhow!(
            "Ed25519 SIGNATURE VERIFICATION FAILED - rejecting update. \
                 This could indicate a tampered binary or mismatched signing key."
        )
    })
}

/// Write `data` to `path`, set executable permissions (0o755).
/// Performs a write to `path.new` then atomically renames to `path`.
fn atomic_replace(data: &[u8], path: &str) -> Result<()> {
    let tmp = format!("{}.new", path);

    fs::write(&tmp, data)
        .with_context(|| format!("Failed to write {}. Are you running as root?", tmp))?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&tmp)
            .with_context(|| format!("Failed to read metadata for {}", tmp))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp, perms)
            .with_context(|| format!("Failed to set permissions on {}", tmp))?;
    }

    fs::rename(&tmp, path).with_context(|| format!("Failed to rename {} → {}", tmp, path))?;

    Ok(())
}

// ── Daemon update path (stage for systemd ExecStopPost) ─────────

/// Download, verify (SHA-256 + Ed25519), and stage a new binary.
///
/// The staged binary is written to `/run/connlog/connlog-agent-new` and an update
/// marker to `/run/connlog/.update_requested`. The caller (main loop) then exits
/// cleanly so systemd's ExecStopPost handler can atomically replace the binary and
/// restart the service.
///
/// `client` should have a long timeout (≥120s) suitable for large binary downloads.
fn stage_verified_update(
    client: &reqwest::blocking::Client,
    download_url: &str,
    signature_url: &str,
    expected_sha256: &str,
    version: &str,
    skip_ed25519: bool,
) -> Result<()> {
    // 1. Download binary
    let binary_data = download_binary(client, download_url)?;
    info!("UPDATE: Downloaded {} bytes", binary_data.len());

    // 2. Verify SHA-256 (always — this is the last integrity check when skip_ed25519 is true)
    let hash = verify_sha256(&binary_data, expected_sha256)?;
    info!("UPDATE: SHA-256 checksum verified ✓");

    if skip_ed25519 {
        warn!(
            "UPDATE: Ed25519 verification SKIPPED (force-update mode, no signing key compiled in)"
        );
    } else {
        // 3. Download Ed25519 signature
        let sig_data = download_signature(client, signature_url)?;

        // 4. Verify Ed25519 signature
        verify_ed25519(&hash, &sig_data)?;
        info!("UPDATE: Ed25519 signature verified ✓");
    }

    // 5. Write staged binary
    fs::write(STAGED_BINARY, &binary_data).context("Failed to write staged binary")?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(STAGED_BINARY)
            .context("Failed to read staged binary metadata")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(STAGED_BINARY, perms)
            .context("Failed to set staged binary permissions")?;
    }

    // 6. Write update marker
    let marker = format!("version={}\n", version);
    fs::write(UPDATE_MARKER, marker).context("Failed to write update marker")?;

    info!(
        "UPDATE: Binary staged at {} and marker written. \
         Exiting for supervisor to complete the update.",
        STAGED_BINARY
    );

    Ok(())
}

// ── GitHub release checking ─────────────────────────────────────

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Fetch the latest release metadata from GitHub and check whether a newer version
/// is available for the current OS/arch.
///
/// Returns `None` if the latest release is a draft/prerelease, is the same version
/// as the running binary, or is a downgrade.
fn fetch_github_release_if_newer(
    client: &reqwest::blocking::Client,
) -> Result<Option<(String, GitHubRelease)>> {
    let release: GitHubRelease = client
        .get(GITHUB_RELEASE_URL)
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("Failed to fetch latest release from GitHub")?
        .error_for_status()
        .context("GitHub API returned an error")?
        .json()
        .context("Failed to parse GitHub release JSON")?;

    if release.draft || release.prerelease {
        return Ok(None);
    }

    let current_version = env!("CARGO_PKG_VERSION");
    let latest_version = release.tag_name.trim_start_matches('v').to_string();

    if latest_version == current_version || !is_version_upgrade(current_version, &latest_version) {
        return Ok(None);
    }

    Ok(Some((latest_version, release)))
}

/// Find the binary, signature, and checksum assets for the current OS/arch.
fn find_release_assets<'a>(
    release: &'a GitHubRelease,
    binary_name: &str,
    sig_name: &str,
    sha256_name: &str,
) -> Result<(&'a GitHubAsset, &'a GitHubAsset, &'a GitHubAsset)> {
    let binary_asset = release
        .assets
        .iter()
        .find(|a| a.name == binary_name)
        .ok_or_else(|| {
            let available = release
                .assets
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!(
                "No binary found for {} in release. Available assets: {}",
                binary_name,
                available
            )
        })?;

    let sig_asset = release
        .assets
        .iter()
        .find(|a| a.name == sig_name)
        .ok_or_else(|| anyhow::anyhow!("No signature file ({}) found in release", sig_name))?;

    let sha256_asset = release
        .assets
        .iter()
        .find(|a| a.name == sha256_name)
        .ok_or_else(|| anyhow::anyhow!("No checksum file ({}) found in release", sha256_name))?;

    Ok((binary_asset, sig_asset, sha256_asset))
}

/// Build the asset names for the current OS/arch from a release tag.
fn asset_names(tag_name: &str) -> (String, String, String) {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let binary_name = format!("connlog-agent-{}-{}-{}", tag_name, os, arch);
    let sig_name = format!("{}.sig", binary_name);
    let sha256_name = format!("{}.sha256", binary_name);
    (binary_name, sig_name, sha256_name)
}

/// Periodically check GitHub releases for a newer version and stage an update.
///
/// This runs independently of the platform heartbeat update mechanism.
/// Designed for automatic background use (every 5 minutes from the main loop).
///
/// Returns:
/// - `Ok(true)`  - update staged, caller should exit for systemd to apply it
/// - `Ok(false)` - no update available or skipped
/// - `Err(..)`   - check or download failed
///
/// NOTE: As of v0.4.x the agent no longer calls this on a timer — updates are
/// delivered exclusively through the platform heartbeat response. This function
/// is retained as a manual / break-glass fallback (e.g. when the platform is
/// unreachable for an extended period and an operator wants to force-pull from
/// upstream). `#[allow(dead_code)]` keeps it linked without warnings.
#[allow(dead_code)]
pub fn check_github_for_update() -> Result<bool> {
    if !has_signing_key() {
        return Ok(false);
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create HTTP client")?;

    let (latest_version, release) = match fetch_github_release_if_newer(&client)? {
        Some(r) => r,
        None => return Ok(false),
    };

    info!(
        "UPDATE (GitHub): v{} → v{} available, preparing update...",
        env!("CARGO_PKG_VERSION"),
        latest_version
    );

    let (binary_name, sig_name, sha256_name) = asset_names(&release.tag_name);
    let (binary_asset, sig_asset, sha256_asset) =
        find_release_assets(&release, &binary_name, &sig_name, &sha256_name)?;

    // Download client: no auth headers, long timeout for binary download
    let dl_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create download client")?;

    let expected_sha256 = download_sha256(&dl_client, &sha256_asset.browser_download_url)?;

    stage_verified_update(
        &dl_client,
        &binary_asset.browser_download_url,
        &sig_asset.browser_download_url,
        &expected_sha256,
        &latest_version,
        false,
    )?;

    Ok(true)
}

/// Run a manual update check against GitHub and apply directly.
///
/// Intended for interactive `connlog-agent --update` usage (as root).
/// Unlike the daemon update path, this writes directly to the installed binary
/// location and optionally restarts the service — no staging or ExecStopPost involved.
pub fn run_manual_update() -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    println!("ConnLog Agent v{}", current_version);
    println!("Checking for updates...");

    if !has_signing_key() {
        anyhow::bail!(
            "This build does not have a signing key compiled in. \
             Manual update requires a CI-built binary with CONNLOG_SIGNING_PUBLIC_KEY."
        );
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create HTTP client")?;

    let (latest_version, release) = match fetch_github_release_if_newer(&client)? {
        Some(r) => r,
        None => {
            // Distinguish "draft/prerelease" from "already up to date"
            println!("Already up to date (or latest release is a draft/prerelease).");
            return Ok(());
        }
    };

    println!("Latest version: v{}", latest_version);
    println!(
        "Update available: v{} → v{}",
        current_version, latest_version
    );

    let (binary_name, sig_name, sha256_name) = asset_names(&release.tag_name);
    let (binary_asset, sig_asset, sha256_asset) =
        find_release_assets(&release, &binary_name, &sig_name, &sha256_name)?;

    println!("Downloading {}...", binary_name);

    let dl_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create download client")?;

    // Download binary
    let binary_data = download_binary(&dl_client, &binary_asset.browser_download_url)?;
    println!("Downloaded {} bytes", binary_data.len());

    // Download SHA-256 checksum
    let expected_sha256 = download_sha256(&dl_client, &sha256_asset.browser_download_url)?;

    // Verify SHA-256
    let hash = verify_sha256(&binary_data, &expected_sha256)?;
    println!("SHA-256 verified ✓");

    // Download Ed25519 signature
    let sig_data = download_signature(&dl_client, &sig_asset.browser_download_url)?;

    // Verify Ed25519 signature
    verify_ed25519(&hash, &sig_data)?;
    println!("Ed25519 signature verified ✓");

    // Atomically replace the installed binary
    atomic_replace(&binary_data, INSTALLED_BINARY)?;
    println!("Binary replaced at {}", INSTALLED_BINARY);

    reload_service_if_active()?;

    println!("\n✓ Updated to v{}", latest_version);
    Ok(())
}

/// Restart the connlog-agent service if it is currently active.
fn reload_service_if_active() -> Result<()> {
    let is_active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "connlog-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if is_active {
        println!("Restarting connlog-agent service...");
        let status = std::process::Command::new("systemctl")
            .args(["restart", "connlog-agent"])
            .status()
            .context("Failed to restart connlog-agent service")?;

        if status.success() {
            println!("Service restarted successfully.");
        } else {
            println!("Warning: systemctl restart returned non-zero exit code.");
            println!("Check with: systemctl status connlog-agent");
        }
    } else {
        println!("connlog-agent service is not running. Start it with:");
        println!("  systemctl start connlog-agent");
    }

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
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("Odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("Invalid hex character"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_version_upgrade() {
        assert!(is_version_upgrade("0.3.6", "0.3.7"));
        assert!(is_version_upgrade("0.3.6", "0.4.0"));
        assert!(is_version_upgrade("0.3.6", "1.0.0"));
        assert!(!is_version_upgrade("0.3.6", "0.3.6"));
        assert!(!is_version_upgrade("0.3.6", "0.3.5"));
        assert!(!is_version_upgrade("0.3.6", "0.2.9"));
        assert!(!is_version_upgrade("0.3.6", "not-a-version"));
    }

    /// Anti-rollback edge cases. These all rejected paths are deliberate —
    /// permitting any of them would either accept a downgrade or accept an
    /// unparseable version (which would then propagate as the agent's reported
    /// version on the next heartbeat).
    #[test]
    fn version_upgrade_edge_cases() {
        // Empty / malformed strings
        assert!(!is_version_upgrade("", "1.0.0"));
        assert!(!is_version_upgrade("1.0.0", ""));
        assert!(
            !is_version_upgrade("1.0", "1.0.0"),
            "two-part version must be rejected"
        );
        assert!(
            !is_version_upgrade("1.0.0", "1.0.0.0"),
            "four-part version must be rejected"
        );
        assert!(
            !is_version_upgrade("v1.0.0", "v1.0.1"),
            "leading 'v' must be rejected by parser"
        );
        assert!(
            !is_version_upgrade("1.0.0-rc1", "1.0.0"),
            "pre-release tags must be rejected"
        );

        // Numeric edge cases
        assert!(is_version_upgrade("0.0.0", "0.0.1"));
        assert!(
            is_version_upgrade("9.9.9", "10.0.0"),
            "major boundary must compare numerically"
        );
        assert!(
            !is_version_upgrade("10.0.0", "9.9.9"),
            "lexicographic compare would say 10<9"
        );
        assert!(
            is_version_upgrade("1.2.3", "1.10.0"),
            "minor must compare numerically (10>2)"
        );
        assert!(
            is_version_upgrade("1.2.9", "1.2.10"),
            "patch must compare numerically (10>9)"
        );
    }

    /// `has_signing_key` gates the entire self-update flow. The placeholder all-zero
    /// key MUST NOT count as a valid key, otherwise unsigned binaries would be
    /// accepted in dev / unsigned builds.
    #[test]
    fn placeholder_signing_key_is_rejected() {
        // We can't override the const at runtime, but we can assert the
        // PLACEHOLDER constant matches the documented sentinel and that
        // has_signing_key()'s behaviour matches whichever build we're in.
        assert_eq!(
            PLACEHOLDER_KEY.len(),
            64,
            "placeholder must be exactly 64 hex chars"
        );
        assert!(
            PLACEHOLDER_KEY.chars().all(|c| c == '0'),
            "placeholder must be all zeros"
        );
        // If signing was compiled in, fine; if not, has_signing_key must be false.
        let key_present =
            SIGNING_PUBLIC_KEY_HEX != PLACEHOLDER_KEY && SIGNING_PUBLIC_KEY_HEX.len() == 64;
        assert_eq!(has_signing_key(), key_present);
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let data = vec![0x01u8, 0xAB, 0xCD, 0xEF];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "01abcdef");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err()); // odd length
    }
}
