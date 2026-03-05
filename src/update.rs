use anyhow::{Context, Result};
use log::{info, warn};
use ring::digest;
use ring::signature;
use serde::Deserialize;
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
/// - `Ok(true)`  - update staged, caller should exit for systemd to apply it
/// - `Ok(false)` - update skipped (missing fields, no signing key, etc.)
/// - `Err(..)`   - update failed (download, checksum, or signature error)
pub fn try_apply_update(update: &UpdateInfo) -> Result<bool> {
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
        warn!(
            "UPDATE SKIP: No signing key compiled into this build (key_hex_len={}). \
             Rebuild with CONNLOG_SIGNING_PUBLIC_KEY=<hex> to enable auto-updates.",
            SIGNING_PUBLIC_KEY_HEX.len()
        );
        return Ok(false);
    }

    info!("UPDATE: Signing key present (first 8 chars: {}...)", &SIGNING_PUBLIC_KEY_HEX[..8]);

    // Skip if we're already running this version or a newer one
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
            "UPDATE: Downloaded file is suspiciously small ({} bytes) - aborting",
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
            "UPDATE: Invalid signature size ({} bytes, expected 64) - aborting",
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
                "UPDATE: Ed25519 SIGNATURE VERIFICATION FAILED - rejecting update. \
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

// ── GitHub release checking ─────────────────────────────────────

const GITHUB_RELEASE_URL: &str =
    "https://api.github.com/repos/connlog/connlog-agent/releases/latest";
const INSTALLED_BINARY: &str = "/usr/local/bin/connlog-agent";

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

/// Periodically check GitHub releases for a newer version and stage an update.
/// This runs independently of the platform heartbeat update mechanism.
/// Designed for automatic background use (every 5 minutes from the main loop).
///
/// Returns:
/// - `Ok(true)`  - update staged, caller should exit for systemd to apply it
/// - `Ok(false)` - no update available or skipped
/// - `Err(..)`   - check or download failed
pub fn check_github_for_update() -> Result<bool> {
    if !has_signing_key() {
        return Ok(false);
    }

    let current_version = env!("CARGO_PKG_VERSION");

    // Fetch latest release from GitHub
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create HTTP client")?;

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
        return Ok(false);
    }

    let latest_version = release.tag_name.trim_start_matches('v');

    if latest_version == current_version {
        return Ok(false);
    }

    if !is_version_upgrade(current_version, latest_version) {
        return Ok(false);
    }

    info!(
        "UPDATE (GitHub): v{} → v{} available, preparing update...",
        current_version, latest_version
    );

    // Find assets for our architecture
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    let binary_name = format!("connlog-agent-{}-{}-{}", release.tag_name, os, arch);
    let sig_name = format!("{}.sig", binary_name);
    let sha256_name = format!("{}.sha256", binary_name);

    let binary_asset = release
        .assets
        .iter()
        .find(|a| a.name == binary_name)
        .ok_or_else(|| {
            anyhow::anyhow!("No binary found for {}-{} in release", os, arch)
        })?;

    let sig_asset = release
        .assets
        .iter()
        .find(|a| a.name == sig_name)
        .ok_or_else(|| anyhow::anyhow!("No signature file found in release"))?;

    let sha256_asset = release
        .assets
        .iter()
        .find(|a| a.name == sha256_name)
        .ok_or_else(|| anyhow::anyhow!("No checksum file found in release"))?;

    // Download and parse SHA-256 checksum
    let download_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create download client")?;

    let sha256_text = download_client
        .get(&sha256_asset.browser_download_url)
        .send()
        .context("Failed to download checksum file")?
        .error_for_status()?
        .text()
        .context("Failed to read checksum body")?;

    let expected_sha256 = sha256_text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty checksum file"))?;

    if expected_sha256.len() != 64 {
        anyhow::bail!("Invalid checksum format (length {})", expected_sha256.len());
    }

    // Use the existing verified update pipeline (download + SHA-256 + Ed25519 + stage)
    perform_verified_update(
        &binary_asset.browser_download_url,
        &sig_asset.browser_download_url,
        expected_sha256,
        latest_version,
    )?;

    Ok(true)
}

/// Run a manual update check against GitHub and apply directly.
/// Intended for interactive `connlog-agent --update` usage (as root).
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

    // ── 1. Fetch latest release from GitHub ─────────────────────
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create HTTP client")?;

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
        println!("Latest release is a draft/prerelease - skipping.");
        return Ok(());
    }

    let latest_version = release.tag_name.trim_start_matches('v');
    println!("Latest version: v{}", latest_version);

    if latest_version == current_version {
        println!("Already up to date.");
        return Ok(());
    }

    if !is_version_upgrade(current_version, latest_version) {
        println!(
            "Current version v{} is already >= v{}. Nothing to do.",
            current_version, latest_version
        );
        return Ok(());
    }

    println!(
        "Update available: v{} → v{}",
        current_version, latest_version
    );

    // ── 2. Find assets for our architecture ─────────────────────
    let arch = std::env::consts::ARCH; // "x86_64", "aarch64", etc.
    let os = std::env::consts::OS; // "linux"

    // Asset naming: connlog-agent-v0.3.2-linux-x86_64
    let binary_name = format!(
        "connlog-agent-{}-{}-{}",
        release.tag_name, os, arch
    );
    let sig_name = format!("{}.sig", binary_name);
    let sha256_name = format!("{}.sha256", binary_name);

    let binary_asset = release
        .assets
        .iter()
        .find(|a| a.name == binary_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No binary found for {}-{} in release. Available assets: {}",
                os,
                arch,
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
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

    println!("Downloading {}...", binary_name);

    // ── 3. Download binary ──────────────────────────────────────
    let download_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("connlog-agent")
        .build()
        .context("Failed to create download client")?;

    let binary_data = download_client
        .get(&binary_asset.browser_download_url)
        .send()
        .context("Failed to download binary")?
        .error_for_status()
        .context("Binary download returned HTTP error")?
        .bytes()
        .context("Failed to read binary body")?;

    println!("Downloaded {} bytes", binary_data.len());

    if binary_data.len() < 100_000 {
        anyhow::bail!(
            "Downloaded file is suspiciously small ({} bytes) - aborting",
            binary_data.len()
        );
    }

    // ── 4. Download and parse SHA-256 checksum ──────────────────
    let sha256_text = download_client
        .get(&sha256_asset.browser_download_url)
        .send()
        .context("Failed to download checksum file")?
        .error_for_status()?
        .text()
        .context("Failed to read checksum body")?;

    // Format: "abc123...  connlog-agent-v0.3.2-linux-x86_64\n"
    let expected_sha256 = sha256_text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty checksum file"))?;

    if expected_sha256.len() != 64 {
        anyhow::bail!(
            "Invalid checksum format (length {}): {}",
            expected_sha256.len(),
            expected_sha256
        );
    }

    // ── 5. Verify SHA-256 ───────────────────────────────────────
    let actual_hash = digest::digest(&digest::SHA256, &binary_data);
    let actual_sha256 = hex_encode(actual_hash.as_ref());

    if actual_sha256 != expected_sha256.to_lowercase() {
        anyhow::bail!(
            "SHA-256 MISMATCH\n  expected: {}\n  actual:   {}\n  Rejecting update.",
            expected_sha256,
            actual_sha256
        );
    }
    println!("SHA-256 verified ✓");

    // ── 6. Download and verify Ed25519 signature ────────────────
    let sig_data = download_client
        .get(&sig_asset.browser_download_url)
        .send()
        .context("Failed to download signature")?
        .error_for_status()?
        .bytes()
        .context("Failed to read signature body")?;

    if sig_data.len() != 64 {
        anyhow::bail!(
            "Invalid signature size ({} bytes, expected 64)",
            sig_data.len()
        );
    }

    let public_key_bytes =
        hex_decode(SIGNING_PUBLIC_KEY_HEX).context("Invalid compiled-in public key")?;
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);

    public_key
        .verify(actual_hash.as_ref(), &sig_data)
        .map_err(|_| {
            anyhow::anyhow!(
                "Ed25519 SIGNATURE VERIFICATION FAILED - the binary may be tampered."
            )
        })?;
    println!("Ed25519 signature verified ✓");

    // ── 7. Replace installed binary ─────────────────────────────
    // Write to a temp file first, then rename for atomicity
    let tmp_path = format!("{}.new", INSTALLED_BINARY);

    fs::write(&tmp_path, &binary_data)
        .with_context(|| format!("Failed to write {}. Are you running as root?", tmp_path))?;

    let mut perms = fs::metadata(&tmp_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_path, perms)?;

    fs::rename(&tmp_path, INSTALLED_BINARY)
        .with_context(|| format!("Failed to replace {}", INSTALLED_BINARY))?;

    println!("Binary replaced at {}", INSTALLED_BINARY);

    // ── 8. Restart systemd service if running ───────────────────
    let is_service_active = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "connlog-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if is_service_active {
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

    println!("\n✓ Updated to v{}", latest_version);
    Ok(())
}
