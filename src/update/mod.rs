use anyhow::{Context, Result};
use log::{error, info, warn};
use ring::digest::{self, Digest};
use ring::signature;
use serde::Deserialize;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::heartbeat::UpdateInfo;
use crate::http::{is_transient_http_status, transient_retry_delay};
use crate::install;
use crate::platform::{
    INSTALLED_BINARY, INSTALLED_BINARY_NEW, INSTALLED_BINARY_OLD, SAFE_PATH, STAGED_BINARY,
    STAGED_SIGNATURE, UPDATE_FAILED_NOTE, UPDATE_MARKER,
};

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

const GITHUB_RELEASE_URL: &str = "https://api.github.com/repos/connlog/agent/releases/latest";

/// Returns true if a real signing key is compiled in (not the placeholder).
pub fn has_signing_key() -> bool {
    SIGNING_PUBLIC_KEY_HEX != PLACEHOLDER_KEY && SIGNING_PUBLIC_KEY_HEX.len() == 64
}

/// Attempt to apply a verified update from the platform heartbeat response.
///
/// Every path through here needs a compiled-in signing key, a matching
/// SHA-256, a valid Ed25519 signature and a strictly higher version. The
/// platform's `force_update` flag (its "Force update" button) is logged and
/// otherwise ignored: it once allowed a build without a signing key to install
/// a binary on the strength of a server-supplied hash alone, which is the one
/// thing a signed update pipeline exists to rule out.
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
        error!(
            "UPDATE REFUSED: this build has no signing key compiled in, so no update can be \
             verified (key_hex_len={}). Release builds always carry the key; rebuild with \
             CONNLOG_SIGNING_PUBLIC_KEY=<hex>.",
            SIGNING_PUBLIC_KEY_HEX.len()
        );
        return Ok(false);
    }

    if update.force_update {
        info!("UPDATE: platform marked this update as forced; verification is unchanged");
    }

    info!(
        "UPDATE: Signing key present (first 8 chars: {}...)",
        SIGNING_PUBLIC_KEY_HEX.get(..8).unwrap_or("?")
    );

    let current_version = env!("CARGO_PKG_VERSION");
    if update.latest_version == current_version {
        info!("UPDATE SKIP: already running v{}", current_version);
        return Ok(false);
    }

    // Reject version downgrades (prevents rollback attacks). This is the
    // platform's claim; the root-side apply step checks what the binary
    // itself reports before it is installed.
    if !is_version_upgrade(current_version, &update.latest_version) {
        warn!(
            "UPDATE: Rejecting downgrade from v{} to v{} - only upgrades are allowed",
            current_version, update.latest_version
        );
        return Ok(false);
    }

    if let Some(reason) = recent_apply_failure(&update.latest_version) {
        warn!(
            "UPDATE SKIP: v{} could not be applied earlier ({}); not downloading it again \
             until the note in {} is older than a day",
            update.latest_version, reason, UPDATE_FAILED_NOTE
        );
        return Ok(false);
    }

    info!(
        "UPDATE: v{} → v{} available, downloading...",
        current_version, update.latest_version
    );

    let dl_client = download_client()?;

    stage_verified_update(
        &dl_client,
        download_url,
        signature_url,
        expected_sha256,
        &update.latest_version,
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

/// Longest redirect chain the download clients follow. GitHub's CDN uses one.
const MAX_DOWNLOAD_REDIRECTS: usize = 5;

/// Follow redirects, but only to HTTPS. `require_https` checks the URL we
/// were handed; this keeps a 302 in the middle of the chain from quietly
/// downgrading the rest of it.
fn https_only_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_DOWNLOAD_REDIRECTS {
            return attempt.error("too many redirects while fetching an update artifact");
        }
        if attempt.url().scheme() != "https" {
            return attempt.error("refusing to follow a redirect to a non-HTTPS URL");
        }
        attempt.follow()
    })
}

/// Client for release metadata: short timeout, HTTPS-only redirects.
fn metadata_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(https_only_redirects())
        .user_agent(concat!("connlog-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Failed to create HTTP client")
}

/// Client for binaries: no auth headers, long timeout, HTTPS-only redirects.
fn download_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(https_only_redirects())
        .user_agent(concat!("connlog-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Failed to create download client")
}

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

const TRANSIENT_DOWNLOAD_ATTEMPTS: u32 = 3;

/// GET with short retries on gateway/transient failures. Used for update
/// artifacts only — heartbeats have their own retry path in `http.rs`.
fn get_with_transient_retries(
    client: &reqwest::blocking::Client,
    url: &str,
    what: &str,
) -> Result<reqwest::blocking::Response> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=TRANSIENT_DOWNLOAD_ATTEMPTS {
        match client.get(url).send() {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return Ok(response);
                }
                if is_transient_http_status(status.as_u16())
                    && attempt < TRANSIENT_DOWNLOAD_ATTEMPTS
                {
                    warn!(
                        "Transient HTTP {} while downloading {} (attempt {}/{})",
                        status, what, attempt, TRANSIENT_DOWNLOAD_ATTEMPTS
                    );
                    std::thread::sleep(transient_retry_delay(attempt));
                    continue;
                }
                return response
                    .error_for_status()
                    .with_context(|| format!("{} download returned HTTP error", what));
            }
            Err(err) if attempt < TRANSIENT_DOWNLOAD_ATTEMPTS => {
                warn!(
                    "Failed to download {} (attempt {}/{}): {}",
                    what, attempt, TRANSIENT_DOWNLOAD_ATTEMPTS, err
                );
                std::thread::sleep(transient_retry_delay(attempt));
                last_err = Some(err.into());
            }
            Err(err) => return Err(err).context(format!("Failed to download {}", what)),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Failed to download {}", what)))
}

/// Download binary bytes from a URL. Uses a long timeout for large binaries.
fn download_binary(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>> {
    require_https(url, "agent binary")?;

    let mut response = get_with_transient_retries(client, url, "agent binary")?;

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

    let sig = get_with_transient_retries(client, url, "update signature")?
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

    let mut response = get_with_transient_retries(client, url, "checksum file")?;

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
/// The staged binary is written to `/run/connlog/connlog-agent-new`, its
/// signature next to it, and an update marker to `/run/connlog/.update_requested`.
/// The caller (main loop) then exits cleanly so systemd's ExecStopPost handler
/// can run `connlog-agent apply-staged-update` as root, which verifies the
/// staged bytes again before they replace the live binary.
///
/// `client` should have a long timeout (≥120s) suitable for large binary downloads.
fn stage_verified_update(
    client: &reqwest::blocking::Client,
    download_url: &str,
    signature_url: &str,
    expected_sha256: &str,
    version: &str,
) -> Result<()> {
    // 1. Download binary
    let binary_data = download_binary(client, download_url)?;
    info!("UPDATE: Downloaded {} bytes", binary_data.len());

    // 2. Verify SHA-256
    let hash = verify_sha256(&binary_data, expected_sha256)?;
    info!("UPDATE: SHA-256 checksum verified ✓");

    // 3. Download Ed25519 signature
    let sig_data = download_signature(client, signature_url)?;

    // 4. Verify Ed25519 signature
    verify_ed25519(&hash, &sig_data)?;
    info!("UPDATE: Ed25519 signature verified ✓");

    // 5. Write staged binary and its signature. The root-side apply step
    //    verifies them again with its own key: this directory is writable by
    //    the service account, so nothing in it is trusted on arrival.
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
    fs::write(STAGED_SIGNATURE, &sig_data).context("Failed to write staged signature")?;

    // 6. Write update marker
    let marker = format!("version={}\nsha256={}\n", version, expected_sha256);
    fs::write(UPDATE_MARKER, marker).context("Failed to write update marker")?;

    info!(
        "UPDATE: Binary staged at {} and marker written. \
         Exiting for supervisor to complete the update.",
        STAGED_BINARY
    );

    Ok(())
}

// ── Root-side apply (run by ExecStopPost) ────────────────────────

/// How long `--version` on the staged binary may take. A real binary answers
/// in milliseconds; one that hangs is not one we install.
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a failed apply keeps the agent from downloading the same version
/// again. The note lives in the state directory, so it survives the restart.
const APPLY_FAILURE_COOLDOWN: Duration = Duration::from_secs(24 * 60 * 60);

/// Apply the update the unprivileged agent staged in `/run/connlog`.
///
/// Runs as root from the systemd `ExecStopPost` hook, using the binary that is
/// currently installed. The hook used to copy the staged file into place and
/// execute it on trust; the staging directory is writable by the service
/// account, so anything running as that account could have put its own binary
/// there and had root execute it. Now nothing reaches `/usr/local/bin` until
/// this step has, with its own compiled-in key, verified the Ed25519 signature
/// over the staged bytes, confirmed the staged binary reports a strictly higher
/// version than this one, and checked that the live binary is still root-owned.
/// The swap is a same-filesystem rename, the previous binary stays reachable as
/// a hard link, and a failed service refresh rolls back before returning.
pub fn apply_staged_update() -> Result<()> {
    if !crate::platform::is_admin() {
        anyhow::bail!(
            "apply-staged-update must run as root (the systemd ExecStopPost hook runs it)"
        );
    }
    let claimed_version = read_marker_version();

    match apply_staged_update_inner() {
        Ok(Some(version)) => {
            let _ = fs::remove_file(UPDATE_FAILED_NOTE);
            println!("ConnLog: updated to v{version}");
            Ok(())
        }
        Ok(None) => {
            let _ = fs::remove_file(UPDATE_FAILED_NOTE);
            println!("ConnLog: staged binary is already the installed version; nothing to apply");
            Ok(())
        }
        Err(err) => {
            note_apply_failure(claimed_version.as_deref().unwrap_or("unknown"), &err);
            eprintln!("ConnLog: update not applied: {err:#}");
            Err(err)
        }
    }
}

/// `Ok(Some(version))` when the live binary was replaced, `Ok(None)` when the
/// staged binary is the version already installed.
fn apply_staged_update_inner() -> Result<Option<String>> {
    if !has_signing_key() {
        anyhow::bail!(
            "this build has no signing key compiled in; refusing to apply a staged binary"
        );
    }

    let staged = read_bounded(STAGED_BINARY, MAX_BINARY_BYTES)?;
    if staged.len() < 100_000 {
        anyhow::bail!(
            "staged binary is suspiciously small ({} bytes)",
            staged.len()
        );
    }
    let sig = fs::read(STAGED_SIGNATURE).context("Failed to read the staged signature")?;
    if sig.len() != 64 {
        anyhow::bail!("staged signature has {} bytes, expected 64", sig.len());
    }

    // Authenticity and integrity in one check: the signature covers the digest.
    let hash = digest::digest(&digest::SHA256, &staged);
    verify_ed25519(&hash, &sig)?;

    assert_live_binary_trusted()?;

    // The verified bytes go next to the live binary (same filesystem), owned
    // by root and executable, before anything runs them.
    let _ = fs::remove_file(INSTALLED_BINARY_NEW);
    write_root_executable(INSTALLED_BINARY_NEW, &staged)?;

    let new_version = match probe_binary_version(INSTALLED_BINARY_NEW) {
        Ok(version) => version,
        Err(err) => {
            let _ = fs::remove_file(INSTALLED_BINARY_NEW);
            return Err(err);
        }
    };

    let current_version = env!("CARGO_PKG_VERSION");
    if new_version == current_version {
        let _ = fs::remove_file(INSTALLED_BINARY_NEW);
        return Ok(None);
    }
    if !is_version_upgrade(current_version, &new_version) {
        let _ = fs::remove_file(INSTALLED_BINARY_NEW);
        anyhow::bail!(
            "refusing to replace v{current_version} with v{new_version}: only upgrades are applied"
        );
    }

    // Keep the previous binary reachable for rollback. A hard link on the same
    // filesystem survives the rename below and costs no copy.
    let _ = fs::remove_file(INSTALLED_BINARY_OLD);
    fs::hard_link(INSTALLED_BINARY, INSTALLED_BINARY_OLD)
        .context("Failed to keep a rollback link to the previous binary")?;
    fs::rename(INSTALLED_BINARY_NEW, INSTALLED_BINARY)
        .context("Failed to move the verified binary into place")?;

    // The new binary refreshes the unit from its own embedded template.
    match refresh_service_via(INSTALLED_BINARY) {
        Ok(()) => {
            let _ = fs::remove_file(INSTALLED_BINARY_OLD);
            Ok(Some(new_version))
        }
        Err(err) => match fs::rename(INSTALLED_BINARY_OLD, INSTALLED_BINARY) {
            Ok(()) => Err(err.context(
                "service refresh failed after the swap; rolled back to the previous binary",
            )),
            Err(rollback_err) => Err(err.context(format!(
                "service refresh failed and rollback also failed ({rollback_err}); \
                 run: sudo connlog-agent refresh-service --restart"
            ))),
        },
    }
}

/// The live binary must be owned by root and writable by root only. Root is
/// about to execute it (and its successor) from the ExecStopPost hook; a
/// binary another account could have written is not one root should run.
pub fn assert_live_binary_trusted() -> Result<()> {
    assert_root_owned_executable(Path::new(INSTALLED_BINARY))
}

#[cfg(unix)]
fn assert_root_owned_executable(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    if meta.uid() != 0 {
        anyhow::bail!(
            "{} is owned by uid {} rather than root; refusing to run it as root. \
             Fix with: sudo chown root:root {}",
            path.display(),
            meta.uid(),
            path.display()
        );
    }
    if meta.mode() & 0o022 != 0 {
        anyhow::bail!(
            "{} is writable by group or others (mode {:o}); refusing to run it as root. \
             Fix with: sudo chmod 0755 {}",
            path.display(),
            meta.mode() & 0o7777,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_root_owned_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Write `data` to `path` as a root-owned 0755 executable.
fn write_root_executable(path: &str, data: &[u8]) -> Result<()> {
    fs::write(path, data).with_context(|| format!("Failed to write {}", path))?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {}", path))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)
            .with_context(|| format!("Failed to set permissions on {}", path))?;
        std::os::unix::fs::chown(path, Some(0), Some(0))
            .with_context(|| format!("Failed to set root ownership on {}", path))?;
    }
    Ok(())
}

/// Read a file into memory, refusing anything larger than `max` bytes.
fn read_bounded(path: &str, max: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path).with_context(|| format!("Failed to open {}", path))?;
    let mut data = Vec::new();
    let mut limited = std::io::Read::take(file, max + 1);
    std::io::Read::read_to_end(&mut limited, &mut data)
        .with_context(|| format!("Failed to read {}", path))?;
    if data.len() as u64 > max {
        anyhow::bail!("{} exceeds the {} byte cap", path, max);
    }
    Ok(data)
}

/// Run `<binary> --version` and return the version it reports.
///
/// Exec is the only reliable way to learn what a binary is. The signature has
/// already been verified at this point, so what runs here is a release we
/// built; the check is that it is the release we were told it is, for this
/// architecture, and newer than what is installed.
fn probe_binary_version(path: &str) -> Result<String> {
    let mut child = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("Failed to execute {} --version", path))?;

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < VERSION_PROBE_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!(
                    "{} --version did not finish within {:?}",
                    path,
                    VERSION_PROBE_TIMEOUT
                );
            }
            Err(err) => return Err(err).context("Failed to wait for --version"),
        }
    };
    if !status.success() {
        anyhow::bail!("{} --version exited with {}", path, status);
    }

    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        let mut limited = std::io::Read::take(&mut out, 4 * 1024);
        std::io::Read::read_to_string(&mut limited, &mut stdout)
            .context("--version output is not UTF-8")?;
    }
    parse_version_output(&stdout).ok_or_else(|| {
        anyhow::anyhow!(
            "{} --version printed something unexpected: {:?}",
            path,
            stdout
        )
    })
}

/// `connlog-agent 1.19.0` → `1.19.0`. Accepts only `MAJOR.MINOR.PATCH`.
fn parse_version_output(output: &str) -> Option<String> {
    let candidate = output.split_whitespace().last()?.trim_start_matches('v');
    let mut parts = candidate.split('.');
    let well_formed = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }) && parts.next().is_none();
    well_formed.then(|| candidate.to_string())
}

fn refresh_service_via(binary: &str) -> Result<()> {
    let status = Command::new(binary)
        .arg("refresh-service")
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("Failed to run {} refresh-service", binary))?;
    if !status.success() {
        anyhow::bail!("{} refresh-service exited with {}", binary, status);
    }
    Ok(())
}

fn read_marker_version() -> Option<String> {
    let text = fs::read_to_string(UPDATE_MARKER).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("version="))
        .map(|v| v.trim().to_string())
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Record that `version` could not be applied, so the agent stops downloading
/// it on every heartbeat. Best effort: a note that cannot be written only
/// costs repeated downloads, never correctness.
fn note_apply_failure(version: &str, err: &anyhow::Error) {
    let reason: String = format!("{err:#}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(300)
        .collect();
    let note = format!(
        "version={}\nat={}\nreason={}\n",
        version,
        unix_now_secs(),
        reason
    );
    if let Err(write_err) = fs::write(UPDATE_FAILED_NOTE, note) {
        eprintln!(
            "ConnLog: could not record the failed update in {}: {}",
            UPDATE_FAILED_NOTE, write_err
        );
        return;
    }
    #[cfg(unix)]
    {
        // The state directory belongs to the service account; the note is
        // root's, so make it readable for the agent that checks it.
        if let Ok(meta) = fs::metadata(UPDATE_FAILED_NOTE) {
            let mut perms = meta.permissions();
            perms.set_mode(0o644);
            let _ = fs::set_permissions(UPDATE_FAILED_NOTE, perms);
        }
    }
}

/// The reason a recent apply of `version` failed, if the note is younger than
/// the cooldown.
fn recent_apply_failure(version: &str) -> Option<String> {
    let text = fs::read_to_string(UPDATE_FAILED_NOTE).ok()?;
    parse_apply_failure(&text, version, unix_now_secs())
}

fn parse_apply_failure(note: &str, version: &str, now: u64) -> Option<String> {
    let field = |key: &str| {
        note.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };
    if field("version=")? != version {
        return None;
    }
    let at: u64 = field("at=")?.parse().ok()?;
    if now.saturating_sub(at) > APPLY_FAILURE_COOLDOWN.as_secs() {
        return None;
    }
    Some(field("reason=").unwrap_or("no reason recorded").to_string())
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

    let client = metadata_client()?;

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

    let dl_client = download_client()?;

    let expected_sha256 = download_sha256(&dl_client, &sha256_asset.browser_download_url)?;

    stage_verified_update(
        &dl_client,
        &binary_asset.browser_download_url,
        &sig_asset.browser_download_url,
        &expected_sha256,
        &latest_version,
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

    let client = metadata_client()?;

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

    let dl_client = download_client()?;

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

    // What the binary says it is has to match what the release says it is,
    // and it has to run on this machine at all, before it replaces anything.
    assert_live_binary_trusted()?;
    let _ = fs::remove_file(INSTALLED_BINARY_NEW);
    write_root_executable(INSTALLED_BINARY_NEW, &binary_data)?;
    let reported = match probe_binary_version(INSTALLED_BINARY_NEW) {
        Ok(version) => version,
        Err(err) => {
            let _ = fs::remove_file(INSTALLED_BINARY_NEW);
            return Err(err);
        }
    };
    if reported != latest_version {
        let _ = fs::remove_file(INSTALLED_BINARY_NEW);
        anyhow::bail!(
            "Downloaded binary reports v{} but the release is v{}; refusing to install it",
            reported,
            latest_version
        );
    }
    println!("Binary reports v{} ✓", reported);

    let previous_binary = fs::read(INSTALLED_BINARY)
        .with_context(|| format!("Failed to read existing binary at {}", INSTALLED_BINARY))?;

    // Atomically replace the installed binary
    fs::rename(INSTALLED_BINARY_NEW, INSTALLED_BINARY)
        .with_context(|| format!("Failed to move the verified binary to {}", INSTALLED_BINARY))?;
    println!("Binary replaced at {}", INSTALLED_BINARY);

    let restart_service = service_is_active();
    if let Err(err) = install::refresh_service(restart_service) {
        let rollback_result = atomic_replace(&previous_binary, INSTALLED_BINARY);
        if let Err(rollback_err) = rollback_result {
            anyhow::bail!(
                "Service refresh failed after binary replacement: {err}. \
                 Rollback also failed: {rollback_err}. \
                 Run: sudo connlog-agent refresh-service --restart"
            );
        }
        anyhow::bail!(
            "Service refresh failed after binary replacement: {err}. \
             Rolled back to the previous binary. \
             Run: sudo connlog-agent refresh-service --restart"
        );
    }

    println!("\n✓ Updated to v{}", latest_version);
    Ok(())
}

fn service_is_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "connlog-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

    // ── require_https ───────────────────────────────────────────
    //
    // SECURITY: All update-path fetches (binary, signature, checksum) must use
    // HTTPS. A non-HTTPS URL means an attacker with network access could serve
    // a malicious binary *before* the Ed25519 / SHA-256 checks run. Tests here
    // pin that guard so a careless refactor can't silently drop it.

    #[test]
    fn require_https_accepts_https_url() {
        assert!(
            require_https("https://example.com/agent", "binary").is_ok(),
            "HTTPS URLs must be accepted"
        );
    }

    #[test]
    fn require_https_rejects_http_url() {
        let err = require_https("http://example.com/agent", "binary").unwrap_err();
        assert!(
            err.to_string().contains("non-HTTPS"),
            "error must name the policy: {err}"
        );
    }

    #[test]
    fn require_https_rejects_empty_url() {
        assert!(
            require_https("", "binary").is_err(),
            "empty URL must be rejected"
        );
    }

    #[test]
    fn require_https_rejects_ftp_and_other_schemes() {
        assert!(require_https("ftp://example.com/agent", "binary").is_err());
        assert!(require_https("file:///usr/local/bin/agent", "binary").is_err());
    }

    // ── verify_sha256 ───────────────────────────────────────────
    //
    // SECURITY: SHA-256 is the last integrity check before the binary is staged.
    // If this check ever returns Ok on a mismatched hash, an attacker who can
    // MITM the download URL (even over HTTPS, e.g. via a CDN compromise) can
    // replace the binary. These tests ensure the check is correct and
    // case-insensitive (the platform may emit uppercase hex).

    #[test]
    fn verify_sha256_accepts_correct_hash() {
        let data = b"hello world";
        // sha256("hello world") = b94d27b9...
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576f6a4e578cd928ba2";
        // Use ring to compute what we expect, then verify our function accepts it.
        use ring::digest;
        let actual = digest::digest(&digest::SHA256, data);
        let actual_hex: String = actual
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let result = verify_sha256(data, &actual_hex);
        assert!(
            result.is_ok(),
            "correct SHA-256 hash must be accepted, actual={actual_hex}"
        );
        // Expected hash must be 32 bytes
        let digest = result.unwrap();
        assert_eq!(digest.as_ref().len(), 32);
        // Suppress the unused variable warning on the constant above
        let _ = expected;
    }

    #[test]
    fn verify_sha256_rejects_wrong_hash() {
        let data = b"hello world";
        let wrong = "0".repeat(64);
        let err = verify_sha256(data, &wrong).unwrap_err();
        assert!(
            err.to_string().contains("SHA-256 MISMATCH"),
            "error must identify mismatch: {err}"
        );
    }

    #[test]
    fn verify_sha256_is_case_insensitive_for_expected() {
        // The platform may return uppercase hex; the agent must accept both cases.
        let data = b"test data";
        use ring::digest;
        let actual = digest::digest(&digest::SHA256, data);
        let upper_hex: String = actual
            .as_ref()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        let result = verify_sha256(data, &upper_hex);
        assert!(
            result.is_ok(),
            "uppercase hex from platform must be accepted: {upper_hex}"
        );
    }
}
