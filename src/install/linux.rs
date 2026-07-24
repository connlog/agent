use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

pub const SYSTEMD_SERVICE_PATH: &str = "/etc/systemd/system/connlog-agent.service";
const SYSTEMD_SERVICE_TMP_PATH: &str = "/etc/systemd/system/connlog-agent.service.new";

pub const SYSTEMD_SERVICE: &str = r#"[Unit]
Description=ConnLog Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=connlog-agent
Group=connlog-agent
EnvironmentFile=/etc/connlog/agent.conf
ExecStart=/usr/local/bin/connlog-agent
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Runtime directory for uninstall marker (/run/connlog)
RuntimeDirectory=connlog
RuntimeDirectoryMode=0700

# Persistent state directory for heartbeat delivery diagnostics (/var/lib/connlog).
# Unlike RuntimeDirectory (tmpfs, wiped on reboot), StateDirectory survives
# reboots, service restarts, and the self-update binary swap. systemd creates it
# owned by connlog-agent and exports the path as $STATE_DIRECTORY. 0700 keeps the
# local heartbeat telemetry readable only by the service account (and root) —
# the same account that runs ConnLog actions, so `diagnostics heartbeats` can
# read it back without sudo. ProtectSystem=strict makes StateDirectory writable.
StateDirectory=connlog
StateDirectoryMode=0700

# ── Security hardening ──────────────────────────────────
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

# AF_NETLINK is required for read-only network inspection Quick Actions
# such as `ip a`, `ip route`, and `ss`.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

CapabilityBoundingSet=
AmbientCapabilities=

# NOTE: We deliberately DO NOT restrict /proc visibility for this service.
# `sysinfo` reads /proc/stat, /proc/meminfo, /proc/loadavg, /proc/uptime, and
# /proc/diskstats to compute CPU, memory, load, uptime and disk metrics —
# hiding those files (e.g. via the proc-subset / protect-proc directives that
# `systemd-analyze security` recommends) makes every read return ENOENT and
# the agent silently sends a perfectly-formed heartbeat full of zeros. The
# remaining hardening (NoNewPrivileges, ProtectSystem=strict, ProtectHome,
# RestrictAddressFamilies, capability drop, etc.) keeps the agent tightly
# contained without breaking metric collection.
#
# NOTE: We also deliberately DO NOT apply a syscall allowlist here.
# Local Quick Actions may run normal host diagnostic tools such as `ip`, `ss`,
# `df`, `docker ps`, and `systemctl status`. A strict SystemCallFilter breaks
# those tools with SIGSYS/"Bad system call".
#
# We keep the rest of the sandboxing in place: unprivileged user,
# NoNewPrivileges, empty capabilities, strict filesystem protection,
# restricted address families, namespace/realtime/SUID restrictions, etc.
RemoveIPC=yes
UMask=0077

# Post-stop hook: handles self-update and self-uninstall (runs as root via + prefix)
ExecStopPost=+/bin/bash -c '\
if [ -f /run/connlog/.update_requested ]; then \
    echo "ConnLog: Update marker detected, applying update..."; \
    cp /usr/local/bin/connlog-agent /run/connlog/connlog-agent-old && \
    cp /run/connlog/connlog-agent-new /usr/local/bin/connlog-agent.new && \
    chmod 755 /usr/local/bin/connlog-agent.new && \
    mv /usr/local/bin/connlog-agent.new /usr/local/bin/connlog-agent; \
    if ! /usr/local/bin/connlog-agent refresh-service; then \
        echo "ConnLog: ERROR - service refresh failed after binary replacement."; \
        echo "ConnLog: Rolling back binary and leaving service stopped."; \
        mv /run/connlog/connlog-agent-old /usr/local/bin/connlog-agent; \
        rm -f /run/connlog/.update_requested /run/connlog/connlog-agent-new; \
        exit 1; \
    fi; \
    rm -f /run/connlog/.update_requested /run/connlog/connlog-agent-new /run/connlog/connlog-agent-old; \
    systemctl start connlog-agent; \
    echo "ConnLog: Update complete."; \
elif [ -f /run/connlog/.uninstall_requested ]; then \
    echo "ConnLog: Uninstall marker detected, performing cleanup..."; \
    systemctl disable connlog-agent 2>/dev/null || true; \
    rm -f /etc/systemd/system/connlog-agent.service; \
    systemctl daemon-reload 2>/dev/null || true; \
    rm -rf /etc/connlog; \
    rm -f /usr/local/bin/connlog-agent; \
    echo "ConnLog: Agent fully uninstalled."; \
fi'

[Install]
WantedBy=multi-user.target
"#;

pub fn install(token: &str, bmc: Option<&crate::features::bmc::BmcConfig>) -> Result<()> {
    // Check if running as root
    if !is_root() {
        anyhow::bail!("Installation requires root privileges. Please run with sudo.");
    }

    println!("Installing ConnLog agent as systemd service...");

    // Get platform URL from environment or use default
    let platform_url = std::env::var("CONNLOG_PLATFORM_URL")
        .unwrap_or_else(|_| crate::defaults::DEFAULT_ENDPOINT.to_string());

    // Create system user
    create_system_user()?;

    // Create config directory
    create_config_dir()?;

    // Write config file with token (+ BMC settings if provided)
    write_config(token, &platform_url, bmc)?;
    if bmc.is_some() {
        println!("  BMC hardware-health polling configured (iDRAC / iLO / OpenBMC)");
    }

    // Copy binary to /usr/local/bin
    install_binary()?;

    // Create systemd service
    create_systemd_service()?;

    // Enable and start service
    enable_service()?;
    start_service()?;

    println!("\n✓ ConnLog agent installed successfully!");
    println!("\nService status:");
    println!("  sudo systemctl status connlog-agent");
    println!("\nView logs:");
    println!("  sudo journalctl -u connlog-agent -f");
    println!("\nAgent configuration:");
    println!("  /etc/connlog/agent.conf (root-only)");

    Ok(())
}

pub fn uninstall() -> Result<()> {
    if !is_root() {
        anyhow::bail!("Uninstallation requires root privileges. Please run with sudo.");
    }

    println!("Uninstalling ConnLog agent...");

    // 1. Stop the service FIRST (prevents resurrection)
    let _ = Command::new("systemctl")
        .args(["stop", "connlog-agent"])
        .status();
    println!("  Stopped service");

    // 2. Disable the service (prevents boot start)
    let _ = Command::new("systemctl")
        .args(["disable", "connlog-agent"])
        .status();
    println!("  Disabled service");

    // 3. Remove systemd service file
    let _ = fs::remove_file("/etc/systemd/system/connlog-agent.service");
    println!("  Removed service file");

    // 4. Reload systemd (forgets the unit)
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    println!("  Reloaded systemd");

    // 5. Remove config (includes token - security critical)
    let _ = fs::remove_dir_all("/etc/connlog");
    println!("  Removed /etc/connlog");

    // 6. Remove binary LAST (we're running from it)
    let _ = fs::remove_file("/usr/local/bin/connlog-agent");
    println!("  Removed binary");

    // Note: We don't remove the system user for safety

    println!("\n✓ ConnLog agent uninstalled successfully!");
    println!("\nNote: System user 'connlog-agent' was preserved for safety.");
    println!("To remove: sudo userdel connlog-agent");

    Ok(())
}

pub fn status() -> Result<()> {
    let output = Command::new("systemctl")
        .args(["status", "connlog-agent"])
        .output()
        .context("Failed to check service status")?;

    println!("{}", String::from_utf8_lossy(&output.stdout));

    if !output.status.success() {
        println!("\nService is not running or not installed.");
        println!("\nTo install:");
        println!("  sudo connlog-agent install --token <your-token>");
    }

    println!();
    print_service_diagnostics()?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct ServiceDiagnostics {
    pub binary_version: &'static str,
    pub service_path: &'static str,
    pub installed: bool,
    pub matches_embedded: bool,
    pub needs_daemon_reload: Option<bool>,
}

pub fn refresh_service(restart: bool) -> Result<()> {
    if !is_root() {
        anyhow::bail!(
            "Refreshing the systemd service requires root privileges. Please run with sudo."
        );
    }

    write_service_atomically(Path::new(SYSTEMD_SERVICE_PATH), SYSTEMD_SERVICE)?;
    run_systemctl(&["daemon-reload"]).context("Failed to reload systemd after service refresh")?;
    println!("  Refreshed {}", SYSTEMD_SERVICE_PATH);
    println!("  Reloaded systemd");

    if restart {
        run_systemctl(&["restart", "connlog-agent"])
            .context("Failed to restart connlog-agent after service refresh")?;
        println!("  Restarted connlog-agent");
    }

    Ok(())
}

pub fn diagnostics() -> Result<ServiceDiagnostics> {
    let matches_embedded =
        installed_service_matches_embedded_path(Path::new(SYSTEMD_SERVICE_PATH))?;
    Ok(ServiceDiagnostics {
        binary_version: env!("CARGO_PKG_VERSION"),
        service_path: SYSTEMD_SERVICE_PATH,
        installed: Path::new(SYSTEMD_SERVICE_PATH).exists(),
        matches_embedded,
        needs_daemon_reload: systemd_needs_daemon_reload(),
    })
}

pub fn print_service_diagnostics() -> Result<()> {
    let diagnostics = diagnostics()?;
    println!("Service template diagnostics:");
    println!("  binary_version:          v{}", diagnostics.binary_version);
    println!("  installed_service_path:  {}", diagnostics.service_path);
    println!("  installed:               {}", diagnostics.installed);
    println!(
        "  matches_embedded:        {}",
        diagnostics.matches_embedded
    );
    match diagnostics.needs_daemon_reload {
        Some(value) => println!("  systemd_needs_reload:    {}", value),
        None => println!("  systemd_needs_reload:    unknown"),
    }
    if diagnostics.installed && !diagnostics.matches_embedded {
        println!();
        println!("Installed systemd service differs from this agent version. Run:");
        println!("  sudo connlog-agent refresh-service --restart");
    }
    Ok(())
}

pub fn warn_if_installed_service_stale_once() {
    match installed_service_matches_embedded_path(Path::new(SYSTEMD_SERVICE_PATH)) {
        Ok(false) => log::warn!(
            "Installed systemd service differs from this agent version. Run: sudo connlog-agent refresh-service --restart"
        ),
        Ok(true) => {}
        Err(e) => log::debug!("Could not inspect installed systemd service: {}", e),
    }
}

fn installed_service_matches_embedded_path(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let installed = fs::read_to_string(path)
        .with_context(|| format!("Failed to read installed service {}", path.display()))?;
    Ok(normalize_service_text(&installed) == normalize_service_text(SYSTEMD_SERVICE))
}

fn normalize_service_text(text: &str) -> String {
    text.replace("\r\n", "\n")
}

fn write_service_atomically(path: &Path, service_text: &str) -> Result<()> {
    let tmp = Path::new(SYSTEMD_SERVICE_TMP_PATH);
    let tmp = if path == Path::new(SYSTEMD_SERVICE_PATH) {
        tmp.to_path_buf()
    } else {
        path.with_extension("service.new")
    };

    fs::write(&tmp, service_text)
        .with_context(|| format!("Failed to write service temp file {}", tmp.display()))?;

    let mut perms = fs::metadata(&tmp)
        .with_context(|| format!("Failed to read metadata for {}", tmp.display()))?
        .permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&tmp, perms)
        .with_context(|| format!("Failed to set permissions on {}", tmp.display()))?;

    fs::rename(&tmp, path).with_context(|| {
        format!(
            "Failed to atomically replace service file {} with {}",
            path.display(),
            tmp.display()
        )
    })?;

    Ok(())
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run systemctl {}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("systemctl {} returned non-zero status", args.join(" "));
    }
    Ok(())
}

fn systemd_needs_daemon_reload() -> Option<bool> {
    let output = Command::new("systemctl")
        .args([
            "show",
            "connlog-agent",
            "--property=NeedDaemonReload",
            "--value",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&output.stdout).trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn create_system_user() -> Result<()> {
    // Check if user already exists
    let output = Command::new("id").arg("connlog-agent").output();

    if output.map(|o| o.status.success()).unwrap_or(false) {
        println!("  User 'connlog-agent' already exists");
        return Ok(());
    }

    // Create system user
    let status = Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "connlog-agent",
        ])
        .status()
        .context("Failed to create system user")?;

    if !status.success() {
        anyhow::bail!("Failed to create system user 'connlog-agent'");
    }

    println!("  Created system user 'connlog-agent'");
    Ok(())
}

fn create_config_dir() -> Result<()> {
    fs::create_dir_all("/etc/connlog").context("Failed to create /etc/connlog directory")?;

    let chown_status = Command::new("chown")
        .args(["root:connlog-agent", "/etc/connlog"])
        .status()
        .context("Failed to set /etc/connlog ownership")?;
    if !chown_status.success() {
        anyhow::bail!("Failed to set /etc/connlog ownership");
    }

    // Allow the service group to traverse the directory for actions.toml.
    // The token file remains 0600 root-only and is read by systemd before the
    // service drops to User=connlog-agent.
    let dir_path = Path::new("/etc/connlog");
    let mut dir_perms = fs::metadata(dir_path)
        .context("Failed to read /etc/connlog metadata")?
        .permissions();
    dir_perms.set_mode(0o750);
    fs::set_permissions(dir_path, dir_perms).context("Failed to set /etc/connlog permissions")?;

    println!("  Created /etc/connlog directory (750 root:connlog-agent)");
    Ok(())
}

/// Escape a value for systemd EnvironmentFile double-quoted context.
/// Prevents shell injection through crafted token or URL values.
fn escape_env_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

fn write_config(
    token: &str,
    platform_url: &str,
    bmc: Option<&crate::features::bmc::BmcConfig>,
) -> Result<()> {
    let mut config = format!(
        "CONNLOG_TOKEN=\"{}\"\nCONNLOG_PLATFORM_URL=\"{}\"\n",
        escape_env_value(token),
        escape_env_value(platform_url),
    );

    // Persist BMC hardware-health settings so the installed systemd service
    // (which sources this EnvironmentFile) polls the BMC. Only written when all
    // of endpoint/username/password were provided. The password is shell-escaped
    // like the token; the file is 0600 root-only (set below), the correct
    // resting place for the credential.
    if let Some(b) = bmc {
        config.push_str(&format!(
            "CONNLOG_BMC_ENDPOINT=\"{}\"\nCONNLOG_BMC_USERNAME=\"{}\"\nCONNLOG_BMC_PASSWORD=\"{}\"\nCONNLOG_BMC_POLL_INTERVAL_SECS=\"{}\"\nCONNLOG_BMC_INSECURE_TLS=\"{}\"\n",
            escape_env_value(&b.endpoint),
            escape_env_value(&b.username),
            escape_env_value(&b.password),
            b.poll_interval_secs,
            b.insecure_tls,
        ));
    }

    fs::write("/etc/connlog/agent.conf", config).context("Failed to write config file")?;

    // Set permissions to 600 (root-only)
    let path = Path::new("/etc/connlog/agent.conf");
    let mut perms = fs::metadata(path)
        .context("Failed to read /etc/connlog/agent.conf metadata")?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .context("Failed to set /etc/connlog/agent.conf permissions")?;

    println!("  Wrote config to /etc/connlog/agent.conf (600 root:root)");
    Ok(())
}

fn install_binary() -> Result<()> {
    let current_exe = std::env::current_exe().context("Failed to get current executable path")?;

    let target_path = Path::new("/usr/local/bin/connlog-agent");

    // Check if we're already running from the target location
    let current_canonical =
        fs::canonicalize(&current_exe).context("Failed to canonicalize current exe path")?;
    let target_canonical = fs::canonicalize(target_path).ok();

    if target_canonical.as_ref() == Some(&current_canonical) {
        println!("  Binary already installed at /usr/local/bin/connlog-agent");
    } else {
        // Copy binary to target location
        fs::copy(&current_exe, target_path).context("Failed to copy binary to /usr/local/bin")?;

        // Make executable
        let mut perms = fs::metadata(target_path)
            .context("Failed to read installed binary metadata")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(target_path, perms)
            .context("Failed to set installed binary permissions")?;

        println!("  Installed binary to /usr/local/bin/connlog-agent");
    }

    Ok(())
}

fn create_systemd_service() -> Result<()> {
    write_service_atomically(Path::new(SYSTEMD_SERVICE_PATH), SYSTEMD_SERVICE)
        .context("Failed to create systemd service file")?;
    run_systemctl(&["daemon-reload"]).context("Failed to reload systemd")?;

    println!("  Created systemd service");
    Ok(())
}

fn enable_service() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["enable", "connlog-agent"])
        .status()
        .context("Failed to enable service")?;

    if !status.success() {
        anyhow::bail!("Failed to enable service");
    }

    println!("  Enabled service");
    Ok(())
}

fn start_service() -> Result<()> {
    // Check if service is already running - use restart to pick up the new binary
    let is_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "connlog-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let action = if is_active { "restart" } else { "start" };

    let status = Command::new("systemctl")
        .args([action, "connlog-agent"])
        .status()
        .with_context(|| format!("Failed to {} service", action))?;

    if !status.success() {
        anyhow::bail!("Failed to {} service", action);
    }

    if is_active {
        println!("  Restarted service (was already running)");
    } else {
        println!("  Started service");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── escape_env_value ────────────────────────────────────────
    //
    // SECURITY: This function defends against shell-injection through a crafted
    // bearer token or platform URL when `/etc/connlog/agent.env` is sourced by
    // systemd. A regression here is a remote-code-execution vector. Tests pin
    // the four metacharacters that matter in a double-quoted shell context.

    #[test]
    fn escape_passes_through_safe_input() {
        assert_eq!(escape_env_value("agent_abc123"), "agent_abc123");
        assert_eq!(
            escape_env_value("https://example.com"),
            "https://example.com"
        );
    }

    #[test]
    fn escape_neutralises_command_substitution() {
        // Without escaping, `$(rm -rf /)` could be interpreted by a downstream
        // shell context. After escaping, every `$` must be preceded by `\`,
        // which systemd's EnvironmentFile parser stores as a literal `$`.
        let escaped = escape_env_value("$(rm -rf /)");
        assert!(
            escaped.contains("\\$("),
            "every $ must be backslash-escaped, got: {}",
            escaped
        );
        assert!(
            !escaped.contains("\\$\\$"),
            "escape function must not double-escape $, got: {}",
            escaped
        );
    }

    #[test]
    fn escape_neutralises_backticks() {
        let escaped = escape_env_value("`whoami`");
        assert!(escaped.contains("\\`"));
        assert!(!escaped.starts_with('`'));
    }

    #[test]
    fn escape_neutralises_double_quote_then_command() {
        // Classic break-out: close the quote, run a command, reopen the quote.
        // After escaping, every literal `"` in the input must be backslash-escaped
        // so it cannot terminate the surrounding double-quoted env value.
        let escaped = escape_env_value("x\"; rm -rf /; echo \"y\"");
        // Count unescaped quotes — there must be zero. We do this by removing
        // every \" pair and checking no bare " remains.
        let stripped = escaped.replace("\\\"", "");
        assert!(
            !stripped.contains('"'),
            "every \" must be backslash-escaped, got: {}",
            escaped
        );
    }

    #[test]
    fn escape_neutralises_backslash() {
        // Backslash must be doubled FIRST so it doesn't accidentally escape a
        // following quote we were trying to escape.
        let escaped = escape_env_value("\\\"");
        // Original: \"  →  expected: \\\"  (backslash doubled, quote escaped)
        assert_eq!(escaped, "\\\\\\\"");
    }

    #[test]
    fn escape_keeps_metacharacters_neutralised_after_round_trip() {
        // Running the escaper twice must keep every metacharacter neutralised.
        // The output WILL grow (backslashes double on each pass), but every
        // active metacharacter must remain preceded by an escape.
        let once = escape_env_value("$(echo)");
        let twice = escape_env_value(&once);
        // After a second pass, the original `$` is still escaped (now via
        // `\\\$` since the first-pass `\` was itself doubled).
        assert!(
            twice.contains("\\$"),
            "$ must remain escaped after second pass, got: {}",
            twice
        );
        // No bare unescaped quote characters either.
        assert!(
            !twice.replace("\\\"", "").contains('"'),
            "no unescaped quote may survive, got: {}",
            twice
        );
    }

    // ── SYSTEMD_SERVICE invariants ──────────────────────────────
    //
    // The systemd unit is a string blob. These tests pin the security and
    // self-update properties that, if broken, would silently leave production
    // agents unable to update or expose them to privilege escalation.

    #[test]
    fn systemd_unit_runs_as_unprivileged_user() {
        assert!(SYSTEMD_SERVICE.contains("User=connlog-agent"));
        assert!(SYSTEMD_SERVICE.contains("Group=connlog-agent"));
        assert!(SYSTEMD_SERVICE.contains("NoNewPrivileges=yes"));
    }

    #[test]
    fn systemd_unit_keeps_self_update_hook() {
        // ExecStopPost is what completes the self-update. If this disappears,
        // the entire auto-update mechanism silently breaks.
        assert!(
            SYSTEMD_SERVICE.contains("ExecStopPost"),
            "ExecStopPost is required for self-update to work"
        );
        assert!(SYSTEMD_SERVICE.contains("/run/connlog/.update_requested"));
        assert!(SYSTEMD_SERVICE.contains("/run/connlog/.uninstall_requested"));
        assert!(SYSTEMD_SERVICE.contains("refresh-service"));
        assert!(SYSTEMD_SERVICE.contains("ConnLog: ERROR - service refresh failed"));
    }

    /// The binary replacement in ExecStopPost MUST NOT overwrite the live binary
    /// directly with `cp`. A crash during `cp` leaves a corrupt binary and a
    /// permanently bricked agent. The correct pattern is:
    ///   1. cp → connlog-agent.new   (safe: original is untouched if cp fails)
    ///   2. chmod                     (sets executable bit on the staging file)
    ///   3. mv .new → connlog-agent  (atomic rename() within the same fs)
    #[test]
    fn systemd_unit_binary_replacement_is_atomic() {
        // The staged binary must land in a .new file first, then be atomically
        // renamed into place. Direct cp to the live path is not atomic.
        assert!(
            SYSTEMD_SERVICE.contains("connlog-agent.new"),
            "binary must be staged to connlog-agent.new before atomic mv into place"
        );
        assert!(
            SYSTEMD_SERVICE
                .contains("mv /usr/local/bin/connlog-agent.new /usr/local/bin/connlog-agent"),
            "final replacement must be an atomic mv, not a direct cp"
        );
    }

    /// The service-file refresh temp file must be created on the same
    /// filesystem as the destination so that `mv` is an atomic rename().
    /// Writing to /run (tmpfs) and then mv-ing to /etc (root fs) crosses
    /// filesystem boundaries — the kernel falls back to copy+unlink, which
    /// is NOT atomic.
    #[test]
    fn systemd_unit_service_file_refresh_is_atomic() {
        assert!(
            SYSTEMD_SERVICE.contains("connlog-agent refresh-service"),
            "self-update must use the shared refresh-service implementation"
        );
        assert!(
            !SYSTEMD_SERVICE.contains("/run/connlog/connlog-agent.service.new"),
            "service file temp must NOT be on /run (tmpfs) — cross-fs mv is not atomic"
        );
    }

    #[test]
    fn write_service_atomically_replaces_target() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("connlog-agent-service-{unique}.service"));
        fs::write(&path, "old").expect("write old service");

        write_service_atomically(&path, "new service\n").expect("atomic service write");

        assert_eq!(fs::read_to_string(&path).unwrap(), "new service\n");
        assert!(
            !path.with_extension("service.new").exists(),
            "temp file must be renamed into place"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn installed_service_match_detection_compares_embedded_template() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("connlog-agent-service-match-{unique}.service"));
        fs::write(&path, SYSTEMD_SERVICE).expect("write matching service");
        assert!(installed_service_matches_embedded_path(&path).unwrap());

        fs::write(&path, "stale service").expect("write stale service");
        assert!(!installed_service_matches_embedded_path(&path).unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn systemd_unit_hardening_flags_present() {
        // These are the systemd sandboxing knobs we depend on. Removing any of
        // them weakens the agent's blast radius if compromised.
        for flag in [
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectControlGroups=yes",
            "ProtectClock=yes",
            "ProtectHostname=yes",
            "RestrictSUIDSGID=yes",
            "RestrictNamespaces=yes",
            "RestrictRealtime=yes",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
            "SystemCallArchitectures=native",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "RemoveIPC=yes",
            "UMask=0077",
        ] {
            assert!(
                SYSTEMD_SERVICE.contains(flag),
                "systemd hardening flag missing: {}",
                flag
            );
        }
    }

    /// The heartbeat diagnostics telemetry must persist across reboots and the
    /// self-update binary swap. That requires a systemd `StateDirectory`
    /// (`/var/lib/connlog`), NOT the tmpfs `RuntimeDirectory` (`/run/connlog`,
    /// wiped on reboot). Pin both the directive and its restrictive mode so a
    /// refactor can't silently drop persistence or world-expose the telemetry.
    #[test]
    fn systemd_unit_provisions_persistent_state_directory() {
        assert!(
            SYSTEMD_SERVICE.contains("StateDirectory=connlog"),
            "StateDirectory=connlog is required so heartbeat telemetry survives reboot/update"
        );
        assert!(
            SYSTEMD_SERVICE.contains("StateDirectoryMode=0700"),
            "heartbeat telemetry directory must be 0700 (service account only)"
        );
    }

    #[test]
    fn systemd_unit_does_not_use_syscall_filter() {
        assert!(
            !SYSTEMD_SERVICE.contains("\nSystemCallFilter="),
            "SystemCallFilter breaks local Quick Actions by killing normal diagnostic tools with SIGSYS"
        );
    }

    /// Regression for the v1.3.x "dashboard shows zeros" bug. With
    /// `ProcSubset=pid` (or `ProtectProc=invisible`) the kernel hides almost
    /// all of /proc from the service, and `sysinfo` silently reports zero
    /// for CPU, memory, load, disk and uptime. Keep this test as a tripwire:
    /// re-introducing either flag without also re-implementing metric
    /// collection will fail here loudly.
    #[test]
    fn systemd_unit_does_not_block_proc_reads() {
        assert!(
            !SYSTEMD_SERVICE.contains("ProcSubset"),
            "ProcSubset=* breaks /proc reads that sysinfo needs for CPU/memory/load metrics"
        );
        assert!(
            !SYSTEMD_SERVICE.contains("ProtectProc=invisible")
                && !SYSTEMD_SERVICE.contains("ProtectProc=ptraceable"),
            "ProtectProc=invisible/ptraceable hides /proc/meminfo etc. from sysinfo"
        );
    }
}
