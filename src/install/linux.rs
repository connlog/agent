use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
# NOTE: We deliberately DO NOT restrict /proc visibility for this service.
# `sysinfo` reads /proc/stat, /proc/meminfo, /proc/loadavg, /proc/uptime, and
# /proc/diskstats to compute CPU, memory, load, uptime and disk metrics —
# hiding those files (e.g. via the proc-subset / protect-proc directives that
# `systemd-analyze security` recommends) makes every read return ENOENT and
# the agent silently sends a perfectly-formed heartbeat full of zeros. The
# remaining hardening (NoNewPrivileges, ProtectSystem=strict, ProtectHome,
# syscall filter, RestrictAddressFamilies, capability drop, etc.) keeps the
# agent tightly contained without breaking metric collection.
RemoveIPC=yes
UMask=0077
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @debug @cpu-emulation @obsolete @raw-io @reboot @swap @module

# Post-stop hook: handles self-update and self-uninstall (runs as root via + prefix)
ExecStopPost=+/bin/bash -c '\
if [ -f /run/connlog/.update_requested ]; then \
    echo "ConnLog: Update marker detected, applying update..."; \
    cp /run/connlog/connlog-agent-new /usr/local/bin/connlog-agent.new && \
    chmod 755 /usr/local/bin/connlog-agent.new && \
    mv /usr/local/bin/connlog-agent.new /usr/local/bin/connlog-agent; \
    if /usr/local/bin/connlog-agent --emit-service > /etc/systemd/system/connlog-agent.service.new 2>/dev/null; then \
        mv /etc/systemd/system/connlog-agent.service.new /etc/systemd/system/connlog-agent.service; \
        echo "ConnLog: Service file refreshed from new binary."; \
    else \
        echo "ConnLog: Warning - could not refresh service file, keeping existing."; \
    fi; \
    systemctl daemon-reload; \
    rm -f /run/connlog/.update_requested /run/connlog/connlog-agent-new; \
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

pub fn install(token: &str) -> Result<()> {
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

    // Write config file with token
    write_config(token, &platform_url)?;

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

    Ok(())
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

fn write_config(token: &str, platform_url: &str) -> Result<()> {
    let config = format!(
        "CONNLOG_TOKEN=\"{}\"\nCONNLOG_PLATFORM_URL=\"{}\"\n",
        escape_env_value(token),
        escape_env_value(platform_url),
    );

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
    fs::write("/etc/systemd/system/connlog-agent.service", SYSTEMD_SERVICE)
        .context("Failed to create systemd service file")?;

    // Reload systemd
    Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .context("Failed to reload systemd")?;

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
        assert!(SYSTEMD_SERVICE.contains("systemctl daemon-reload"));
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
            SYSTEMD_SERVICE.contains("/etc/systemd/system/connlog-agent.service.new"),
            "service file temp must be on the same fs as the target (/etc/systemd/system)"
        );
        assert!(
            !SYSTEMD_SERVICE.contains("/run/connlog/connlog-agent.service.new"),
            "service file temp must NOT be on /run (tmpfs) — cross-fs mv is not atomic"
        );
    }

    #[test]
    fn systemd_unit_hardening_flags_present() {
        // These are the systemd sandboxing knobs we depend on. Removing any of
        // them weakens the agent's blast radius if compromised.
        for flag in [
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "ProtectKernelModules=yes",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "CapabilityBoundingSet=",
            "RemoveIPC=yes",
            "UMask=0077",
            "SystemCallFilter=@system-service",
        ] {
            assert!(
                SYSTEMD_SERVICE.contains(flag),
                "systemd hardening flag missing: {}",
                flag
            );
        }
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
