use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

pub(crate) const SYSTEMD_SERVICE: &str = r#"[Unit]
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

# Post-stop hook: handles self-update and self-uninstall (runs as root via + prefix)
ExecStopPost=+/bin/bash -c '\
if [ -f /run/connlog/.update_requested ]; then \
    echo "ConnLog: Update marker detected, applying update..."; \
    cp /run/connlog/connlog-agent-new /usr/local/bin/connlog-agent; \
    chmod 755 /usr/local/bin/connlog-agent; \
    if /usr/local/bin/connlog-agent --emit-service > /tmp/connlog-agent.service.new 2>/dev/null; then \
        mv /tmp/connlog-agent.service.new /etc/systemd/system/connlog-agent.service; \
        echo "ConnLog: Service file refreshed from new binary."; \
    else \
        echo "ConnLog: Warning — could not refresh service file, keeping existing."; \
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
        .unwrap_or_else(|_| "https://connlog.com".to_string());

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
    let _ = Command::new("systemctl")
        .arg("daemon-reload")
        .status();
    println!("  Reloaded systemd");

    // 5. Remove config (includes token — security critical)
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
    let output = Command::new("id")
        .arg("connlog-agent")
        .output();

    if output.is_ok() && output.unwrap().status.success() {
        println!("  User 'connlog-agent' already exists");
        return Ok(());
    }

    // Create system user
    let status = Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell", "/usr/sbin/nologin",
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
    fs::create_dir_all("/etc/connlog")
        .context("Failed to create /etc/connlog directory")?;

    // Set directory permissions to 0700 (root-only, prevents other users listing contents)
    let dir_path = Path::new("/etc/connlog");
    let mut dir_perms = fs::metadata(dir_path)?.permissions();
    dir_perms.set_mode(0o700);
    fs::set_permissions(dir_path, dir_perms)?;

    println!("  Created /etc/connlog directory (700 root:root)");
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

    fs::write("/etc/connlog/agent.conf", config)
        .context("Failed to write config file")?;

    // Set permissions to 600 (root-only)
    let path = Path::new("/etc/connlog/agent.conf");
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;

    println!("  Wrote config to /etc/connlog/agent.conf (600 root:root)");
    Ok(())
}

fn install_binary() -> Result<()> {
    let current_exe = std::env::current_exe()
        .context("Failed to get current executable path")?;

    let target_path = Path::new("/usr/local/bin/connlog-agent");

    // Check if we're already running from the target location
    let current_canonical = fs::canonicalize(&current_exe)
        .context("Failed to canonicalize current exe path")?;
    let target_canonical = fs::canonicalize(target_path).ok();

    if target_canonical.as_ref() == Some(&current_canonical) {
        println!("  Binary already installed at /usr/local/bin/connlog-agent");
    } else {
        // Copy binary to target location
        fs::copy(&current_exe, target_path)
            .context("Failed to copy binary to /usr/local/bin")?;

        // Make executable
        let mut perms = fs::metadata(target_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(target_path, perms)?;

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
    let status = Command::new("systemctl")
        .args(["start", "connlog-agent"])
        .status()
        .context("Failed to start service")?;

    if !status.success() {
        anyhow::bail!("Failed to start service");
    }

    println!("  Started service");
    Ok(())
}
