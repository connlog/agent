use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const SYSTEMD_SERVICE: &str = r#"[Unit]
Description=ConnLog Monitoring Agent
After=network.target

[Service]
Type=simple
User=connlog-agent
EnvironmentFile=/etc/connlog/agent.conf
ExecStart=/usr/local/bin/connlog-agent
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#;

pub fn install(token: &str, platform_url: &str) -> Result<()> {
    // Check if running as root
    if !is_root() {
        anyhow::bail!("Installation requires root privileges. Please run with sudo.");
    }

    println!("Installing ConnLog agent as systemd service...");

    // Create system user
    create_system_user()?;

    // Create config directory
    create_config_dir()?;

    // Write config file with token
    write_config(token, platform_url)?;

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

    // Stop and disable service
    let _ = Command::new("systemctl")
        .args(["stop", "connlog-agent"])
        .status();

    let _ = Command::new("systemctl")
        .args(["disable", "connlog-agent"])
        .status();

    // Remove systemd service file
    let _ = fs::remove_file("/etc/systemd/system/connlog-agent.service");

    // Reload systemd
    let _ = Command::new("systemctl")
        .arg("daemon-reload")
        .status();

    // Remove config
    let _ = fs::remove_dir_all("/etc/connlog");

    // Remove binary
    let _ = fs::remove_file("/usr/local/bin/connlog-agent");

    // Note: We don't remove the system user for safety

    println!("✓ ConnLog agent uninstalled successfully!");
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

    println!("  Created /etc/connlog directory");
    Ok(())
}

fn write_config(token: &str, platform_url: &str) -> Result<()> {
    let config = format!(
        "CONNLOG_TOKEN={}\nCONNLOG_PLATFORM_URL={}\n",
        token, platform_url
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

    fs::copy(&current_exe, "/usr/local/bin/connlog-agent")
        .context("Failed to copy binary to /usr/local/bin")?;

    // Make executable
    let path = Path::new("/usr/local/bin/connlog-agent");
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;

    println!("  Installed binary to /usr/local/bin/connlog-agent");
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
