use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::platform::{SAFE_PATH, STATE_DIR};

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
# Opt-in last words (CONNLOG_SHARE_POSTMORTEM): after an unclean previous
# boot, root saves that boot's last warnings for the outage report. `-` so a
# failure never keeps the agent from starting; a no-op unless opted in.
ExecStartPre=-+/usr/local/bin/connlog-agent collect-postmortem
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

# Post-stop hook: handles self-update, self-uninstall, and host reboot
# (runs as root via + prefix). The agent process itself is unprivileged and
# /run/connlog is writable by it, so nothing found there is trusted here:
# `apply-staged-update` re-verifies the staged binary's Ed25519 signature with
# the key compiled into the installed binary, checks the version the staged
# binary reports, swaps it in with a same-filesystem rename, and rolls back if
# the new binary cannot refresh the service. The service is started again in
# every case, so a rejected update never leaves a host silent.
ExecStopPost=+/bin/bash -c '\
if [ -f /run/connlog/.update_requested ]; then \
    echo "ConnLog: Update marker detected, verifying staged binary..."; \
    if /usr/local/bin/connlog-agent apply-staged-update; then \
        echo "ConnLog: Update complete."; \
    else \
        echo "ConnLog: Update not applied; the previous binary stays in place."; \
    fi; \
    rm -f /run/connlog/.update_requested /run/connlog/connlog-agent-new /run/connlog/connlog-agent-new.sig; \
    systemctl start connlog-agent; \
elif [ -f /run/connlog/.uninstall_requested ]; then \
    echo "ConnLog: Uninstall marker detected, performing cleanup..."; \
    systemctl disable connlog-agent 2>/dev/null || true; \
    rm -f /etc/systemd/system/connlog-agent.service; \
    systemctl daemon-reload 2>/dev/null || true; \
    rm -rf /etc/connlog /var/lib/connlog; \
    rm -f /usr/local/bin/connlog-agent /usr/local/bin/connlog-agent.old /usr/local/bin/connlog-agent.new; \
    echo "ConnLog: Agent fully uninstalled."; \
elif [ -f /run/connlog/.reboot_requested ]; then \
    rm -f /run/connlog/.reboot_requested; \
    # The marker is writable by the service account, so root re-reads the
    # host's own setting from the root-only agent.conf (last assignment wins,
    # as for EnvironmentFile). Only an explicit true reboots: a missing file,
    # a missing line or any other value refuses. `$$` is a literal `$` for
    # systemd; quotes and spaces are dropped by keeping only alphanumerics.
    # No line here may start with `;` (so no `case`): systemd reads that as a
    # comment and drops it.
    allow=$$(grep -E "^[[:space:]]*CONNLOG_ALLOW_REMOTE_REBOOT=" /etc/connlog/agent.conf 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -dc "[:alnum:]" | tr "[:upper:]" "[:lower:]"); \
    if ! echo "$$allow" | grep -qxE "true|1|yes|on|y|t"; then \
        echo "ConnLog: Remote reboot is off on this host (CONNLOG_ALLOW_REMOTE_REBOOT is not true); not rebooting."; \
        systemctl start --no-block connlog-agent; \
    else \
        echo "ConnLog: Reboot marker detected, scheduling host reboot..."; \
        # MUST use --no-block: a synchronous `systemctl reboot` waits for every
        # unit (including this one) to finish deactivating, but we are still
        # inside ExecStopPost — that deadlocks and the host never reboots.
        if ! systemctl reboot --no-block; then \
            echo "ConnLog: systemctl reboot --no-block failed; falling back to systemd-run"; \
            # Neither worked: bring the agent back so the host is not left
            # silent. It finds itself on the same boot and reports the failure.
            if ! systemd-run --collect --on-active=2s /bin/systemctl reboot --no-block; then \
                echo "ConnLog: Could not schedule a reboot; starting the agent again."; \
                systemctl start --no-block connlog-agent; \
            fi; \
        fi; \
    fi; \
fi'

[Install]
WantedBy=multi-user.target
"#;

pub fn install(
    token: &str,
    bmc: Option<&crate::features::bmc::BmcConfig>,
    expose_system_info: bool,
    remote_reboot: Option<bool>,
    network_map: &crate::features::network_map::ConfChoice,
) -> Result<()> {
    // Check if running as root
    if !is_root() {
        anyhow::bail!("Installation requires root privileges. Please run with sudo.");
    }

    println!("Installing ConnLog agent as systemd service...");

    validate_token_format(token)?;

    // Get platform URL from environment or use default
    let platform_url = std::env::var("CONNLOG_PLATFORM_URL")
        .unwrap_or_else(|_| crate::defaults::DEFAULT_ENDPOINT.to_string());

    // Create system user
    create_system_user()?;

    // Create config directory
    create_config_dir()?;

    // A reinstall keeps the host's existing remote-reboot choice unless this
    // install makes a new one; with neither, the line is left out (off).
    let remote_reboot = remote_reboot.or_else(existing_conf_remote_reboot);
    // The same for the network map: its flag, site, ports and public probes.
    let network_map = network_map
        .clone()
        .or_existing(read_agent_conf().as_deref());

    // Write config file with token (+ BMC settings if provided)
    write_config(
        token,
        &platform_url,
        bmc,
        expose_system_info,
        remote_reboot,
        &network_map,
    )?;
    if bmc.is_some() {
        println!("  BMC hardware-health polling configured (iDRAC / iLO / OpenBMC)");
    }

    if expose_system_info {
        println!("  Hostname sharing enabled (CONNLOG_EXPOSE_SYSTEM_INFO=true)");
    }

    if remote_reboot == Some(true) {
        println!("  Remote reboot allowed (CONNLOG_ALLOW_REMOTE_REBOOT=true)");
    } else {
        println!(
            "  Remote reboot off (to allow it: sudo connlog-agent config enable-remote-reboot)"
        );
    }

    if network_map.enabled == Some(true) {
        println!("  Network map on (CONNLOG_NETWORK_MAP=true)");
        if let Some(site) = &network_map.site {
            println!("    site: {site}");
        }
        if let Some(ports) = &network_map.ports {
            println!(
                "    extra ports: {}",
                crate::features::network_map::format_ports(ports)
            );
        }
    } else {
        println!("  Network map off (to join it: sudo connlog-agent config enable-network-map)");
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
    let _ = system_command("systemctl")
        .args(["stop", "connlog-agent"])
        .status();
    println!("  Stopped service");

    // 2. Disable the service (prevents boot start)
    let _ = system_command("systemctl")
        .args(["disable", "connlog-agent"])
        .status();
    println!("  Disabled service");

    // 3. Remove systemd service file
    let _ = fs::remove_file("/etc/systemd/system/connlog-agent.service");
    println!("  Removed service file");

    // 4. Reload systemd (forgets the unit)
    let _ = system_command("systemctl").arg("daemon-reload").status();
    println!("  Reloaded systemd");

    // 5. Remove config (includes token - security critical)
    let _ = fs::remove_dir_all("/etc/connlog");
    println!("  Removed /etc/connlog");

    // 6. Remove local diagnostics (heartbeat telemetry, update notes)
    let _ = fs::remove_dir_all(STATE_DIR);
    println!("  Removed {}", STATE_DIR);

    // 7. Remove binary LAST (we're running from it), plus any swap leftovers
    let _ = fs::remove_file("/usr/local/bin/connlog-agent.old");
    let _ = fs::remove_file("/usr/local/bin/connlog-agent.new");
    let _ = fs::remove_file("/usr/local/bin/connlog-agent");
    println!("  Removed binary");

    // Note: We don't remove the system user for safety

    println!("\n✓ ConnLog agent uninstalled successfully!");
    println!("\nNote: System user 'connlog-agent' was preserved for safety.");
    println!("To remove: sudo userdel connlog-agent");

    Ok(())
}

pub fn status() -> Result<()> {
    let output = system_command("systemctl")
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
    let status = system_command("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run systemctl {}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("systemctl {} returned non-zero status", args.join(" "));
    }
    Ok(())
}

fn systemd_needs_daemon_reload() -> Option<bool> {
    let output = system_command("systemctl")
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

/// A system tool with a fixed `PATH`, so a root-run install never resolves
/// `systemctl` or `useradd` through whatever the caller's shell put first.
fn system_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env("PATH", SAFE_PATH);
    command
}

/// Tokens are `agent_` followed by 64 hex characters, which is also what the
/// platform generates and validates. Checking it here keeps anything else,
/// control characters included, out of the systemd EnvironmentFile.
fn validate_token_format(token: &str) -> Result<()> {
    let hex = token.strip_prefix("agent_").unwrap_or("");
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!(
            "Invalid token format: expected agent_ followed by 64 hex characters (copy it from the dashboard)"
        );
    }
    Ok(())
}

/// Values written to the EnvironmentFile are one line each. A newline or
/// other control character would end the assignment early and start another
/// one, so it is refused rather than escaped.
fn validate_env_value(name: &str, value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        anyhow::bail!("{name} contains a control character and cannot be written to agent.conf");
    }
    Ok(())
}

fn create_system_user() -> Result<()> {
    // Check if user already exists
    let output = system_command("id").arg("connlog-agent").output();

    if output.map(|o| o.status.success()).unwrap_or(false) {
        println!("  User 'connlog-agent' already exists");
        return Ok(());
    }

    // Create system user
    let status = system_command("useradd")
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

    let chown_status = system_command("chown")
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
/// Prevents shell injection through crafted token or URL values. Control
/// characters are refused earlier by `validate_env_value`; this only quotes.
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
    expose_system_info: bool,
    remote_reboot: Option<bool>,
    network_map: &crate::features::network_map::ConfChoice,
) -> Result<()> {
    validate_env_value("CONNLOG_TOKEN", token)?;
    validate_env_value("CONNLOG_PLATFORM_URL", platform_url)?;
    if let Some(b) = bmc {
        validate_env_value("CONNLOG_BMC_ENDPOINT", &b.endpoint)?;
        validate_env_value("CONNLOG_BMC_USERNAME", &b.username)?;
        validate_env_value("CONNLOG_BMC_PASSWORD", &b.password)?;
    }

    let mut config = format!(
        "CONNLOG_TOKEN=\"{}\"\nCONNLOG_PLATFORM_URL=\"{}\"\n",
        escape_env_value(token),
        escape_env_value(platform_url),
    );

    if expose_system_info {
        config.push_str("CONNLOG_EXPOSE_SYSTEM_INFO=\"true\"\n");
    }

    if let Some(allowed) = remote_reboot {
        config.push_str(&format!("CONNLOG_ALLOW_REMOTE_REBOOT=\"{allowed}\"\n"));
    }

    // Validated by `ConfChoice` (site and port characters are a closed set),
    // escaped anyway like every other value.
    for (key, value) in network_map.conf_lines() {
        config.push_str(&format!("{key}=\"{}\"\n", escape_env_value(&value)));
    }

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

    write_agent_conf(&config)?;
    println!("  Wrote config to /etc/connlog/agent.conf (600 root:root)");
    Ok(())
}

/// Create `/etc/connlog/agent.conf` if missing, turn hostname sharing on or
/// off, and restart the service so systemd reloads the EnvironmentFile.
pub fn set_hostname_sharing(enabled: bool) -> Result<()> {
    set_agent_conf_value(
        "CONNLOG_EXPOSE_SYSTEM_INFO",
        if enabled { "true" } else { "false" },
    )
}

/// Share (or stop sharing) the previous boot's last warnings, then restart.
pub fn set_postmortem_sharing(enabled: bool) -> Result<()> {
    set_agent_conf_value(
        "CONNLOG_SHARE_POSTMORTEM",
        if enabled { "true" } else { "false" },
    )
}

/// Allow or refuse remote reboot from the dashboard, then restart the service.
pub fn set_remote_reboot(allowed: bool) -> Result<()> {
    set_agent_conf_value(
        "CONNLOG_ALLOW_REMOTE_REBOOT",
        if allowed { "true" } else { "false" },
    )
}

/// Join (with any site or ports the command gave) or leave the network map,
/// then restart the service. Leaving keeps the site and ports for next time.
pub fn set_network_map(choice: &crate::features::network_map::ConfChoice) -> Result<()> {
    let lines = choice.conf_lines();
    let pairs: Vec<(&str, &str)> = lines.iter().map(|(k, v)| (*k, v.as_str())).collect();
    set_agent_conf_values(&pairs)
}

const AGENT_CONF_PATH: &str = "/etc/connlog/agent.conf";

/// The explicit remote-reboot choice in the installed `agent.conf`, if any.
/// Unreadable or missing means no choice (off).
fn existing_conf_remote_reboot() -> Option<bool> {
    read_agent_conf().and_then(|conf| conf_remote_reboot(&conf))
}

/// The reading the systemd hook's `grep` makes of the same file (see
/// `SYSTEMD_SERVICE`): the last assignment wins, as it does for systemd.
/// `Some(true)` only for a value the hook reboots on, `Some(false)` for an
/// explicit refusal, `None` when there is no line or the value is neither
/// (the hook refuses those too).
fn conf_remote_reboot(conf: &str) -> Option<bool> {
    conf_bool(conf, "CONNLOG_ALLOW_REMOTE_REBOOT")
}

/// Whether this host's `agent.conf` lets the dashboard reboot it, as the
/// agent and the root hook read it: only an explicit true.
pub fn conf_allows_remote_reboot(conf: &str) -> bool {
    conf_remote_reboot(conf) == Some(true)
}

/// The installed `agent.conf`, when this process may read it (root only).
pub fn read_agent_conf() -> Option<String> {
    fs::read_to_string(AGENT_CONF_PATH).ok()
}

/// `key`'s value in an EnvironmentFile body: the last assignment wins, as
/// for systemd; surrounding quotes are removed and backslash escapes (as
/// `escape_env_value` writes them) undone.
pub fn conf_value(conf: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let raw = conf
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))?
        .trim();
    let inner = raw
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(raw);
    let mut value = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        value.push(if c == '\\' {
            chars.next().unwrap_or(c)
        } else {
            c
        });
    }
    Some(value)
}

/// `key` read as clap's boolish parser reads it; `None` when unset or not a
/// boolean.
pub fn conf_bool(conf: &str, key: &str) -> Option<bool> {
    match conf_value(conf, key)?.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "y" | "t" => Some(true),
        "false" | "0" | "no" | "off" | "n" | "f" => Some(false),
        _ => None,
    }
}

/// Create `/etc/connlog/agent.conf` if missing, upsert `key`, and restart the
/// service so systemd reloads the EnvironmentFile. Token, URL and BMC keys are
/// left as they are.
fn set_agent_conf_value(key: &str, value: &str) -> Result<()> {
    set_agent_conf_values(&[(key, value)])
}

/// `set_agent_conf_value` for several keys at once, with one restart.
fn set_agent_conf_values(pairs: &[(&str, &str)]) -> Result<()> {
    if !is_root() {
        anyhow::bail!("This command requires root. Please run with sudo.");
    }

    if !Path::new("/etc/connlog").exists() {
        create_config_dir()?;
    }

    let path = Path::new("/etc/connlog/agent.conf");
    let created = !path.exists();
    let existing = if created {
        String::new()
    } else {
        fs::read_to_string(path).context("Failed to read /etc/connlog/agent.conf")?
    };
    let mut next = existing;
    for (key, value) in pairs {
        validate_env_value(key, value)?;
        next = upsert_env_line(&next, key, value);
    }
    write_agent_conf(&next)?;

    if created {
        println!("  Created /etc/connlog/agent.conf (600 root:root)");
    }
    for (key, value) in pairs {
        println!("  Set {key}={value}");
    }

    restart_agent_service()
}

fn write_agent_conf(contents: &str) -> Result<()> {
    let path = Path::new("/etc/connlog/agent.conf");
    fs::write(path, contents).context("Failed to write /etc/connlog/agent.conf")?;

    let mut perms = fs::metadata(path)
        .context("Failed to read /etc/connlog/agent.conf metadata")?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .context("Failed to set /etc/connlog/agent.conf permissions")?;
    Ok(())
}

/// Replace or append `KEY="value"` in a systemd EnvironmentFile body.
/// Duplicate keys are collapsed to a single assignment.
fn upsert_env_line(existing: &str, key: &str, value: &str) -> String {
    let assignment = format!("{}=\"{}\"\n", key, escape_env_value(value));
    let prefix = format!("{key}=");
    let mut found = false;
    let mut out = String::new();
    for line in existing.lines() {
        if line.trim_start().starts_with(&prefix) {
            if !found {
                out.push_str(&assignment);
                found = true;
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found {
        out.push_str(&assignment);
    }
    out
}

fn restart_agent_service() -> Result<()> {
    if !Path::new(SYSTEMD_SERVICE_PATH).exists() {
        println!(
            "  Agent service is not installed. The setting is saved; start the agent to apply it."
        );
        return Ok(());
    }

    let status = system_command("systemctl")
        .args(["restart", "connlog-agent"])
        .status()
        .context("Failed to restart connlog-agent")?;
    if !status.success() {
        anyhow::bail!("Failed to restart connlog-agent. Try: sudo systemctl restart connlog-agent");
    }
    println!("  Restarted connlog-agent");
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

        // Root-owned and writable by root only: the ExecStopPost hook runs
        // this file as root, so it must not be anyone else's to change.
        let mut perms = fs::metadata(target_path)
            .context("Failed to read installed binary metadata")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(target_path, perms)
            .context("Failed to set installed binary permissions")?;
        std::os::unix::fs::chown(target_path, Some(0), Some(0))
            .context("Failed to set installed binary ownership")?;

        println!("  Installed binary to /usr/local/bin/connlog-agent (0755 root:root)");
    }

    crate::update::assert_live_binary_trusted()?;

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
    let status = system_command("systemctl")
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
    let is_active = system_command("systemctl")
        .args(["is-active", "--quiet", "connlog-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let action = if is_active { "restart" } else { "start" };

    let status = system_command("systemctl")
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

    #[test]
    fn conf_value_reads_the_last_assignment_and_undoes_escapes() {
        let conf = concat!(
            "CONNLOG_TOKEN=\"agent_first\"\n",
            "  CONNLOG_TOKEN=\"agent_second\"  \n",
            "CONNLOG_PLATFORM_URL=https://x\n",
        );
        assert_eq!(
            conf_value(conf, "CONNLOG_TOKEN").as_deref(),
            Some("agent_second")
        );
        assert_eq!(
            conf_value(conf, "CONNLOG_PLATFORM_URL").as_deref(),
            Some("https://x")
        );
        assert_eq!(conf_value(conf, "CONNLOG_EXPOSE_SYSTEM_INFO"), None);
        // What the writer escapes comes back as it was.
        let secret = "p\"$`\\w";
        let written = upsert_env_line("", "CONNLOG_BMC_PASSWORD", secret);
        assert_eq!(
            conf_value(&written, "CONNLOG_BMC_PASSWORD").as_deref(),
            Some(secret)
        );
    }

    #[test]
    fn conf_bool_reads_like_clap() {
        for (value, expected) in [
            ("true", Some(true)),
            ("\"YES\"", Some(true)),
            ("1", Some(true)),
            ("off", Some(false)),
            ("\"0\"", Some(false)),
            ("maybe", None),
        ] {
            let conf = format!("CONNLOG_SHARE_POSTMORTEM={value}\n");
            assert_eq!(
                conf_bool(&conf, "CONNLOG_SHARE_POSTMORTEM"),
                expected,
                "{value}"
            );
        }
        assert_eq!(conf_bool("", "CONNLOG_SHARE_POSTMORTEM"), None);
    }

    #[test]
    fn conf_remote_reboot_reading() {
        for (conf, expected) in [
            ("", None),
            ("CONNLOG_TOKEN=\"t\"\n", None),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\n", Some(false)),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=0\n", Some(false)),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=\"true\"\n", Some(true)),
            ("  CONNLOG_ALLOW_REMOTE_REBOOT=\"YES\"  \n", Some(true)),
            ("CONNLOG_ALLOW_REMOTE_REBOOT=maybe\n", None),
            // The last assignment wins, as for systemd's EnvironmentFile.
            (
                "CONNLOG_ALLOW_REMOTE_REBOOT=false\nCONNLOG_ALLOW_REMOTE_REBOOT=true\n",
                Some(true),
            ),
            (
                "CONNLOG_ALLOW_REMOTE_REBOOT=true\nCONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\n",
                Some(false),
            ),
        ] {
            assert_eq!(conf_remote_reboot(conf), expected, "{conf:?}");
        }
    }

    #[test]
    fn upsert_creates_file_body_when_empty() {
        assert_eq!(
            upsert_env_line("", "CONNLOG_EXPOSE_SYSTEM_INFO", "true"),
            "CONNLOG_EXPOSE_SYSTEM_INFO=\"true\"\n"
        );
    }

    #[test]
    fn upsert_appends_without_touching_token() {
        let existing =
            "CONNLOG_TOKEN=\"agent_abc\"\nCONNLOG_PLATFORM_URL=\"https://connlog.com\"\n";
        let next = upsert_env_line(existing, "CONNLOG_EXPOSE_SYSTEM_INFO", "true");
        assert!(next.contains("CONNLOG_TOKEN=\"agent_abc\""));
        assert!(next.contains("CONNLOG_PLATFORM_URL=\"https://connlog.com\""));
        assert!(next.contains("CONNLOG_EXPOSE_SYSTEM_INFO=\"true\""));
        assert_eq!(
            next.matches("CONNLOG_EXPOSE_SYSTEM_INFO=").count(),
            1,
            "must not duplicate the key"
        );
    }

    #[test]
    fn upsert_replaces_existing_false_value() {
        let existing = "CONNLOG_TOKEN=\"agent_abc\"\nCONNLOG_EXPOSE_SYSTEM_INFO=\"false\"\n";
        let next = upsert_env_line(existing, "CONNLOG_EXPOSE_SYSTEM_INFO", "true");
        assert!(next.contains("CONNLOG_EXPOSE_SYSTEM_INFO=\"true\""));
        assert!(!next.contains("false"));
        assert!(next.contains("CONNLOG_TOKEN=\"agent_abc\""));
    }

    #[test]
    fn upsert_collapses_duplicate_keys() {
        let existing = "CONNLOG_EXPOSE_SYSTEM_INFO=false\nCONNLOG_TOKEN=\"t\"\nCONNLOG_EXPOSE_SYSTEM_INFO=true\n";
        let next = upsert_env_line(existing, "CONNLOG_EXPOSE_SYSTEM_INFO", "true");
        assert_eq!(next.matches("CONNLOG_EXPOSE_SYSTEM_INFO=").count(), 1);
        assert!(next.contains("CONNLOG_TOKEN=\"t\""));
    }

    // ── The ExecStopPost hook, run ───────────────────────────────
    //
    // String checks cannot say whether the hook reboots, refuses or brings
    // the agent back. These run the script bash would receive, against a
    // scratch /run/connlog and /etc/connlog, with `systemctl` and
    // `systemd-run` stubbed to record their arguments.

    /// The ExecStopPost script as bash receives it: systemd joins continuation
    /// lines (the backslash becomes a space), skips comment lines inside
    /// them (`#` and `;` alike, which is why the hook has no `case ... ;;`),
    /// and turns `$$` into `$`.
    fn exec_stop_post_script() -> String {
        const PREFIX: &str = "ExecStopPost=+/bin/bash -c '";
        let start = SYSTEMD_SERVICE.find(PREFIX).expect("ExecStopPost hook");
        let mut joined = String::new();
        for line in SYSTEMD_SERVICE[start..].lines() {
            let trimmed = line.trim_start();
            if !joined.is_empty() && (trimmed.starts_with('#') || trimmed.starts_with(';')) {
                continue;
            }
            match line.strip_suffix('\\') {
                Some(head) => {
                    joined.push_str(head);
                    joined.push(' ');
                }
                None => {
                    joined.push_str(line);
                    break;
                }
            }
        }
        let script = joined
            .strip_prefix(PREFIX)
            .and_then(|rest| rest.strip_suffix('\''))
            .expect("one single-quoted bash -c argument");
        assert!(
            !script.contains('\''),
            "a quote would end the argument early"
        );
        assert!(
            !script.contains('\\'),
            "systemd unescapes backslashes; bash must see what the unit says"
        );
        assert!(
            !script.replace("%%", "").contains('%'),
            "a bare % is a systemd specifier"
        );
        script.replace("$$", "$")
    }

    struct HookRun {
        calls: Vec<String>,
        marker_left: bool,
    }

    fn run_reboot_hook(conf: Option<&str>, reboot_exit: u8, systemd_run_exit: u8) -> HookRun {
        use std::sync::atomic::{AtomicU32, Ordering};
        static RUN: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "connlog-hook-{}-{}",
            std::process::id(),
            RUN.fetch_add(1, Ordering::SeqCst)
        ));
        let (run, etc, bin) = (root.join("run"), root.join("etc"), root.join("bin"));
        for dir in [&run, &etc, &bin] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(run.join(".reboot_requested"), "test").unwrap();
        if let Some(conf) = conf {
            fs::write(etc.join("agent.conf"), conf).unwrap();
        }
        let calls = root.join("calls");
        for (stub, exit) in [
            ("systemctl", reboot_exit),
            ("systemd-run", systemd_run_exit),
        ] {
            let body = format!(
                "#!/bin/sh\necho \"{stub} $*\" >> {calls}\nif [ \"{stub}\" = systemd-run ] || [ \"$1\" = reboot ]; then exit {exit}; fi\n",
                calls = calls.display()
            );
            let path = bin.join(stub);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let script = exec_stop_post_script()
            .replace("/run/connlog", &run.display().to_string())
            .replace("/etc/connlog", &etc.display().to_string());
        let status = Command::new("/bin/bash")
            .arg("-c")
            .arg(&script)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .status()
            .expect("run hook");
        assert!(status.success(), "hook exited {status}");

        let result = HookRun {
            calls: fs::read_to_string(&calls)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect(),
            marker_left: run.join(".reboot_requested").exists(),
        };
        let _ = fs::remove_dir_all(&root);
        result
    }

    const ALLOWS_REBOOT: &str = "CONNLOG_ALLOW_REMOTE_REBOOT=\"true\"\n";

    #[test]
    fn reboot_hook_reboots_only_when_the_host_allows_it() {
        for conf in [
            ALLOWS_REBOOT,
            "CONNLOG_ALLOW_REMOTE_REBOOT=1\n",
            "  CONNLOG_ALLOW_REMOTE_REBOOT=\"YES\"  \n",
            "CONNLOG_ALLOW_REMOTE_REBOOT=on\n",
            // The last assignment wins.
            "CONNLOG_ALLOW_REMOTE_REBOOT=false\nCONNLOG_ALLOW_REMOTE_REBOOT=true\n",
        ] {
            let run = run_reboot_hook(Some(conf), 0, 0);
            assert_eq!(run.calls, ["systemctl reboot --no-block"], "{conf:?}");
            assert!(!run.marker_left);
            assert_eq!(
                conf_remote_reboot(conf),
                Some(true),
                "the agent and the hook must read {conf:?} the same way"
            );
        }
    }

    #[test]
    fn reboot_hook_refuses_unless_the_host_allows_it() {
        for conf in [
            None,
            Some("CONNLOG_TOKEN=\"t\"\n"),
            Some("CONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\n"),
            Some("CONNLOG_ALLOW_REMOTE_REBOOT=0\n"),
            Some("  CONNLOG_ALLOW_REMOTE_REBOOT=\"FALSE\"  \n"),
            Some("CONNLOG_ALLOW_REMOTE_REBOOT=maybe\n"),
            Some("CONNLOG_ALLOW_REMOTE_REBOOT=\n"),
            Some("CONNLOG_ALLOW_REMOTE_REBOOT=true\nCONNLOG_ALLOW_REMOTE_REBOOT=\"false\"\n"),
        ] {
            let run = run_reboot_hook(conf, 0, 0);
            assert_eq!(
                run.calls,
                ["systemctl start --no-block connlog-agent"],
                "{conf:?}"
            );
            assert!(!run.marker_left);
            assert_ne!(
                conf.and_then(conf_remote_reboot),
                Some(true),
                "the agent and the hook must read {conf:?} the same way"
            );
        }
    }

    #[test]
    fn reboot_hook_falls_back_then_brings_the_agent_back() {
        let run = run_reboot_hook(Some(ALLOWS_REBOOT), 1, 0);
        assert_eq!(run.calls.len(), 2, "{:?}", run.calls);
        assert!(run.calls[1].starts_with("systemd-run --collect --on-active=2s"));

        let run = run_reboot_hook(Some(ALLOWS_REBOOT), 1, 1);
        assert_eq!(run.calls.len(), 3, "{:?}", run.calls);
        assert_eq!(run.calls[2], "systemctl start --no-block connlog-agent");
    }

    // ── SYSTEMD_SERVICE invariants ──────────────────────────────
    //
    // The systemd unit is a string blob. These tests pin the security and
    // self-update properties that, if broken, would silently leave production
    // agents unable to update or expose them to privilege escalation.

    #[test]
    fn systemd_unit_collects_last_words_as_root_without_blocking_start() {
        let line = SYSTEMD_SERVICE
            .lines()
            .find(|l| l.starts_with("ExecStartPre="))
            .expect("ExecStartPre");
        // `-`: a failure never blocks the start. `+`: root, for the journal.
        assert_eq!(
            line,
            "ExecStartPre=-+/usr/local/bin/connlog-agent collect-postmortem"
        );
    }

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
        assert!(SYSTEMD_SERVICE.contains("/run/connlog/.reboot_requested"));
        assert!(
            SYSTEMD_SERVICE.contains("systemctl reboot --no-block"),
            "reboot must be non-blocking or ExecStopPost deadlocks"
        );
        assert!(
            !SYSTEMD_SERVICE.contains("systemctl reboot;"),
            "synchronous systemctl reboot inside ExecStopPost deadlocks"
        );
        assert!(SYSTEMD_SERVICE.contains("apply-staged-update"));
        assert!(SYSTEMD_SERVICE.contains("ConnLog: Update not applied"));
    }

    /// The update hook must never move anything out of /run/connlog on trust.
    /// That directory is writable by the unprivileged service account, so the
    /// only path into /usr/local/bin is `apply-staged-update`, which verifies
    /// the staged bytes with the installed binary's own key first.
    #[test]
    fn systemd_unit_update_hook_verifies_before_swapping() {
        assert!(
            SYSTEMD_SERVICE.contains("/usr/local/bin/connlog-agent apply-staged-update"),
            "the installed binary must verify and apply the staged update"
        );
        assert!(
            !SYSTEMD_SERVICE.contains("cp /run/connlog/")
                && !SYSTEMD_SERVICE.contains("mv /run/connlog/connlog-agent-new"),
            "the hook must not copy a file from /run/connlog into place itself"
        );
        assert!(
            SYSTEMD_SERVICE.contains("rm -f /run/connlog/.update_requested /run/connlog/connlog-agent-new /run/connlog/connlog-agent-new.sig"),
            "the staged binary, its signature and the marker are removed after every attempt"
        );
    }

    /// A rejected or failed update must leave the host with a running agent,
    /// not a stopped one.
    #[test]
    fn systemd_unit_update_hook_always_starts_the_service_again() {
        let update_branch = SYSTEMD_SERVICE
            .split("elif [ -f /run/connlog/.uninstall_requested ]")
            .next()
            .expect("update branch precedes the uninstall branch");
        assert!(
            update_branch.contains("systemctl start connlog-agent"),
            "the update branch must start the service whether or not the update applied"
        );
        assert!(
            !update_branch.contains("exit 1"),
            "the update branch must not exit early and leave the service stopped"
        );
    }

    /// Uninstall means uninstall: config, local diagnostics and the binary
    /// (with any swap leftovers) all go.
    #[test]
    fn systemd_unit_uninstall_removes_state_and_binaries() {
        assert!(SYSTEMD_SERVICE.contains("rm -rf /etc/connlog /var/lib/connlog"));
        assert!(SYSTEMD_SERVICE.contains(
            "rm -f /usr/local/bin/connlog-agent /usr/local/bin/connlog-agent.old /usr/local/bin/connlog-agent.new"
        ));
    }

    /// The service-file refresh temp file must be created on the same
    /// filesystem as the destination so that `mv` is an atomic rename().
    /// Writing to /run (tmpfs) and then mv-ing to /etc (root fs) crosses
    /// filesystem boundaries — the kernel falls back to copy+unlink, which
    /// is NOT atomic.
    #[test]
    fn systemd_unit_service_file_refresh_is_atomic() {
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
    fn token_format_is_agent_prefix_plus_64_hex() {
        let good = format!("agent_{}", "ab".repeat(32));
        assert!(validate_token_format(&good).is_ok());
        for bad in [
            "agent_short",
            "token_0000",
            "",
            &format!("agent_{}\n", "ab".repeat(32)),
            &format!("agent_{}", "zz".repeat(32)),
        ] {
            assert!(validate_token_format(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn env_values_with_control_characters_are_refused() {
        assert!(validate_env_value("X", "https://connlog.com").is_ok());
        for bad in ["a\nb", "a\rb", "a\0b", "tab\tvalue"] {
            assert!(validate_env_value("X", bad).is_err(), "{bad:?}");
        }
    }

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
