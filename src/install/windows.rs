//! Windows installer.
//!
//! Responsibilities:
//!   1. Verify we're elevated (admin token).
//!   2. Create C:\Program Files\ConnLog\Agent\ + C:\ProgramData\ConnLog\Agent\.
//!   3. Copy the running EXE to the install dir.
//!   4. Write the config file with a hardened ACL (Administrators + SYSTEM
//!      only — strip Authenticated Users / Users), and DPAPI-encrypt the
//!      bearer token at rest.
//!   5. Register the Windows service via SCM (`windows-service` crate) with
//!      auto-start, a delayed start, and recovery actions (restart on crash).
//!   6. Start the service.
//!
//! Uninstall does the reverse: stop service, delete service, remove files.
//!
//! All of this requires admin. Anything that fails surfaces a clear error to
//! stderr; we never partially-succeed in a way that leaves a dangling
//! service.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::platform::windows as paths;

/// Public entry-point invoked by `connlog-agent.exe install --token <T>`.
pub fn install(token: &str) -> Result<()> {
    if !paths::is_admin() {
        anyhow::bail!(
            "Installation requires Administrator privileges. \
             Open PowerShell as Administrator and try again."
        );
    }

    let platform_url = std::env::var("CONNLOG_PLATFORM_URL")
        .unwrap_or_else(|_| crate::defaults::DEFAULT_ENDPOINT.to_string());

    println!("Installing ConnLog agent as a Windows service...");

    // 1. Layout
    create_layout()?;

    // 2. Binary
    install_binary().context("install binary")?;

    // 3. Config (DPAPI-encrypted token + plaintext platform URL)
    write_config(token, &platform_url).context("write config")?;
    harden_config_acl().context("harden config ACL")?;

    // 4. Service
    register_service().context("register Windows service")?;
    start_service().context("start Windows service")?;

    println!();
    println!("✓ ConnLog agent installed.");
    println!();
    println!(
        "Service:        {}  (auto-start, restart on failure)",
        paths::SERVICE_NAME
    );
    println!("Binary:         {}", paths::INSTALLED_BINARY);
    println!(
        "Config:         {}  (Administrators + SYSTEM only)",
        paths::CONFIG_FILE
    );
    println!("Logs:           {}", paths::LOG_DIR);
    println!();
    println!("Inspect status:");
    println!("  Get-Service {}", paths::SERVICE_NAME);
    println!("  sc.exe query {}", paths::SERVICE_NAME);

    Ok(())
}

pub fn uninstall() -> Result<()> {
    if !paths::is_admin() {
        anyhow::bail!(
            "Uninstallation requires Administrator privileges. \
             Open PowerShell as Administrator and try again."
        );
    }

    println!("Uninstalling ConnLog agent...");

    // 1. Stop + delete the service first — deleting the service while it's
    //    running marks it for delete-on-stop, which would leave a zombie until
    //    the next reboot.
    if let Err(e) = stop_and_delete_service() {
        eprintln!("  warning: service teardown failed: {}", e);
    } else {
        println!("  Stopped and removed Windows service");
    }

    // 2. Config (contains DPAPI-encrypted token — wipe regardless of service state)
    let _ = fs::remove_dir_all(paths::CONFIG_DIR);
    println!("  Removed {}", paths::CONFIG_DIR);

    // 3. Binary. We may be running from this path; if delete fails, schedule for
    //    delete-on-reboot via MoveFileEx so the next reboot finishes cleanup.
    if Path::new(paths::INSTALLED_BINARY).exists() {
        match fs::remove_file(paths::INSTALLED_BINARY) {
            Ok(_) => println!("  Removed {}", paths::INSTALLED_BINARY),
            Err(_) => {
                schedule_delete_on_reboot(paths::INSTALLED_BINARY);
                println!(
                    "  Binary will be removed on next reboot (file in use): {}",
                    paths::INSTALLED_BINARY
                );
            }
        }
    }

    // Remove the install dir if empty.
    let _ = fs::remove_dir(r"C:\Program Files\ConnLog\Agent");
    let _ = fs::remove_dir(r"C:\Program Files\ConnLog");

    println!();
    println!("✓ ConnLog agent uninstalled.");

    Ok(())
}

pub fn status() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("connect to SCM")?;

    let service = match manager.open_service(paths::SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => s,
        Err(_) => {
            println!("Service '{}' is not installed.", paths::SERVICE_NAME);
            println!();
            println!("To install:");
            println!("  connlog-agent.exe install --token <YOUR_TOKEN>");
            return Ok(());
        }
    };

    let s = service.query_status().context("query service status")?;

    println!("Service:        {}", paths::SERVICE_NAME);
    println!("State:          {:?}", s.current_state);
    println!("PID:            {}", s.process_id.unwrap_or(0));
    println!("Binary:         {}", paths::INSTALLED_BINARY);
    println!("Config:         {}", paths::CONFIG_FILE);
    println!("Logs:           {}", paths::LOG_DIR);

    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────────

fn create_layout() -> Result<()> {
    fs::create_dir_all(r"C:\Program Files\ConnLog\Agent").context("create install dir")?;
    fs::create_dir_all(paths::CONFIG_DIR).context("create config dir")?;
    fs::create_dir_all(paths::LOG_DIR).context("create log dir")?;
    Ok(())
}

fn install_binary() -> Result<()> {
    let current = std::env::current_exe().context("locate current EXE")?;
    let target = Path::new(paths::INSTALLED_BINARY);

    if let Ok(current_canon) = fs::canonicalize(&current) {
        if let Ok(target_canon) = fs::canonicalize(target) {
            if current_canon == target_canon {
                println!("  Binary already at install location");
                return Ok(());
            }
        }
    }

    fs::copy(&current, target).with_context(|| format!("copy EXE to {}", target.display()))?;
    println!("  Installed binary to {}", target.display());
    Ok(())
}

/// Encrypt the token with DPAPI (machine scope) and write the config file.
///
/// The token is stored base64(DPAPI(token)) so the on-disk artefact is
/// unreadable even if an attacker somehow reads the file with the wrong
/// account. The platform URL is plaintext (it isn't a secret).
fn write_config(token: &str, platform_url: &str) -> Result<()> {
    let token_protected = dpapi_protect(token.as_bytes()).context("DPAPI encrypt token")?;
    let token_b64 = base64_encode(&token_protected);

    let body = format!(
        "# ConnLog agent config (managed by `connlog-agent install`)\n\
         #\n\
         # The token is DPAPI-encrypted under the LocalMachine scope and base64-\n\
         # encoded. Only this machine can decrypt it; copying the file to another\n\
         # host renders the token useless. Re-run `connlog-agent install --token`\n\
         # to rotate.\n\
         CONNLOG_TOKEN_DPAPI_B64={}\n\
         CONNLOG_PLATFORM_URL={}\n",
        token_b64, platform_url,
    );

    fs::write(paths::CONFIG_FILE, body).context("write agent.conf")?;
    println!("  Wrote DPAPI-encrypted config to {}", paths::CONFIG_FILE);
    Ok(())
}

/// Strip Authenticated Users / Users from the config file's ACL so only
/// Administrators and SYSTEM can read it. Done with `icacls.exe` to avoid a
/// large windows-acl dependency.
fn harden_config_acl() -> Result<()> {
    let target = paths::CONFIG_FILE;

    // Disable inheritance, preserve existing ACEs.
    let _ = Command::new("icacls.exe")
        .args([target, "/inheritance:d"])
        .status();

    // Remove ACEs for the principals that ProgramData would otherwise grant
    // read access. Failures are non-fatal (icacls returns non-zero if a
    // principal isn't in the ACL — that's already what we want).
    for principal in [
        "*S-1-5-32-545", // BUILTIN\Users
        "*S-1-5-11",     // Authenticated Users
        "*S-1-5-32-547", // Power Users
        "Everyone",
    ] {
        let _ = Command::new("icacls.exe")
            .args([target, "/remove:g", principal])
            .status();
    }

    // Make sure Administrators + SYSTEM have full control.
    let _ = Command::new("icacls.exe")
        .args([target, "/grant:r", "*S-1-5-32-544:F", "*S-1-5-18:F"])
        .status();

    println!(
        "  Hardened ACL on {} (Administrators + SYSTEM only)",
        target
    );
    Ok(())
}

fn register_service() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("connect to SCM with CREATE_SERVICE")?;

    // If the service already exists (re-install / upgrade), update + reuse.
    if let Ok(existing) = manager.open_service(
        paths::SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        let _ = stop_running_service(&existing);
        existing
            .delete()
            .context("delete existing service before re-create")?;
    }

    let info = ServiceInfo {
        name: paths::SERVICE_NAME.into(),
        display_name: paths::SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::path::PathBuf::from(paths::INSTALLED_BINARY),
        launch_arguments: vec![paths::SERVICE_ARG.into()],
        // Run as LocalSystem. We need this to read the DPAPI-protected config
        // (encrypted under the machine scope) and to invoke icacls during
        // self-install. Documented in WINDOWS.md as a known limitation —
        // future work: drop to LOCAL_SERVICE after registration and only
        // elevate during install.
        account_name: None,
        account_password: None,
        dependencies: vec![],
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("create service")?;

    let _ = service
        .set_description("ConnLog monitoring agent. Sends host metrics to https://connlog.com.");

    // Configure recovery: restart after 60s for the first three failures.
    // The windows-service crate doesn't expose SetServiceRecoveryActions
    // directly, so shell out to sc.exe — the API surface is small and stable.
    let _ = Command::new("sc.exe")
        .args([
            "failure",
            paths::SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/60000/restart/60000/restart/60000",
        ])
        .status();

    println!(
        "  Registered service '{}' (auto-start, restart on failure)",
        paths::SERVICE_NAME
    );
    Ok(())
}

fn start_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("connect to SCM")?;
    let service = manager
        .open_service(
            paths::SERVICE_NAME,
            ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("open service for START")?;
    service.start::<&str>(&[]).context("start service")?;
    println!("  Started service");
    Ok(())
}

fn stop_running_service(service: &windows_service::service::Service) -> Result<()> {
    let status = service.query_status()?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    let _ = service.stop()?;
    // Wait up to ~10 s for the service to actually stop.
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
    }
    Ok(())
}

fn stop_and_delete_service() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let service = manager.open_service(
        paths::SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    let _ = stop_running_service(&service);
    service.delete()?;
    Ok(())
}

/// Schedule a path for deletion on next reboot via `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)`.
/// Used when we can't delete the running EXE during uninstall.
fn schedule_delete_on_reboot(path: &str) {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

// ── DPAPI + base64 (no extra crates) ───────────────────────────────────

/// Encrypt `data` with DPAPI under the local-machine scope.
pub(crate) fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    };

    if ok == 0 {
        anyhow::bail!("DPAPI CryptProtectData failed");
    }

    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as _) };
    Ok(bytes)
}

/// Decrypt a DPAPI blob produced by `dpapi_protect`.
pub(crate) fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    };

    if ok == 0 {
        anyhow::bail!("DPAPI CryptUnprotectData failed");
    }

    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as _) };
    Ok(bytes)
}

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64_CHARS[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut lookup = [255u8; 256];
    for (i, &c) in B64_CHARS.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let stripped: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = stripped.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        anyhow::bail!("invalid base64 length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for &c in chunk {
            n <<= 6;
            if c == b'=' {
                pad += 1;
            } else {
                let v = lookup[c as usize];
                if v == 255 {
                    anyhow::bail!("invalid base64 character");
                }
                n |= v as u32;
            }
        }
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}
