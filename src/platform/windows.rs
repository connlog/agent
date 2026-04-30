//! Windows paths and primitives.
//!
//! Layout:
//!   - Binary:        C:\Program Files\ConnLog\Agent\connlog-agent.exe
//!   - Staged binary: C:\ProgramData\ConnLog\Agent\connlog-agent-new.exe
//!   - Config:        C:\ProgramData\ConnLog\Agent\agent.conf
//!   - Logs:          C:\ProgramData\ConnLog\Agent\logs\
//!   - Markers:       C:\ProgramData\ConnLog\Agent\.update_requested
//!                    C:\ProgramData\ConnLog\Agent\.uninstall_requested
//!
//! `C:\Program Files` is the conventional read-only location for installed
//! binaries; `C:\ProgramData` is the writable per-machine application data
//! root. Both inherit ACLs that grant Administrators full control and
//! Authenticated Users read access — we tighten that on the config file
//! using `icacls` after install (see `install::windows`).

pub const INSTALLED_BINARY: &str = r"C:\Program Files\ConnLog\Agent\connlog-agent.exe";
pub const STAGED_BINARY: &str = r"C:\ProgramData\ConnLog\Agent\connlog-agent-new.exe";
pub const UPDATE_MARKER: &str = r"C:\ProgramData\ConnLog\Agent\.update_requested";
pub const UNINSTALL_MARKER: &str = r"C:\ProgramData\ConnLog\Agent\.uninstall_requested";
pub const CONFIG_DIR: &str = r"C:\ProgramData\ConnLog\Agent";
pub const CONFIG_FILE: &str = r"C:\ProgramData\ConnLog\Agent\agent.conf";
pub const LOG_DIR: &str = r"C:\ProgramData\ConnLog\Agent\logs";

/// Internal Windows service name. Visible in `sc query`, `Get-Service`, etc.
pub const SERVICE_NAME: &str = "connlog-agent";

/// Display name shown in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "ConnLog Agent";

/// Helper that the SCM-launched binary uses to enter service mode.
pub const SERVICE_ARG: &str = "--run-service";

/// Returns true when the current process token has elevated (admin) privileges.
///
/// Uses `windows-sys` GetTokenInformation on the process token. Safe to call
/// from any thread, returns false on any failure (treated as "not admin").
pub fn is_admin() -> bool {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            return false;
        }

        let mut elevation = MaybeUninit::<TOKEN_ELEVATION>::uninit();
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            elevation.as_mut_ptr() as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let elevated = ok != FALSE && elevation.assume_init().TokenIsElevated != 0;
        CloseHandle(token);
        elevated
    }
}
