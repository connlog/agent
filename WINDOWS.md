# ConnLog Agent on Windows

The ConnLog agent runs on Windows 10, Windows 11, and Windows Server 2016+
as a native Windows service. It uses the same heartbeat protocol, the same
update channel, and the same Rust crate as the Linux build — the differences
are confined to the `install/`, `service/`, and `platform/` modules.

> **Status:** GA in v1.2.0. Built nightly in CI on `windows-latest`. The
> Windows release is currently unsigned; see
> [Windows security notice](#windows-security-notice) and
> [Security model](#security-model) for the current trust boundaries.

---

## Install

Run **PowerShell as Administrator** and paste:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://connlog.com/install/windows.ps1 | iex; Install-ConnLogAgent -AgentToken 'agent_xxxxxxxxxxxx'"
```

This:

1. Downloads `connlog-agent.exe` from `https://connlog.com/api/agents/updates/windows/x86_64/binary`.
2. Verifies the SHA-256 against the value published by the platform (which itself derives from the GitHub release `.sha256` asset).
3. Copies the EXE to `C:\Program Files\ConnLog\Agent\connlog-agent.exe`.
4. Hands off to `connlog-agent.exe install --token <token>`, which:
   - Encrypts the token with **DPAPI** (LocalMachine scope) and writes it to `C:\ProgramData\ConnLog\Agent\agent.conf`.
   - Tightens the ACL on `agent.conf` to **Administrators + SYSTEM only** (Authenticated Users / Users / Everyone are removed).
   - Registers the Windows service `connlog-agent` (display name *ConnLog Agent*) with auto-start and a recovery action of "restart after 60 s, three times".
   - Starts the service.

Idempotent: if the service already exists, re-running with `-Force` reinstalls. Re-running without `-Force` prints a hint and exits.

## Windows security notice

The Windows agent is not code-signed yet, so Windows SmartScreen may show an
"Unknown publisher" warning during installation.

ConnLog is a small independent startup, and signed Windows releases are part
of our roadmap as the product matures. Until then, we keep the installer
transparent: it downloads only from `connlog.com` over HTTPS and verifies the
SHA-256 checksum before installing the agent.

The agent runs as a Windows service and only communicates outbound with the
ConnLog API. The full agent source code is public and can be reviewed at
[github.com/connlog/connlog-agent](https://github.com/connlog/connlog-agent).

For managed environments, ask your IT administrator to review the installer
and source code before running it.

To rotate the token without reinstalling everything:

```powershell
& 'C:\Program Files\ConnLog\Agent\connlog-agent.exe' install --token <new-token>
```

## Uninstall

```powershell
& 'C:\Program Files\ConnLog\Agent\connlog-agent.exe' uninstall
```

This stops the service, deletes it from the SCM, removes
`C:\ProgramData\ConnLog\Agent\` (including the encrypted token), and deletes
the EXE. If the EXE can't be deleted because it's in use, it is queued for
deletion on next reboot via `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`.

## Status

```powershell
& 'C:\Program Files\ConnLog\Agent\connlog-agent.exe' status
# or
Get-Service connlog-agent
sc.exe query connlog-agent
```

## Files & locations

| Path                                                 | Purpose                                              |
| ---------------------------------------------------- | ---------------------------------------------------- |
| `C:\Program Files\ConnLog\Agent\connlog-agent.exe`   | The agent binary (read-only after install).          |
| `C:\ProgramData\ConnLog\Agent\agent.conf`            | DPAPI-encrypted token + plaintext platform URL.      |
| `C:\ProgramData\ConnLog\Agent\logs\`                 | Service-fatal log written when initialisation fails. |
| `C:\ProgramData\ConnLog\Agent\connlog-agent-new.exe` | Staged update binary (transient).                    |
| `C:\ProgramData\ConnLog\Agent\.update_requested`     | Marker file consumed by the recovery / restart path. |
| `C:\ProgramData\ConnLog\Agent\.uninstall_requested`  | Marker file consumed by the recovery / cleanup path. |

## Service account

The service runs as **LocalSystem**. This is required so that:

1. The DPAPI blob in `agent.conf` (encrypted under the machine scope) can be decrypted.
2. The agent can read its own config and write to `C:\ProgramData\ConnLog\Agent\` without having to negotiate ACLs with another principal.

A future hardening pass can evaluate `NT AUTHORITY\NetworkService` after install.

## Auto-update on Windows

Updates are server-driven, identical to Linux: the platform heartbeat
response advertises a new version + signed download URL. The agent verifies
**SHA-256** and **Ed25519** against its compiled-in public key, writes the new
EXE to `C:\ProgramData\ConnLog\Agent\connlog-agent-new.exe`, writes the
`.update_requested` marker, and exits with code 0.

The Windows service's recovery actions restart the agent after a brief delay.
On the next start, the agent (TODO in v1.2.x) detects the marker, atomically
replaces `C:\Program Files\ConnLog\Agent\connlog-agent.exe` with the staged
file, removes the marker, and continues. Until that helper ships, an
operator can complete the swap manually:

```powershell
Stop-Service connlog-agent
Move-Item -Force `
  'C:\ProgramData\ConnLog\Agent\connlog-agent-new.exe' `
  'C:\Program Files\ConnLog\Agent\connlog-agent.exe'
Remove-Item 'C:\ProgramData\ConnLog\Agent\.update_requested'
Start-Service connlog-agent
```

## Security model

Current protections:

- **Token exfiltration via casual file read.** `agent.conf` is DPAPI-encrypted
  under the machine scope; copying the file off the host yields ciphertext
  that the destination can't decrypt.
- **Token exfiltration via low-privilege accounts.** The ACL on `agent.conf`
  removes Authenticated Users / Users / Everyone, leaving Administrators +
  SYSTEM only.
- **Update tampering.** All updates verify SHA-256 + Ed25519 against the
  agent's compiled-in public key, end-to-end, regardless of where the bytes
  came from. The platform proxy is untrusted.
- **TLS interception.** All platform calls go to `https://connlog.com` with
  rustls' default cert validation.

Current limitations:

- **A local administrator** can read DPAPI blobs because they are encrypted
  under the machine scope. If your threat model includes hostile local
  administrators, the current Windows agent is not a good fit.
- **A compromised SYSTEM process** can also decrypt the DPAPI blob for the same
  reason.
- **Unsigned Windows release.** The EXE and installer are not code-signed yet,
  so Windows SmartScreen may show an "Unknown publisher" warning. The installer
  downloads only from `connlog.com` over HTTPS and verifies the SHA-256 checksum
  before placing the binary. This verifies the expected file integrity, but it
  is not the same as publisher signing. ConnLog is working toward signed Windows
  releases as the product matures. In managed environments with WDAC, App
  Control for Business, or AppLocker, ask your IT administrator to review the
  installer and source code before installing.
- **No anti-tamper.** The agent does not detect or resist a local admin
  modifying its EXE. Integrity is enforced *before* install (SHA-256 + Ed25519
  on the download path), not after.

## Troubleshooting

| Symptom                                           | What to check                                                                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `Install-ConnLogAgent` fails immediately          | You're not in an elevated PowerShell. Right-click → *Run as Administrator*.                                            |
| `Get-Service connlog-agent` says *Stopped*        | Check `C:\ProgramData\ConnLog\Agent\logs\service-fatal.log`. Most common cause: corrupt `agent.conf` (re-run install). |
| `Start-Service` returns 1053 (timed out)          | The agent panicked before reporting `SERVICE_RUNNING`. Same log as above.                                              |
| Defender / SmartScreen blocks the installer       | The Windows release is currently unsigned. In managed environments, ask your IT administrator to review the installer and source code before installing. |
| Disk usage in dashboard looks wrong               | Open an issue with the fixed-drive details. The agent skips UNC mounts and relies on sysinfo for fixed-drive enumeration. |
| Agent's `arch` shows `aarch64` on a Surface Pro X | Expected. ARM64 Windows is built into the same release matrix.                                                         |
