# ConnLog Agent on Windows

The ConnLog agent runs on Windows 10, Windows 11, and Windows Server 2016+
as a native Windows service. It uses the same heartbeat protocol, the same
update channel, and the same Rust crate as the Linux build — the differences
are confined to the `install/`, `service/`, and `platform/` modules.

> **Status:** GA in v1.2.0. Built nightly in CI on `windows-latest`. The
> agent is **not** "100% secure" — see [Security model](#security-model)
> for the honest take on what we do and do not protect against.

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

A future hardening pass can drop to `NT AUTHORITY\NetworkService` after install — that's a follow-up, not a v1.2 ship blocker.

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

What the agent **does** protect against:

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

What the agent **does not** protect against (and we will not pretend it does):

- **A local administrator** can read DPAPI blobs because they are encrypted
  under the machine scope. If your threat model is hostile local admins, this
  is the wrong tool.
- **A compromised SYSTEM process** can also decrypt the DPAPI blob. Same
  reason.
- **No Authenticode signing.** The EXE ships unsigned. Defender SmartScreen
  will warn on first run — click *More info → Run anyway*. The installer
  verifies the SHA-256 checksum before placing the binary, so integrity is
  guaranteed even without a CA signature. In managed environments with WDAC,
  App Control for Business, or AppLocker, unsigned binaries may be blocked
  entirely and will need explicit allow-listing by hash or path.
- **No anti-tamper.** The agent does not detect or resist a local admin
  modifying its EXE. Integrity is enforced *before* install (SHA-256 + Ed25519
  on the download path), not after.

## Troubleshooting

| Symptom                                           | What to check                                                                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `Install-ConnLogAgent` fails immediately          | You're not in an elevated PowerShell. Right-click → *Run as Administrator*.                                            |
| `Get-Service connlog-agent` says *Stopped*        | Check `C:\ProgramData\ConnLog\Agent\logs\service-fatal.log`. Most common cause: corrupt `agent.conf` (re-run install). |
| `Start-Service` returns 1053 (timed out)          | The agent panicked before reporting `SERVICE_RUNNING`. Same log as above.                                              |
| Defender / SmartScreen blocks the installer       | Click *More info -> Run anyway*. The binary is unsigned; WDAC/AppLocker envs need an explicit allow-list entry.        |
| Disk usage in dashboard looks wrong               | Filed → file an issue. We skip UNC mounts and rely on sysinfo for fixed-drive enumeration; bugs in that surface here.  |
| Agent's `arch` shows `aarch64` on a Surface Pro X | Expected. ARM64 Windows is built into the same release matrix.                                                         |
