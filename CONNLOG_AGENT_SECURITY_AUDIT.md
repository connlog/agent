# ConnLog Agent — Security Audit

**Version audited:** 0.2.1  
**Date:** 2025-02-06  
**Scope:** All Rust source (`src/`), systemd service definition, install scripts (`install.sh`, `dev-install.sh`)

---

## 1. Threat Model

### What the agent is
A lightweight Rust daemon deployed on customer Linux servers. It collects system metrics (CPU, memory, disk, load) and sends them as heartbeat payloads over HTTPS to the ConnLog platform. It runs continuously under systemd and accepts server-authoritative configuration.

### Attack surface

| Surface | Exposure | Trust boundary |
|---------|----------|---------------|
| **Network (outbound HTTPS)** | Single endpoint (`connlog.com`). Bearer token in every request. | TLS termination at platform; rustls for client-side TLS. |
| **Local filesystem** | Token at `/etc/connlog/agent.conf` (0600). Binary at `/usr/local/bin/`. Uninstall marker at `/run/connlog/`. | Root-only config; agent runs as `connlog-agent` user. |
| **Server-authoritative config** | Platform dictates heartbeat interval, metrics toggles, payload size, uninstall command. | Agent trusts signed-in responses; mitigated by client-side clamping. |
| **Self-uninstall** | Agent can remove itself on 410, remote uninstall flag, or 50 consecutive 401s. | Marker-file + systemd ExecStopPost. Controlled by platform auth. |
| **Supply chain** | GitHub Releases, SHA-256 checksum, `install.sh` via `curl \| sh`. | Checksum verification mandatory. |

### Threat actors

| Actor | Capability | Risk |
|-------|-----------|------|
| **Network MITM** | Intercept/modify traffic | Mitigated by TLS (rustls). No cert pinning — relies on system trust store. |
| **Co-tenant on shared host** | Read processes, probe filesystem | Token file 0600 root-only. Config dir 0700. Agent user has nologin shell. |
| **Compromised platform** | Send arbitrary config/commands | Interval clamped [10s, 86400s]. Only action is uninstall (not arbitrary exec). |
| **Compromised DNS/CDN** | Redirect HTTPS requests | Redirect policy set to `none` — token never follows redirects. |
| **Malicious workspace admin** | Revoke token, force uninstall | By design — workspace owners control their agents. |

### What the agent explicitly does NOT do
- Execute arbitrary commands from the server
- Download or run binaries (update info is informational only)
- Open inbound ports or listen on any socket
- Store or forward customer application data
- Modify system configuration beyond its own install footprint

---

## 2. Code Audit — File-Level Findings

### `src/main.rs` (339 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| M1 | **HIGH** | Non-401 errors used fixed 30s sleep — no exponential backoff. Extended outages cause steady 30s polling. | ✅ Fixed — exponential backoff 30→3600s |
| M2 | **MED** | No client-side clamping of `heartbeat_interval_secs`. Server sending 0 causes CPU spin. | ✅ Fixed — `config.clamp()` enforces [10, 86400] |
| M3 | **MED** | Uninstall marker written to `/etc/connlog/` (root-owned). Required agent to run as root. | ✅ Fixed — marker now at `/run/connlog/` (RuntimeDirectory) |
| M4 | **LOW** | `MAX_UNAUTHORIZED_ATTEMPTS = 50` is generous — 50 × backoff(60×n) = hours of 401 retries. | Acceptable — exponential backoff limits impact. Server-side token revocation is the primary control. |
| M5 | **INFO** | Token `String` not zeroed on drop. | Accepted risk — process memory is root-only, no crash dumps configured. Would require `zeroize` crate for marginal gain. |

### `src/http.rs` (140 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| H1 | **HIGH** | No redirect policy. Default reqwest follows 10 redirects — could leak Bearer token to attacker on DNS hijack. | ✅ Fixed — `Policy::none()` |
| H2 | **MED** | Single 10s timeout covers both connect and read. A slow-read attack holds the thread for 10s. | Acceptable — blocking client, single-threaded. 10s is reasonable. |
| H3 | **LOW** | `fetch_config()` logs full response text on parse failure. Could include unexpected server content. | Acceptable — logged at ERROR level, useful for debugging. No token exposure. |

### `src/heartbeat.rs` (110 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| B1 | **MED** | No bounds validation on deserialized config values from server. | ✅ Fixed — `clamp()` method added |
| B2 | **LOW** | `max_payload_size_kb` enforcement warns but sends anyway. | Acceptable — server is the real enforcement point. Client warning is informational. |

### `src/config.rs` (44 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| C1 | **LOW** | `--endpoint` flag is debug-only (`#[cfg(debug_assertions)]`). Good — prevents production abuse. | ✓ Already safe |
| C2 | **INFO** | Token accepted via `--token` CLI arg — visible in `/proc/PID/cmdline`. | Acceptable — systemd uses EnvironmentFile, not CLI args. Manual runs are operator-initiated. |

### `src/install.rs` (250 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| I1 | **CRITICAL** | Service ran as `User=root`. Agent only needs outbound HTTP + read `/proc`. Full root = any vuln = full compromise. | ✅ Fixed — `User=connlog-agent` with 20 sandboxing directives |
| I2 | **HIGH** | No systemd sandboxing directives at all. No `NoNewPrivileges`, `ProtectSystem`, etc. | ✅ Fixed — comprehensive sandbox (see §4) |
| I3 | **HIGH** | Token written to EnvironmentFile without quoting. Shell metacharacters in token → config injection. | ✅ Fixed — double-quoted with `\`, `"`, `$`, `` ` `` escaping |
| I4 | **MED** | `/etc/connlog/` created with umask-dependent permissions (typically 0755). Other users can list contents. | ✅ Fixed — explicit 0700 |
| I5 | **LOW** | Uninstall preserves `connlog-agent` system user. | ✓ By design — safer than removing a potentially-in-use UID. |

### `src/metrics.rs` (81 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| X1 | **INFO** | `System::new_all()` over-collects. Only needs CPU, memory, disk, load. | Accepted — performance, not security. |
| X2 | **INFO** | Only first disk reported. Multi-disk servers underreport. | Known limitation, not a security issue. |

### `install.sh` (228 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| S1 | **HIGH** | Checksum verification silently skipped if `sha256sum` not found. Binary installed without integrity check. | ✅ Fixed — mandatory, falls back to `shasum -a 256`, errors if neither available |
| S2 | **MED** | Unknown CLI arguments silently ignored. Typos like `--instal` go unnoticed. | ✅ Fixed — errors on unknown arguments |
| S3 | **LOW** | `curl \| sudo sh` pattern is inherently risky (pipe-to-shell). | Accepted — industry standard for agent installers. Checksum verification mitigates tampering. |

### `dev-install.sh` (69 lines)

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| D1 | **INFO** | Prints first 20 chars of token. | Acceptable for dev-only script. Contains `agent_` prefix + 14 chars of entropy. |

---

## 3. Failure Scenario Analysis

### Scenario: Platform is down for 24 hours
- **Before:** Agent retries every 30s forever = 2,880 requests during outage.
- **After:** Exponential backoff 30→60→120→...→3600s. ~30 requests total in 24h.
- **Agent state:** Keeps running with last-known config. Resumes normally on recovery.

### Scenario: Token is revoked server-side
- Agent receives 401 on heartbeat.
- Exponential backoff: 60s, 120s, 180s, ... up to 3600s.
- After 50 consecutive 401s (takes ~70+ hours with backoff), agent self-uninstalls.
- **Risk:** Zombie agent pings for hours. **Mitigation:** Server can send 410 Gone for immediate removal.

### Scenario: Compromised DNS redirects heartbeat
- **Before:** reqwest followed redirects, sending Bearer token to redirect target.
- **After:** Redirect policy `none` — request fails immediately. Agent retries to real endpoint on next cycle.

### Scenario: Server sends `heartbeat_interval_secs: 0`
- **Before:** `thread::sleep(Duration::from_secs(0))` = CPU spin, hundreds of heartbeats/sec.
- **After:** Clamped to minimum 10s. Logged if clamped.

### Scenario: Server sends uninstall command
- Agent writes marker to `/run/connlog/.uninstall_requested`.
- Exits with code 0 (`Restart=on-failure` does not restart on clean exit).
- systemd `ExecStopPost` (running as root via `+` prefix) detects marker → disables service → removes service file → removes config → removes binary.
- **Integrity:** Only the authenticated platform can trigger this (requires valid 200 response with `uninstall: true`).

### Scenario: Local user tries to read agent token
- Config file: `/etc/connlog/agent.conf` → 0600 root:root
- Config directory: `/etc/connlog/` → 0700 root:root
- Process environment: not visible to non-root (agent runs as `connlog-agent`)
- CLI args: token is in EnvironmentFile, not cmdline (not visible in `/proc/PID/cmdline`)

### Scenario: Agent binary has a remote code execution vulnerability
- **Before:** Running as root — full system compromise.
- **After:** Running as `connlog-agent` with sandbox:
  - `NoNewPrivileges` — can't escalate
  - `ProtectSystem=strict` — filesystem is read-only
  - `CapabilityBoundingSet=` — no capabilities
  - `MemoryDenyWriteExecute` — no JIT/shellcode
  - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` — no raw sockets
  - **Impact:** Attacker confined to read-only sandbox with no capabilities, cannot pivot.

---

## 4. Hardening Changes Applied

### 4a. Systemd service — privilege drop + sandbox

**Changed `User=root` → `User=connlog-agent`** and added:

```ini
# Wait for actual network connectivity
After=network-online.target
Wants=network-online.target

# Run as dedicated unprivileged user
User=connlog-agent
Group=connlog-agent

# Writable runtime directory for uninstall marker
RuntimeDirectory=connlog
RuntimeDirectoryMode=0700

# 20 sandboxing directives
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
```

`ExecStopPost` uses `+` prefix to run cleanup as root.

### 4b. HTTP client — redirect disabled

```rust
.redirect(reqwest::redirect::Policy::none())
```

Prevents Bearer token leakage on DNS hijack / open redirect.

### 4c. Config clamping

```rust
pub fn clamp(&mut self) {
    self.heartbeat_interval_secs = self.heartbeat_interval_secs.clamp(10, 86400);
    self.missed_threshold = self.missed_threshold.clamp(1, 100);
    if self.max_payload_size_kb > 0 {
        self.max_payload_size_kb = self.max_payload_size_kb.clamp(1, 1024);
    }
}
```

Called after every config fetch (initial + in-loop updates).

### 4d. Exponential backoff for general errors

```rust
// Before: fixed 30s
// After: 30 → 60 → 120 → 240 → ... → 3600s
let backoff = std::cmp::min(30 * 2u64.pow(n.min(7)), 3600);
```

### 4e. Config file hardening

- `/etc/connlog/` directory: explicit 0700 permissions
- `agent.conf` values: double-quoted with `\`, `"`, `$`, `` ` `` escaping
- Prevents shell injection via crafted token values

### 4f. Installer hardening (`install.sh`)

- Checksum verification: **mandatory** (sha256sum → shasum → error)
- Unknown arguments: **error** instead of silent ignore

---

## 5. Self-Uninstall Review

The agent can self-uninstall through three triggers:

| Trigger | Condition | Confidence |
|---------|-----------|-----------|
| **410 Gone** | Server explicitly decommissions agent | High — unambiguous server signal |
| **Remote uninstall** | `HeartbeatResponse.uninstall == true` | High — requires authenticated 200 OK response |
| **50× consecutive 401** | Token revoked/expired | Medium — could be transient auth infra failure |

### Mechanism (under systemd)

1. Agent writes reason string to `/run/connlog/.uninstall_requested`
2. Agent exits with code 0 (`Restart=on-failure` won't restart)
3. systemd runs `ExecStopPost` as root (`+` prefix)
4. Script checks for marker file → disables service → removes service file → daemon-reload → removes `/etc/connlog` → removes binary

### Mechanism (standalone / no systemd)

1. Agent calls `install::uninstall()` directly
2. Stops/disables service, removes files, removes config

### Safety properties

- ✅ Only authenticated server responses can trigger uninstall
- ✅ 401 trigger requires 50 consecutive failures (not a single transient error)
- ✅ Clean exit code prevents systemd restart loop
- ✅ Marker file lives in `/run/connlog/` (RuntimeDirectory, connlog-agent writable)
- ✅ Cleanup runs as root via `+` prefix (can remove service files and binary)
- ✅ `Restart=on-failure` distinguishes clean shutdown (exit 0) from crash

### Residual risk

A prolonged platform auth outage (>70 hours of continuous 401s) could trigger unintended self-uninstall. Mitigation: platform should return 503 (not 401) during maintenance. The agent only self-uninstalls on 401, not on 5xx errors.

---

## 6. Remaining Accepted Risks

| Risk | Severity | Justification |
|------|----------|---------------|
| Token `String` not zeroed in memory | LOW | Process memory requires root to read. No core dumps configured. `zeroize` crate adds complexity for minimal gain in this threat model. |
| No TLS certificate pinning | LOW | Relies on system trust store via rustls. Pinning is fragile (cert rotation) and this isn't a high-value financial target. |
| `curl \| sh` install pattern | LOW | Industry standard. Now protected by mandatory SHA-256 checksum verification. |
| Token visible in `/proc/PID/cmdline` during manual runs | LOW | Only during operator-initiated manual runs. Systemd uses EnvironmentFile. |
| sysinfo over-collection | INFO | Collects all system info even when some metrics are disabled. Performance, not security. |
| Single 10s timeout (connect + read) | INFO | Blocking single-threaded client. 10s is reasonable. Slow-read attack impact = 10s delay per cycle. |

---

## 7. Security Posture Statement

The ConnLog Agent has a deliberately minimal attack surface: it is a read-only monitoring daemon that makes outbound HTTPS calls and executes zero server-supplied commands. After this audit, the agent runs as an unprivileged `connlog-agent` user inside a comprehensive systemd sandbox (20 hardening directives, zero capabilities, read-only filesystem, architecture-locked syscalls). All server-supplied configuration is clamped to safe bounds client-side. The HTTP client refuses redirects to prevent Bearer token leakage. Token storage is root-only (0600 in a 0700 directory), and the install pipeline now requires mandatory SHA-256 checksum verification. The self-uninstall mechanism is gated behind authenticated server responses with a high threshold for ambiguous signals (50× 401). The residual risks — no cert pinning, no token memory zeroing, `curl|sh` install — are accepted as proportionate to the threat model of a lightweight infrastructure monitoring agent.
