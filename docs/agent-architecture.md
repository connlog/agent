# ConnLog Agent — Architecture Reference

This document is for contributors, auditors, and security researchers. It
describes what the agent does, how it is structured, and the invariants that
must never be broken.

---

## What the agent does

The agent is a small, static binary that runs as a systemd service on Linux.
Its only job is to send authenticated heartbeats to the ConnLog platform every
~60 seconds, carrying a small set of system metrics (CPU, memory, disk, load
average, uptime).

It does nothing else. There is no log shipping, no script execution, no
service discovery, no network probing.

---

## Source map

```
src/
  main.rs         — CLI parsing, main loop, back-off/retry, heartbeat send
  config.rs       — Clap Config; reads CONNLOG_TOKEN, CONNLOG_PLATFORM_URL
  defaults.rs     — Shared constants (endpoint, backoff durations)
  heartbeat.rs    — Wire types: HeartbeatPayload, HeartbeatResponse, AgentConfig
  http.rs         — ApiClient (heartbeat POST, config GET); encode_heartbeat
  identity.rs     — X-Machine-Id derivation (SHA-256 of /etc/machine-id)
  metrics.rs      — MetricsCollector wrapping sysinfo; panic-isolated collect()
  update.rs       — Self-update: download → verify → atomic stage; version compare
  simulation.rs   — In-process HTTP mock used by tests (no network required)
  install/
    linux.rs      — systemd unit (embedded string), install/uninstall helpers
  platform/
    unix.rs       — Filesystem paths for Linux (installed binary, staging, markers)
```

---

## Startup flow

```
main()
  ├─ Handle --status / --update / --check-config / --test-heartbeat / --emit-service
  ├─ Handle --install / --uninstall
  └─ run_agent_with_shutdown_inner()
       ├─ validate token prefix (must start with "agent_")
       ├─ ApiClient::new() — builds reqwest client, derives machine-id
       ├─ MetricsCollector::new() — initial sysinfo warmup
       ├─ fetch_config_with_retry() — up to 3 attempts, falls back to safe defaults
       └─ main loop (see Heartbeat flow)
```

---

## Heartbeat flow

Every iteration of the main loop:

```
send_heartbeat()
  ├─ MetricsCollector::collect()    — panic-isolated; sends zeros on failure
  ├─ Apply server metrics toggles   — zero out disabled metric fields
  ├─ Build HeartbeatPayload
  ├─ encode_heartbeat()             — 32-byte LE binary frame
  └─ ApiClient::send_heartbeat()    — POST /api/agents/heartbeat
       Headers: Content-Type: application/octet-stream
                Authorization: Bearer agent_<token>
                X-Agent-Version, X-Protocol-Version, X-Config-Version
                X-Hostname, X-OS, X-Arch
                X-Machine-Id (if available)

On OK response:
  ├─ Reset consecutive error counters
  ├─ Check response.uninstall       — accumulate, act after 3 consecutive
  ├─ Check response.update          — try_apply_update() (see Update flow)
  ├─ Check response.config_outdated — fetch new config if true
  └─ Sleep jittered(interval_secs)  — ±10% to spread fleet load

On error:
  ├─ 401 Unauthorized  → linear backoff; self-uninstall after 50 consecutive
  ├─ 410 Gone          → immediate self-uninstall
  ├─ 423 Locked        → 5-minute backoff; do NOT uninstall
  └─ Other             → exponential backoff (30s → 3600s cap)
```

---

## Update flow

Updates are delivered exclusively through the platform heartbeat response
(`response.update`). The agent **never** talks directly to GitHub during
the daemon update path. The platform proxies release artifacts.

```
try_apply_update(UpdateInfo)
  ├─ Guard: available=true, download_url present, signature_url present, sha256 present
  ├─ Guard: has_signing_key() — rejects unsigned builds unless force=true
  ├─ Guard: is_version_upgrade() — rejects same version and downgrades
  ├─ download_binary()     — HTTPS only, 50 MB cap, 100 KB minimum
  ├─ verify_sha256()       — must match; Err aborts the update
  ├─ download_signature()  — HTTPS only, must be exactly 64 bytes
  ├─ verify_ed25519()      — signature over SHA-256 hash; Err aborts the update
  ├─ Write staged binary   → /run/connlog/connlog-agent-new
  ├─ Write update marker   → /run/connlog/.update_requested
  └─ Return Ok(true)       — caller exits with code 0
```

The caller (`run_agent_with_shutdown_inner`) exits cleanly on `Ok(true)`.
The systemd service is configured with `Restart=on-failure`, so a clean exit
(code 0) does NOT restart the agent. Instead, `ExecStopPost` runs as root and
completes the update atomically:

```
ExecStopPost (runs as root, +/bin/bash)
  ├─ If /run/connlog/.update_requested exists:
  │    ├─ cp /run/connlog/connlog-agent-new → /usr/local/bin/connlog-agent.new
  │    ├─ chmod 755 /usr/local/bin/connlog-agent.new
  │    ├─ mv /usr/local/bin/connlog-agent.new → /usr/local/bin/connlog-agent
  │    │    └─ atomic rename() within the same filesystem
  │    ├─ Refresh service file (if --emit-service succeeds)
  │    │    ├─ Write to /etc/systemd/system/connlog-agent.service.new
  │    │    └─ mv .service.new → .service  (atomic within /etc/systemd/system)
  │    ├─ systemctl daemon-reload
  │    ├─ rm update marker + staged binary
  │    └─ systemctl start connlog-agent
  └─ If /run/connlog/.uninstall_requested exists:
       ├─ systemctl disable connlog-agent
       ├─ rm /etc/systemd/system/connlog-agent.service
       ├─ systemctl daemon-reload
       ├─ rm -rf /etc/connlog  (removes token — security-critical)
       └─ rm /usr/local/bin/connlog-agent
```

### Updater safety invariants

These invariants must never be broken. They are pinned by tests in
`src/install/linux.rs` and `src/update.rs`.

| Invariant                                              | How it is enforced                                                                                                                            |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Current binary untouched until replacement is verified | Staged to `/run/connlog/connlog-agent-new`; original at `/usr/local/bin/connlog-agent` is only replaced after a verified copy+rename sequence |
| Binary replacement is atomic                           | `cp → .new` on the destination filesystem, `chmod`, then `mv` (kernel `rename()` — atomic within same fs)                                     |
| Service file refresh is atomic                         | Temp file written directly to `/etc/systemd/system/*.new`, then `mv` within same fs                                                           |
| SHA-256 always checked                                 | `verify_sha256()` called before `verify_ed25519()`; mismatch aborts immediately                                                               |
| Ed25519 always checked                                 | `verify_ed25519()` called after SHA-256; can only be skipped with `force=true` AND no compiled-in key                                         |
| Downgrades rejected                                    | `is_version_upgrade()` blocks any version ≤ current                                                                                           |
| Non-HTTPS URLs rejected                                | `require_https()` called before every download                                                                                                |
| Oversized downloads rejected                           | 50 MB hard cap + streaming read; also a 100 KB floor (too small = suspicious)                                                                 |
| Failed update leaves agent running                     | `try_apply_update()` returns `Err` on any failure; main loop catches it, logs, and continues                                                  |
| Signing key placeholder ≠ real key                     | All-zero 64-char hex key is a sentinel; `has_signing_key()` returns false                                                                     |

---

## Install / uninstall flow

### Install (`install --token agent_<token>`)

1. Require root (`geteuid() == 0`)
2. Create system user `connlog-agent` (no home, no login shell)
3. Create `/etc/connlog/` (mode 0700, root:connlog-agent)
4. Write `/etc/connlog/agent.conf` (mode 0600) with `CONNLOG_TOKEN=` and
   `CONNLOG_PLATFORM_URL=`. Values are shell-escaped before writing to
   prevent injection via crafted tokens.
5. Copy the current binary to `/usr/local/bin/connlog-agent`
6. Write the embedded systemd unit to `/etc/systemd/system/connlog-agent.service`
7. `systemctl daemon-reload && systemctl enable && systemctl start`

### Uninstall (`uninstall`)

Reverse order, most critical last:
1. `systemctl stop` → prevents resurrection
2. `systemctl disable`
3. Remove service file
4. `systemctl daemon-reload`
5. Remove `/etc/connlog/` (includes token — security-critical)
6. Remove `/usr/local/bin/connlog-agent` **last** (we are running from it)

The system user `connlog-agent` is deliberately preserved. Removing a user
that may own files elsewhere is a destructive irreversible action; operators
can remove it manually with `userdel connlog-agent` if desired.

### Remote uninstall (HTTP 410 / heartbeat `uninstall: true`)

- HTTP 410 (Decommissioned): immediate self-uninstall
- `uninstall: true` in heartbeat response: requires 3 consecutive confirmations
  before acting (prevents a single transient response from uninstalling)

Self-uninstall under systemd writes `/run/connlog/.uninstall_requested` and
exits cleanly (code 0). `ExecStopPost` performs the actual cleanup as root.

---

## Config persistence

There is no config file on disk for the agent config. Config comes exclusively
from the server (`GET /api/agents/config`). The only persistent file is the
token + platform URL in `/etc/connlog/agent.conf`.

`AgentConfig::clamp()` is called on every config response to prevent a buggy
or malicious server from pushing values that would spin the CPU or prevent
check-ins:

| Field                     | Minimum              | Maximum        |
| ------------------------- | -------------------- | -------------- |
| `heartbeat_interval_secs` | 10 s                 | 86400 s (24 h) |
| `missed_threshold`        | 1                    | 100            |
| `max_payload_size_kb`     | 1 KB (0 = unlimited) | 1024 KB        |

---

## Wire protocol

Binary frame (v1), 32 bytes, little-endian:

| Offset | Size | Field                      |
| ------ | ---- | -------------------------- |
| 0      | 8    | uptime_seconds (u64 LE)    |
| 8      | 2    | cpu_percent × 100 (u16 LE) |
| 10     | 2    | cpu_max × 100 (u16 LE)     |
| 12     | 4    | memory_used_mb (u32 LE)    |
| 16     | 4    | memory_total_mb (u32 LE)   |
| 20     | 4    | disk_used_mb (u32 LE)      |
| 24     | 4    | disk_total_mb (u32 LE)     |
| 28     | 2    | load_1m × 100 (u16 LE)     |
| 30     | 2    | load_max × 100 (u16 LE)    |

Identity metadata travels in HTTP headers (`X-Agent-Version`, `X-Hostname`,
`X-OS`, `X-Arch`, `X-Machine-Id`, etc.). There is no JSON fallback.

See `src/http.rs::encode_heartbeat` and `src/http.rs::tests` for the
byte-level encoding tests that pin this layout.

---

## Versioning rules

Follows [Semantic Versioning 2.0.0](https://semver.org/) — see `VERSIONING.md`.

- **Patch** (x.y.Z): bug fixes, hardening, docs, tests, readability
- **Minor** (x.Y.0): backwards-compatible new features
- **Major** (X.0.0): breaking change (almost never; requires platform coordination)

Version string lives only in `Cargo.toml`. All other references use
`env!("CARGO_PKG_VERSION")` so there is a single source of truth.

The agent refuses updates to a version ≤ its current version
(`is_version_upgrade()` in `src/update.rs`).

---

## Testing changes safely

```bash
# Formatting (must pass before commit)
cargo fmt --check

# Lints (no warnings allowed)
cargo clippy --all-targets -- -D warnings

# Tests (includes simulation tests that mock the platform)
cargo test

# Release build (catches linker errors and binary-size budget)
cargo build --release
```

The simulation tests in `src/simulation.rs` spin up an in-process HTTP server
and verify the full heartbeat round-trip, error handling (401, 410, 423, 500),
redirect rejection, and update-info parsing — all without touching the network.

---

## What must never be broken

In rough priority order:

1. **Auto-update chain** — an agent that cannot update is frozen forever at
   its current version. Every change that touches `update.rs` or the
   `ExecStopPost` script must preserve all updater safety invariants above.
2. **Heartbeat reliability** — the agent must keep beating even when metric
   collection panics, config fetches fail, or the platform returns transient
   errors. The fallback paths (zero metrics, safe config, exponential backoff)
   are deliberate.
3. **Token safety** — the bearer token must never appear in logs. `Config`
   implements `Debug` with `[REDACTED]`. The `// SECURITY: Never log the
   token` comment in `http.rs` is not decorative.
4. **Self-uninstall safeguards** — 410 and repeated `uninstall: true` must
   trigger cleanup. The 3-heartbeat confirmation threshold prevents a single
   transient response from destroying the install.
5. **Binary protocol** — the 32-byte frame layout is shared with the platform.
   Any change to field offsets or encoding must be coordinated with
   `../connlog-platform/src/app/api/agents/heartbeat/route.ts` in the same
   commit and must bump `PROTOCOL_VERSION`.
