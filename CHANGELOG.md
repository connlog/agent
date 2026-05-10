# Changelog

All notable changes to **connlog-agent** are recorded here.

This project follows [Semantic Versioning 2.0.0](https://semver.org/) — see
[`VERSIONING.md`](./VERSIONING.md) for the full policy. Format inspired by
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.8.5] — 2026-05-10

### Added

- Added a lightweight quick-action command poll while the agent is waiting for
  the next heartbeat. Agents now check `/api/agents/actions/pending` every
  5 seconds by default during the heartbeat sleep window so dashboard-requested commands
  start much faster without increasing the full metric heartbeat rate.
- Added `connlog-agent refresh-service [--restart]` and
  `connlog-agent diagnostics service` so operators can refresh or inspect the
  installed systemd unit without reinstalling the agent.

### Fixed

- Kept the existing heartbeat-delivered quick-action path intact and covered
  the new poll endpoint with a simulation test so pending requests are still
  claimed and executed by ID only.
- Self-update now refreshes the installed systemd service from the new binary
  before restarting. If refresh fails, the update hook logs loudly, rolls the
  binary back, and leaves the service stopped instead of silently running a new
  binary under a stale unit file.

## [1.8.3] — 2026-05-09

### Fixed

- Removed the systemd `SystemCallFilter` sandbox from the agent service because
  it caused locally registered Quick Actions to fail with `Bad system call`
  when running common host diagnostic tools such as `ip a`, `ip route`, `ss`,
  `df`, `docker ps`, and `systemctl status`.

### Security

- Kept the rest of the service hardening intact: the agent still runs as the
  unprivileged `connlog-agent` user with `NoNewPrivileges`, strict filesystem
  protection, empty capabilities, namespace restrictions, and restricted address
  families.
- Kept `AF_NETLINK` allowed in `RestrictAddressFamilies` so network inspection
  tools can query interface and route information without removing the broader
  sandbox.

## [1.8.2] — 2026-05-09

### Fixed

- Allowed `AF_NETLINK` in the systemd service sandbox so locally registered
  Quick Actions can run read-only network inspection tools such as `ip a`,
  `ip route`, and `ss`. The previous sandbox only allowed `AF_INET`,
  `AF_INET6`, and `AF_UNIX`, causing `iproute2` commands to fail with
  `Bad system call` when executed from the unprivileged `connlog-agent`
  service.

### Security

- Kept the existing systemd hardening intact and added only the minimal address
  family required for network diagnostics. Privileged syscalls, reboot, mount,
  raw I/O, module loading, and other denied syscall groups remain blocked.

## [1.8.1] — 2026-05-09

### Fixed

- `/etc/connlog` is now installed as `0750 root:connlog-agent` (was `0700
  root:root`), and `actions.toml` is written as `0640`. The unprivileged
  service user (`connlog-agent`) could not traverse the directory, so it
  silently published an empty action list on every heartbeat — newly registered
  local actions never appeared in the dashboard. Running as root (e.g.
  `connlog-agent action add`) also auto-repairs the permissions on load so
  existing installs are fixed without a reinstall.

## [1.8.0] — 2026-05-09

### Added

- Added `connlog-agent action add`, a beginner-friendly interactive flow for
  registering local dashboard actions with a label, description, command,
  output preference, and confirmation preference.
- Added `connlog-agent action list`, `action remove`, `action enable`,
  `action disable`, and `action test`, while keeping the plural `actions`
  command working as an alias.
- Added simple shell-like command-line parsing for interactive action setup so
  commands such as `df -h` and `systemctl status nginx` are stored as argv
  arrays without running through a shell.
- Added risky-command detection for common state-changing commands, defaulting
  dashboard confirmation to required when a command looks risky.

### Changed

- Simplified root `--help` around common install/status/action workflows and
  moved detailed action usage into `connlog-agent action --help`.
- Added a `diagnostics` command group for config and heartbeat checks while
  keeping the previous top-level diagnostic commands and legacy flags working.
- Default simple actions now use category `Custom`, risk `medium`, a 15-second
  timeout, and bounded ephemeral output when users choose to show output.

### Security

- Preserved the existing local action security contract: ConnLog receives only
  action metadata and IDs, raw command argv remains local on the agent host, and
  dashboard requests still validate action IDs locally before execution.

## [1.7.0] — 2026-05-09

### Added

- Added `connlog-agent actions register` so operators can register a local
  action from the agent CLI and have it appear in the dashboard after the next
  heartbeat.
- Added `connlog-agent actions list` and `connlog-agent actions remove` for
  inspecting and removing local action definitions.

### Changed

- The local action config file remains the source of truth, but operators
  no longer need to hand-edit it for the common add/list/remove workflow.

## [1.6.1] — 2026-05-09

### Changed

- Modernized the CLI help around first-run setup:
  - Added first-class `register`, `install`, `uninstall`, `status`,
    `update`, `check-config`, and `test-heartbeat` subcommands.
  - Kept legacy flags such as `--install`, `--status`, `--check-config`,
    and `--test-heartbeat` working for existing scripts.
  - Clarified that `register` runs in the foreground and `install` is the
    normal systemd service path for servers.

## [1.6.0] — 2026-05-09

### Added

- Added locally registered quick actions. The platform can request registered
  action IDs, and the agent remains the authority for what executable argv may
  run.
- Added per-action output controls for hidden vs ephemeral output, bounded
  stdout/stderr capture, timeout enforcement, and a local quick-actions kill
  switch.

### Security

- Quick actions execute without `sh -c`, receive no dashboard-provided stdin or
  arguments, and refuse unknown or disabled action IDs.

## [1.5.1] — 2026-05-08

### Fixed

- Remote uninstall now reliably cleans up all agent files. Previously, if
  `INVOCATION_ID` was not set, the agent fell back to an in-process uninstall
  that always failed because the runtime process is never root. The fix writes
  the `/run/connlog/.uninstall_requested` marker unconditionally and exits;
  the systemd `ExecStopPost=+` hook (runs as root) performs the actual
  cleanup. If the marker write fails, a clear manual-cleanup instruction is
  logged instead of a misleading "requires sudo" error.

## [1.5.0] — 2026-05-08

### Added

- Added interval-based Linux CPU measurement from `/proc/stat` counters.
- Added peak-core CPU reporting in the existing heartbeat frame's `cpu_max`
  field.

### Changed

- The first CPU sample is now reported as unavailable until a real interval
  delta exists, instead of sending a misleading fake zero.
- Heartbeat JSON keeps the public metrics field set stable while omitting CPU
  only when the first interval is still collecting.

## [1.4.1] — 2026-05-07

### Changed

- Renamed public GitHub repository usage from `connlog/connlog-agent` to
  `connlog/agent` in the updater metadata path (`src/update.rs`) and package
  metadata (`Cargo.toml`).
- Kept installed runtime identity stable: binary name (`connlog-agent`),
  systemd service (`connlog-agent`), install path
  (`/usr/local/bin/connlog-agent`), config/state paths, release artifact
  naming, and signature/checksum verification behavior are unchanged.
- Added repository-rename compatibility note at `docs/REPO_RENAME.md` to
  document redirect expectations for older installed agents.

## [1.4.0] — 2026-05-07

### Added

- **Opt-in extended Linux metrics: disk mount and network interface monitoring.**
  Agents on paid plans (Developer+) can be enabled for extended metrics via the
  dashboard. When enabled, the agent discovers disk mounts and network interfaces
  on the host and reports them to the platform. Only Linux is supported.
  - `ExtendedMetricsConfig` in agent config controls whether extended metrics
    are enabled, which disk/network keys to sample, and whether discovery should
    be re-run.
  - New `extended_metrics.rs` module: discovers disk mounts from
    `/proc/self/mountinfo` + `statvfs()`, and network interfaces from
    `/proc/net/dev`. Virtual/container filesystems and loopback/virtual network
    interfaces are automatically excluded from default monitoring.
  - Disk samples include: used/available/total MB, usage %, inode usage %.
  - Network samples include: rx/tx bytes/second (rate-calculated), rx/tx
    errors delta, rx/tx dropped delta. Counter resets (interface restart or
    overflow) are detected and skipped to avoid false spikes.
  - Discovery is sent to `POST /api/agents/resources/discovery`; samples to
    `POST /api/agents/resources/samples`. Both are separate lightweight JSON
    calls — the 32-byte binary heartbeat is unchanged.
- `src/extended_metrics.rs` — new module with `ExtendedMetricsState`,
  `collect_discovery()`, and `collect_samples()`.

### Changed

- Heartbeat config response now carries `extendedMetrics` block:
  `enabled`, `discoverResources`, `collectDisks`, `collectNetwork`,
  `monitoredDiskKeys`, `monitoredNetworkKeys`.
- Main loop now conditionally runs the discovery + sample collection cycle
  in parallel with the heartbeat when `extendedMetrics.enabled` is true.
- Discovery is only sent when `discoverResources` flag is set by the platform
  (cleared after first successful ingestion).
- Removed Windows support. Windows-specific files (`WINDOWS.md`,
  `src/install/windows.rs`, `src/platform/windows.rs`, `src/service/windows.rs`)
  have been removed. The agent is Linux-first and the Windows path was untested
  and incomplete.

## [1.3.8] — 2026-05-07

### Security

- **ExecStopPost binary replacement is now atomic.** The previous
  `cp /run/connlog/connlog-agent-new /usr/local/bin/connlog-agent` wrote
  directly to the live binary path. A power failure or OOM-kill during
  the copy would leave a partially-written, corrupt binary — bricking the
  agent permanently. Fixed by staging to
  `/usr/local/bin/connlog-agent.new` first, setting permissions, then
  using `mv` (an atomic `rename()` within the same filesystem). The live
  binary is never touched until the replacement is fully written to disk.
- **Service-file refresh in ExecStopPost is now atomic.** The previous
  implementation wrote the new `.service` file to `/run/connlog/` (tmpfs)
  and then `mv`-ed it to `/etc/systemd/system/`. A cross-filesystem `mv`
  is not atomic (kernel falls back to copy + unlink). Fixed by writing
  the temp file directly to `/etc/systemd/system/connlog-agent.service.new`
  then using `mv` within the same filesystem.

### Added

- `docs/agent-architecture.md` — architecture reference for contributors,
  auditors, and security researchers. Covers startup, heartbeat, update,
  install/uninstall flows, updater safety invariants, wire protocol layout,
  versioning rules, and what must never be broken.
- `LICENSE` — MIT license file (copyright IA Solutions B.V.)
- Tests for `require_https` in `update.rs`: verifies that HTTP, FTP, and
  empty URLs are rejected by the update download path.
- Tests for `verify_sha256` in `update.rs`: verifies correct hash is
  accepted, wrong hash is rejected with a named error, and the comparison
  is case-insensitive (platform may return uppercase hex).
- Tests for ExecStopPost atomicity in `install/linux.rs`: pins the
  `.new` staging + `mv` pattern and the same-filesystem service file temp
  location so they cannot be silently reverted.

### Changed

- `README.md` License section now links to the `LICENSE` file and names
  the copyright holder.

## [1.3.7] — 2026-05-04

### Fixed

- **CPU usage no longer stuck at 0%.** `MetricsCollector::new()` was using
  `System::new()`, which creates an *empty* sysinfo system with no CPUs
  enumerated. `refresh_cpu_usage()` only refreshes CPUs already in the
  list, so the list stayed empty forever and `global_cpu_usage()` always
  returned `0.0`. Switched to `System::new_all()` for the initial
  enumeration; subsequent ticks still use the cheap `refresh_cpu_usage()`
  + sleep + `refresh_cpu_usage()` recipe.
- **1-minute load average reads `/proc/loadavg` directly on Linux.** The
  sysinfo wrapper has been observed to silently return `0.00` on some
  hosts. Reading the file directly is a single `read_to_string` of a
  ~30-byte file with a stable, well-defined format — no extra deps and no
  surprise-zeros. Falls back to `sysinfo::System::load_average()` on
  non-Linux.

## [1.3.6] — 2026-05-04

### Fixed

- **Systemd sandbox no longer blocks `/proc` reads.** The unit shipped
  `ProtectProc=invisible` and `ProcSubset=pid`, which together hide almost
  all of `/proc` from the service. `sysinfo` reads `/proc/meminfo`,
  `/proc/stat`, `/proc/loadavg`, `/proc/uptime`, and `/proc/diskstats` to
  produce metrics; with those two flags set, every read returned ENOENT and
  the agent silently sent zeros for CPU, memory, disk, load, *and uptime*.
  The dashboard cards then displayed `0%` / `0 MB` even though heartbeats
  were arriving normally. Removed both directives. The remaining hardening
  (NoNewPrivileges, ProtectSystem=strict, ProtectHome, syscall filter,
  RestrictAddressFamilies, capability drop, namespace and realtime
  restrictions, MemoryDenyWriteExecute, etc.) is unchanged. Added a
  regression test that fails if either flag is reintroduced.

## [1.3.5] — 2026-05-04

### Added

- **Per-heartbeat diagnostic line.** Every heartbeat now logs a single
  `info!` line containing the agent version, fetched config (version +
  metric toggles), the raw values sysinfo returned, and the values
  actually placed on the wire. This is the fastest way to diagnose the
  "dashboard shows zeros" class of issue end-to-end without flipping the
  global log level — it disambiguates between (a) the platform telling
  the agent a metric is disabled, (b) sysinfo returning zero on this host,
  and (c) the wire encoding masking real samples.

## [1.3.4] — 2026-05-04

### Fixed

- **Config fetch now unwraps the platform response envelope.** The platform
  returns `GET /api/agents/config` as `{"ok":true,"data":<AgentConfig>}`,
  but the agent was deserialising the envelope directly into `AgentConfig`
  and failing every config refresh with `Failed to parse config response`.
  The agent silently fell back to `safe_fallback()` (version `0`),
  triggering a `config_outdated` round-trip on every heartbeat and never
  picking up the real server-side config — including any metric toggles
  the workspace plan dictates. Fixed by parsing through an `Envelope<T>`
  wrapper and pulling out `data`.

## [1.3.3] — 2026-05-04

### Fixed

- **CPU usage no longer reports 0 % on every host.** `MetricsCollector::collect_inner`
  was issuing a single `refresh_cpu_all()` per heartbeat and immediately
  reading `global_cpu_usage()`. sysinfo's documented contract requires two
  `refresh_cpu_*` calls separated by at least
  `MINIMUM_CPU_UPDATE_INTERVAL` (~200 ms) per *sample* — relying on the
  previous tick's refresh from 60 s ago is unsupported and silently produces
  0 % on a number of Linux kernels (notably the ones running our CI
  runners). Each collect now does the canonical
  `refresh_cpu_usage → sleep → refresh_cpu_usage → read` dance. The 200 ms
  cost is paid once per heartbeat and is invisible against the 60 s tick.
- Switched both startup baseline and per-tick samples from `refresh_cpu_all`
  to the lighter `refresh_cpu_usage`; we never read frequency or per-CPU
  data, so the heavier call was wasted work.

## [1.3.2] — 2026-05-04

### Fixed

- **Heartbeats reach the platform again.** The agent has been advertising
  `protocol_version: 2` (binary wire format) in headers, but the platform's
  validation gate only accepted `protocol_version === 1` and rejected every
  heartbeat with `400 Unsupported protocol version`. Result: no
  `AgentSnapshot` writes, no rollups, and a completely blank dashboard
  (overview cards and per-agent details). The wire format itself was always
  correct; only the version integer was wrong.

### Changed

- **Single, unified wire protocol (v1 binary).** Pre-launch decision: there
  is now exactly one supported transport — the 32-byte little-endian binary
  frame over `application/octet-stream`, identified as `protocol_version: 1`.
  The legacy JSON heartbeat path has been removed from both the agent and the
  platform. `encode_heartbeat_v2` is now `encode_heartbeat`. The
  `ApiClient.use_binary` toggle and `send_heartbeat_json` fallback are gone.

### Added

- **Panic isolation around metrics collection.** `MetricsCollector::collect()`
  now returns `Result` and wraps the inner sysinfo refresh in
  `panic::catch_unwind`. A panic from `sysinfo` (quirky kernels, syscall
  surprises) can no longer kill the daemon — the heartbeat loop falls back to
  a zero-valued sample with cached identity and keeps reporting liveness.
- **`--check-config` diagnostic.** Validates the bearer token, fetches the
  agent config from the platform, and prints version / interval /
  missed_threshold / metric toggles. Exits non-zero on any failure — scriptable
  in install smoke tests.
- **`--test-heartbeat` diagnostic.** Sends exactly one heartbeat and prints
  the platform's response (config_outdated, uninstall, update). Used as a
  post-install verification step in `install.sh`.
- **Structured log lines.** Daemon logs are now formatted as
  `<ts> level=info component=<module> <message>` so operators can
  `grep component=heartbeat` / `grep level=error` without regex acrobatics.
  No new dependency.
- **Heartbeat sleep jitter.** Sleeps between heartbeats are now spread by
  ±10% so a fleet installed at the same minute doesn't hammer the platform
  on the same second every interval.
- **Tighter HTTP timeouts.** `connect_timeout` is now an explicit 5 s in
  addition to the existing 10 s overall request timeout, with a unit test
  pinning both bounds against accidental relaxations.
- **Extra systemd hardening.** `ProtectProc=invisible`, `ProcSubset=pid`,
  `RemoveIPC=yes`, `UMask=0077`, and a `SystemCallFilter` that allows
  `@system-service` while denying privileged / mount / module / debug /
  raw-io / reboot / swap / cpu-emulation / obsolete syscalls.
- **CI binary-size budget.** The Linux release build now fails CI if the
  unstripped binary exceeds 12 MiB — a regression guard against accidental
  `tokio` / `serde_yaml` / heavy-derive dependencies.

### Removed

- `src/wire.rs` and `src/sampler.rs`. Both were exploratory work, never
  declared in `main.rs`, and explicitly disabled for V1 by `CLAUDE.md §0.3`.
  The encoder used by every heartbeat lives in `http.rs::encode_heartbeat_v2`
  and is fully tested. The pre-cut tree is preserved on
  `archive/pre-v1-scope-cut-2026-04-30`.

## [1.1.2] — 2026-04-29

### Added

- **`423 Locked` (`AGENT_DISABLED`) handling.** The platform now distinguishes
  between a *disabled* agent (reversible, returns `423`) and a *decommissioned*
  agent (permanent, returns `410 Gone`). The agent recognises the new status
  in both the binary and JSON heartbeat code paths via a new
  `ApiError::Disabled` variant.

  When a heartbeat is rejected with `423`, the agent:

  - logs the disabled state clearly (no error spam),
  - resets the consecutive-unauthorized and consecutive-error counters so a
    later re-enable doesn't immediately trip the self-uninstall threshold,
  - sleeps for a fixed 5-minute backoff regardless of the configured
    heartbeat interval, and
  - **does not self-uninstall** — `trigger_self_uninstall()` remains reserved
    for `410 Gone` / `WORKSPACE_DISABLED` / repeated `401 Unauthorized`.

  Re-enabling the agent from the dashboard restores normal operation on the
  next heartbeat cycle without manual intervention on the host.

## [1.1.1] — 2026-04-29

### Removed

- **`--force-update` CLI flag** and `update::run_force_update()`. The
  heartbeat-driven force-update path (`update.forceUpdate=true` from the
  platform) is the single, audited way to bypass the Ed25519 check, and it
  is gated by workspace-owner auth on the dashboard. Carrying a parallel
  CLI flag duplicated the bypass surface for no real-world benefit and made
  the trust boundary harder to reason about.

The heartbeat path is unchanged: `try_apply_update(&UpdateInfo, force: bool)`
still skips Ed25519 only when the platform sets `force_update=true`, and
SHA-256 integrity is always verified.

## [1.1.0] — 2026-04-29

### Added

- **Force-update mode** for bootstrapping agents that were compiled without a
  `CONNLOG_SIGNING_PUBLIC_KEY`. Two entry points:
  - **`--force-update` CLI flag** (`sudo connlog-agent --force-update`) —
    fetches the latest GitHub release, verifies its SHA-256, and atomically
    replaces the installed binary while skipping Ed25519 verification. Useful
    for self-recovery on a single host.
  - **Platform-driven force-update** — the heartbeat response may now carry
    `update.forceUpdate: true`. When set, the agent applies the update on the
    next heartbeat cycle even if no signing key is compiled in. The flag is
    one-shot: the platform clears `pendingForceUpdate` once the request has
    been delivered. SHA-256 integrity is always verified — only the Ed25519
    check is bypassed, and only when explicitly authorised by the workspace.

### Changed

- `update::try_apply_update` now takes an explicit `force: bool` argument so
  call sites are forced to opt in to the bypass; the GitHub-poll path
  (`check_github_for_update`) always passes `false`.
- `stage_verified_update` gained a `skip_ed25519` parameter; when `true` the
  signature download and verification are skipped and a prominent warning is
  logged.

### Wire contract

- `UpdateInfo` (heartbeat → agent) gains an optional `forceUpdate: bool` field.
  Defaults to `false` and is backward-compatible with older platforms.

## [1.0.1] — 2026-04-29

### Changed

- **Self-uninstall threshold:** raised `MAX_UNAUTHORIZED_ATTEMPTS` from `10` to
  `50`. Only true `401 Unauthorized` responses count toward this counter —
  network failures, DNS errors, machine-down scenarios, and other transport
  errors are tracked separately in `consecutive_errors` and never trigger
  self-uninstall. This guarantees the agent only removes itself when the
  platform has authoritatively rejected the token (deleted agent, deleted
  workspace, revoked auth) and not because the host is briefly offline.
- **Tighter 401 backoff:** replaced the old exponential `60 × n` capped at
  3600 s with a linear `30 + 10 × n` capped at 120 s. A `401` is cheap on the
  platform side, so there's no reason to back off for hours; at the cap, 50
  attempts now complete in ≈ 95 minutes (down from ≈ 21 hours), so a revoked
  agent disappears from a host within ~1.5 h instead of nearly a day.

## [1.0.0] — 2026-04-28

First **stable** release. The wire protocol, update mechanism, and CLI are now
considered stable; breaking changes from this point on require a major bump.

### Added

- Comprehensive test suite (40 tests, up from 8) pinning:
  - heartbeat clamp boundaries (interval, missed-threshold, payload size),
  - the camelCase wire-contract with the platform (rejects snake_case),
  - `HeartbeatResponse` / `UpdateInfo` defaults,
  - `dev_mode` is omitted on the wire when `None`,
  - `escape_env_value` neutralises `$()`, backticks, `"; cmd; "`, and `\`,
  - the systemd unit runs unprivileged with all hardening flags,
  - the self-update `ExecStopPost` hook,
  - anti-rollback edge cases (`9.9.9 → 10.0.0`, `1.2.9 → 1.2.10`, two-/four-part
    rejection, `v`-prefix rejection, pre-release rejection),
  - the placeholder all-zero signing key is rejected.
- `User-Agent: connlog-agent/<version>` header on every outbound HTTP request.
- Hard caps on update-artifact downloads: 50 MB binary, 4 KB checksum,
  64 B signature; bodies read with `Read::take(cap+1)`.
- `require_https()` gate — binary, signature, and checksum URLs **must** be
  HTTPS; `http://` is refused.

### Changed

- **Breaking (operational, not protocol):** the agent no longer polls the
  GitHub Releases API directly. Update metadata now arrives exclusively in the
  heartbeat response from the platform, which proxies and caches the artifacts
  via `/api/agents/updates/<arch>/<kind>`. Existing v0.3.x agents continue to
  work — the proxy URLs are opaque HTTPS GETs, indistinguishable from GitHub.
  Removes the GitHub-rate-limit DoS vector.
- The hardcoded `"0.3.6"` test helper now sources its version from
  `env!("CARGO_PKG_VERSION")` so it can never drift from `Cargo.toml`.
- `check_github_for_update` retained as a `#[allow(dead_code)]` break-glass
  fallback; not invoked on any hot path.
- Replaced manual `len() % 2 != 0` with `len().is_multiple_of(2)`
  (clippy `manual_is_multiple_of` is now `-D warnings` clean).

### Security

- Bearer token is never rendered in `Debug` output (now pinned by a unit test).
- All systemd hardening flags (`NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectKernelModules`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  empty `CapabilityBoundingSet`, `PrivateTmp`, `ProtectHome`) are pinned by
  unit tests so they cannot be silently weakened.
- Shell-injection guard for `agent.env` values (`escape_env_value`) is now
  fuzz-resistant against the classic break-out vectors.

## [0.3.6] — 2026-04-25

- Last pre-1.0 release. See git history for prior changes.

[Unreleased]: https://github.com/connlog/agent/compare/v1.8.5...HEAD
[1.8.5]: https://github.com/connlog/agent/compare/v1.8.4...v1.8.5
[1.8.4]: https://github.com/connlog/agent/compare/v1.8.3...v1.8.4
[1.8.3]: https://github.com/connlog/agent/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/connlog/agent/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/connlog/agent/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/connlog/agent/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/connlog/agent/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/connlog/agent/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/connlog/agent/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/connlog/agent/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/connlog/agent/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/connlog/agent/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/connlog/agent/compare/v1.3.8...v1.4.0
[1.3.8]: https://github.com/connlog/agent/compare/v1.0.0...v1.3.8
[1.0.0]: https://github.com/connlog/agent/compare/v0.3.6...v1.0.0
[0.3.6]: https://github.com/connlog/agent/releases/tag/v0.3.6
