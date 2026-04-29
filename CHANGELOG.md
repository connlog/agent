# Changelog

All notable changes to **connlog-agent** are recorded here.

This project follows [Semantic Versioning 2.0.0](https://semver.org/) — see
[`VERSIONING.md`](./VERSIONING.md) for the full policy. Format inspired by
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

[Unreleased]: https://github.com/connlog/connlog-agent/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/connlog/connlog-agent/compare/v0.3.6...v1.0.0
[0.3.6]: https://github.com/connlog/connlog-agent/releases/tag/v0.3.6
