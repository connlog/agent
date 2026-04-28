# Changelog

All notable changes to **connlog-agent** are recorded here.

This project follows [Semantic Versioning 2.0.0](https://semver.org/) — see
[`VERSIONING.md`](./VERSIONING.md) for the full policy. Format inspired by
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
