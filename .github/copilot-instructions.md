# ConnLog Agent — Copilot Instructions

If anything about the request is ambiguous — protocol, flags, systemd, or which repo to change — **stop and ask** before implementing. Do not guess.

## Stack

- **Language**: Rust (stable), cross-compiled via `cross` for `x86_64` and `aarch64` musl
- **Service**: systemd unit, installed to `/usr/local/bin/connlog-agent`
- **Config**: TOML at `/etc/connlog-agent/config.toml`

## Key Commands

```bash
cargo build                              # Debug build
cargo test --all                         # Full test suite
cargo clippy --all-targets -- -D warnings  # Lint (must be clean)
cargo fmt --check                        # Format check
```

## Release Process

**Always create a new release when committing and pushing changes to the agent.**

Steps (in order):
1. Determine the version bump per `VERSIONING.md`:
   - **PATCH** (x.y.Z) — bug fix, security fix, no public contract change
   - **MINOR** (x.Y.0) — new backwards-compatible feature, or feature removal
   - **MAJOR** (X.0.0) — breaking change to wire protocol, CLI flags, or systemd contract
2. Update `version` in `Cargo.toml`
3. Add a new dated section to `CHANGELOG.md` (move Unreleased items if present)
4. Commit: `git add -A && git commit -m "chore: release v<version>"`
5. Push: `git push`
6. Tag and push: `git tag v<version> && git push origin v<version>`

The GitHub Actions `release.yml` workflow triggers on `v*` tags and automatically
builds cross-compiled musl binaries, signs them, and publishes a GitHub release.
The platform update proxy picks the new release up on the next poll; no manual
platform action is needed.

## Architecture

Core plumbing lives at the crate root; optional capabilities live under
`src/features/`; self-update is isolated under `src/update/`. Full source map
in `docs/agent-architecture.md`.

- `src/main.rs` — entry point, main agent loop (heartbeat, quick actions, updates)
- `src/heartbeat.rs` — `HeartbeatPayload`, `HeartbeatResponse`, `AgentConfig` structs
- `src/http.rs` — `AgentApiClient` (all outbound HTTP calls)
- `src/config.rs` — CLI arg parsing (clap), config file loading
- `src/features/metrics.rs` — CPU, memory, disk, load metric collection
- `src/features/quick_actions.rs` — quick action polling and execution
- `src/features/bmc.rs` — optional BMC (iDRAC/iLO) hardware health poller
- `src/update/mod.rs` — self-update logic (Ed25519 signature verification)
- `src/install/` — installation logic (systemd, binary placement)
- `src/platform/` — platform-specific abstractions

## Public Contract (do not break without MAJOR bump)

1. HTTP wire format with the platform (heartbeat request/response field names)
2. `PROTOCOL_VERSION` integer in `src/main.rs`
3. CLI flags in `src/config.rs`
4. systemd unit contract (file location, env file path, service name)
5. Ed25519 signing key + signature verification flow
6. Version comparison rules in `is_version_upgrade` (anti-rollback)
