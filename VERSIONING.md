# Versioning Policy

All connlog projects (`connlog-agent`, `connlog-platform`) use
[**Semantic Versioning 2.0.0**](https://semver.org/).

A version number `MAJOR.MINOR.PATCH` increments as follows:

| Bump   | When                                                                              |
| ------ | --------------------------------------------------------------------------------- |
| MAJOR  | Backwards-incompatible change to a public contract                                |
| MINOR  | New, backwards-compatible functionality                                           |
| PATCH  | Backwards-compatible bug or security fix                                          |

## What is "the public contract"?

For the **agent**, the public contract is everything an existing deployment
depends on:

1. The HTTP wire format with the platform — request bodies, response shapes,
   and field names (camelCase). Owned by `src/heartbeat.rs` and the heartbeat
   route on the platform. Pinned by tests in `heartbeat::tests`.
2. The protocol version integer (`PROTOCOL_VERSION` in `src/main.rs`).
3. The CLI flags exposed by `src/config.rs` (clap derive).
4. The systemd unit contract (file location, environment file path, service
   name, ExecStopPost trigger files). Pinned by tests in `install::tests`.
5. The signing key + signature verification flow for self-updates.
6. The version-comparison rules in `is_version_upgrade` (anti-rollback).

For the **platform**, the public contract is:

1. The agent-facing API (`/api/agents/*`).
2. Database schema (any non-additive change is breaking).
3. Public web routes referenced by external systems (auth callbacks, billing
   webhooks, the install script URL).

Everything else — internal modules, repositories, services, UI components —
is private and may change in any release.

## Pre-1.0 vs 1.0+

- `0.x.y`: anything may break in a `0.x` → `0.x+1` bump (per semver §4).
- `1.0.0+`: every breaking change to the public contract requires a major bump.

We graduated to `1.0.0` once the wire protocol, update mechanism, and CLI were
considered stable.

## Pre-release tags

Pre-release versions use a hyphen suffix: `1.1.0-rc1`, `2.0.0-beta.3`,
`1.0.1-alpha`. They sort below the corresponding stable release.

> ⚠️ The agent's `is_version_upgrade()` function deliberately **rejects** any
> version with a pre-release suffix as a downgrade target. Pre-releases must
> not be auto-installed; they require manual deployment.

## Release ritual

For the agent, see `connlog-agent/scripts/sign-release.py` and the GitHub
Actions release workflow. Each release must:

1. Bump `version` in `Cargo.toml`.
2. Update `CHANGELOG.md` — move `[Unreleased]` items into a new dated section.
3. Run `cargo test`, `cargo clippy --all-targets -- -D warnings`,
   `cargo fmt --check`.
4. Build cross-compiled `x86_64` and `aarch64` musl binaries.
5. Sign the binaries with the Ed25519 signing key
   (`CONNLOG_SIGNING_PUBLIC_KEY` baked into the agent at build time, signed
   with the matching private key held in CI secrets).
6. Tag `v<version>` and create a GitHub release with the binaries, signatures,
   and `sha256` checksums attached.
7. The platform's update proxy will pick the new release up automatically;
   agents will see it on their next heartbeat (no agent-side action needed).

## Why we did not jump to 5.0.0

We considered jumping `0.3.6 → 5.0.0` to "look mature". We didn't, because:

- Semver doesn't allow it: each major bump is meant to denote one round of
  breaking change. Jumping straight to 5 implies four breaking-change majors
  that never happened.
- It permanently burns version slots `1.x`, `2.x`, `3.x`, `4.x`. Future
  meaningful breaking changes would have to go to 6.x, 7.x, ..., compressing
  the meaningful version range and confusing automated dependency tooling.
- The actual "look" of maturity comes from the changelog and release cadence,
  not the major-version integer.

`1.0.0` is the right number for "first stable release" and leaves the entire
future major-version space open.
