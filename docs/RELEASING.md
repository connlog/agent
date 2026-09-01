# Releasing connlog-agent

The runbook for cutting a release. Follow it top to bottom; every step
exists because skipping it has bitten us (or would). Versioning policy
(SemVer, what counts as the public contract) lives in
[`VERSIONING.md`](../VERSIONING.md).

## The one invariant that must never break

> **The tag `vX.Y.Z` must point at a commit on `canary` whose `Cargo.toml`
> says `version = "X.Y.Z"`.**

The release workflow builds whatever the tag points at. If the binary
self-reports an older version than the tag, every agent in the fleet
downloads the "new" binary, sees its own version unchanged, and re-downloads
on every heartbeat — an update loop across the entire fleet. Check it
explicitly before tagging (step 6).

## Prerequisites

- All changes you want to ship are merged into `canary` via PR with CI green.
- You can approve the `release` GitHub environment (required for signing).
- `gh` CLI authenticated against `connlog/agent`.

## Steps

### 1. Pick the version

Per [`VERSIONING.md`](../VERSIONING.md):

| Bump  | When                                                    |
| ----- | ------------------------------------------------------- |
| MAJOR | Breaking change to the public contract (wire format, CLI, systemd unit, update/signing flow) |
| MINOR | New backwards-compatible functionality                   |
| PATCH | Backwards-compatible bug/security fix                    |

Never use a pre-release suffix (`-rc1`, `-beta`) for anything agents should
auto-install — `is_version_upgrade()` in `src/update/mod.rs` deliberately rejects
pre-release versions as update targets.

### 2. Branch from the canary tip

```bash
git fetch origin canary
git checkout -b release/vX.Y.Z origin/canary
```

Branching from anywhere else risks tagging a commit that is not an ancestor
of `canary`.

### 3. Bump the version and changelog

- `Cargo.toml`: `version = "X.Y.Z"`.
- `cargo build` once so `Cargo.lock` picks up the new version.
- `CHANGELOG.md`:
  - Rename the `## [Unreleased]` heading to `## [X.Y.Z] — YYYY-MM-DD`
    (create the section from the shipped changes if there is no Unreleased
    section).
  - Add the compare link at the bottom of the file:
    `[X.Y.Z]: https://github.com/connlog/agent/compare/vPREV...vX.Y.Z`

### 4. Run the release ritual

All four must pass locally — CI will enforce them anyway, but failing fast
here keeps the PR clean:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release && ./target/release/connlog-agent --version   # must print X.Y.Z
```

### 5. Land the release commit on canary

Feature work lands via PR as usual. The version bump itself goes straight to
`canary`: CI runs on every push there, and the Release workflow only runs on
a tag, so a broken bump fails before anything can ship. A separate PR for
`chore: release vX.Y.Z` adds clicks without adding safety.

```bash
git checkout canary && git pull --ff-only origin canary
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore: release vX.Y.Z"
git push origin canary
```

A hardening or feature PR may carry the bump itself (v1.19.0 did). Then
merge the PR and continue with step 6 against the merge commit.

### 6. Verify, then tag

```bash
git fetch origin canary

# BOTH checks must pass before tagging:
git show origin/canary:Cargo.toml | grep '^version'      # must say X.Y.Z
RELEASE_COMMIT=$(git log origin/canary --format=%H --grep "release vX.Y.Z" -1)
git merge-base --is-ancestor "$RELEASE_COMMIT" origin/canary && echo ok

git tag -a vX.Y.Z -m "ConnLog Agent vX.Y.Z" "$RELEASE_COMMIT"
git push origin vX.Y.Z
```

Tags are immutable once pushed: never delete, move, or re-use a released
tag — agents and the platform cache have already seen it. A bad release is
fixed by shipping `vX.Y.Z+1`, not by re-tagging.

### 7. Approve the signing step

Pushing the tag triggers `.github/workflows/release.yml`:

1. `build` — cross-compiles static musl binaries for `x86_64` and `aarch64`
   (the compiled-in signing **public** key comes from the
   `CONNLOG_SIGNING_PUBLIC_KEY` secret).
2. `sign-and-release` — runs in the protected `release` environment and
   waits for **your approval** (GitHub → the run → *Review deployments*).
   On approval it signs each raw binary with the Ed25519 private key held in
   CI secrets (`scripts/sign-release.sh`, OpenSSL only, which also refuses
   to sign if the key does not match `CONNLOG_SIGNING_PUBLIC_KEY`), attaches
   build provenance attestations, and creates the GitHub release. The
   `build` job fails first if `CONNLOG_SIGNING_PUBLIC_KEY` is missing or if
   the built binary does not report the tagged version.

Watch it with:

```bash
gh run watch --repo connlog/agent "$(gh run list --repo connlog/agent --workflow Release --limit 1 --json databaseId --jq '.[0].databaseId')"
```

### 8. Verify the release

```bash
gh release view vX.Y.Z --repo connlog/agent --json assets --jq '.assets[].name'
```

Expected: for each of `linux-x86_64` and `linux-aarch64` — the raw binary,
`.sig`, `.sha256`, `.tar.gz`, and `.tar.gz.sha256` (10 assets total), and
the release marked **Latest**.

### 9. Rollout (automatic)

Nothing to do. The platform's update proxy re-checks GitHub releases every
~10 minutes (`ARTIFACT_TTL_MS` in
`connlog-platform/src/features/agents/server/agent-update-cache.ts`); agents
learn about the update in their next heartbeat response, verify the Ed25519
signature against the compiled-in public key, and swap binaries via the
systemd `ExecStopPost` hook. Downgrades and unsigned binaries are rejected
by the agent regardless of what the platform serves.

### Coordinated platform changes

If the release changes anything the platform must understand (wire format,
new endpoints the agent calls), deploy the platform **first** — platform
deploys are instant (push to `main` → production), while an agent release
rolls out over minutes to hours. The agent must keep working against the
previous platform version whenever possible; if it can't, that's a MAJOR
bump and needs an explicit migration plan.
