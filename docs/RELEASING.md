# Releasing connlog-agent

The runbook for cutting a release. Follow it top to bottom; every step
exists because skipping it has bitten us (or would). Versioning policy
(SemVer, what counts as the public contract) lives in
[`VERSIONING.md`](../VERSIONING.md).

## How a release travels

The agent's code lives in `connlog/platform` (`apps/agent`). Its signed
releases are published on the public `connlog/agent`, because the installer
and the platform's update cache read them there and because the source the
site calls auditable is the source customers can read.

```
agent-vX.Y.Z tag on a canary commit here
  └─ .github/workflows/agent-release.yml (this repository)
       ├─ checks: Cargo.toml says X.Y.Z, the commit is on canary,
       │          connlog/agent has no vX.Y.Z yet
       ├─ one commit on connlog/agent's canary: apps/agent at the tag,
       │  byte for byte (less the AGENTS.md/CLAUDE.md symlinks into
       │  law-and-order/), as a fast-forward; never a force push
       └─ tag vX.Y.Z there
            └─ connlog/agent's Release workflow (apps/agent/.github/
               workflows/release.yml, carried by the mirror)
                 ├─ build x86_64 + aarch64, check the reported version
                 ├─ waits for your approval (environment `release`)
                 └─ sign, attest, publish
```

Nobody commits to `connlog/agent` by hand: a hand-made commit there makes
the next mirror push fail instead of being overwritten.

## The one invariant that must never break

> **The tag `agent-vX.Y.Z` must point at a commit on `canary` whose
> `apps/agent/Cargo.toml` says `version = "X.Y.Z"`.**

The release workflow builds whatever the tag points at. If the binary
self-reports an older version than the tag, every agent in the fleet
downloads the "new" binary, sees its own version unchanged, and re-downloads
on every heartbeat — an update loop across the entire fleet. The mirror
workflow refuses such a tag, and connlog/agent's build refuses a binary that
reports another version; check it yourself anyway (step 4).

## Prerequisites

- All changes you want to ship are merged into `canary` via PR with CI green.
- You can approve the `release` environment on `connlog/agent` (signing).
- The `agent-mirror` environment on `connlog/platform` holds
  `AGENT_MIRROR_TOKEN` (docs/migration/PLAN.md G.1, item 6).

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
pre-release versions as update targets. The mirror workflow refuses one.

### 2. Bump the version and changelog, in a pull request

On a branch from `canary`:

- `apps/agent/Cargo.toml`: `version = "X.Y.Z"`.
- `cargo build` once (from `apps/agent`) so `Cargo.lock` picks up the version.
- `apps/agent/CHANGELOG.md`:
  - Rename the `## [Unreleased]` heading to `## [X.Y.Z] — YYYY-MM-DD`.
  - Add the compare link at the bottom of the file:
    `[X.Y.Z]: https://github.com/connlog/agent/compare/vPREV...vX.Y.Z`
- If `Cargo.lock` changed since the last release, regenerate the licence
  notices: `apps/agent/scripts/third-party-licenses.sh`.

Commit as `chore(agent): release vX.Y.Z`, run `pnpm agent:check` and the
release build (`./target/release/connlog-agent --version` must print X.Y.Z),
open the pull request and merge it when CI is green. A feature PR may carry
the bump itself.

### 3. Ship the platform side first

If the release changes anything the platform must understand, the platform
change is already on `canary` (it lands in the same pull request as the
agent change, per `law-and-order/agent.md`); promote it to production
before or with the agent release. An agent release reaches the fleet over
hours; the platform must already accept what the new agent sends.

### 4. Verify, then tag

From a phone or anywhere without a checkout: **Actions → Agent release →
Run workflow**, branch `canary`, version `X.Y.Z`. The run checks that
`canary`'s `apps/agent/Cargo.toml` says X.Y.Z, creates `agent-vX.Y.Z` on that
commit, and goes on to step 5 by itself. Re-running a failed run is safe: it
accepts a tag it already made on the same commit and a mirror that already
holds the same tree, and refuses anything else.

From a checkout:

```bash
git fetch origin canary
git show origin/canary:apps/agent/Cargo.toml | grep '^version'   # must say X.Y.Z
COMMIT=$(git log origin/canary --format=%H --grep "release vX.Y.Z" -1)
git merge-base --is-ancestor "$COMMIT" origin/canary && echo ok

git tag -a agent-vX.Y.Z -m "ConnLog Agent vX.Y.Z" "$COMMIT"
git push origin agent-vX.Y.Z
```

Tags are immutable once pushed: never delete, move, or re-use a released
tag, here or on `connlog/agent` — agents and the platform cache have already
seen it. A bad release is fixed by shipping `vX.Y.Z+1`, not by re-tagging.

### 5. The mirror runs

`Agent release` (this repository's Actions) mirrors `apps/agent` and tags
`vX.Y.Z` on `connlog/agent`. Its summary links the run to approve. If it
fails, nothing was published; read the error, fix, and push a new tag only
if the old one was wrong (a failed run with a correct tag can be re-run).

### 6. Approve the signing step

The tag starts `connlog/agent`'s Release workflow:

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

### 7. Verify the release

```bash
gh release view vX.Y.Z --repo connlog/agent --json assets --jq '.assets[].name'
```

Expected: for each of `linux-x86_64` and `linux-aarch64` — the raw binary,
`.sig`, `.sha256`, `.tar.gz`, and `.tar.gz.sha256` — plus
`THIRD-PARTY-LICENSES.md` (11 assets total), and the release marked **Latest**.
The Release workflow attaches the licence notices; keeping them current is
step 2.

### 8. Rollout (automatic)

Nothing to do. The platform's update proxy re-checks GitHub releases every
~10 minutes (`ARTIFACT_TTL_MS` in
`apps/web/src/features/agents/server/agent-update-cache.ts`); agents
learn about the update in their next heartbeat response, verify the Ed25519
signature against the compiled-in public key, and swap binaries via the
systemd `ExecStopPost` hook. Downgrades and unsigned binaries are rejected
by the agent regardless of what the platform serves.
