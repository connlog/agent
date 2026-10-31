#!/bin/sh
# Every change to what the agent ships raises its version (owner,
# 2026-10-30), so no two pull requests carry the same version and a release
# never has to be bumped after the fact. Run by `pnpm agent:check`.
#
# "What the agent ships": everything under apps/agent but its docs (*.md,
# docs/) and the public repository's workflows (.github/). Against
# origin/canary: when this branch changes any of it, its Cargo.toml version
# must be higher than canary's (VERSIONING.md says by how much: a patch for
# a fix, a minor for a feature, a major for a broken contract).
set -eu

cd "$(dirname "$0")/.."
base=${CONNLOG_VERSION_BASE:-origin/canary}

if ! git rev-parse -q --verify "$base^{commit}" >/dev/null 2>&1; then
    echo "version-bumped: $base is not here (git fetch origin canary); not checked" >&2
    exit 0
fi

changed=$(git diff --name-only "$base" -- . ':(exclude)*.md' ':(exclude)docs' ':(exclude).github' | head -n 1)
if [ -z "$changed" ]; then
    exit 0
fi

ours=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
theirs=$(git show "$base:apps/agent/Cargo.toml" | sed -n 's/^version = "\(.*\)"$/\1/p' | head -n 1)
highest=$(printf '%s\n%s\n' "$theirs" "$ours" | sort -V | tail -n 1)

if [ "$ours" = "$theirs" ] || [ "$highest" != "$ours" ]; then
    echo "version-bumped: apps/agent changed ($changed, and maybe more) but its version is $ours, and $base has $theirs." >&2
    echo "Raise apps/agent/Cargo.toml above $theirs (VERSIONING.md: patch for a fix, minor for a feature), run cargo build, and add its section to CHANGELOG.md." >&2
    exit 1
fi
echo "version-bumped: $theirs -> $ours"
