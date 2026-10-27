#!/usr/bin/env bash
#
# Regenerates THIRD-PARTY-LICENSES.md: the notices the agent's statically
# linked dependencies require to travel with the binary. Run after any change
# to Cargo.lock, and attach the file to every release.
#
# Needs cargo-about: cargo install cargo-about --locked --features cli

set -euo pipefail
cd "$(dirname "$0")/.."
cargo about generate --locked --fail about.hbs -o THIRD-PARTY-LICENSES.md
echo "Wrote $(pwd)/THIRD-PARTY-LICENSES.md"
