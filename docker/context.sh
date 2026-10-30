#!/bin/sh
# Prepares the build context for ./Dockerfile:
#
#   sh docker/context.sh <out-dir> <amd64-binary> [<arm64-binary>]
#
# from apps/agent (the release job runs it from the mirror's root). Only the
# binaries given are copied; an image is built only for those architectures.
set -eu

out=$1
amd64=$2
arm64=${3:-}
here=$(dirname "$0")

rm -rf "$out"
mkdir -p "$out/bin/amd64" "$out/rootfs/var/lib/connlog" "$out/rootfs/etc/connlog/integrations.d"
chmod 0700 "$out/rootfs/var/lib/connlog" "$out/rootfs/etc/connlog/integrations.d"
cp "$amd64" "$out/bin/amd64/connlog-agent"
if [ -n "$arm64" ]; then
  mkdir -p "$out/bin/arm64"
  cp "$arm64" "$out/bin/arm64/connlog-agent"
fi
cp "$here/Dockerfile" "$here/../LICENSE" "$here/../THIRD-PARTY-LICENSES.md" "$out/"
