#!/bin/sh
# Builds the FreeBSD package of the ConnLog agent (docs/topology/PLAN.md,
# T13.5d), on FreeBSD (the release workflow's VM):
#
#   sh packaging/freebsd/build-pkg.sh <binary> <version> <out-dir>
#
# It holds the binary, the rc.d script and nothing else; the install script
# makes the `connlog` user and the agent's private directories. The settings
# file is never in the package: install.sh writes it, so upgrading the
# package never touches a token.
set -eu

binary=$1
version=$2
out=$3
here=$(cd "$(dirname "$0")" && pwd)

stage=$(mktemp -d)
meta=$(mktemp -d)
trap 'rm -rf "$stage" "$meta"' EXIT

install -d "$stage/usr/local/bin" "$stage/usr/local/etc/rc.d"
install -m 0755 "$binary" "$stage/usr/local/bin/connlog-agent"
install -m 0755 "$here/connlog_agent" "$stage/usr/local/etc/rc.d/connlog_agent"

sed "s/@VERSION@/$version/" "$here/manifest.ucl" > "$meta/+MANIFEST"
cp "$here/post-install.sh" "$meta/+POST_INSTALL"
cp "$here/pre-deinstall.sh" "$meta/+PRE_DEINSTALL"

# The files, relative to the prefix, with their owner and mode.
cat > "$meta/plist" <<'PLIST'
@(root,wheel,0755) bin/connlog-agent
@(root,wheel,0755) etc/rc.d/connlog_agent
PLIST

mkdir -p "$out"
pkg create -m "$meta" -p "$meta/plist" -r "$stage" -o "$out"
ls -l "$out"
