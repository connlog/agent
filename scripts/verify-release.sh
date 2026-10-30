#!/bin/sh
# Verify a ConnLog Agent release artifact's signature with the public key:
# the check `sign-release.sh` makes before it publishes, made again by a job
# that only holds the public half (the Docker image's, which packs the
# binaries it verified here).
#
# Usage:
#   scripts/verify-release.sh <artifact> <public-key-hex>
#
# <artifact>.sig must sit next to the artifact (64 raw bytes: Ed25519 over
# the SHA-256 digest, what src/update/mod.rs verify_ed25519 checks).
set -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <artifact> <public-key-hex>" >&2
    exit 1
fi

artifact=$1
public_hex=$(printf '%s' "$2" | tr -d '[:space:]' | tr 'A-F' 'a-f')

[ -f "$artifact" ] || { echo "error: $artifact is not a file" >&2; exit 1; }
[ -f "$artifact.sig" ] || { echo "error: $artifact.sig is missing" >&2; exit 1; }
case "$public_hex" in
    *[!0-9a-f]* | "") echo "error: public key must be hex" >&2; exit 1 ;;
esac
[ "${#public_hex}" -eq 64 ] || { echo "error: public key must be 32 bytes (64 hex chars)" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

hex_to_bin() {
    python3 -c 'import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))' "$1"
}

# SubjectPublicKeyInfo DER for Ed25519: a fixed 12-byte prefix, then the key.
hex_to_bin "302a300506032b6570032100${public_hex}" > "$tmp/pub.der"
openssl dgst -sha256 -binary "$artifact" > "$tmp/digest"
openssl pkeyutl -verify -pubin -inkey "$tmp/pub.der" -keyform DER -rawin \
    -in "$tmp/digest" -sigfile "$artifact.sig" >/dev/null
echo "verified $artifact"
