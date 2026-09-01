#!/bin/sh
# Sign a ConnLog Agent release artifact with the Ed25519 release key.
#
# Uses OpenSSL only (3.x, as shipped on the release runner), so the job that
# holds the private key installs nothing from a package index.
#
# Writes next to the artifact:
#   <artifact>.sha256   sha256sum-compatible checksum line
#   <artifact>.sig      64 raw bytes: Ed25519 over the SHA-256 digest of the
#                       artifact (what src/update/mod.rs verify_ed25519 checks)
#
# Usage:
#   scripts/sign-release.sh <artifact> <private-key-seed-hex>
#
# When CONNLOG_SIGNING_PUBLIC_KEY is set, the public key derived from the seed
# must match it, so a release can never be signed with a key the binaries were
# not built to trust.
set -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <artifact> <private-key-seed-hex>" >&2
    exit 1
fi

artifact=$1
seed_hex=$(printf '%s' "$2" | tr -d '[:space:]')

[ -f "$artifact" ] || { echo "error: $artifact is not a file" >&2; exit 1; }
case "$seed_hex" in
    *[!0-9a-fA-F]* | "") echo "error: private key seed must be hex" >&2; exit 1 ;;
esac
[ "${#seed_hex}" -eq 64 ] || { echo "error: private key seed must be 32 bytes (64 hex chars), got ${#seed_hex}" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

hex_to_bin() {
    # Prefer the Python standard library (always on the runner); fall back to xxd.
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))' "$1"
    else
        printf '%s' "$1" | xxd -r -p
    fi
}

# PKCS#8 DER for an Ed25519 private key is a fixed 16-byte prefix followed by
# the 32-byte seed. Building it by hand keeps the seed format the CI secret
# has always used.
hex_to_bin "302e020100300506032b657004220420${seed_hex}" > "$tmp/key.der"
chmod 600 "$tmp/key.der"

openssl pkey -in "$tmp/key.der" -inform DER -pubout -out "$tmp/pub.pem"
public_hex=$(openssl pkey -pubin -in "$tmp/pub.pem" -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')

if [ -n "${CONNLOG_SIGNING_PUBLIC_KEY:-}" ]; then
    expected=$(printf '%s' "$CONNLOG_SIGNING_PUBLIC_KEY" | tr -d '[:space:]' | tr 'A-F' 'a-f')
    if [ "$expected" != "$public_hex" ]; then
        echo "error: the signing key's public half ($public_hex) is not the key compiled into the binaries ($expected)" >&2
        exit 1
    fi
fi

openssl dgst -sha256 -binary "$artifact" > "$tmp/digest"
openssl pkeyutl -sign -inkey "$tmp/key.der" -keyform DER -rawin -in "$tmp/digest" -out "$artifact.sig"

# Never publish a signature that does not verify with the public key.
openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/digest" -sigfile "$artifact.sig" >/dev/null

sha256_hex=$(od -An -v -tx1 "$tmp/digest" | tr -d ' \n')
printf '%s  %s\n' "$sha256_hex" "$(basename "$artifact")" > "$artifact.sha256"

echo "signed $artifact"
echo "  sha256:     $sha256_hex"
echo "  signature:  $artifact.sig ($(wc -c < "$artifact.sig" | tr -d ' ') bytes)"
echo "  public key: $public_hex"
