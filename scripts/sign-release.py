#!/usr/bin/env python3
"""
Sign a ConnLog Agent release binary with Ed25519.

Creates:
  <binary>.sha256  — SHA-256 checksum file
  <binary>.sig     — 64-byte Ed25519 signature (over the SHA-256 hash)

The agent verifies both the checksum and the signature before accepting an update.

Usage:
  python3 scripts/sign-release.py <binary-path> <private-key-hex>

Example (CI):
  python3 scripts/sign-release.py \\
    target/release/connlog-agent \\
    "$CONNLOG_SIGNING_PRIVATE_KEY"
"""

import hashlib
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: 'cryptography' package is required.")
    print("Install it with: pip install cryptography")
    sys.exit(1)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <binary-path> <private-key-hex>")
        print(f"       {sys.argv[0]} target/release/connlog-agent $CONNLOG_SIGNING_PRIVATE_KEY")
        sys.exit(1)

    binary_path = sys.argv[1]
    private_key_hex = sys.argv[2].strip()

    # Read binary
    with open(binary_path, "rb") as f:
        binary_data = f.read()

    # Compute SHA-256
    sha256_digest = hashlib.sha256(binary_data).digest()
    sha256_hex = sha256_digest.hex()

    # Write checksum file
    checksum_path = binary_path + ".sha256"
    with open(checksum_path, "w") as f:
        f.write(sha256_hex + "\n")

    # Load private key from hex seed
    private_bytes = bytes.fromhex(private_key_hex)
    if len(private_bytes) != 32:
        print(f"Error: Private key must be 32 bytes (64 hex chars), got {len(private_bytes)}")
        sys.exit(1)

    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    # Sign the SHA-256 hash (not the raw binary — this matches agent verification)
    signature = private_key.sign(sha256_digest)

    # Write signature file
    sig_path = binary_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    # Also output the public key for verification
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    print(f"✓ Signed {binary_path}")
    print(f"  SHA-256:   {sha256_hex}")
    print(f"  Signature: {sig_path} ({len(signature)} bytes)")
    print(f"  Checksum:  {checksum_path}")
    print(f"  Public key: {public_bytes.hex()}")
    print(f"\nUpload these alongside the release binary:")
    print(f"  {binary_path}")
    print(f"  {checksum_path}")
    print(f"  {sig_path}")


if __name__ == "__main__":
    main()
