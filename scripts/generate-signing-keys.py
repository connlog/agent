#!/usr/bin/env python3
"""
Generate an Ed25519 signing keypair for ConnLog Agent release signing.

Output:
  - signing_key.hex    (64-char hex private seed — keep SECRET, store in CI secrets)
  - signing_key.pub    (64-char hex public key  — compile into agent binary)

Usage:
  python3 scripts/generate-signing-keys.py

Then:
  1. Store signing_key.hex content as a GitHub Secret (e.g. CONNLOG_SIGNING_PRIVATE_KEY)
  2. Build the agent with:
     CONNLOG_SIGNING_PUBLIC_KEY=$(cat signing_key.pub) cargo build --release
"""

import hashlib
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: 'cryptography' package is required.")
    print("Install it with: pip install cryptography")
    sys.exit(1)


def main():
    # Generate keypair
    private_key = Ed25519PrivateKey.generate()

    # Extract raw 32-byte seed (private) and 32-byte public key
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_hex = private_bytes.hex()
    public_hex = public_bytes.hex()

    # Write files
    with open("signing_key.hex", "w") as f:
        f.write(private_hex + "\n")
    os.chmod("signing_key.hex", 0o600)

    with open("signing_key.pub", "w") as f:
        f.write(public_hex + "\n")

    print("✓ Ed25519 signing keypair generated\n")
    print(f"  Private seed: signing_key.hex  (keep SECRET)")
    print(f"  Public key:   signing_key.pub")
    print(f"\n  Public key hex: {public_hex}\n")
    print("Next steps:")
    print("  1. Add private key to GitHub Secrets as CONNLOG_SIGNING_PRIVATE_KEY")
    print("  2. Add public key to GitHub Secrets as CONNLOG_SIGNING_PUBLIC_KEY")
    print("  3. Build agent with:")
    print(f'     CONNLOG_SIGNING_PUBLIC_KEY="{public_hex}" cargo build --release')
    print("  4. Sign releases with: scripts/sign-release.py")
    print("\n⚠️  Delete signing_key.hex from disk after storing in CI secrets!")


if __name__ == "__main__":
    main()
