//! Release builds must carry the release signing public key.
//!
//! `src/update/mod.rs` reads `CONNLOG_SIGNING_PUBLIC_KEY` with `option_env!`
//! and falls back to a placeholder when it is unset. A release binary built
//! that way cannot verify any update, and until v1.19 it would have installed
//! whatever the platform sent under `force_update`. Nothing in the build made
//! that visible, so this script does: a release profile build without a valid
//! key fails. A local release build that will never ship can opt out with
//! `CONNLOG_ALLOW_UNSIGNED_BUILD=1`.
//!
//! It also tells the tests where the protocol fixtures are; see
//! `protocol_fixtures` below.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=CONNLOG_SIGNING_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=CONNLOG_ALLOW_UNSIGNED_BUILD");
    protocol_fixtures();

    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile != "release" || std::env::var_os("CONNLOG_ALLOW_UNSIGNED_BUILD").is_some() {
        return;
    }

    let key = std::env::var("CONNLOG_SIGNING_PUBLIC_KEY").unwrap_or_default();
    let well_formed = key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit());
    let placeholder = key.bytes().all(|b| b == b'0');
    if !well_formed || placeholder {
        panic!(
            "\n\nRelease build without a valid CONNLOG_SIGNING_PUBLIC_KEY (64 hex characters).\n\
             A release binary without the key cannot verify updates and must not ship.\n\
             Set the key, or for a local build that will never ship set\n\
             CONNLOG_ALLOW_UNSIGNED_BUILD=1.\n\n"
        );
    }
}

/// `CONNLOG_PROTOCOL_FIXTURES`: the directory `protocol_fixture!` (in
/// `src/main.rs`) reads the wire-format fixtures from, the ones the agent's
/// tests and the platform's both check against. In connlog/platform that is
/// `packages/agent-protocol/fixtures`, beside this crate. connlog/agent
/// mirrors this crate alone, so the mirror carries them inside it as
/// `protocol-fixtures/` (connlog/platform's
/// `.github/workflows/agent-release.yml`). Only tests read them.
fn protocol_fixtures() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let manifest = Path::new(&manifest);
    let beside = manifest.join("../../packages/agent-protocol/fixtures");
    let fixtures = if beside.is_dir() {
        beside
    } else {
        manifest.join("protocol-fixtures")
    };
    println!(
        "cargo:rustc-env=CONNLOG_PROTOCOL_FIXTURES={}",
        fixtures.display()
    );
}
