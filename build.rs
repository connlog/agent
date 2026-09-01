//! Release builds must carry the release signing public key.
//!
//! `src/update/mod.rs` reads `CONNLOG_SIGNING_PUBLIC_KEY` with `option_env!`
//! and falls back to a placeholder when it is unset. A release binary built
//! that way cannot verify any update, and until v1.19 it would have installed
//! whatever the platform sent under `force_update`. Nothing in the build made
//! that visible, so this script does: a release profile build without a valid
//! key fails. A local release build that will never ship can opt out with
//! `CONNLOG_ALLOW_UNSIGNED_BUILD=1`.

fn main() {
    println!("cargo:rerun-if-env-changed=CONNLOG_SIGNING_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=CONNLOG_ALLOW_UNSIGNED_BUILD");

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
