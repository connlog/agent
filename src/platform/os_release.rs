//! What the host runs, exactly (agent 1.23, owner 2026-10-30): its
//! distribution, what that derives from, and its version, so the console can
//! draw the distribution's mark and say when a host falls behind its
//! release's latest.
//!
//! Read from the host's own files, under `CONNLOG_HOST_ROOT` in a container
//! (T13.1): the firewall distributions and Proxmox VE by theirs, since their
//! os-release says only FreeBSD or Debian; everything else by os-release.
//!
//! The distribution and its family go on every heartbeat (`X-Os-Id`,
//! `X-Os-Like`): a name shared by millions of hosts, which is what the map's
//! mark needs. The exact version (`X-Os-Version`) goes only while the host
//! shares system info (`CONNLOG_EXPOSE_SYSTEM_INFO`), as its hostname does:
//! a patch level says which hosts are behind.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const OS_ID_HEADER: &str = "X-Os-Id";
pub const OS_LIKE_HEADER: &str = "X-Os-Like";
pub const OS_VERSION_HEADER: &str = "X-Os-Version";

/// The longest id, family member or version that goes on the wire.
const MAX_LEN: usize = 32;
/// The most family members `X-Os-Like` carries.
const MAX_LIKE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsRelease {
    /// `ubuntu`, `debian`, `pfsense`, `proxmox-ve`: os-release's `ID`, lowercase.
    pub id: String,
    /// What it derives from, nearest first, space separated: `rhel centos fedora`.
    pub like: Option<String>,
    /// As exact as the host says: `22.04.3`, `12.7`, `14.1-RELEASE-p5`.
    pub version: Option<String>,
}

fn token(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= MAX_LEN
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

/// An os-release `ID` as the platform reads `X-Os-Id`; `None` for anything else.
pub fn sanitize_id(raw: &str) -> Option<String> {
    let value = raw.trim().to_ascii_lowercase();
    token(&value).then_some(value)
}

/// An `ID_LIKE` as the platform reads `X-Os-Like`: one to four ids.
pub fn sanitize_like(raw: &str) -> Option<String> {
    let ids: Vec<String> = raw
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    ((1..=MAX_LIKE).contains(&ids.len()) && ids.iter().all(|id| token(id))).then(|| ids.join(" "))
}

/// A version as the platform reads `X-Os-Version`: `22.04.3`, `14.1-RELEASE-p5`.
pub fn sanitize_version(raw: &str) -> Option<String> {
    let value = raw.trim();
    let mut chars = value.chars();
    (value.len() <= MAX_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "._+~-_".contains(c)))
    .then(|| value.to_string())
}

impl OsRelease {
    /// What this host runs; through `CONNLOG_HOST_ROOT` in a container.
    pub fn read() -> Option<Self> {
        let root = super::host_root().unwrap_or_else(|| PathBuf::from("/"));
        Self::read_at(&root)
    }

    /// What the host whose root filesystem is at `root` runs.
    pub fn read_at(root: &Path) -> Option<Self> {
        opnsense(root)
            .or_else(|| pfsense(root))
            .or_else(|| proxmox(root))
            .or_else(|| os_release(root))
    }
}

fn read(root: &Path, relative: &str) -> Option<String> {
    fs::read_to_string(root.join(relative)).ok()
}

/// OPNsense says itself in its core package's version file.
fn opnsense(root: &Path) -> Option<OsRelease> {
    let core: serde_json::Value =
        serde_json::from_str(&read(root, "usr/local/opnsense/version/core")?).ok()?;
    Some(OsRelease {
        id: "opnsense".into(),
        like: Some("freebsd".into()),
        version: core["product_version"].as_str().and_then(sanitize_version),
    })
}

/// pfSense says itself in `/etc/platform`, its version in `/etc/version`.
fn pfsense(root: &Path) -> Option<OsRelease> {
    if !read(root, "etc/platform")?
        .trim()
        .eq_ignore_ascii_case("pfsense")
    {
        return None;
    }
    let version = read(root, "etc/version")
        .and_then(|text| text.split_whitespace().next().and_then(sanitize_version));
    Some(OsRelease {
        id: "pfsense".into(),
        like: Some("freebsd".into()),
        version,
    })
}

/// Proxmox VE is Debian with `pveversion`; its version is its manager's package.
fn proxmox(root: &Path) -> Option<OsRelease> {
    if !root.join("usr/bin/pveversion").exists() {
        return None;
    }
    let version = read(root, "var/lib/dpkg/status")
        .and_then(|status| dpkg_version(&status, "pve-manager"))
        .and_then(|version| sanitize_version(&version));
    Some(OsRelease {
        id: "proxmox-ve".into(),
        like: Some("debian".into()),
        version,
    })
}

/// A package's `Version:` in dpkg's status file.
fn dpkg_version(status: &str, package: &str) -> Option<String> {
    let mut ours = false;
    for line in status.lines() {
        if let Some(name) = line.strip_prefix("Package: ") {
            ours = name.trim() == package;
        } else if ours {
            if let Some(version) = line.strip_prefix("Version: ") {
                return Some(version.trim().to_string());
            }
        }
    }
    None
}

/// os-release's `KEY=value` lines, the value's quotes taken off.
fn fields(text: &str) -> HashMap<&str, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let unquoted = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.insert(key.trim(), unquoted.replace("\\\"", "\""));
    }
    out
}

fn os_release(root: &Path) -> Option<OsRelease> {
    let text = read(root, "etc/os-release").or_else(|| read(root, "usr/lib/os-release"))?;
    let fields = fields(&text);
    let id = sanitize_id(fields.get("ID")?)?;
    let like = fields.get("ID_LIKE").and_then(|like| sanitize_like(like));
    let version = exact_version(
        root,
        &id,
        fields.get("VERSION_ID").map(String::as_str),
        fields.get("VERSION").map(String::as_str),
    )
    .and_then(|version| sanitize_version(&version));
    Some(OsRelease { id, like, version })
}

/// The most exact version the host says: Debian's point release from
/// `debian_version`; else `VERSION`'s first word where it carries on from
/// `VERSION_ID` (Ubuntu's `22.04.3 LTS`, FreeBSD's `14.1-RELEASE-p5`);
/// else `VERSION_ID`.
fn exact_version(
    root: &Path,
    id: &str,
    version_id: Option<&str>,
    version: Option<&str>,
) -> Option<String> {
    let base = version_id?.trim();
    if base.is_empty() {
        return None;
    }
    if id == "debian" {
        if let Some(point) = read(root, "etc/debian_version") {
            let point = point.trim();
            if point.starts_with(&format!("{base}.")) {
                return Some(point.to_string());
            }
        }
    }
    let first = version.and_then(|v| v.split_whitespace().next());
    Some(match first {
        Some(first) if first.len() > base.len() && first.starts_with(base) => first.to_string(),
        _ => base.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    /// A host's root with these files in it, gone again when dropped.
    struct Root(PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn root(files: &[(&str, &str)]) -> Root {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "connlog-os-release-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for (path, text) in files {
            let path = dir.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        Root(dir)
    }

    fn os(files: &[(&str, &str)]) -> Option<OsRelease> {
        OsRelease::read_at(&root(files).0)
    }

    #[test]
    fn reads_ubuntus_point_release_from_its_version() {
        let ubuntu = os(&[(
            "etc/os-release",
            "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\n",
        )]);
        assert_eq!(
            ubuntu,
            Some(OsRelease {
                id: "ubuntu".into(),
                like: Some("debian".into()),
                version: Some("22.04.3".into()),
            })
        );
    }

    #[test]
    fn reads_debians_point_release_from_debian_version() {
        let debian = os(&[
            (
                "usr/lib/os-release",
                "ID=debian\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\n",
            ),
            ("etc/debian_version", "12.7\n"),
        ])
        .unwrap();
        assert_eq!(debian.version.as_deref(), Some("12.7"));
        assert_eq!(debian.like, None);
    }

    #[test]
    fn keeps_a_derivatives_family_nearest_first() {
        let rocky = os(&[(
            "etc/os-release",
            "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n",
        )])
        .unwrap();
        assert_eq!(rocky.like.as_deref(), Some("rhel centos fedora"));
        assert_eq!(rocky.version.as_deref(), Some("9.4"));
    }

    #[test]
    fn reads_freebsd_with_its_patch_level() {
        let freebsd = os(&[(
            "etc/os-release",
            "NAME=FreeBSD\nVERSION=\"14.1-RELEASE-p5\"\nVERSION_ID=\"14.1\"\nID=freebsd\n",
        )])
        .unwrap();
        assert_eq!(freebsd.version.as_deref(), Some("14.1-RELEASE-p5"));
    }

    #[test]
    fn tells_the_firewalls_from_the_freebsd_under_them() {
        let freebsd = ("etc/os-release", "ID=freebsd\nVERSION_ID=14.1\n");
        let opnsense = os(&[
            freebsd,
            (
                "usr/local/opnsense/version/core",
                r#"{"product_id":"opnsense","product_name":"OPNsense","product_version":"24.7.5_3"}"#,
            ),
        ])
        .unwrap();
        assert_eq!(opnsense.id, "opnsense");
        assert_eq!(opnsense.version.as_deref(), Some("24.7.5_3"));

        let pfsense = os(&[
            freebsd,
            ("etc/platform", "pfSense\n"),
            ("etc/version", "2.7.2-RELEASE\n"),
        ])
        .unwrap();
        assert_eq!(
            (pfsense.id.as_str(), pfsense.version.as_deref()),
            ("pfsense", Some("2.7.2-RELEASE"))
        );
    }

    #[test]
    fn tells_proxmox_ve_from_the_debian_under_it() {
        let pve = os(&[
            ("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n"),
            ("usr/bin/pveversion", "#!/usr/bin/perl\n"),
            (
                "var/lib/dpkg/status",
                "Package: pve-kernel\nVersion: 6.8.12\n\nPackage: pve-manager\nStatus: install ok installed\nVersion: 8.2.4\n",
            ),
        ])
        .unwrap();
        assert_eq!(
            pve,
            OsRelease {
                id: "proxmox-ve".into(),
                like: Some("debian".into()),
                version: Some("8.2.4".into()),
            }
        );
    }

    #[test]
    fn says_nothing_it_cannot_read() {
        assert_eq!(os(&[]), None);
        assert_eq!(os(&[("etc/os-release", "NAME=Weird\n")]), None);
        let odd = os(&[("etc/os-release", "ID=\"two words\"\nVERSION_ID=1\n")]);
        assert_eq!(odd, None);
        let no_version = os(&[("etc/os-release", "ID=arch\n")]).unwrap();
        assert_eq!(no_version.version, None);
    }

    #[test]
    fn sanitizes_as_the_platform_reads() {
        assert_eq!(sanitize_id(" Ubuntu ").as_deref(), Some("ubuntu"));
        assert_eq!(sanitize_id("-x"), None);
        assert_eq!(
            sanitize_like("  ubuntu   debian ").as_deref(),
            Some("ubuntu debian")
        );
        assert_eq!(sanitize_like("a b c d e"), None);
        assert_eq!(sanitize_version("22.04.3 LTS"), None);
        assert_eq!(sanitize_version("24.7.5_3").as_deref(), Some("24.7.5_3"));
    }
}
