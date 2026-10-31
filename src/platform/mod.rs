//! Platform-gated path constants and OS shims.

pub mod os_release;
pub mod signals;
pub mod unix;
pub use unix::*;

/// How this agent was installed, and so how it is updated and configured
/// (`X-Packaging` on every heartbeat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packaging {
    /// `install.sh`: a systemd service, settings in the root-only agent.conf,
    /// updates applied by the root-side `ExecStopPost` step.
    Systemd,
    /// The Docker image (docs/topology/PLAN.md, T13.1): settings are the
    /// container's environment, and a new image is the update. There is no
    /// root-side step to verify and swap a binary, and none is wanted: the
    /// image's digest is what the operator pinned.
    Docker,
    /// The FreeBSD package for OPNsense and pfSense (T13.5d): an rc.d
    /// service, settings in `/usr/local/etc/connlog/agent.conf`, and a new
    /// package is the update. The agent never swaps its own binary on a
    /// firewall.
    Freebsd,
}

impl Packaging {
    #[cfg(test)]
    pub const ALL: [Packaging; 3] = [Packaging::Systemd, Packaging::Docker, Packaging::Freebsd];

    pub const fn as_str(self) -> &'static str {
        match self {
            Packaging::Systemd => "systemd",
            Packaging::Docker => "docker",
            Packaging::Freebsd => "freebsd",
        }
    }

    /// Whether this agent updates itself, configures itself with `install`
    /// and `config`, and can reboot its host: only the systemd install. A
    /// container and a package are replaced and configured from outside.
    pub const fn manages_itself(self) -> bool {
        matches!(self, Packaging::Systemd)
    }

    /// `CONNLOG_PACKAGING=docker` (the image sets it) or `freebsd` (the
    /// package's rc.d script does). Anything else, or nothing, is the systemd
    /// install every agent before them was; except on FreeBSD, where the
    /// package is the only install and a root shell running `config` is not
    /// told so by the rc script.
    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("docker") => Packaging::Docker,
            Some(v) if v.eq_ignore_ascii_case("freebsd") => Packaging::Freebsd,
            _ if cfg!(target_os = "freebsd") => Packaging::Freebsd,
            _ => Packaging::Systemd,
        }
    }

    pub fn current() -> Self {
        Self::from_env_value(std::env::var("CONNLOG_PACKAGING").ok().as_deref())
    }
}

/// Where the host's root filesystem is mounted when the agent does not run
/// in it (`CONNLOG_HOST_ROOT=/host` in the image's Compose file): the
/// agent's disks and machine id are the host's, read through it. Only an
/// absolute path other than `/` that is there counts: the image names
/// `/host`, and a container started without that mount reads its own.
pub fn host_root() -> Option<std::path::PathBuf> {
    let value = std::env::var("CONNLOG_HOST_ROOT").ok()?;
    let path = std::path::PathBuf::from(value.trim());
    (path.is_absolute() && path != std::path::Path::new("/") && path.is_dir()).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::Packaging;

    #[test]
    fn only_the_images_word_is_docker() {
        // Unsaid is the systemd install, except on FreeBSD, where the package
        // is the only one.
        let unsaid = if cfg!(target_os = "freebsd") {
            Packaging::Freebsd
        } else {
            Packaging::Systemd
        };
        assert_eq!(Packaging::from_env_value(None), unsaid);
        assert_eq!(Packaging::from_env_value(Some("")), unsaid);
        assert_eq!(Packaging::from_env_value(Some("podman")), unsaid);
        assert_eq!(Packaging::from_env_value(Some("docker")), Packaging::Docker);
        assert_eq!(
            Packaging::from_env_value(Some(" Docker\n")),
            Packaging::Docker
        );
        assert_eq!(
            Packaging::from_env_value(Some("freebsd")),
            Packaging::Freebsd
        );
        assert!(Packaging::Systemd.manages_itself());
        assert!(!Packaging::Docker.manages_itself());
        assert!(!Packaging::Freebsd.manages_itself());
    }
}
