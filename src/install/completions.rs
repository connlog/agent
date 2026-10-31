//! Tab completion for `connlog-agent` (owner, 2026-10-31): generated from
//! the clap definition, so it always offers exactly the subcommands and
//! setting names this binary takes. `install` writes a script for each shell
//! installed here, where that shell looks for one; uninstall removes them.

use std::fs;
use std::path::Path;

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::Shell;

use crate::config::Config;

/// Where each shell looks for a system-wide completion, and the file's name.
pub const PLACES: &[(Shell, &str, &str)] = &[
    (
        Shell::Bash,
        "/usr/share/bash-completion/completions",
        "connlog-agent",
    ),
    (
        Shell::Zsh,
        "/usr/local/share/zsh/site-functions",
        "_connlog-agent",
    ),
    (
        Shell::Fish,
        "/usr/share/fish/vendor_completions.d",
        "connlog-agent.fish",
    ),
];

pub fn script(shell: Shell) -> Vec<u8> {
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut Config::command(), "connlog-agent", &mut out);
    out
}

pub fn print(shell: Shell) {
    use std::io::Write;
    let _ = std::io::stdout().write_all(&script(shell));
}

/// Write each shell's script where it looks, for the shells installed here
/// (their directory is there). A shell that is not gets nothing.
pub fn install() -> Result<()> {
    for (shell, dir, name) in PLACES {
        let dir = Path::new(dir);
        if !dir.is_dir() {
            continue;
        }
        let path = dir.join(name);
        fs::write(&path, script(*shell))?;
        println!("  Installed {shell} completion: {}", path.display());
    }
    Ok(())
}

pub fn uninstall() {
    for (_, dir, name) in PLACES {
        let _ = fs::remove_file(Path::new(dir).join(name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn each_script_offers_the_config_commands_and_setting_names() {
        for (shell, _, _) in PLACES {
            let text = String::from_utf8(script(*shell)).unwrap();
            for word in [
                "config",
                "set",
                "show",
                "check",
                "discovery",
                "remote-reboot",
            ] {
                assert!(text.contains(word), "{shell}: {word}");
            }
        }
    }

    #[test]
    fn get_refuses_a_name_that_is_not_a_setting() {
        assert!(Config::try_parse_from(["connlog-agent", "config", "get", "discovery"]).is_ok());
        assert!(Config::try_parse_from(["connlog-agent", "config", "get", "discover"]).is_err());
    }
}
