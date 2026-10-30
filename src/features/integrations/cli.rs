//! `connlog-agent integration`: add, list, test and remove the
//! integrations this host reads as a collector. Run as root; a secret is
//! read from standard input, never taken from the command line, where any
//! user on the host could read it in the process list.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::{
    https, load_all, opnsense, parse_snmp_url, pinning, proxmox, read_one, snmp, switch,
    valid_name, valid_url, Access, Integration, Kind, State, DIR,
};
use crate::config::IntegrationCommand;

/// `collector`: whether this agent already runs as a collector
/// (CONNLOG_COLLECTOR), said only where it cannot be turned on from here.
pub fn run(command: IntegrationCommand, collector: bool) -> Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        bail!("Integrations are root's to manage: run this with sudo");
    }
    match command {
        IntegrationCommand::Add {
            name,
            kind,
            url,
            token_id,
            snmp_version,
            user,
            auth,
            no_privacy,
            fingerprint,
            system_trust,
        } => {
            if !valid_name(&name) {
                bail!("Name it with a-z, 0-9 and -, at most 32, starting with a letter or digit");
            }
            let kind = match kind.as_str() {
                "snmp" => Kind::Snmp,
                "opnsense" => Kind::Opnsense,
                _ => Kind::Proxmox,
            };
            let access = match kind {
                Kind::Snmp => snmp_access(&url, snmp_version.as_deref(), user, &auth, no_privacy)?,
                _ => https_access(
                    kind,
                    &url,
                    token_id.as_deref(),
                    fingerprint.as_deref(),
                    system_trust,
                )?,
            };
            add(Integration { name, kind, access }, collector)
        }
        IntegrationCommand::List => list(),
        IntegrationCommand::Test { name } => test(&name),
        IntegrationCommand::Remove { name } => remove(&name),
    }
}

/// Proxmox or OPNsense: the URL checked, the certificate pinned, the secret read.
fn https_access(
    kind: Kind,
    url: &str,
    token_id: Option<&str>,
    fingerprint: Option<&str>,
    system_trust: bool,
) -> Result<Access> {
    let url = url.trim_end_matches('/');
    if !valid_url(url) {
        bail!("--url: expected https://host[:port], nothing after the port");
    }
    let token_id = token_id.context(match kind {
        Kind::Opnsense => "--key: the API key is needed",
        _ => "--token-id: the token's id is needed",
    })?;
    check_id(kind, token_id)?;
    let fingerprint = match (fingerprint, system_trust) {
        (Some(text), _) => Some(
            pinning::parse(text)
                .context("--fingerprint: expected the SHA-256 fingerprint in hex")?,
        ),
        (None, true) => None,
        (None, false) => Some(trust_presented(url)?),
    };
    let token_secret = read_secret(match kind {
        Kind::Opnsense => "API secret: ",
        _ => "Token secret: ",
    })?;
    Ok(Access::Https {
        url: url.to_string(),
        token_id: token_id.to_string(),
        token_secret,
        fingerprint,
    })
}

/// SNMP: the address checked, the community or the v3 passwords read.
fn snmp_access(
    url: &str,
    version: Option<&str>,
    user: Option<String>,
    auth: &str,
    no_privacy: bool,
) -> Result<Access> {
    let (host, port) =
        parse_snmp_url(url.trim_end_matches('/')).context("--url: expected snmp://host[:port]")?;
    let security = match version.context("--snmp-version: 2c or 3")? {
        "2c" => snmp::Security::V2c {
            community: read_secret("Community: ")?,
        },
        _ => {
            let user = user
                .filter(|u| !u.is_empty() && !u.chars().any(char::is_control))
                .context("--user: the SNMPv3 user is needed")?;
            let password = |prompt: &str| -> Result<String> {
                let p = read_secret(prompt)?;
                if p.len() < 8 {
                    bail!("An SNMPv3 password is at least 8 characters");
                }
                Ok(p)
            };
            snmp::Security::V3 {
                user,
                auth: snmp::usm::AuthProtocol::parse(auth).context("--auth: sha256 or sha")?,
                auth_password: password("Authentication password: ")?,
                priv_password: if no_privacy {
                    None
                } else {
                    Some(password("Privacy password: ")?)
                },
            }
        }
    };
    Ok(Access::Snmp {
        host,
        port,
        security,
    })
}

fn add(integration: Integration, collector: bool) -> Result<()> {
    let (name, kind) = (integration.name.as_str(), integration.kind);
    // Kept only once it reads: a typo is found here, not in the console.
    // No device names: whether the workspace takes them is the platform's.
    let state = read_one(&integration, false);
    if let Some(failure) = state.error {
        bail!("{name}: {}. Nothing was saved.", failure.explain(kind));
    }
    crate::install::write_integration_file(Path::new(DIR), name, &integration.to_file())?;
    if let Some(line) = summary_of(&state) {
        println!("{name}: {line}");
    }
    match crate::platform::Packaging::current() {
        crate::platform::Packaging::Docker => {
            // The container's environment is its settings: nothing to write.
            println!("Saved to {DIR}/{name}.conf (the agent's user only).");
            if !collector {
                println!("Set CONNLOG_COLLECTOR=true in the container's environment to read it.");
            }
            return Ok(());
        }
        crate::platform::Packaging::Freebsd => {
            println!("Saved to {DIR}/{name}.conf (root and the agent's user only).");
            if !collector {
                println!(
                    "Set CONNLOG_COLLECTOR=true in {} and run `service connlog_agent restart` to read it.",
                    crate::install::freebsd::CONF
                );
            }
            return Ok(());
        }
        crate::platform::Packaging::Systemd => {}
    }
    println!("Saved to {DIR}/{name}.conf (root and the agent's service account only).");
    crate::install::set_collector(true)
}

/// Proxmox's token id is `user@realm!tokenname`; OPNsense's key is one word.
fn check_id(kind: Kind, id: &str) -> Result<()> {
    let one_word = !id.is_empty() && !id.chars().any(|c| c.is_control() || c.is_whitespace());
    match kind {
        Kind::Proxmox if !(one_word && id.contains('!') && id.contains('@')) => {
            bail!("--token-id: expected user@realm!tokenname")
        }
        Kind::Opnsense if !one_word => bail!("--key: expected the API key, one word"),
        _ => Ok(()),
    }
}

/// Shows the certificate the device presents and asks before trusting it.
fn trust_presented(url: &str) -> Result<pinning::Fingerprint> {
    let presented = https::presented_fingerprint(&format!("{url}/"))
        .context("Could not reach the device to read its certificate")?;
    println!(
        "Its certificate has the SHA-256 fingerprint\n  {}\nCheck it on the device (Proxmox: the node → System → Certificates; OPNsense: System → Trust → Certificates) before trusting it.",
        pinning::format(&presented)
    );
    if !std::io::stdin().is_terminal() {
        bail!("Pass it as --fingerprint once checked, or --system-trust for a certificate a public authority signed");
    }
    let yes = dialoguer::Confirm::new()
        .with_prompt("Trust this certificate for this integration?")
        .default(false)
        .interact()?;
    if !yes {
        bail!("Not trusted; nothing was saved");
    }
    Ok(presented)
}

fn summary_of(state: &State) -> Option<String> {
    state
        .proxmox
        .as_ref()
        .map(summary)
        .or_else(|| state.opnsense.as_ref().map(firewall_summary))
        .or_else(|| state.switch.as_ref().map(switch_summary))
}

/// "sw-core: 48 ports (31 up), 6 VLANs, 2 LLDP neighbours, 214 MAC addresses".
fn switch_summary(report: &switch::Report) -> String {
    let up = report.ports.iter().filter(|p| p.up).count();
    format!(
        "{}{} ({up} up), {}, {}, {}",
        report
            .name
            .as_deref()
            .map(|n| format!("{n}: "))
            .unwrap_or_default(),
        plural(report.ports.len(), "port", "ports"),
        plural(report.vlans.len(), "VLAN", "VLANs"),
        plural(report.neighbours.len(), "LLDP neighbour", "LLDP neighbours"),
        plural(report.macs.len(), "MAC address", "MAC addresses"),
    )
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "4 interfaces (2 VLANs), 2 gateways (1 down), 37 leases".
fn firewall_summary(report: &opnsense::Report) -> String {
    let vlans = report
        .interfaces
        .iter()
        .filter(|i| i.vlan.is_some())
        .count();
    let down = report
        .gateways
        .iter()
        .filter(|g| g.state == opnsense::GatewayState::Down)
        .count();
    let mut line = plural(report.interfaces.len(), "interface", "interfaces");
    if vlans > 0 {
        line.push_str(&format!(" ({})", plural(vlans, "VLAN", "VLANs")));
    }
    line.push_str(&format!(
        ", {}",
        plural(report.gateways.len(), "gateway", "gateways")
    ));
    if down > 0 {
        line.push_str(&format!(" ({down} down)"));
    }
    match &report.leases {
        Some(leases) => line.push_str(&format!(", {}", plural(leases.len(), "lease", "leases"))),
        None => line.push_str(", no DHCP leases readable"),
    }
    line
}

fn summary(report: &proxmox::Report) -> String {
    let guests = report.guests.len();
    format!(
        "{}{} {}, {} {}, {} bridge{}",
        report
            .cluster
            .as_deref()
            .map(|c| format!("cluster {c}, "))
            .unwrap_or_default(),
        report.nodes.len(),
        if report.nodes.len() == 1 {
            "node"
        } else {
            "nodes"
        },
        guests,
        if guests == 1 { "guest" } else { "guests" },
        report.bridges.len(),
        if report.bridges.len() == 1 { "" } else { "s" },
    )
}

fn list() -> Result<()> {
    let integrations = load_all(Path::new(DIR));
    if integrations.is_empty() {
        println!("No integration on this host. Add one with `sudo connlog-agent integration add`.");
    }
    for i in integrations {
        println!("{}  {}  {}", i.name, i.kind.word(), i.access.describe());
    }
    Ok(())
}

fn test(name: &str) -> Result<()> {
    let integration = load_all(Path::new(DIR))
        .into_iter()
        .find(|i| i.name == name)
        .with_context(|| format!("No integration named {name}"))?;
    let state = read_one(&integration, false);
    if let Some(failure) = state.error {
        bail!("{name}: {}", failure.explain(integration.kind));
    }
    println!(
        "{name}: {}",
        summary_of(&state).unwrap_or_else(|| "read".into())
    );
    Ok(())
}

fn remove(name: &str) -> Result<()> {
    if !valid_name(name) {
        bail!("No integration named {name}");
    }
    let path = Path::new(DIR).join(format!("{name}.conf"));
    std::fs::remove_file(&path).with_context(|| format!("No integration named {name}"))?;
    println!("Removed {name}. ConnLog forgets what it read on the collector's next report.");
    Ok(())
}

/// One line from standard input; with a terminal, typed without echo.
fn read_secret(prompt: &str) -> Result<String> {
    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    if terminal {
        print!("{prompt}");
        std::io::stdout().flush().ok();
    }
    let _echo = terminal.then(EchoOff::new).flatten();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    if terminal {
        println!();
    }
    let secret = line.trim().to_string();
    if secret.is_empty() || secret.chars().any(char::is_control) {
        bail!("The secret is one line, and not empty");
    }
    Ok(secret)
}

/// The terminal's echo off for as long as it lives.
struct EchoOff(libc::termios);

impl EchoOff {
    fn new() -> Option<Self> {
        // SAFETY: tcgetattr and tcsetattr on stdin with a zeroed, then
        // filled, termios; failure leaves echo as it was.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut saved) != 0 {
                return None;
            }
            let mut quiet = saved;
            quiet.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &quiet) != 0 {
                return None;
            }
            Some(Self(saved))
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the attributes read in `new`.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_up_what_it_read() {
        let report = proxmox::Report {
            cluster: Some("lab".into()),
            nodes: vec![
                proxmox::Node {
                    name: "a".into(),
                    online: true,
                    address: None,
                };
                2
            ],
            bridges: vec![],
            guests: vec![],
        };
        assert_eq!(
            summary(&report),
            "cluster lab, 2 nodes, 0 guests, 0 bridges"
        );
    }

    #[test]
    fn sums_up_a_firewall() {
        let interface = opnsense::Interface {
            name: "opt1".into(),
            description: "IoT".into(),
            device: None,
            up: true,
            cidrs: vec![],
            vlan: Some(20),
        };
        let gateway = opnsense::Gateway {
            name: "WAN".into(),
            address: None,
            state: opnsense::GatewayState::Down,
            rtt_ms: None,
            loss_pct: None,
        };
        let report = opnsense::Report {
            interfaces: vec![interface.clone(), interface],
            gateways: vec![gateway],
            leases: None,
        };
        assert_eq!(
            firewall_summary(&report),
            "2 interfaces (2 VLANs), 1 gateway (1 down), no DHCP leases readable"
        );
    }

    #[test]
    fn checks_the_id_for_its_kind() {
        assert!(check_id(Kind::Proxmox, "connlog@pve!collector").is_ok());
        assert!(check_id(Kind::Proxmox, "w86XNZob").is_err());
        assert!(check_id(Kind::Opnsense, "w86XNZob").is_ok());
        assert!(check_id(Kind::Opnsense, "two words").is_err());
    }
}
