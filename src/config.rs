use clap::{Args, Parser, Subcommand, ValueEnum};
use std::fmt;

use crate::features::discovery::{parse_discovery, DiscoveryLevel, CONF_DISCOVERY};

#[derive(Parser)]
#[command(name = "connlog-agent")]
#[command(about = "ConnLog monitoring agent")]
#[command(long_about = "ConnLog monitoring agent")]
#[command(
    after_help = "Common usage:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent install\n  sudo connlog-agent action add\n  sudo connlog-agent config enable-hostname\n  sudo connlog-agent status\n\nTip:\n  Run `sudo connlog-agent` with no arguments in a terminal for an interactive menu.\n  Use `connlog-agent action --help` to manage dashboard buttons.\n  Use `connlog-agent diagnostics --help` for heartbeat/config checks.\n\nLegacy flags still work for existing scripts: --install, --uninstall, --status, --update, --check-config, --test-heartbeat."
)]
#[command(version)]
pub struct Config {
    #[command(subcommand)]
    pub command: Option<AgentCommand>,

    /// Agent authentication token
    #[arg(
        short,
        long,
        env = "CONNLOG_TOKEN",
        global = true,
        value_name = "TOKEN"
    )]
    pub token: Option<String>,

    /// Legacy alias for `install`
    #[arg(short, long, hide = true)]
    pub install: bool,

    /// Legacy alias for `uninstall`
    #[arg(short, long, hide = true)]
    pub uninstall: bool,

    /// Legacy alias for `status`
    #[arg(short, long, hide = true)]
    pub status: bool,

    /// Legacy alias for `update`
    #[arg(long, hide = true)]
    pub update: bool,

    /// Diagnostic: fetch + print the agent config from the platform without
    /// starting the heartbeat loop. Exits non-zero on auth/network failure.
    #[arg(long = "check-config", hide = true)]
    pub check_config: bool,

    /// Diagnostic: send exactly one heartbeat and print the platform's
    /// response, then exit. Exits non-zero on auth/network failure.
    #[arg(long = "test-heartbeat", hide = true)]
    pub test_heartbeat: bool,

    /// Print the embedded systemd service file and exit (used by self-updater)
    #[arg(long = "emit-service", hide = true)]
    pub emit_service: bool,

    #[cfg(debug_assertions)]
    /// Custom platform endpoint (debug builds only)
    #[arg(
        short,
        long,
        env = "CONNLOG_ENDPOINT",
        help = "Platform endpoint URL (debug builds only)",
        global = true
    )]
    pub endpoint: Option<String>,

    /// Opt-in: share this machine's hostname with ConnLog.
    ///
    /// By default the hostname is NOT transmitted (privacy-preserving default).
    /// Set CONNLOG_EXPOSE_SYSTEM_INFO=true in /etc/connlog/agent.conf to enable.
    /// This is intentionally off by default to comply with GDPR and similar
    /// regulations — exposing the machine's identity is the operator's
    /// explicit choice.
    ///
    /// Note: OS and CPU architecture (e.g. "linux"/"x86_64") are always sent
    /// with every heartbeat regardless of this setting. The platform needs
    /// them to pick the correct self-update binary for this host. These are
    /// generic platform descriptors, not machine-identifying, and the
    /// platform does not store or display them unless hostname sharing is
    /// also enabled.
    #[arg(
        long = "expose-system-info",
        env = "CONNLOG_EXPOSE_SYSTEM_INFO",
        default_value_t = false,
        hide = true
    )]
    pub expose_system_info: bool,

    /// Whether the dashboard may reboot this host. Off unless set to true.
    ///
    /// Set CONNLOG_ALLOW_REMOTE_REBOOT=true in /etc/connlog/agent.conf (or run
    /// `connlog-agent config enable-remote-reboot`) to allow it. Unset, or any
    /// other value, and the agent refuses every remote reboot request and
    /// tells the platform so; the root-side systemd hook checks the same file
    /// before it reboots anything. The file is root-only, so neither the
    /// platform nor the running agent can turn the setting on. `None` is
    /// "not set", which `install` needs to tell apart from an explicit false.
    #[arg(
        long = "allow-remote-reboot",
        env = "CONNLOG_ALLOW_REMOTE_REBOOT",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        global = true,
        hide = true
    )]
    pub allow_remote_reboot: Option<bool>,

    /// Opt-in: after the host went down without a clean stop, send the
    /// previous boot's last journal and kernel warnings (redacted, at most
    /// 8 KB) with the outage report. Off by default: logs can hold anything.
    #[arg(
        long = "share-postmortem",
        env = "CONNLOG_SHARE_POSTMORTEM",
        default_value_t = false,
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        global = true,
        hide = true
    )]
    pub share_postmortem: bool,

    /// With `install`: write CONNLOG_ALLOW_REMOTE_REBOOT=true, so the
    /// dashboard may reboot this host.
    #[arg(
        long = "enable-remote-reboot",
        global = true,
        conflicts_with = "disable_remote_reboot"
    )]
    pub enable_remote_reboot: bool,

    /// With `install`: write CONNLOG_ALLOW_REMOTE_REBOOT=false. Off is already
    /// the default; the flag stays so existing install scripts keep working,
    /// and it records the refusal explicitly.
    #[arg(long = "disable-remote-reboot", global = true)]
    pub disable_remote_reboot: bool,

    // ── Network map (docs/topology/PLAN.md) ──
    //
    // Off unless the root-only agent.conf says CONNLOG_NETWORK_MAP=true. Site
    // and ports are read as plain text and checked by
    // `features::network_map`: a bad value is refused by `install` and
    // `config`, and ignored with a warning by the daemon, so a typo in the
    // file can never stop the agent from starting.
    /// Whether this host takes part in the network map. Off unless set to true.
    #[arg(
        long = "network-map",
        env = "CONNLOG_NETWORK_MAP",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        global = true,
        hide = true
    )]
    pub network_map: Option<bool>,

    /// With `install`: write CONNLOG_DISCOVERY=peers (at least), so this host
    /// takes part in the network map (its workspace must turn the map on too).
    #[arg(long = "enable-network-map", global = true)]
    pub enable_network_map: bool,

    /// With `install`: map this host's network from here, the one question
    /// the installer asks (T13.4): write CONNLOG_DISCOVERY=active. ConnLog's
    /// console still chooses at or below it, and the workspace's "Map
    /// networks automatically" decides whether it does so by itself.
    #[arg(long = "map-network", global = true)]
    pub map_network: bool,

    /// Whether this host runs the checks ConnLog assigns (CONNLOG_CHECKS):
    /// ping, TCP, HTTP(S) and DNS checks of devices without an agent. Off
    /// unless set to true.
    #[arg(
        long = "checks",
        env = "CONNLOG_CHECKS",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        global = true,
        hide = true
    )]
    pub checks: Option<bool>,

    /// With `install`: write CONNLOG_CHECKS=true, so this host runs the
    /// checks ConnLog assigns.
    #[arg(long = "enable-checks", global = true)]
    pub enable_checks: bool,

    /// Whether this host is a collector (CONNLOG_COLLECTOR): it reads the
    /// integrations in /etc/connlog/integrations.d and reports them. Off
    /// unless set to true.
    #[arg(
        long = "collector",
        env = "CONNLOG_COLLECTOR",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        global = true,
        hide = true
    )]
    pub collector: Option<bool>,

    /// How much this host may find out about its network (CONNLOG_DISCOVERY):
    /// off, peers (the network map), passive or active. The ceiling the
    /// console chooses under; read as text and checked by
    /// `features::discovery`, like the site and ports.
    #[arg(
        long = "discovery",
        env = "CONNLOG_DISCOVERY",
        global = true,
        value_name = "LEVEL"
    )]
    pub discovery: Option<String>,

    /// Network map site name (CONNLOG_NETWORK_SITE): hosts with the same name
    /// are drawn as one site. Lowercase letters, digits, `.`, `_`, `-`; at
    /// most 64.
    #[arg(
        long = "network-site",
        env = "CONNLOG_NETWORK_SITE",
        global = true,
        value_name = "NAME"
    )]
    pub network_site: Option<String>,

    /// Extra TCP ports others should try on this host even if nothing listens
    /// yet (CONNLOG_NETWORK_MAP_PORTS): a comma list of at most 16 ports.
    #[arg(
        long = "network-map-ports",
        env = "CONNLOG_NETWORK_MAP_PORTS",
        global = true,
        value_name = "PORTS"
    )]
    pub network_map_ports: Option<String>,

    /// Let network map probes reach addresses outside the private ranges.
    /// Off unless set to true.
    #[arg(
        long = "probe-public",
        env = "CONNLOG_PROBE_PUBLIC",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        global = true,
        hide = true
    )]
    pub probe_public: Option<bool>,

    // ── BMC hardware-health (Dell iDRAC / HPE iLO / OpenBMC via Redfish) ──
    //
    // All three of endpoint/username/password must be set to enable the
    // poller; everything else has a default. These fold CLI > env >
    // agent.conf (agent.conf is the systemd EnvironmentFile, so its lines
    // arrive as env vars that clap reads here). Prefer the env/agent.conf
    // path for the password so it never lands in `ps`/shell history.
    /// BMC Redfish endpoint, e.g. https://10.0.0.120 (the BMC IP, not the OS).
    #[arg(
        long = "bmc-endpoint",
        env = "CONNLOG_BMC_ENDPOINT",
        global = true,
        value_name = "URL"
    )]
    pub bmc_endpoint: Option<String>,

    /// BMC account username (a read-only monitoring account is recommended).
    #[arg(
        long = "bmc-username",
        env = "CONNLOG_BMC_USERNAME",
        global = true,
        value_name = "USER"
    )]
    pub bmc_username: Option<String>,

    /// BMC account password. Prefer CONNLOG_BMC_PASSWORD / agent.conf over the flag.
    #[arg(
        long = "bmc-password",
        env = "CONNLOG_BMC_PASSWORD",
        global = true,
        value_name = "PASS"
    )]
    pub bmc_password: Option<String>,

    /// BMC poll interval in seconds (default 300, clamped to 60..=3600).
    #[arg(
        long = "bmc-poll-interval",
        env = "CONNLOG_BMC_POLL_INTERVAL_SECS",
        global = true,
        value_name = "SECS"
    )]
    pub bmc_poll_interval_secs: Option<u64>,

    /// Accept the BMC's self-signed TLS certificate (common on iDRAC / iLO).
    #[arg(
        long = "bmc-insecure-tls",
        env = "CONNLOG_BMC_INSECURE_TLS",
        global = true,
        default_value_t = false
    )]
    pub bmc_insecure_tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum AgentCommand {
    /// Install, register, and start as a systemd service
    #[command(
        long_about = "Install connlog-agent as a systemd service, write the token to /etc/connlog/agent.conf, start the service, and let the service register with ConnLog.\n\nUse this on normal Linux servers.\n\nExamples:\n  sudo connlog-agent install --token agent_xxxxxxxxxxxx\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent install"
    )]
    Install,

    /// Register with ConnLog and run in the foreground
    #[command(
        long_about = "Register with ConnLog using an agent token and run the heartbeat loop in the foreground.\n\nThis command is useful for manual testing and containers. It does not install or start a systemd service, and it keeps running until stopped.\n\nExamples:\n  connlog-agent register --token agent_xxxxxxxxxxxx\n  CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent register"
    )]
    Register,

    /// Show the systemd service status
    Status,

    /// Refresh the installed systemd service file from this binary
    RefreshService {
        /// Restart connlog-agent after writing the service and daemon-reload
        #[arg(long)]
        restart: bool,
    },

    /// Check for and apply the latest release
    Update,

    /// Apply a verified staged update (root; run by the systemd ExecStopPost hook)
    #[command(hide = true)]
    ApplyStagedUpdate,

    /// Save the previous boot's last warnings when it ended badly (root; run
    /// by the systemd ExecStartPre hook, only with CONNLOG_SHARE_POSTMORTEM)
    #[command(hide = true)]
    CollectPostmortem,

    /// Manage local dashboard actions
    #[command(
        alias = "actions",
        long_about = "Manage dashboard actions registered on this agent host.\n\nActions are stored locally in /etc/connlog/actions.toml by default. The running agent reloads that file and publishes action metadata to ConnLog on the next heartbeat.\n\nThe dashboard can request registered action IDs only. Command argv stays on the agent host.",
        after_help = "Examples:\n  sudo connlog-agent action add\n  sudo connlog-agent action list\n  sudo connlog-agent action test check_disk_usage\n  sudo connlog-agent action remove check_disk_usage"
    )]
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },

    /// Integrations this host reads as a collector (Proxmox VE)
    #[command(
        long_about = "Manage the integrations this host reads as a collector.\n\nEach one is a file in /etc/connlog/integrations.d, readable by root and the agent's service account only. Its secret is read from standard input, never from the command line, and never leaves this host.",
        after_help = "Examples:\n  sudo connlog-agent integration add pve --url https://pve.lan:8006 --token-id connlog@pve!collector\n  sudo connlog-agent integration list\n  sudo connlog-agent integration test pve\n  sudo connlog-agent integration remove pve"
    )]
    Integration {
        #[command(subcommand)]
        command: IntegrationCommand,
    },

    /// Print tab completion for a shell: bash, zsh or fish
    #[command(
        long_about = "Print a tab-completion script for bash, zsh or fish. `install` already puts one where each shell installed here looks; this is for another shell or place.\n\nExamples:\n  connlog-agent completions bash > ~/.local/share/bash-completion/completions/connlog-agent\n  connlog-agent completions zsh > \"${fpath[1]}/_connlog-agent\""
    )]
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Diagnostic tools
    Diagnostics {
        #[command(subcommand)]
        command: DiagnosticCommand,
    },

    /// Local `/etc/connlog/agent.conf` settings
    #[command(
        long_about = "Create or update /etc/connlog/agent.conf on this machine.\n\nThe running service cannot write that file (it is 0600 root-only and the process is sandboxed). These commands run as root and then restart the service so the new values take effect.\n\nExamples:\n  sudo connlog-agent config enable-hostname"
    )]
    Config {
        #[command(subcommand)]
        command: LocalConfigCommand,
    },

    /// Uninstall the agent
    Uninstall,

    /// Fetch and print platform config, then exit
    #[command(
        hide = true,
        long_about = "Fetch the agent config from the platform and print it, then exit without starting another heartbeat loop.\n\nUse this after installing to verify that the token and platform connectivity are correct.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent check-config\n  connlog-agent check-config --token agent_xxxxxxxxxxxx"
    )]
    CheckConfig,

    /// Send one heartbeat, print the response, then exit
    #[command(
        hide = true,
        long_about = "Send exactly one heartbeat to the platform, print the response, then exit without starting the normal retry loop.\n\nUse this as a smoke test after registration or service changes.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent test-heartbeat\n  connlog-agent test-heartbeat --token agent_xxxxxxxxxxxx"
    )]
    TestHeartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum LocalConfigCommand {
    /// Share this machine's hostname with ConnLog
    #[command(
        long_about = "Create /etc/connlog/agent.conf if it is missing, set CONNLOG_EXPOSE_SYSTEM_INFO=true, and restart the agent service.\n\nHostname sharing is off by default. Run this on the server when you want ConnLog to display the hostname.\n\nExample:\n  sudo connlog-agent config enable-hostname"
    )]
    EnableHostname,

    /// Stop sharing this machine's hostname with ConnLog (the default)
    #[command(
        long_about = "Set CONNLOG_EXPOSE_SYSTEM_INFO=false in /etc/connlog/agent.conf and restart the agent service.\n\nThe agent then stops sending the hostname; ConnLog keeps showing the server's name.\n\nExample:\n  sudo connlog-agent config disable-hostname"
    )]
    DisableHostname,

    /// Refuse remote reboot requests from the dashboard (the default)
    #[command(
        long_about = "Set CONNLOG_ALLOW_REMOTE_REBOOT=false in /etc/connlog/agent.conf and restart the agent service.\n\nRemote reboot is already off unless the file says true; this records the refusal explicitly. The agent refuses every remote reboot request and reports that to ConnLog, which disables the reboot button for this host. The root-side systemd hook checks the same file, so the setting holds even if the agent process were compromised.\n\nExample:\n  sudo connlog-agent config disable-remote-reboot"
    )]
    DisableRemoteReboot,

    /// Allow remote reboot requests from the dashboard
    #[command(
        long_about = "Set CONNLOG_ALLOW_REMOTE_REBOOT=true in /etc/connlog/agent.conf and restart the agent service.\n\nRemote reboot is off until this is run. Only root on this machine can turn it on; neither ConnLog nor the running agent can.\n\nExample:\n  sudo connlog-agent config enable-remote-reboot"
    )]
    EnableRemoteReboot,

    /// Send the previous boot's last warnings with an outage report (opt-in)
    #[command(
        long_about = "Set CONNLOG_SHARE_POSTMORTEM=true in /etc/connlog/agent.conf and restart the agent service.\n\nAfter the host goes down without a clean stop (a crash, a power cut, a hard reset), the agent then sends the previous boot's last journal and kernel warnings, with anything that looks like a password, token or bearer credential masked and at most 8 KB kept, along with the outage report. Needs a persistent journal. Off by default.\n\nExample:\n  sudo connlog-agent config enable-postmortem"
    )]
    EnablePostmortem,

    /// Stop sending the previous boot's last warnings (the default)
    DisablePostmortem,

    /// Take part in the network map
    #[command(
        long_about = "Set CONNLOG_DISCOVERY=peers in /etc/connlog/agent.conf (a higher level stays as it is) and restart the agent service.\n\nThe agent then sends this host's interface addresses (with prefix length), the TCP port numbers listening on a non-loopback address, its default gateway and the gateway's MAC address, every 15 minutes when they change; and it runs the reachability probes ConnLog asks for: TCP handshakes (never a payload) and ICMP echoes to other opted-in hosts in the same workspace, at most 32 addresses and 8 ports per request, 4 at a time, private addresses only unless CONNLOG_PROBE_PUBLIC=true. No process names, users, interface names or connections leave the host. Off by default; a workspace admin can still turn the map off for the whole workspace.\n\nWith --network-site or --network-map-ports, those are written too.\n\nExamples:\n  sudo connlog-agent config enable-network-map\n  sudo connlog-agent config enable-network-map --network-site hq --network-map-ports 443,8443"
    )]
    EnableNetworkMap,

    /// Map this host's network from here: the highest discovery level
    #[command(
        long_about = "Set CONNLOG_DISCOVERY=active in /etc/connlog/agent.conf and restart the agent service: what `set-discovery active` does, and what the installer asks with \"Map this network from here?\".\n\nThe host may then take part in the network map, read what it already knows about its network, and sweep the subnets it is on when ConnLog asks (see set-discovery). The level is a ceiling: ConnLog's console chooses at or below it, by hand or, with the workspace's \"Map networks automatically\" on, by itself; one host per subnet sweeps.\n\nExample:\n  sudo connlog-agent config map-network"
    )]
    MapNetwork,

    /// Stop taking part in the network map (the default)
    #[command(
        long_about = "Set CONNLOG_DISCOVERY=off in /etc/connlog/agent.conf and restart the agent service.\n\nThe agent then sends no inventory, runs no probes, and tells ConnLog so; ConnLog stops offering this host as a target.\n\nExample:\n  sudo connlog-agent config disable-network-map"
    )]
    DisableNetworkMap,

    /// Run the checks ConnLog assigns: ping, TCP, HTTP(S) and DNS
    #[command(
        long_about = "Set CONNLOG_CHECKS=true in /etc/connlog/agent.conf and restart the agent service.\n\nThe agent then runs the checks ConnLog assigns to it, for devices that have no agent: a ping (three echoes), a TCP connect, an HTTP(S) GET (its status, its time to the first byte and the certificate's days left; never a byte of the body), a DNS query to a given resolver. At most 16 at a time, 10 seconds each, each target at most once a minute. Public targets always; a private one only when this host's discovery level is passive or above. Off by default.\n\nExample:\n  sudo connlog-agent config enable-checks"
    )]
    EnableChecks,

    /// Stop running checks (the default)
    DisableChecks,

    /// Make this host a collector, reading the integrations set up on it
    #[command(
        long_about = "Set CONNLOG_COLLECTOR=true in /etc/connlog/agent.conf and restart the agent service.\n\nThe agent then reads the integrations in /etc/connlog/integrations.d (see `connlog-agent integration`) every five minutes while ConnLog asks for them, and reports what they read: for Proxmox VE, its nodes, bridges, guests, their interfaces' MAC addresses, bridges and VLAN tags. Credentials stay on this host; a report never carries one. Off by default. `integration add` turns it on too.\n\nExample:\n  sudo connlog-agent config enable-collector"
    )]
    EnableCollector,

    /// Stop reading integrations (the default)
    DisableCollector,

    /// Set how much this host may find out about its network
    #[command(
        long_about = "Set CONNLOG_DISCOVERY in /etc/connlog/agent.conf and restart the agent service.\n\nThe level is a ceiling: ConnLog's console chooses at or below it for this host, and can never raise it.\n\n  off      nothing (the default)\n  peers    the network map: see enable-network-map\n  passive  peers, and what the host already knows about its network: the VLAN id of each address on a VLAN interface, its neighbour table (private addresses, their MAC and state, at most 1,024), and its path out (a trace of at most 16 hops towards its gateway and ConnLog, every 6 hours, over the ping socket the probes use); never an interface's name, never a device's name\n  active   passive, and sweeps of the host's own subnets the console lists: an IPv4 subnet this host is on, a /22 at most, 64 addresses a second, an echo and handshakes to at most 8 well-known ports per address (never a byte of payload), one mDNS question and one SSDP search; what answered, its open ports and what it announces (never an mDNS name, never a UUID)\n\nThe host runs at the lower of this and what the console allows for it.\n\nExamples:\n  sudo connlog-agent config set-discovery peers\n  sudo connlog-agent config set-discovery off"
    )]
    SetDiscovery {
        #[arg(value_enum)]
        level: DiscoveryLevel,
    },

    /// Change one or more settings at once: name=value
    #[command(
        long_about = "Change one or more settings in agent.conf, then restart the agent once and wait for its first heartbeat. Every value is checked before anything is written; if the agent does not come back on the new settings, the previous file is put back.\n\n`connlog-agent config show` lists the names. Switches take on or off. A password is never typed on the command line: name it without a value to be asked for it, or pipe it in.\n\nExamples:\n  sudo connlog-agent config set hostname=on discovery=passive checks=on\n  sudo connlog-agent config set network-site=hq network-map-ports=443,8443\n  sudo connlog-agent config set bmc-endpoint=https://10.0.0.120 bmc-username=root bmc-password"
    )]
    Set {
        #[arg(value_name = "NAME=VALUE", required = true)]
        pairs: Vec<String>,
    },

    /// Print one setting's value
    #[command(
        long_about = "Print one setting's value as the agent reads it, for scripts: on or off for a switch, set or not set for a password.\n\nExample:\n  sudo connlog-agent config get discovery"
    )]
    Get {
        /// One of the names `config show` lists; tab completes them.
        #[arg(value_parser = clap::builder::PossibleValuesParser::new(
            crate::features::settings::SETTINGS.iter().map(|s| s.name)
        ))]
        name: String,
    },

    /// List every setting, its value and what it does
    #[command(
        long_about = "List every setting in agent.conf (in Docker: the container's environment) with its value or default and what it does. The token is shortened and a password is never shown.\n\nExample:\n  sudo connlog-agent config show"
    )]
    Show,

    /// Find settings the agent would refuse, ignore or misread
    #[command(
        long_about = "Read agent.conf as the agent will and say what it would refuse (and so not start), ignore or read differently: misspelt names, with the nearest real one; values a switch does not take; settings set twice. Exits non-zero when the agent would not start or not report.\n\nExample:\n  sudo connlog-agent config check"
    )]
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum IntegrationCommand {
    /// Add a Proxmox VE, OPNsense or SNMP integration (or replace one of the same name)
    #[command(
        long_about = "Add an integration, test it, and make this host a collector.\n\nProxmox VE (the default kind): create the token first, under Datacenter → Permissions → API Tokens, for a user with the PVEAuditor role on /, privilege separation off (or give the token PVEAuditor itself). Pass its id as --token-id.\n\nOPNsense (--kind opnsense): create a user that is not an administrator, in a group with only these pages: Status: Interfaces overview, System: Gateways, and the lease page of the DHCP server it runs (Services: Kea DHCP, Services: Dnsmasq DNS/DHCP, or Status: DHCP leases for the ISC plugin). Create an API key for that user (System → Access → Users) and pass the key as --key.\n\nA switch or router over SNMP (--kind snmp, --url snmp://host[:port]): v2c with a read-only community (--snmp-version 2c), or, better, v3 with a read-only user (--snmp-version 3 --user …), SHA-256 or SHA authentication (--auth) and AES-128 privacy (--no-privacy for authNoPriv). MD5 and DES are not offered: they are broken. It reads the interfaces, VLANs, LLDP neighbours and bridge table; give the community or user a view of no more.\n\nThe secrets (token secret, API secret, community, v3 passwords) are read from standard input, one per line, never from the command line.\n\nA device's own certificate is usually self-signed: the command shows its SHA-256 fingerprint and asks before trusting it, or takes it from --fingerprint. With a certificate a public authority signed, pass --system-trust instead.\n\nExamples:\n  sudo connlog-agent integration add pve --url https://pve.lan:8006 --token-id connlog@pve!collector\n  echo \"$SECRET\" | sudo connlog-agent integration add lab --url https://10.0.20.2:8006 --token-id connlog@pve!collector --fingerprint AB:CD:…\n  sudo connlog-agent integration add fw --kind opnsense --url https://10.0.0.1 --key w86XNZob…\n  sudo connlog-agent integration add core --kind snmp --url snmp://10.0.0.2 --snmp-version 3 --user connlog"
    )]
    Add {
        /// A short name: a-z, 0-9 and -, at most 32
        name: String,
        /// What it is: proxmox, opnsense or snmp
        #[arg(long, default_value = "proxmox", value_parser = ["proxmox", "opnsense", "snmp"])]
        kind: String,
        /// The address: https://host:8006 for Proxmox, https://host for OPNsense, snmp://host[:port]
        #[arg(long)]
        url: String,
        /// Proxmox: the token's id, user@realm!tokenname. OPNsense: the API key (--key)
        #[arg(long = "token-id", alias = "key")]
        token_id: Option<String>,
        /// SNMP: 2c or 3
        #[arg(long = "snmp-version", value_parser = ["2c", "3"])]
        snmp_version: Option<String>,
        /// SNMP v3: the user
        #[arg(long)]
        user: Option<String>,
        /// SNMP v3: sha256 or sha
        #[arg(long, default_value = "sha256", value_parser = ["sha256", "sha"])]
        auth: String,
        /// SNMP v3: authentication without privacy (authNoPriv)
        #[arg(long = "no-privacy")]
        no_privacy: bool,
        /// The certificate's SHA-256 fingerprint, to trust it without asking
        #[arg(long, conflicts_with = "system_trust")]
        fingerprint: Option<String>,
        /// Trust the certificate as any website's, by a public authority
        #[arg(long = "system-trust")]
        system_trust: bool,
    },
    /// List the integrations on this host, never their secrets
    List,
    /// Read one now and say what it found, or why not
    Test { name: String },
    /// Remove one
    Remove { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum DiagnosticCommand {
    /// Fetch and print platform config, then exit
    #[command(
        long_about = "Fetch the agent config from the platform and print it, then exit without starting another heartbeat loop.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent diagnostics check-config\n  connlog-agent diagnostics check-config --token agent_xxxxxxxxxxxx"
    )]
    CheckConfig,

    /// Send one heartbeat, print the response, then exit
    #[command(
        long_about = "Send exactly one heartbeat to the platform, print the response, then exit without starting the normal retry loop.\n\nExamples:\n  sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent diagnostics test-heartbeat\n  connlog-agent diagnostics test-heartbeat --token agent_xxxxxxxxxxxx"
    )]
    TestHeartbeat,

    /// Inspect the installed systemd service template
    #[command(
        long_about = "Compare the installed systemd service with the template embedded in this binary.\n\nExamples:\n  connlog-agent diagnostics service\n  sudo connlog-agent refresh-service --restart"
    )]
    Service,

    /// Inspect recent heartbeat delivery diagnostics from the agent's local store
    #[command(
        long_about = "Show what the agent believes happened to recent heartbeat attempts — retries, response codes, and transport failures — from a bounded, agent-owned local store.\n\nReads only local state: it requires no root, never sends a heartbeat, never contacts the platform, and never prints secrets, signatures, credentials, or raw heartbeat payloads. Safe to run through a ConnLog remote action without sudo.\n\nExamples:\n  connlog-agent diagnostics heartbeats\n  connlog-agent diagnostics heartbeats --since 72h --limit 500 --format text\n  connlog-agent diagnostics heartbeats --since 72h --limit 500 --format json"
    )]
    Heartbeats {
        /// Look-back window: e.g. 24h, 72h, 30m, 90s, 7d (a bare number = seconds)
        #[arg(long, default_value = "24h")]
        since: String,

        /// Maximum number of event records to inspect (most recent are kept)
        #[arg(long, default_value_t = 100)]
        limit: usize,

        /// Output format
        #[arg(long, value_enum, default_value_t = DiagnosticsFormat::Text)]
        format: DiagnosticsFormat,
    },
    /// Show the flight recorder: the last day of this host, one record a minute
    #[command(
        long_about = "Show what the flight recorder kept: one record a minute for the last 24 hours (CPU, memory, disk, load, OOM kills, pressure), written whether or not ConnLog was reachable, and what happened in between: reboots (clean, unclean, requested), agent restarts and updates, and stretches when the platform could not be reached.\n\nReads only the local ring file: no root, no network, no token.\n\nExamples:\n  connlog-agent diagnostics history\n  connlog-agent diagnostics history --since 2h --limit 120\n  connlog-agent diagnostics history --format json"
    )]
    History {
        /// Look-back window: e.g. 24h, 2h, 30m (a bare number = seconds)
        #[arg(long, default_value = "24h")]
        since: String,

        /// Maximum number of records to list (the most recent are kept)
        #[arg(long, default_value_t = 30)]
        limit: usize,

        /// Output format
        #[arg(long, value_enum, default_value_t = DiagnosticsFormat::Text)]
        format: DiagnosticsFormat,
    },
}

/// Output format for `diagnostics heartbeats` and `diagnostics history`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiagnosticsFormat {
    /// Human-readable summary plus event list
    Text,
    /// Stable, machine-readable JSON document
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum ActionCommand {
    /// Add a local dashboard action
    #[command(
        long_about = "Add a local dashboard action.\n\nRun without arguments for a beginner-friendly prompt:\n  sudo connlog-agent action add\n\nScripted usage keeps command argv local and executes without a shell:\n  sudo connlog-agent action add disk_usage --label \"Check disk usage\" --description \"Shows disk usage\" --output -- df -h"
    )]
    Add(AddActionArgs),

    /// Advanced/backward-compatible action registration
    #[command(
        long_about = "Advanced registration for local dashboard actions.\n\nThis keeps the original `actions register` workflow working. Everything after `--` is stored as an argv array and executed directly by the agent. No shell is used, and the dashboard cannot provide command text or arguments.\n\nExample:\n  sudo connlog-agent actions register disk_usage \\\n    --label \"Check disk usage\" \\\n    --description \"Shows mounted filesystem usage\" \\\n    --category Diagnostics \\\n    --risk low \\\n    --output-mode ephemeral \\\n    --timeout-seconds 10 \\\n    --max-output-bytes 8192 \\\n    -- df -h"
    )]
    Register(RegisterActionArgs),

    /// List local dashboard actions from this host
    List,

    /// Remove a local dashboard action from this host
    Remove {
        /// Local action ID to remove
        action_id: String,
    },

    /// Enable a local dashboard action
    Enable {
        /// Local action ID to enable
        action_id: String,
    },

    /// Disable a local dashboard action
    Disable {
        /// Local action ID to disable
        action_id: String,
    },

    /// Run a local action directly on this host
    Test {
        /// Local action ID to run
        action_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddActionArgs {
    /// Stable local action ID, for example `disk_usage`
    pub action_id: Option<String>,

    /// Label shown in the dashboard
    #[arg(long)]
    pub label: Option<String>,

    /// Optional dashboard description
    #[arg(long)]
    pub description: Option<String>,

    /// Optional dashboard category
    #[arg(long)]
    pub category: Option<String>,

    /// Risk level shown in the dashboard
    #[arg(long, value_enum)]
    pub risk: Option<CliActionRisk>,

    /// Require confirmation before the dashboard can request this action
    #[arg(long)]
    pub requires_confirmation: bool,

    /// Do not require confirmation, even if the command looks risky
    #[arg(long, conflicts_with = "requires_confirmation")]
    pub no_confirmation: bool,

    /// Show command output once in the dashboard
    #[arg(long, conflicts_with = "no_output")]
    pub output: bool,

    /// Hide command output from the dashboard
    #[arg(long, conflicts_with = "output")]
    pub no_output: bool,

    /// Advanced output mode override
    #[arg(long, value_enum)]
    pub output_mode: Option<CliActionOutputMode>,

    /// Action timeout in seconds, 1..=60
    #[arg(long)]
    pub timeout_seconds: Option<u64>,

    /// Maximum combined stdout/stderr bytes, up to 65536
    #[arg(long)]
    pub max_output_bytes: Option<usize>,

    /// Command argv to run on this host. Put this after `--`, for example `-- df -h`.
    #[arg(last = true, num_args = 1.., value_name = "EXEC_ARG")]
    pub exec: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct RegisterActionArgs {
    /// Stable local action ID, for example `disk_usage`
    pub action_id: Option<String>,

    /// Label shown in the dashboard
    #[arg(long)]
    pub label: Option<String>,

    /// Optional dashboard description
    #[arg(long)]
    pub description: Option<String>,

    /// Optional dashboard category
    #[arg(long)]
    pub category: Option<String>,

    /// Risk level shown in the dashboard
    #[arg(long, value_enum)]
    pub risk: Option<CliActionRisk>,

    /// Require confirmation before the dashboard can request this action
    #[arg(long)]
    pub requires_confirmation: bool,

    /// Do not require confirmation, even if the command looks risky
    #[arg(long, conflicts_with = "requires_confirmation")]
    pub no_confirmation: bool,

    /// Show command output once in the dashboard
    #[arg(long, conflicts_with = "no_output")]
    pub output: bool,

    /// Hide command output from the dashboard
    #[arg(long, conflicts_with = "output")]
    pub no_output: bool,

    /// Whether command output is hidden or shown once to the requesting browser
    #[arg(long, value_enum)]
    pub output_mode: Option<CliActionOutputMode>,

    /// Action timeout in seconds, 1..=60
    #[arg(long)]
    pub timeout_seconds: Option<u64>,

    /// Maximum combined stdout/stderr bytes, up to 65536
    #[arg(long)]
    pub max_output_bytes: Option<usize>,

    /// Command argv to run on this host. Put this after `--`, for example `-- df -h`.
    #[arg(last = true, num_args = 1.., value_name = "EXEC_ARG")]
    pub exec: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliActionRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliActionOutputMode {
    Hidden,
    Ephemeral,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("command", &self.command)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("install", &self.install)
            .field("uninstall", &self.uninstall)
            .field("status", &self.status)
            .field("update", &self.update)
            .field("check_config", &self.check_config)
            .field("test_heartbeat", &self.test_heartbeat)
            .field("emit_service", &self.emit_service)
            .field("bmc_endpoint", &self.bmc_endpoint)
            .field("bmc_username", &self.bmc_username)
            .field(
                "bmc_password",
                &self.bmc_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("bmc_poll_interval_secs", &self.bmc_poll_interval_secs)
            .field("bmc_insecure_tls", &self.bmc_insecure_tls)
            .field("allow_remote_reboot", &self.allow_remote_reboot)
            .field("share_postmortem", &self.share_postmortem)
            .field("enable_remote_reboot", &self.enable_remote_reboot)
            .field("disable_remote_reboot", &self.disable_remote_reboot)
            .field("network_map", &self.network_map)
            .field("enable_network_map", &self.enable_network_map)
            .field("map_network", &self.map_network)
            .field("discovery", &self.discovery)
            .field("checks", &self.checks)
            .field("enable_checks", &self.enable_checks)
            .field("collector", &self.collector)
            .field("network_site", &self.network_site)
            .field("network_map_ports", &self.network_map_ports)
            .field("probe_public", &self.probe_public)
            .finish()
    }
}

impl Config {
    /// Whether the running agent accepts remote reboot: only an explicit true,
    /// and never with `--disable-remote-reboot`.
    pub fn remote_reboot_allowed(&self) -> bool {
        self.allow_remote_reboot == Some(true) && !self.disable_remote_reboot
    }

    /// The remote-reboot choice this `install` makes, if it makes one: the
    /// install flags first, then an explicit CONNLOG_ALLOW_REMOTE_REBOOT.
    /// `None` keeps whatever the host's agent.conf already says.
    pub fn requested_remote_reboot(&self) -> Option<bool> {
        if self.disable_remote_reboot {
            Some(false)
        } else if self.enable_remote_reboot {
            Some(true)
        } else {
            self.allow_remote_reboot
        }
    }

    /// Whether the running agent runs checks: only an explicit true.
    pub fn checks_enabled(&self) -> bool {
        self.checks == Some(true)
    }

    /// Whether the running agent is a collector: only an explicit true.
    pub fn collector_enabled(&self) -> bool {
        self.collector == Some(true)
    }

    /// The checks choice this `install` makes, if it makes one:
    /// `--enable-checks`, then an explicit CONNLOG_CHECKS. `None` keeps
    /// whatever the host's agent.conf already says.
    pub fn requested_checks(&self) -> Option<bool> {
        if self.enable_checks {
            Some(true)
        } else {
            self.checks
        }
    }

    /// The running agent's discovery ceiling: CONNLOG_DISCOVERY, else
    /// CONNLOG_NETWORK_MAP=true as peers, else off. A level that does not
    /// read is warned about and left out, so a typo in the file never stops
    /// the agent, nor raises its level.
    pub fn discovery_ceiling(&self) -> DiscoveryLevel {
        match parse_discovery(self.discovery.as_deref()) {
            Ok(Some(level)) => level,
            Ok(None) => DiscoveryLevel::from_network_map(self.network_map),
            Err(e) => {
                log::warn!("Ignoring {CONF_DISCOVERY}: {e}");
                DiscoveryLevel::from_network_map(self.network_map)
            }
        }
    }

    /// The discovery choice this `install` makes, if it makes one:
    /// `--discovery` (or CONNLOG_DISCOVERY), else CONNLOG_NETWORK_MAP as
    /// peers or off; `--enable-network-map` raises either to at least peers,
    /// and `--map-network` to active.
    /// `None` keeps whatever the host's agent.conf already says; a level that
    /// does not read is an error, and nothing is written.
    pub fn requested_discovery(&self) -> Result<Option<DiscoveryLevel>, String> {
        let chosen = parse_discovery(self.discovery.as_deref())?.or(self
            .network_map
            .map(|flag| DiscoveryLevel::from_network_map(Some(flag))));
        Ok(if self.map_network {
            Some(DiscoveryLevel::Active)
        } else if self.enable_network_map {
            Some(chosen.map_or(DiscoveryLevel::Peers, |level| {
                level.max(DiscoveryLevel::Peers)
            }))
        } else {
            chosen
        })
    }

    pub fn get_platform_url(&self) -> Option<String> {
        // Check environment variable set by systemd service
        std::env::var("CONNLOG_PLATFORM_URL").ok()
    }

    /// Resolve the platform endpoint:
    ///   1. `--endpoint` CLI flag (debug builds only)
    ///   2. `CONNLOG_PLATFORM_URL` env (set by systemd EnvironmentFile)
    ///   3. `default` (the compiled-in `DEFAULT_ENDPOINT`)
    pub fn resolve_endpoint(&self, default: &str) -> String {
        #[cfg(debug_assertions)]
        {
            self.endpoint
                .clone()
                .or_else(|| self.get_platform_url())
                .unwrap_or_else(|| default.to_string())
        }
        #[cfg(not(debug_assertions))]
        {
            self.get_platform_url()
                .unwrap_or_else(|| default.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SECURITY-CRITICAL: the bearer token must NEVER appear in any rendered
    /// `Config`. Regressing this would leak tokens into journalctl, panics, etc.
    /// Lifted to a hard test so a careless `#[derive(Debug)]` swap can't sneak
    /// past review.
    #[test]
    fn debug_redacts_token() {
        let cfg = Config::parse_from(["connlog-agent", "--token", "agent_super_secret_xyz"]);
        let rendered = format!("{:?}", cfg);
        assert!(
            !rendered.contains("agent_super_secret_xyz"),
            "Debug must NEVER include the raw token, got: {}",
            rendered
        );
        assert!(
            rendered.contains("REDACTED"),
            "Expected [REDACTED] marker, got: {}",
            rendered
        );
    }

    /// SECURITY-CRITICAL: the BMC password must NEVER appear in a rendered
    /// `Config` either (the codebase never forwards or logs BMC creds).
    #[test]
    fn debug_redacts_bmc_password() {
        let cfg = Config::parse_from([
            "connlog-agent",
            "--bmc-endpoint",
            "https://10.0.0.120",
            "--bmc-username",
            "monitor",
            "--bmc-password",
            "bmc_super_secret_pw",
        ]);
        let rendered = format!("{:?}", cfg);
        assert!(
            !rendered.contains("bmc_super_secret_pw"),
            "Debug must NEVER include the raw BMC password, got: {}",
            rendered
        );
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn debug_handles_missing_token_without_panic() {
        let cfg = Config::parse_from(["connlog-agent", "--status"]);
        let rendered = format!("{:?}", cfg);
        // Either "None" or absence of REDACTED is fine — the only thing that's
        // not fine is a panic or a leaked token (and there's no token here).
        assert!(rendered.contains("token"));
    }

    #[test]
    fn register_subcommand_accepts_token_after_command() {
        let cfg = Config::parse_from(["connlog-agent", "register", "--token", "agent_example"]);
        assert_eq!(cfg.command, Some(AgentCommand::Register));
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));
    }

    #[test]
    fn install_subcommand_accepts_env_token_style() {
        let cfg = Config::parse_from(["connlog-agent", "install"]);
        assert_eq!(cfg.command, Some(AgentCommand::Install));
    }

    #[test]
    fn legacy_install_flag_still_parses() {
        let cfg = Config::parse_from(["connlog-agent", "--install", "--token", "agent_example"]);
        assert!(cfg.install);
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));
    }

    #[test]
    fn diagnostic_subcommands_parse() {
        let cfg = Config::parse_from(["connlog-agent", "check-config", "--token", "agent_example"]);
        assert_eq!(cfg.command, Some(AgentCommand::CheckConfig));
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));

        let cfg = Config::parse_from([
            "connlog-agent",
            "test-heartbeat",
            "--token",
            "agent_example",
        ]);
        assert_eq!(cfg.command, Some(AgentCommand::TestHeartbeat));
        assert_eq!(cfg.token.as_deref(), Some("agent_example"));

        let cfg = Config::parse_from([
            "connlog-agent",
            "diagnostics",
            "check-config",
            "--token",
            "agent_example",
        ]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Diagnostics {
                command: DiagnosticCommand::CheckConfig
            })
        );

        let cfg = Config::parse_from(["connlog-agent", "diagnostics", "service"]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Diagnostics {
                command: DiagnosticCommand::Service
            })
        );
    }

    #[test]
    fn diagnostics_heartbeats_defaults_when_flags_omitted() {
        let cfg = Config::parse_from(["connlog-agent", "diagnostics", "heartbeats"]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Diagnostics {
                command: DiagnosticCommand::Heartbeats {
                    since: "24h".to_string(),
                    limit: 100,
                    format: DiagnosticsFormat::Text,
                }
            })
        );
        // The command must NOT require a token (local-only diagnostics).
        assert!(cfg.token.is_none());
    }

    #[test]
    fn diagnostics_heartbeats_parses_all_flags() {
        let cfg = Config::parse_from([
            "connlog-agent",
            "diagnostics",
            "heartbeats",
            "--since",
            "72h",
            "--limit",
            "500",
            "--format",
            "json",
        ]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Diagnostics {
                command: DiagnosticCommand::Heartbeats {
                    since: "72h".to_string(),
                    limit: 500,
                    format: DiagnosticsFormat::Json,
                }
            })
        );
    }

    #[test]
    fn diagnostics_history_parses_with_defaults_and_flags() {
        let cfg = Config::parse_from(["connlog-agent", "diagnostics", "history"]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Diagnostics {
                command: DiagnosticCommand::History {
                    since: "24h".to_string(),
                    limit: 30,
                    format: DiagnosticsFormat::Text,
                }
            })
        );
        let cfg = Config::parse_from([
            "connlog-agent",
            "diagnostics",
            "history",
            "--since",
            "2h",
            "--format",
            "json",
        ]);
        assert!(matches!(
            cfg.command,
            Some(AgentCommand::Diagnostics {
                command: DiagnosticCommand::History {
                    format: DiagnosticsFormat::Json,
                    ..
                }
            })
        ));
    }

    #[test]
    fn diagnostics_heartbeats_rejects_unknown_format() {
        let result = Config::try_parse_from([
            "connlog-agent",
            "diagnostics",
            "heartbeats",
            "--format",
            "yaml",
        ]);
        assert!(result.is_err(), "only text|json are valid formats");
    }

    #[test]
    fn refresh_service_subcommand_parses_restart_flag() {
        let cfg = Config::parse_from(["connlog-agent", "refresh-service", "--restart"]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::RefreshService { restart: true })
        );
    }

    #[test]
    fn remote_reboot_is_refused_unless_set_to_true() {
        let cfg = Config::parse_from(["connlog-agent"]);
        assert_eq!(cfg.allow_remote_reboot, None);
        assert!(!cfg.remote_reboot_allowed());

        // agent.conf reaches clap as the environment; the flag form is the
        // same parser.
        for (value, allowed) in [
            ("false", false),
            ("0", false),
            ("off", false),
            ("true", true),
            ("yes", true),
            ("1", true),
        ] {
            let cfg = Config::parse_from(["connlog-agent", "--allow-remote-reboot", value]);
            assert_eq!(cfg.allow_remote_reboot, Some(allowed), "{value}");
            assert_eq!(cfg.remote_reboot_allowed(), allowed, "{value}");
        }

        let cfg = Config::parse_from([
            "connlog-agent",
            "--allow-remote-reboot",
            "true",
            "--disable-remote-reboot",
        ]);
        assert!(!cfg.remote_reboot_allowed());
    }

    #[test]
    fn install_remote_reboot_choice() {
        for (args, requested) in [
            (&["install"][..], None),
            (&["install", "--enable-remote-reboot"][..], Some(true)),
            (&["install", "--disable-remote-reboot"][..], Some(false)),
            (
                &["install", "--allow-remote-reboot", "true"][..],
                Some(true),
            ),
            (
                &["install", "--allow-remote-reboot", "false"][..],
                Some(false),
            ),
            (
                &[
                    "install",
                    "--allow-remote-reboot",
                    "true",
                    "--disable-remote-reboot",
                ][..],
                Some(false),
            ),
        ] {
            let cfg =
                Config::parse_from(std::iter::once("connlog-agent").chain(args.iter().copied()));
            assert_eq!(cfg.command, Some(AgentCommand::Install), "{args:?}");
            assert_eq!(cfg.requested_remote_reboot(), requested, "{args:?}");
        }
    }

    #[test]
    fn install_refuses_both_remote_reboot_flags() {
        let parsed = Config::try_parse_from([
            "connlog-agent",
            "install",
            "--enable-remote-reboot",
            "--disable-remote-reboot",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn config_remote_reboot_subcommands_parse() {
        for (arg, command) in [
            (
                "disable-remote-reboot",
                LocalConfigCommand::DisableRemoteReboot,
            ),
            (
                "enable-remote-reboot",
                LocalConfigCommand::EnableRemoteReboot,
            ),
        ] {
            let cfg = Config::parse_from(["connlog-agent", "config", arg]);
            assert_eq!(cfg.command, Some(AgentCommand::Config { command }));
        }
    }

    #[test]
    fn config_network_map_subcommands_parse() {
        for (arg, command) in [
            ("enable-network-map", LocalConfigCommand::EnableNetworkMap),
            ("map-network", LocalConfigCommand::MapNetwork),
            ("disable-network-map", LocalConfigCommand::DisableNetworkMap),
        ] {
            let cfg = Config::parse_from(["connlog-agent", "config", arg]);
            assert_eq!(cfg.command, Some(AgentCommand::Config { command }));
        }
        let cfg = Config::parse_from([
            "connlog-agent",
            "config",
            "enable-network-map",
            "--network-site",
            "hq",
            "--network-map-ports",
            "443,8443",
        ]);
        assert_eq!(cfg.network_site.as_deref(), Some("hq"));
        assert_eq!(cfg.network_map_ports.as_deref(), Some("443,8443"));

        let cfg = Config::parse_from(["connlog-agent", "config", "set-discovery", "passive"]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Config {
                command: LocalConfigCommand::SetDiscovery {
                    level: DiscoveryLevel::Passive
                }
            })
        );
        assert!(
            Config::try_parse_from(["connlog-agent", "config", "set-discovery", "all"]).is_err()
        );
    }

    #[test]
    fn discovery_is_off_unless_set() {
        let cfg = Config::parse_from(["connlog-agent"]);
        assert_eq!(cfg.network_map, None);
        assert_eq!(cfg.discovery_ceiling(), DiscoveryLevel::Off);
        for (args, level) in [
            (&["--network-map", "true"][..], DiscoveryLevel::Peers),
            (&["--network-map", "yes"][..], DiscoveryLevel::Peers),
            (&["--network-map", "0"][..], DiscoveryLevel::Off),
            (&["--discovery", "passive"][..], DiscoveryLevel::Passive),
            (
                &["--discovery", "off", "--network-map", "true"][..],
                DiscoveryLevel::Off,
            ),
        ] {
            let cfg =
                Config::parse_from(std::iter::once("connlog-agent").chain(args.iter().copied()));
            assert_eq!(cfg.discovery_ceiling(), level, "{args:?}");
        }
    }

    #[test]
    fn install_network_map_choice() {
        for (args, requested) in [
            (&["install"][..], None),
            (
                &["install", "--enable-network-map"][..],
                Some(DiscoveryLevel::Peers),
            ),
            (
                &["install", "--network-map", "false"][..],
                Some(DiscoveryLevel::Off),
            ),
            (
                &["install", "--network-map", "false", "--enable-network-map"][..],
                Some(DiscoveryLevel::Peers),
            ),
            (
                &["install", "--discovery", "active"][..],
                Some(DiscoveryLevel::Active),
            ),
            // The installer's one question (T13.4): active, whatever else.
            (
                &["--map-network", "install"][..],
                Some(DiscoveryLevel::Active),
            ),
            (
                &["install", "--discovery", "off", "--map-network"][..],
                Some(DiscoveryLevel::Active),
            ),
        ] {
            let cfg =
                Config::parse_from(std::iter::once("connlog-agent").chain(args.iter().copied()));
            assert_eq!(cfg.command, Some(AgentCommand::Install), "{args:?}");
            assert_eq!(cfg.requested_discovery(), Ok(requested), "{args:?}");
        }
        let cfg = Config::parse_from([
            "connlog-agent",
            "install",
            "--enable-network-map",
            "--network-site",
            "dc-1",
            "--network-map-ports",
            "8443",
        ]);
        assert_eq!(cfg.network_site.as_deref(), Some("dc-1"));
        assert_eq!(cfg.network_map_ports.as_deref(), Some("8443"));
    }

    #[test]
    fn config_disable_hostname_subcommand_parses() {
        let cfg = Config::parse_from(["connlog-agent", "config", "disable-hostname"]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Config {
                command: LocalConfigCommand::DisableHostname
            })
        );
    }

    #[test]
    fn config_enable_hostname_subcommand_parses() {
        let cfg = Config::parse_from(["connlog-agent", "config", "enable-hostname"]);
        assert_eq!(
            cfg.command,
            Some(AgentCommand::Config {
                command: LocalConfigCommand::EnableHostname
            })
        );
    }

    #[test]
    fn actions_register_subcommand_captures_exec_argv() {
        let cfg = Config::parse_from([
            "connlog-agent",
            "actions",
            "register",
            "disk_usage",
            "--label",
            "Check disk usage",
            "--output-mode",
            "ephemeral",
            "--",
            "df",
            "-h",
        ]);

        let Some(AgentCommand::Action {
            command: ActionCommand::Register(args),
        }) = cfg.command
        else {
            panic!("expected actions register command");
        };

        assert_eq!(args.action_id.as_deref(), Some("disk_usage"));
        assert_eq!(args.label.as_deref(), Some("Check disk usage"));
        assert_eq!(args.output_mode, Some(CliActionOutputMode::Ephemeral));
        assert_eq!(args.exec, ["df", "-h"]);
    }

    #[test]
    fn action_add_subcommand_supports_simple_and_scripted_forms() {
        let cfg = Config::parse_from(["connlog-agent", "action", "add"]);
        let Some(AgentCommand::Action {
            command: ActionCommand::Add(args),
        }) = cfg.command
        else {
            panic!("expected action add command");
        };
        assert!(args.action_id.is_none());
        assert!(args.exec.is_empty());

        let cfg = Config::parse_from([
            "connlog-agent",
            "action",
            "add",
            "disk_usage",
            "--label",
            "Check disk usage",
            "--description",
            "Shows disk usage",
            "--output",
            "--",
            "df",
            "-h",
        ]);
        let Some(AgentCommand::Action {
            command: ActionCommand::Add(args),
        }) = cfg.command
        else {
            panic!("expected action add command");
        };
        assert_eq!(args.action_id.as_deref(), Some("disk_usage"));
        assert_eq!(args.label.as_deref(), Some("Check disk usage"));
        assert!(args.output);
        assert_eq!(args.exec, ["df", "-h"]);

        let cfg = Config::parse_from(["connlog-agent", "actions", "add"]);
        assert!(matches!(
            cfg.command,
            Some(AgentCommand::Action {
                command: ActionCommand::Add(_)
            })
        ));
    }

    #[test]
    fn help_explains_register_command() {
        use clap::CommandFactory;

        let help = Config::command().render_long_help().to_string();
        assert!(help.contains("sudo CONNLOG_TOKEN=agent_xxxxxxxxxxxx connlog-agent install"));
        assert!(help.contains("sudo connlog-agent action add"));
        assert!(help.contains("Commands:"));
        assert!(help.contains("action"));
        assert!(help.contains("diagnostics"));
        assert!(help.contains("refresh-service"));
        assert!(help.contains("Legacy flags still work"));
    }

    #[test]
    fn action_help_contains_action_examples() {
        use clap::CommandFactory;

        let mut command = Config::command();
        let action = command
            .find_subcommand_mut("action")
            .expect("action command exists");
        let help = action.render_long_help().to_string();

        assert!(help.contains("add"));
        assert!(help.contains("list"));
        assert!(help.contains("remove"));
        assert!(help.contains("enable"));
        assert!(help.contains("disable"));
        assert!(help.contains("test"));
        assert!(help.contains("sudo connlog-agent action add"));
    }
}
