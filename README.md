# ConnLog Agent

Lightweight Linux monitoring agent for [ConnLog](https://connlog.com). Collects CPU, memory, disk, and load metrics and sends them to the ConnLog platform via authenticated heartbeats.

Single static binary. One-command install. No runtime dependencies.

> **Source:** [github.com/connlog/agent](https://github.com/connlog/agent)  
> **Binary/service name:** `connlog-agent`  
> **Supported platforms:** Linux x86_64 and Linux aarch64

## Install

```bash
curl -fsSL https://connlog.com/install.sh | sudo CONNLOG_TOKEN=<TOKEN> sh -s -- --install
```

This detects your architecture, downloads the latest release from GitHub, checks its SHA-256 and verifies its Ed25519 signature against the ConnLog release key pinned in the script, installs the binary root-owned to `/usr/local/bin/connlog-agent`, stores your token in `/etc/connlog/agent.conf`, and starts a systemd service. The agent begins reporting immediately. Every check fails closed: nothing is installed if a download, checksum or signature does not verify.

The token goes in the environment rather than on the command line, so it never shows up in `ps` or `/proc/<pid>/cmdline` for other users on the host. `--token <TOKEN>` still works for older scripts. To review the script first, download it and run it with `sh install.sh`; `--version vX.Y.Z` installs a specific release.

The installer itself lives in the platform repository (`connlog-platform/public/install.sh`) and is served at `https://connlog.com/install.sh`.

Get your token from the [ConnLog dashboard](https://connlog.com) under **Servers → Add server**.

### Supported platforms

| OS    | Architecture | Release asset                       |
| ----- | ------------ | ----------------------------------- |
| Linux | x86_64       | `connlog-agent-vX.Y.Z-linux-x86_64`  |
| Linux | aarch64      | `connlog-agent-vX.Y.Z-linux-aarch64` |

Each raw binary ships with a `.sha256` checksum and a `.sig` (Ed25519 over the SHA-256 digest). Tarballs of the same binaries are published with a `.sha256` for convenience.

### Two-step install

```bash
# 1. Download and verify the binary only
curl -fsSL https://connlog.com/install.sh | sudo sh

# 2. Install as systemd service
sudo CONNLOG_TOKEN=<TOKEN> connlog-agent install
```

### Run without systemd

```bash
CONNLOG_TOKEN=<TOKEN> connlog-agent register
```

`--token <TOKEN>` is accepted too, but a command-line argument is readable by every user on the host; prefer the environment variable.

### Run in Docker

On a host that runs Docker (a NAS, a Raspberry Pi, a home server), the image
`ghcr.io/connlog/agent` holds the same signed static binary and nothing else
(`docker/Dockerfile`; `docker/compose.yaml` is the reference setup):

```bash
CONNLOG_TOKEN=<TOKEN> docker compose -f docker/compose.yaml up -d
```

It runs with the host's network, so the addresses, neighbours, connections
and listening ports it reports are the host's, and the host's root mounted
read-only at `/host` (`CONNLOG_HOST_ROOT`), so its disks and machine id are
too. Unprivileged, with no capabilities and a read-only root filesystem, as
the systemd unit runs it. Settings are the environment variables below; the
`install`, `config` and `update` commands refuse to run in the container
(`CONNLOG_PACKAGING=docker`, which the image sets). It never updates itself
and never reboots its host: a new image is the update (`docker compose pull
&& docker compose up -d`), and it reports `X-Packaging: docker`, so the
console offers no self-update. `docker exec -it <container> connlog-agent
integration add …` stores an integration in the `integrations.d` volume,
readable by the agent's user only.

### Run on OPNsense, pfSense or FreeBSD

On a firewall (amd64), as root in its shell:

```sh
fetch -o - https://connlog.com/install.sh | CONNLOG_TOKEN=<TOKEN> sh -s -- --install --map-network
```

The installer verifies the signed package (`connlog-agent-vX.Y.Z-freebsd-x86_64.pkg`, SHA-256 and
Ed25519 as for the Linux binary), `pkg add`s it, writes `/usr/local/etc/connlog/agent.conf`
(root:connlog 0640, the same `CONNLOG_*` names as on Linux, one per line, no quotes) and starts the
rc.d service (`packaging/freebsd/connlog_agent`, enabled in `/etc/rc.conf.d/connlog_agent`). It
runs as the unprivileged `connlog` user: it reads the firewall's ARP and NDP tables, routes and
VLANs through sysctl and ioctls, and finds devices without ping (each sweep's handshakes fill the
ARP table). For ping, run it as root: `sysrc -f /etc/rc.conf.d/connlog_agent
connlog_agent_user=root` and `service connlog_agent restart`. A new package is the update (the
installer again); the agent never replaces its own binary there, and `install`, `config` and
`update` refuse (`CONNLOG_PACKAGING=freebsd`, which the rc.d script sets).

### Environment variables

| Variable                          | Description                                                                                                                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CONNLOG_TOKEN`                   | Agent auth token (`agent_...`), alternative to `--token`                                                                                                                            |
| `CONNLOG_PLATFORM_URL`            | Override the control-plane URL (defaults to `https://connlog.com`); mainly for self-hosted deployments                                                                              |
| `CONNLOG_EXPOSE_SYSTEM_INFO`      | Set to `true` to opt in to sending hostname with heartbeats (off by default). Prefer `sudo connlog-agent config enable-hostname`, which creates `/etc/connlog/agent.conf` if needed and restarts the service. |
| `CONNLOG_ALLOW_REMOTE_REBOOT`     | `true` to let the dashboard reboot this host; unset or anything else refuses (the default). Prefer `sudo connlog-agent config enable-remote-reboot`, or `install --enable-remote-reboot`. The root-side hook checks the same root-only file, so neither the platform nor the running agent can turn it on. |
| `CONNLOG_SHARE_POSTMORTEM`        | `true` to send, after the host went down without a clean stop, the previous boot's last journal and kernel warnings with the outage report: redacted, at most 8 KB, needs a persistent journal. Off by default. Prefer `sudo connlog-agent config enable-postmortem`. |
| `CONNLOG_CHECKS`                  | `true` to run the checks ConnLog assigns, for devices without an agent: ping (3 echoes), TCP connect, HTTP(S) (status, time to the first byte, the certificate's days left; never a byte of the body) and DNS (answers from a given resolver). At most 16 at a time, 10 s each, each target at most once a minute; a private target only at the `passive` discovery level. Off by default. Prefer `sudo connlog-agent config enable-checks`, or `install --enable-checks`. |
| `CONNLOG_COLLECTOR`               | `true` to make this host a collector: it reads the integrations in `/etc/connlog/integrations.d` (Proxmox VE: nodes, bridges, guests, their interfaces' MAC addresses, bridges and VLAN tags; OPNsense: interfaces, VLANs, gateways and their state, DHCP leases, with hostnames only while the workspace collects device names; switches and routers over SNMP v2c or v3: interfaces, VLANs, LLDP neighbours, the bridge table) every five minutes while ConnLog asks, and reports them. Credentials stay on the host, readable by root and the service account only; a report never carries one. Off by default. `sudo connlog-agent integration add` turns it on; `config enable-collector` / `disable-collector` too. |
| `CONNLOG_DISCOVERY`               | How much this host may find out about its network: `off` (the default), `peers` (the network map, below), `passive` (peers, the VLAN id of each address on a VLAN interface, the neighbour table's private entries: address, MAC and state, at most 1,024; read with netlink dumps without privilege; and a trace of at most 16 hops towards the gateway and ConnLog every 6 hours, over the unprivileged ping socket where `net.ipv4.ping_group_range` allows it; never an interface's or a device's name). When ConnLog asks for them, the host's established connections are sent too (peer, port, direction; never the process or a byte count): at `peers` only with the other opted-in hosts on its site, at `passive` with any private address or `active` (passive, and sweeps of the host's own IPv4 subnets the console lists: a /22 at most, 64 addresses a second, an echo and handshakes to at most 8 well-known ports per address, one mDNS question and one SSDP search; never an mDNS name or a UUID). The host runs at the lower of this and what the console allows. A ceiling: ConnLog's console chooses at or below it per host and can never raise it. Set with `sudo connlog-agent config set-discovery <level>` or `install --discovery <level>`; `install --map-network` and `config map-network` set `active` (the installer asks "Map this network from here?" in a terminal). When unset, `CONNLOG_NETWORK_MAP=true` reads as `peers`. A value that is not a level is refused by `install` and `config`; the running agent warns and ignores it. |
| `CONNLOG_NETWORK_MAP`             | `true` to take part in the network map: the agent sends its interface addresses (with prefix length), the TCP port numbers listening on a non-loopback address, its default gateway and the gateway's MAC, and runs the reachability probes ConnLog asks for. Unset or anything else is off (the default). Prefer `sudo connlog-agent config enable-network-map`, or `install --enable-network-map`. The workspace must turn the map on too. |
| `CONNLOG_NETWORK_SITE`            | Optional network map site name: hosts with the same name are drawn as one site. Lowercase letters, digits, `.`, `_`, `-`, starting with a letter or digit; at most 64. Also set by `install --network-site` or `config enable-network-map --network-site`. |
| `CONNLOG_NETWORK_MAP_PORTS`       | Optional comma list of at most 16 TCP ports (1..65535) other hosts should try on this one even if nothing listens yet, e.g. `443,8443`. Also set by `install --network-map-ports` or `config enable-network-map --network-map-ports`. A bad site or port list is refused by `install` and `config`; the running agent warns and ignores it. |
| `CONNLOG_PROBE_PUBLIC`            | `true` to let network map probes reach addresses outside the private ranges (RFC 1918, 100.64/10, 169.254/16, fc00::/7, fe80::/10). Off by default: public targets are reported `skipped`. |
| `CONNLOG_PACKAGING`               | `docker` in the Docker image: no self-update, no remote reboot, and the commands that change a systemd install refuse. Set by the image; anything else is a systemd install. |
| `CONNLOG_HOST_ROOT`               | Where the host's root is mounted when the agent does not run in it (`/host` in the image): disks and the machine id are read through it. Only an absolute path other than `/` that exists counts. |
| `CONNLOG_ALLOWED_ENDPOINT_DOMAINS`| Comma-separated extra domains the agent will trust for heartbeat **endpoint assignments** (see below), in addition to `connlog.com`; only relevant for self-hosted/regional setups |
| `CONNLOG_BMC_ENDPOINT`            | Optional. The Redfish endpoint of this machine's BMC (iDRAC, iLO, OpenBMC), e.g. `https://10.0.0.120`. With the username and password below, the agent polls it for hardware health (drives, volumes, controllers, fans, PSUs, temperatures) and reports it to ConnLog. Also set by `install --bmc-endpoint ...`. |
| `CONNLOG_BMC_USERNAME`, `CONNLOG_BMC_PASSWORD` | BMC credentials. Stored in `/etc/connlog/agent.conf` (0600 root), sent only to the configured BMC origin, never to ConnLog. |
| `CONNLOG_BMC_POLL_INTERVAL_SECS`  | How often the BMC is polled (clamped to a sane range).                                                                                                                             |
| `CONNLOG_BMC_INSECURE_TLS`        | `true` to accept the BMC's self-signed certificate. Applies to the BMC connection only, never to ConnLog traffic.                                                                  |

## Management

Run `sudo connlog-agent` with no arguments in a terminal for an interactive menu: arrow keys to
move, Enter to choose, Esc or Ctrl-C to leave. It shows the service state and the last accepted
heartbeat, turns remote reboot, hostname sharing and crash reports on or off (through the same
code as the `config` commands below, so the agent restarts to apply each change), checks the
config, sends a test heartbeat, shows heartbeat diagnostics and uninstalls behind a typed
confirmation. It never shows the token or the BMC password. Without `sudo` it shows the status and
offers to reopen itself with `sudo`. The menu opens only for a bare command typed into a
terminal: with any argument, without a terminal, under systemd (`INVOCATION_ID`) or with
`CONNLOG_TOKEN` set, `connlog-agent` does exactly what it did before, so the service still starts
the daemon. Every command below keeps working for scripts.

```bash
# Check service status
connlog-agent status
# or
systemctl status connlog-agent

# View logs
journalctl -u connlog-agent -f

# Refresh the installed systemd unit from the current binary
sudo connlog-agent refresh-service --restart

# Share this machine's hostname with ConnLog (creates /etc/connlog/agent.conf if needed), and stop
sudo connlog-agent config enable-hostname
sudo connlog-agent config disable-hostname

# Send the previous boot's last warnings after a crash (opt-in; and off again)
sudo connlog-agent config enable-postmortem
sudo connlog-agent config disable-postmortem

# Let the dashboard reboot this machine (off by default), and refuse it again
sudo connlog-agent config enable-remote-reboot
sudo connlog-agent config disable-remote-reboot

# Take part in the network map (off by default), optionally with a site name
# and extra ports, and leave it again
sudo connlog-agent config enable-network-map
sudo connlog-agent config enable-network-map --network-site hq --network-map-ports 443,8443
sudo connlog-agent config disable-network-map

# Run the checks ConnLog assigns (off by default), and stop again
sudo connlog-agent config enable-checks
sudo connlog-agent config disable-checks

# Read a Proxmox VE cluster as a collector: the token's secret is asked for,
# the node's certificate shown and pinned, and the host made a collector
sudo connlog-agent integration add pve --url https://pve.lan:8006 --token-id connlog@pve!collector
sudo connlog-agent integration list
sudo connlog-agent integration test pve
sudo connlog-agent integration remove pve
# An OPNsense firewall: the API key's secret is asked for the same way.
sudo connlog-agent integration add fw --kind opnsense --url https://10.0.0.1 --key w86XNZob…
# A switch over SNMPv3 (SHA-256 and AES-128); the two passwords are asked for.
sudo connlog-agent integration add core --kind snmp --url snmp://10.0.0.2 --snmp-version 3 --user connlog

# The discovery ceiling directly (off, peers, passive, active)
sudo connlog-agent config set-discovery peers

# Or at install time
sudo CONNLOG_TOKEN=<TOKEN> connlog-agent install --enable-network-map --network-site hq

# Uninstall (stops the service; removes the config, local diagnostics and the binary)
sudo connlog-agent uninstall
```

Note: uninstall preserves the `connlog-agent` system user. Remove it manually if needed: `sudo userdel connlog-agent`.

You can also request removal from the ConnLog dashboard. The agent acts after three consecutive heartbeats confirm the request, or immediately when the platform answers 410 for an agent that has been deleted. A rejected token (401) never removes anything: the agent keeps its files and keeps retrying.

### Diagnostics

```bash
# Fetch and print the agent config from the platform
connlog-agent diagnostics check-config --token <TOKEN>

# Send one heartbeat and print the platform response
connlog-agent diagnostics test-heartbeat --token <TOKEN>

# Compare the installed systemd unit with this binary's embedded template
connlog-agent diagnostics service
```

The older top-level commands `connlog-agent check-config` and
`connlog-agent test-heartbeat` still work for existing scripts.

### The flight recorder

The agent keeps the last 24 hours of this host on the host: one record a
minute (CPU, memory, disk, load, OOM kills, CPU/memory/IO pressure) in a
fixed 92 KB file, `/var/lib/connlog/flight.ring`, written whether or not ConnLog
is reachable. It never grows; the oldest record is simply overwritten. After an
outage it answers the question the dashboard alone cannot: did the host crash,
reboot cleanly, get rebooted on request, or stay up while the network was down?

```bash
connlog-agent diagnostics history                 # what happened, and the latest records
connlog-agent diagnostics history --since 2h --limit 120
connlog-agent diagnostics history --format json
```

It reads only the local file: no root, no network, no token.

### Heartbeat delivery diagnostics

When an agent occasionally trips an offline alert after a few missed heartbeats
and then recovers, you usually want to know **what the agent itself thinks
happened** to those heartbeats — without root and without reading protected
systemd journals. That's what this command is for:

```bash
connlog-agent diagnostics heartbeats --since 72h --limit 500 --format text
connlog-agent diagnostics heartbeats --since 72h --limit 500 --format json
```

Flags (all optional):

| Flag       | Default | Meaning                                                     |
| ---------- | ------- | ----------------------------------------------------------- |
| `--since`  | `24h`   | Look-back window: `24h`, `72h`, `30m`, `90s`, `7d` (a bare number = seconds) |
| `--limit`  | `100`   | Maximum number of event records to inspect (most recent kept) |
| `--format` | `text`  | `text` (human summary + event list) or `json` (machine-readable) |

The command:

- **requires no root** and **never uses `sudo`**;
- reads only the agent's own local history — it **never** contacts the API,
  sends a heartbeat, or mutates service state;
- **never prints secrets** — no HMAC signatures, agent tokens, authorization
  headers, raw request bodies, tokenised URLs, cookies, environment secrets, or
  raw backend response bodies. Any error text is sanitized, redacted, and
  length-capped before it is stored or shown;
- fails gracefully when no history exists yet, and clearly distinguishes
  "no telemetry available yet" from "all heartbeats succeeded".

The history is stored locally at `/var/lib/connlog/heartbeat-telemetry.jsonl`,
owned `0700` by the `connlog-agent` service account — the same account ConnLog
actions run as. It survives restarts, reboots, and self-updates, and is bounded
in size (rotated; ~2 MiB cap).

#### Sample text output

```text
Heartbeat diagnostics
Period: last 72h
Records inspected: 500
Heartbeat cycles: 412
Accepted: 409
Failed: 3
Retried: 3
Last accepted heartbeat: 2026-06-23T01:19:42Z
Last failure: 2026-06-23T00:48:12Z (connect_timeout)

Failure categories:
- connect_timeout: 2
- dns_error: 1

Events (most recent last):
2026-06-23T00:48:12Z  hb=0898cb49  attempt=1  connect_timeout   status=-     dur=5001ms    host=connlog.com
2026-06-23T00:48:12Z  hb=0898cb49  attempt=1  retry_scheduled   status=-     dur=-         host=connlog.com  retry_in=250ms
2026-06-23T00:48:13Z  hb=0898cb49  attempt=2  accepted          status=200   dur=72ms      host=connlog.com
```

#### Sample JSON output

```json
{
  "schema_version": 1,
  "generated_at_utc": "2026-06-23T01:20:00Z",
  "period": "72h",
  "period_seconds": 259200,
  "limit": 500,
  "status": "ok",
  "store_present": true,
  "records_inspected": 500,
  "corrupt_skipped": 0,
  "summary": {
    "heartbeat_cycles": 412,
    "accepted": 409,
    "failed": 3,
    "retried": 3,
    "last_accepted_utc": "2026-06-23T01:19:42Z",
    "last_failure_utc": "2026-06-23T00:48:12Z",
    "last_failure_category": "connect_timeout",
    "failure_categories": { "connect_timeout": 2, "dns_error": 1 }
  },
  "events": [
    {
      "schema_version": 1,
      "timestamp_utc": "2026-06-23T00:48:13Z",
      "ts_unix_ms": 1782175693000,
      "request_id": "0898cb49559510a2cb7e2477e13d52b1",
      "attempt": 2,
      "event_type": "accepted",
      "outcome": "accepted",
      "http_status": 200,
      "duration_ms": 72,
      "endpoint_host": "connlog.com"
    }
  ]
}
```

The JSON format emits **only** JSON — no human-readable lines before or after —
so it is safe to pipe into `jq` or store as an artifact.

#### Register it as a safe ConnLog action

The command is designed to be exposed as a dashboard action so you can pull
heartbeat diagnostics from an affected host remotely. Registration still needs
`sudo` (writing the action definition is a privileged, host-local operation),
but the **action itself runs unprivileged** as `connlog-agent` and needs no
`sudo`, no journal access, and no added groups:

```bash
sudo connlog-agent actions add heartbeatdebug \
  --label "Heartbeat delivery debug" \
  --description "Shows recent ConnLog heartbeat attempts, retries, response codes and transport failures" \
  --output \
  -- connlog-agent diagnostics heartbeats --since 72h --limit 500 --format text
```

#### What the outcomes mean

| Outcome / category | What it means | What to check |
| ------------------ | ------------- | ------------- |
| `dns_error`       | The platform hostname could not be resolved. | Host DNS / `resolv.conf`, split-horizon DNS, resolver outages. |
| `connect_timeout` | TCP/TLS connection did not establish within the connect budget (5 s). | Egress firewall, packet loss, an overloaded NAT/proxy, blackholed routes. |
| `request_timeout` | Connected, but no response within the request budget (10 s). | Platform/proxy latency, a stalled upstream, MTU/path issues. |
| `tls_error`       | TLS handshake or certificate validation failed. | Clock skew, a TLS-intercepting middlebox, an outdated CA bundle. |
| `401` (`unauthorized`) | The platform rejected the agent token. | Token revoked/rotated, agent deleted; re-register if intended. |
| `403` (`forbidden`)    | The request was authenticated but refused. | Workspace/plan gating, an upstream WAF/proxy rule. |
| `429` (`rate_limited`) | The agent exceeded its heartbeat budget. | Heartbeat interval too fast for the plan; let config catch up. |
| `5xx` (`server_error`) | The platform (or a gateway) returned a server error. | Usually transient — the agent retries 502/503/504 automatically. |
| `retry_exhausted` | All transient retries for a cycle were used and it still failed. | Look at the per-attempt categories in the same cycle for the root cause. |

This command does **not** expose secrets, HMACs, credentials, or raw heartbeat
payloads, and it does **not** require `sudo`.

## Local dashboard actions

Local dashboard actions are buttons shown in ConnLog that run pre-registered
commands on the agent host. They are stored in `/etc/connlog/actions.toml`,
reloaded by the running service, and published to the dashboard on the next
heartbeat.

Action requests are picked up independently from the normal metrics heartbeat.
The platform sends a `quickActions` config block and the agent polls
`/api/agents/actions/pending` every 5 seconds by default, clamped to 2..60
seconds. The dashboard shows the latest known last/next action check times, so
queued actions can estimate when the agent should pick them up.

The simple setup flow asks for a label, description, command, output preference,
and confirmation preference:

```bash
sudo connlog-agent action add
```

Examples:

```bash
# Check disk usage and show the output in the dashboard
sudo connlog-agent action add disk_usage \
  --label "Check disk usage" \
  --description "Shows current disk usage" \
  --output \
  -- df -h

# Check Docker containers
sudo connlog-agent action add docker_containers \
  --label "Check Docker containers" \
  --description "Lists running Docker containers" \
  --output \
  -- docker ps

# Restart nginx with dashboard confirmation
sudo connlog-agent action add restart_nginx \
  --label "Restart nginx" \
  --description "Restarts the nginx service" \
  --requires-confirmation \
  -- systemctl restart nginx

connlog-agent action list
sudo connlog-agent action test disk_usage
sudo connlog-agent action remove disk_usage
```

Advanced registration is still available and keeps the original plural command
working:

```bash
sudo connlog-agent actions register disk_usage \
  --label "Check disk usage" \
  --description "Shows mounted filesystem usage" \
  --category Diagnostics \
  --risk low \
  --output-mode ephemeral \
  --timeout-seconds 10 \
  --max-output-bytes 8192 \
  -- df -h

connlog-agent actions list
sudo connlog-agent actions remove disk_usage
```

Everything after `--` is stored locally as an argv array and executed directly by
the agent without a shell. ConnLog only receives safe metadata and action IDs:
the raw command remains on the agent machine, and the dashboard cannot send
arbitrary shell commands or command arguments.

## How it works

1. Agent sends a heartbeat to the platform every 60 seconds (configurable server-side)
2. Platform responds with the latest config (metric toggles, intervals)
3. Agent applies config changes without restart
4. On startup, then roughly once a day (or sooner after repeated heartbeat
   failures), the agent asks the platform which heartbeat endpoint to use and
   switches to it if — and only if — it's a trusted, validated HTTPS URL
5. When the platform offers a newer release, the agent downloads it, checks the SHA-256 and verifies the Ed25519 signature with the key compiled into the binary, stages it, and exits. The systemd `ExecStopPost` hook then runs `connlog-agent apply-staged-update` as root, which verifies the signature again, runs the staged binary to confirm it reports a strictly higher version, swaps it in with an atomic rename, refreshes the unit from the new binary, and rolls back if that fails. The service is started again either way.
6. If the platform requests removal (three consecutive confirmations, or HTTP 410 for a deleted agent), the agent triggers a self-cleanup via systemd `ExecStopPost`

ConnLog does **not** remotely execute arbitrary commands. Host reboot can be
requested from the dashboard and is confirmed on three consecutive heartbeats
before systemd reboots the machine; the agent then tells the platform whether
the host came back on a new boot, did not reboot, or refused. A host refuses
every request unless its root-only `agent.conf` sets
`CONNLOG_ALLOW_REMOTE_REBOOT=true`. Local
`connlog-agent action` tooling may still exist on disk; the platform will not
trigger it.

### Network map (opt-in)

With a discovery ceiling of `peers` or above (`CONNLOG_DISCOVERY`, or the
older `CONNLOG_NETWORK_MAP=true`), the map turned on for the workspace and
not turned off for this server in the console, the
agent sends an inventory to ConnLog: this host's interface addresses with
their prefix length (loopback, IPv6 link-local and container bridges left
out), the TCP port numbers listening on a non-loopback address, the default
gateway and its MAC address, and the site name and extra ports above. It is
read every 15 minutes and sent when it changes, at least once a day. No
interface names, process names, users, UDP sockets or connections leave the
host.

ConnLog can then ask the agent, on a heartbeat answer, to test whether it can
reach other opted-in hosts in the same workspace. What the agent will do is
compiled in, whatever it is asked: at most 32 addresses and 8 ports per
address per request, 4 probes at a time with a 1 second timeout, one request
at a time. A TCP probe is a handshake and a close, never a byte of data; an
ICMP echo uses the kernel's unprivileged ping socket and is reported
`skipped` where `net.ipv4.ping_group_range` does not allow the agent's group
(the agent gains no capability for it). Addresses outside the private ranges
are `skipped` unless `CONNLOG_PROBE_PUBLIC=true`. With the flag off the agent
sends no inventory and runs no probe, and tells ConnLog so with every
heartbeat (`X-Network-Map: disabled`).

### Collected metrics

| Metric            | Description                         |
| ----------------- | ----------------------------------- |
| `cpu_percent`     | CPU usage across all cores          |
| `cpu_max`         | Busiest single core                 |
| `cpu_core_count`  | Logical CPU count (header)          |
| `memory_used_mb`  | Used RAM in MB                      |
| `memory_total_mb` | Total RAM in MB                     |
| `disk_used_mb`    | Used disk in MB, summed across real filesystems (deduplicated by device) |
| `disk_total_mb`   | Total disk in MB, same set of filesystems |
| `load_1m`         | 1-minute load average               |
| `hostname`        | System hostname, only with the opt-in (`CONNLOG_EXPOSE_SYSTEM_INFO=true`) |
| `os`              | Operating system                    |
| `arch`            | CPU architecture                    |
| `uptime_seconds`  | System uptime                       |
| `machine_id`      | SHA-256 hash of `/etc/machine-id` (header), never the raw value |

Each metric category (CPU, memory, disk, load) can be toggled on/off from the dashboard.

With a BMC configured, the agent also reports hardware health (drive, volume, controller, fan, PSU and temperature status with model and capacity attributes) to `POST /api/agents/hardware-health`. Drive serial numbers are included only with the same opt-in as the hostname.

## File layout

```txt
/usr/local/bin/connlog-agent              # Binary (0755 root:root; the update path refuses anything else)
/etc/connlog/agent.conf                   # Token, platform URL, opt-ins, BMC settings (mode 600, root-only)
/etc/connlog/actions.toml                 # Local dashboard actions, if any (group-readable)
/etc/systemd/system/connlog-agent.service
/var/lib/connlog/heartbeat-telemetry.jsonl # Heartbeat delivery diagnostics (dir mode 700, connlog-agent)
/var/lib/connlog/update-failed            # Present only after an update was rejected; cleared on the next success
```

`connlog-agent uninstall` (and a remote uninstall) removes all of these.

## Development

Requires [Rust](https://rustup.rs) (stable).

```bash
# Debug build — includes --endpoint flag for local testing
cargo run -- --token <TOKEN> --endpoint http://localhost:3000

# Release build. The platform URL is https://connlog.com unless
# CONNLOG_PLATFORM_URL is set in the environment; the --endpoint flag is
# debug-only. A release build refuses to compile without the release
# signing public key, so a local one needs the opt-out:
CONNLOG_ALLOW_UNSIGNED_BUILD=1 cargo build --release
```

### Cross-compilation

CI uses [cross](https://github.com/cross-rs/cross):

```bash
cargo install cross@0.2.5 --locked

# Linux x86_64 (musl static)
cross build --release --target x86_64-unknown-linux-musl

# Linux aarch64 (musl static)
cross build --release --target aarch64-unknown-linux-musl
```

### Releases

Push a version tag to trigger CI:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```

GitHub Actions builds both Linux targets (`x86_64-musl`, `aarch64-musl`) with the release signing public key compiled in (the build fails without it), signs each raw binary with the Ed25519 release key using OpenSSL (`scripts/sign-release.sh`, which also checks that the private key matches the compiled-in public key), attaches SHA-256 checksums and build provenance attestations, and publishes a GitHub release. The install script picks up the latest release automatically and verifies it with the pinned public key. The full runbook is in [`docs/RELEASING.md`](docs/RELEASING.md).

## Security

- **Transport.** All platform traffic is HTTPS with rustls. Redirects are disabled on every request that carries the token. Heartbeats can be reassigned only to a `*.connlog.com` host (or a domain you list in `CONNLOG_ALLOWED_ENDPOINT_DOMAINS`).
- **Updates.** Only a release signed with the ConnLog Ed25519 key is ever installed, and only if it is newer than the running version. The running (unprivileged) agent verifies the download; the root-side `apply-staged-update` step verifies the staged bytes again with its own compiled-in key and runs the binary to confirm the version before the atomic swap. There is no way to skip verification: a build without the key refuses all updates.
- **Privilege.** The service runs as the `connlog-agent` system user with the systemd sandbox in `src/install/linux.rs`. Root is used only by the `ExecStopPost` hook, for the three things the agent cannot do itself: apply a verified update, remove itself, reboot the host.
- **What leaves the host.** Exactly the fields in the table above, plus hardware health when a BMC is configured. Local actions are never executed on request from the platform in this version.
- **Secrets.** The token and BMC password live in `/etc/connlog/agent.conf` (0600 root). They are redacted from logs and diagnostics and never inherited by local action processes.
- **Reporting.** See the [ConnLog security page](https://connlog.com/security) for how to report a vulnerability.

## Platform support

ConnLog V1 supports Linux servers: VPSs, bare metal, Docker hosts, and CI runners.

Windows support is planned after the Linux agent reaches production stability.

## License

[MIT](LICENSE) — Copyright (c) 2026 ConnLog.

The MIT license terms in [`LICENSE`](LICENSE) are authoritative; the line above
is a convenience reference only.

The release binary statically links third-party crates whose licences require
their notices to travel with it: [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
Regenerate it with `scripts/third-party-licenses.sh` after any `Cargo.lock`
change.

## Ownership and contact

To avoid confusion between the brand, the rights holder, and where to get help:

| | |
| --- | --- |
| **Project / brand** | ConnLog — see [connlog.com](https://connlog.com) |
| **Copyright holder** | ConnLog (the registered legal entity operating ConnLog; the legal entity name is published on the [ConnLog Legal Notice](https://connlog.com/legal-notice)) |
| **Repository** | [github.com/connlog/agent](https://github.com/connlog/agent) |
| **Maintainer** | The ConnLog team |
| **Support** | [support@connlog.com](mailto:support@connlog.com) / the ConnLog dashboard |
| **Security reports** | [security@connlog.com](mailto:security@connlog.com) |

This notice does not assert ownership of any trademark, patent, or third-party
contributor rights. Bundled third-party crates remain under their own licenses.
