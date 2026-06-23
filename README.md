# ConnLog Agent

Lightweight Linux monitoring agent for [ConnLog](https://connlog.com). Collects CPU, memory, disk, and load metrics and sends them to the ConnLog platform via authenticated heartbeats.

Single static binary. One-command install. Zero dependencies.

> **Source:** [github.com/connlog/agent](https://github.com/connlog/agent)  
> **Binary/service name:** `connlog-agent`  
> **Supported platforms:** Linux x86_64 and Linux aarch64

## Install

```bash
curl -fsSL https://connlog.com/install.sh | sudo sh -s -- --install --token <TOKEN>
```

This detects your architecture, downloads the latest release, verifies its SHA-256 checksum, installs the binary to `/usr/local/bin/connlog-agent`, stores your token in `/etc/connlog/agent.conf`, and starts a systemd service. The agent begins reporting immediately.

Get your token from the [ConnLog dashboard](https://connlog.com) under **Agents → Add Agent**.

### Supported platforms

| OS    | Architecture | Binary                                 |
| ----- | ------------ | -------------------------------------- |
| Linux | x86_64       | `connlog-agent-*-linux-x86_64.tar.gz`  |
| Linux | aarch64      | `connlog-agent-*-linux-aarch64.tar.gz` |

### Two-step install

```bash
# 1. Download binary only
curl -fsSL https://connlog.com/install.sh | sh

# 2. Install as systemd service
sudo connlog-agent install --token <TOKEN>
```

### Run without systemd

```bash
connlog-agent register --token <TOKEN>
```

You can also pass the token via the `CONNLOG_TOKEN` environment variable:

```bash
export CONNLOG_TOKEN=agent_xxxxxxxxxxxx
connlog-agent register
```

### Environment variables

| Variable                          | Description                                                                                                                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CONNLOG_TOKEN`                   | Agent auth token (`agent_...`), alternative to `--token`                                                                                                                            |
| `CONNLOG_PLATFORM_URL`            | Override the control-plane URL (defaults to `https://connlog.com`); mainly for self-hosted deployments                                                                              |
| `CONNLOG_EXPOSE_SYSTEM_INFO`      | Set to `true` to opt in to sending hostname/OS/arch with heartbeats (off by default)                                                                                                |
| `CONNLOG_ALLOWED_ENDPOINT_DOMAINS`| Comma-separated extra domains the agent will trust for heartbeat **endpoint assignments** (see below), in addition to `connlog.com`; only relevant for self-hosted/regional setups |

## Management

```bash
# Check service status
connlog-agent status
# or
systemctl status connlog-agent

# View logs
journalctl -u connlog-agent -f

# Refresh the installed systemd unit from the current binary
sudo connlog-agent refresh-service --restart

# Uninstall (stops service, removes all files)
sudo connlog-agent uninstall
```

Note: uninstall preserves the `connlog-agent` system user. Remove it manually if needed: `sudo userdel connlog-agent`.

You can also trigger a remote uninstall from the ConnLog dashboard.

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
2. Platform responds with the latest config (metric toggles, intervals, payload limits)
3. Agent polls Quick Action requests on its own short interval when local actions are enabled
4. Agent applies config changes without restart
5. On startup, then roughly once a day (or sooner after repeated heartbeat
   failures), the agent asks the platform which heartbeat endpoint to use and
   switches to it if — and only if — it's a trusted, validated HTTPS URL; this
   lets ConnLog migrate heartbeat traffic to regional servers later with no
   agent-side changes (today there are no regions configured, so this is a
   no-op and every agent keeps using the platform's own URL)
6. Self-updates refresh the systemd unit from the new binary before the service restarts
7. If the platform marks the agent for uninstall (HTTP 410), the agent triggers a self-cleanup via systemd `ExecStopPost`

### Collected metrics

| Metric            | Description                         |
| ----------------- | ----------------------------------- |
| `cpu_percent`     | CPU usage across all cores          |
| `memory_used_mb`  | Used RAM in MB                      |
| `memory_total_mb` | Total RAM in MB                     |
| `disk_used_mb`    | Used disk on root filesystem in MB  |
| `disk_total_mb`   | Total disk on root filesystem in MB |
| `load_1m`         | 1-minute load average               |
| `hostname`        | System hostname                     |
| `os`              | Operating system                    |
| `arch`            | CPU architecture                    |
| `uptime_seconds`  | System uptime                       |

Each metric category (CPU, memory, disk, load) can be toggled on/off from the dashboard.

## File layout

```txt
/usr/local/bin/connlog-agent              # Binary
/etc/connlog/agent.conf                   # Token + platform URL (mode 600, root-only)
/etc/systemd/system/connlog-agent.service
/var/lib/connlog/heartbeat-telemetry.jsonl # Heartbeat delivery diagnostics (mode 700, connlog-agent)
```

## Development

Requires [Rust](https://rustup.rs) (stable).

```bash
# Debug build — includes --endpoint flag for local testing
cargo run -- --token <TOKEN> --endpoint http://localhost:3000

# Release build — hardcoded to https://connlog.com
cargo build --release
```

### Cross-compilation

CI uses [cross](https://github.com/cross-rs/cross):

```bash
cargo install cross --git https://github.com/cross-rs/cross

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

GitHub Actions builds both Linux targets (`x86_64-musl`, `aarch64-musl`), creates tarballs with SHA-256 checksums and Ed25519 signatures, and publishes a GitHub release. The install script picks up the latest release automatically.

## Platform support

ConnLog V1 supports Linux servers: VPSs, bare metal, Docker hosts, and CI runners.

Windows support is planned after the Linux agent reaches production stability.

## License

[MIT](LICENSE) — Copyright (c) 2026 IA Solutions B.V.
