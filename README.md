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
5. Self-updates refresh the systemd unit from the new binary before the service restarts
6. If the platform marks the agent for uninstall (HTTP 410), the agent triggers a self-cleanup via systemd `ExecStopPost`

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
