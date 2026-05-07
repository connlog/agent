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
sudo connlog-agent --install --token <TOKEN>
```

### Run without systemd

```bash
connlog-agent --token <TOKEN>
```

You can also pass the token via the `CONNLOG_TOKEN` environment variable:

```bash
export CONNLOG_TOKEN=agent_xxxxxxxxxxxx
connlog-agent
```

## Management

```bash
# Check service status
connlog-agent --status
# or
systemctl status connlog-agent

# View logs
journalctl -u connlog-agent -f

# Uninstall (stops service, removes all files)
sudo connlog-agent --uninstall
```

Note: uninstall preserves the `connlog-agent` system user. Remove it manually if needed: `sudo userdel connlog-agent`.

You can also trigger a remote uninstall from the ConnLog dashboard.

### Diagnostics

```bash
# Fetch and print the agent config from the platform
connlog-agent --check-config --token <TOKEN>

# Send one heartbeat and print the platform response
connlog-agent --test-heartbeat --token <TOKEN>
```

## How it works

1. Agent sends a heartbeat to the platform every 60 seconds (configurable server-side)
2. Platform responds with the latest config (metric toggles, intervals, payload limits)
3. Agent applies config changes without restart
4. If the platform marks the agent for uninstall (HTTP 410), the agent triggers a self-cleanup via systemd `ExecStopPost`

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
