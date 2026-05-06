# ConnLog Agent

Lightweight system monitoring agent for Linux servers. Collects CPU, memory, disk, and load metrics and sends them to the [ConnLog](https://connlog.com) platform via authenticated heartbeats.

Single static binary. One-command install. Zero dependencies.

## Install

```bash
curl -fsSL https://connlog.com/install.sh | sudo sh -s -- --install --token <TOKEN>
```

This will detect your architecture, download the latest release, verify its checksum, install the binary to `/usr/local/bin`, store your token in `/etc/connlog/agent.conf`, and start a systemd service. The agent begins reporting immediately.

Get your token from the [ConnLog dashboard](https://connlog.com) under **Agents → Add Agent**.

### Supported platforms

| OS    | Architecture | Binary                              |
|-------|-------------|--------------------------------------|
| Linux | x86_64      | `connlog-agent-*-linux-x86_64.tar.gz`  |
| Linux | aarch64     | `connlog-agent-*-linux-aarch64.tar.gz` |

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

## Management

```bash
# Check service status
connlog-agent --status

# View logs
journalctl -u connlog-agent -f

# Uninstall (stops service, removes all files)
sudo connlog-agent --uninstall
```

You can also trigger a remote uninstall from the ConnLog dashboard. The agent will clean itself up on the next heartbeat.

## How it works

1. Agent sends a heartbeat to the platform every 60 seconds (configurable server-side)
2. Platform responds with the latest config (metric toggles, intervals, payload limits)
3. Agent applies config changes without restart
4. If the platform marks the agent for uninstall (HTTP 410), the agent triggers a self-cleanup via systemd `ExecStopPost`

### Collected metrics

| Metric           | Description                         |
|------------------|-------------------------------------|
| `cpu_percent`    | CPU usage across all cores          |
| `memory_used_mb` | Used RAM in MB                      |
| `memory_total_mb`| Total RAM in MB                     |
| `disk_used_mb`   | Used disk on root filesystem in MB  |
| `disk_total_mb`  | Total disk on root filesystem in MB |
| `load_1m`        | 1-minute load average               |
| `hostname`       | System hostname                     |
| `os`             | Operating system                    |
| `arch`           | CPU architecture                    |
| `uptime_seconds` | System uptime                       |

Each metric category (CPU, memory, disk, load) can be toggled on/off from the dashboard.

## File layout

```
/usr/local/bin/connlog-agent       # Binary
/etc/connlog/agent.conf            # Token + config (mode 600)
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

The `--endpoint` flag is stripped from release builds at compile time. Production agents always connect to `https://connlog.com`.

### Cross-compilation

CI uses [cross](https://github.com/cross-rs/cross) for multi-arch builds:

```bash
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --target aarch64-unknown-linux-musl
```

### Releases

Push a version tag to trigger CI:

```bash
git tag v0.2.1 && git push origin v0.2.1
```

GitHub Actions builds both architectures, creates tarballs with SHA-256 checksums, and publishes a GitHub release. The install script picks up the latest release automatically.

## License

[MIT](LICENSE) — Copyright (c) 2026 IA Solutions B.V.
