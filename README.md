# ConnLog Agent

The ConnLog Agent is a lightweight system monitoring daemon that collects metrics and sends heartbeats to the ConnLog platform.

## Features

- **Token-only setup** - Just provide a token, everything else is auto-detected
- **Automatic system detection** - Hostname, OS, architecture detected automatically
- **Comprehensive metrics** - CPU, memory, disk, and load average monitoring
- **Production-ready** - Systemd integration, automatic restart, proper logging
- **Dev mode** - Local development with fake metrics and failure simulation
- **Secure by default** - Tokens never logged, stored with 600 permissions
- **Zero dependencies** - Single static binary, no runtime requirements

## Quick Start

### Local Development

**Run agent in dev mode (dev builds only):**

```bash
cargo run --features dev-mode -- dev --token agent_xxx
```

**Note:** Dev mode is NOT compiled into production binaries. It's only available when building from source with the `dev-mode` feature flag.

See [DEV_MODE.md](DEV_MODE.md) for complete local development guide.

### Production Installation

**One-liner install:**

```bash
curl -fsSL https://connlog.com/install.sh | sh
```

This will:
- Detect your OS and architecture
- Download the latest release
- Verify checksum
- Install to `/usr/local/bin`

### Running the Agent

**Basic usage (manual):**

```bash
connlog-agent --token agent_xxx
```

**Install as systemd service:**

```bash
sudo connlog-agent install --token agent_xxx
```

This will:
- Create system user `connlog-agent`
- Store config in `/etc/connlog/agent.conf` (600 permissions)
- Install systemd service
- Enable and start the service

## Usage

### Commands

```bash
# Production: Run agent manually
connlog-agent --token <token>

# Production: Install as systemd service
sudo connlog-agent install --token <token>

# Production: Check service status
sudo connlog-agent status

# Production: Uninstall service (preserves user for safety)
sudo connlog-agent uninstall

# Development: Run in dev mode (requires dev-mode feature)
cargo run --features dev-mode -- dev --token <token>

# Development: With fake metrics
cargo run --features dev-mode -- dev --token <token> --fake-metrics

# Development: Simulate failures
cargo run --features dev-mode -- dev --token <token> --simulate-high-cpu
cargo run --features dev-mode -- dev --token <token> --simulate-offline
cargo run --features dev-mode -- dev --token <token> --simulate-heartbeat-drop 3

# Show version
connlog-agent --version
```

**Important:** Dev mode commands are only available when building from source with `--features dev-mode`. Production binaries do NOT include dev mode code.

See [DEV_MODE.md](DEV_MODE.md) for detailed development guide.

### Environment Variables

- `CONNLOG_TOKEN` - Agent authentication token
- `CONNLOG_PLATFORM_URL` - Platform URL (defaults to https://app.connlog.com)

### Systemd Management

After installing as a service:

```bash
# Check status
sudo systemctl status connlog-agent

# View logs
sudo journalctl -u connlog-agent -f

# Restart service
sudo systemctl restart connlog-agent

# Stop service
sudo systemctl stop connlog-agent

# Start service
sudo systemctl start connlog-agent
```

## Configuration

When installed as a systemd service, configuration is stored in `/etc/connlog/agent.conf`:

```env
CONNLOG_TOKEN=agent_xxx
CONNLOG_PLATFORM_URL=https://app.connlog.com
```

**Security:**
- File permissions: `600` (root read/write only)
- Owner: `root:root`
- Never committed to version control
- Never logged or displayed

## Building from Source

**Prerequisites:**
- Rust 1.70 or later

**Build:**

```bash
cargo build --release
```

The binary will be at `target/release/connlog-agent`.

**Cross-compile for Linux (static binary):**

```bash
# Install cross
cargo install cross

# Build for x86_64
cross build --release --target x86_64-unknown-linux-musl

# Build for ARM64
cross build --release --target aarch64-unknown-linux-musl
```

## How it Works

1. Agent starts with only a token
2. Auto-detects system information (hostname, OS, arch)
3. Collects system metrics (CPU, memory, disk, load)
4. Sends heartbeat to platform every 60 seconds
5. Platform transitions agent from PENDING → ONLINE
6. Dashboard shows live metrics

## Architecture

```
┌─────────────────┐
│  ConnLog Agent  │
│                 │
│  - Metrics      │──┐
│  - Heartbeat    │  │
│  - Auto-detect  │  │
└─────────────────┘  │
                     │ HTTPS (Bearer Token)
                     ▼
            ┌──────────────────┐
            │  ConnLog Platform │
            │  /api/agents/     │
            │    heartbeat      │
            └──────────────────┘
```

### Code Structure

- [main.rs](main.rs) - Entry point and command router
- [config.rs](config.rs) - CLI argument parsing
- [heartbeat.rs](heartbeat.rs) - Heartbeat payload structures
- [http.rs](http.rs) - API client implementation
- [metrics.rs](metrics.rs) - System metrics collection
- [install.rs](install.rs) - Systemd installation

### Heartbeat Protocol

**Endpoint:** `POST /api/agents/heartbeat`

**Authentication:** Bearer token

**Payload:**
```json
{
  "hostname": "web-01",
  "os": "linux",
  "arch": "x86_64",
  "metrics": {
    "cpuUsage": 45.2,
    "memoryUsed": 4294967296,
    "memoryTotal": 17179869184,
    "diskUsed": 53687091200,
    "diskTotal": 107374182400,
    "loadAverage": [1.5, 1.2, 0.9]
  },
  "agentVersion": "0.1.0",
  "protocolVersion": 1,
  "uptime": 86400
}
```

**Response:**
```json
{
  "success": true,
  "nextHeartbeat": 60
}
```

### Status Transitions

```
PENDING ──first heartbeat──> ONLINE
ONLINE ──timeout (5min)───> OFFLINE
OFFLINE ──heartbeat──────> ONLINE
any ──admin action──────> DISABLED
```

## Troubleshooting

### Agent not connecting

**Check logs:**
```bash
# If running manually
# Logs go to stdout

# If running as service
sudo journalctl -u connlog-agent -f
```

**Common issues:**

1. **Invalid token format**
   - Token must start with `agent_`
   - Get token from ConnLog dashboard

2. **Network connectivity**
   - Check firewall rules
   - Verify platform URL is reachable
   - Check DNS resolution

3. **Permission denied**
   - Install command requires sudo
   - Config file requires root access

### Service won't start

**Check service status:**
```bash
sudo systemctl status connlog-agent
```

**Check config file:**
```bash
sudo cat /etc/connlog/agent.conf
```

**Check permissions:**
```bash
sudo ls -l /etc/connlog/agent.conf
# Should show: -rw------- 1 root root
```

### High CPU usage

The agent is designed to be lightweight:
- Collects metrics once per heartbeat (default 60s)
- Uses blocking HTTP (minimal overhead)
- No background threads

If seeing high CPU:
1. Check logs for errors/retry loops
2. Verify network connectivity
3. Check for platform issues

## Development

Run in development mode:

```bash
cargo run -- --token agent_xxx --platform-url http://localhost:3000
```

Set log level:

```bash
RUST_LOG=debug cargo run -- --token agent_xxx
```

## Security

**Token storage:**
- Stored in `/etc/connlog/agent.conf`
- Permissions: 600 (root only)
- Never logged or echoed

**Process security:**
- Runs as system user `connlog-agent`
- No shell access (nologin)
- Minimal privileges

**Network security:**
- HTTPS only
- Bearer token authentication
- No sensitive data in URLs

## Support

- **Issues:** https://github.com/connlog/connlog-agent/issues
- **Docs:** https://docs.connlog.com
- **Email:** support@connlog.com

## License

MIT License - see LICENSE file for details
