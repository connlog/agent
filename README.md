# ConnLog Agent

Lightweight system monitoring agent that collects metrics and sends heartbeats to the ConnLog platform.

## Features

- **One-command install** - Install and run with a single command
- **Token-only setup** - Just provide a token, everything else is auto-detected
- **Automatic system detection** - Hostname, OS, architecture detected automatically
- **Comprehensive metrics** - CPU, memory, disk, and load average monitoring
- **Production-ready** - Systemd integration, automatic restart, proper logging
- **Secure by default** - Tokens never logged, stored with 600 permissions
- **Zero dependencies** - Single static binary, no runtime requirements

## Quick Start

### One-Command Install (Production)

```bash
curl -fsSL https://connlog.com/install.sh | sudo sh -s -- --install --token agent_xxx
```

This single command will:
1. Detect your OS and architecture
2. Download the latest release
3. Verify checksum
4. Install to `/usr/local/bin`
5. Create system user `connlog-agent`
6. Store config in `/etc/connlog/agent.conf` (600 permissions)
7. Install and start systemd service

**That's it!** Your agent is now running and sending data to ConnLog.

### Alternative: Two-Step Install

If you prefer to install the binary first:

```bash
# Step 1: Install binary
curl -fsSL https://connlog.com/install.sh | sh

# Step 2: Install as service
sudo connlog-agent --install --token agent_xxx
```

### Running Manually (No systemd)

```bash
connlog-agent --token agent_xxx
```

## Development

**Local testing (debug builds only):**

```bash
# Build and run with custom endpoint
cargo run -- --token agent_xxx --endpoint http://localhost:3000

# Production build (no custom endpoint)
cargo build --release
./target/release/connlog-agent --token agent_xxx
```

**Note:** The `--endpoint` flag is ONLY available in debug builds (`cargo run`, `cargo build`). Production releases (`cargo build --release`) connect exclusively to https://connlog.com.

This ensures that production agents always send data to the platform, making local endpoint override useless for end users.

## Building

```bash
# Debug build (has --endpoint flag for local testing)
cargo build

# Release build (production, no --endpoint flag)
cargo build --release
```

## Environment Variables

- `CONNLOG_TOKEN` - Agent authentication token
- `CONNLOG_ENDPOINT` - Custom endpoint (debug builds only)

## License

MIT
