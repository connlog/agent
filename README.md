# ConnLog Agent

Lightweight system monitoring agent that collects metrics and sends heartbeats to the ConnLog platform.

## Features

- **Token-only setup** - Just provide a token, everything else is auto-detected
- **Automatic system detection** - Hostname, OS, architecture detected automatically
- **Comprehensive metrics** - CPU, memory, disk, and load average monitoring
- **Production-ready** - Systemd integration, automatic restart, proper logging
- **Secure by default** - Tokens never logged, stored with 600 permissions
- **Zero dependencies** - Single static binary, no runtime requirements

## Quick Start

### Production Installation

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
