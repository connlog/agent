# Local Development Guide

## Important: Dev Mode is NOT in Production Binaries

Dev mode is **compile-time conditional** using Cargo features. Production binaries built for releases do NOT include any dev mode code. This ensures:

- Zero code bloat in production
- No accidental dev mode execution
- Smaller binary size
- Clear separation of concerns

Dev mode is ONLY available when building from source with `--features dev-mode`.

## Quick Start

Running the ConnLog agent in development mode allows you to test the full heartbeat and metrics pipeline locally without production setup requirements.

### Start the Platform

```bash
cd connlog-platform
pnpm dev
```

Platform will be available at `http://localhost:3000`.

### Create a Dev Agent

1. Go to `http://localhost:3000/dashboard/agents`
2. Click "Add Agent"
3. Enter a name (e.g., "my-dev-agent")
4. Copy the generated token (starts with `agent_`)

### Run the Agent in Dev Mode

```bash
cd connlog-agent

# Basic dev mode (requires dev-mode feature)
cargo run --features dev-mode -- dev --token agent_xxx

# OR with fake metrics (no real system stats needed)
cargo run --features dev-mode -- dev --token agent_xxx --fake-metrics
```

### Verify

- Agent appears in dashboard as **ONLINE**
- Status badge shows **DEV MODE**
- Metrics update every **10 seconds**
- Press `Ctrl+C` to stop

## Dev Mode Features

### Automatic Defaults

When you run `connlog-agent dev`:

- **Endpoint**: `http://localhost:3000` (no HTTPS)
- **Heartbeat interval**: `10s` (vs 60s production)
- **Foreground process**: Logs to stdout
- **No systemd**: Runs as your user
- **No config files**: Token stays in-memory

### Command Options

```bash
cargo run --features dev-mode -- dev --help
```

**Required:**
- `--token <token>` - Agent auth token from dashboard

**Optional:**
- `--endpoint <url>` - Override platform URL (default: http://localhost:3000)
- `--interval <secs>` - Heartbeat interval (default: 10)
- `--fake-metrics` - Generate realistic fake metrics
- `--simulate-offline` - Random offline behavior (5% chance per check)
- `--simulate-high-cpu` - Report 95% CPU usage
- `--simulate-heartbeat-drop <N>` - Drop every Nth heartbeat

### Examples

**Basic dev mode:**
```bash
cargo run --features dev-mode -- dev --token agent_abcd1234
```

**With fake metrics:**
```bash
cargo run --features dev-mode -- dev --token agent_abcd1234 --fake-metrics
```

**Simulate failures:**
```bash
# High CPU simulation
cargo run --features dev-mode -- dev --token agent_abcd1234 --simulate-high-cpu

# Offline simulation
cargo run --features dev-mode -- dev --token agent_abcd1234 --simulate-offline

# Drop every 3rd heartbeat
cargo run --features dev-mode -- dev --token agent_abcd1234 --simulate-heartbeat-drop 3
```

**Custom endpoint:**
```bash
cargo run --features dev-mode -- dev --token agent_abcd1234 --endpoint http://staging.connlog.com
```

## What You'll See

### Agent Output

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              🔧 ConnLog Agent (DEV MODE) 🔧                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

  Version:          v0.1.0
  Token:            ********1234
  Endpoint:         http://localhost:3000
  Interval:         10s
  Fake Metrics:     true

────────────────────────────────────────────────────────────────
  Press Ctrl+C to stop

[INFO] Starting heartbeat loop (interval: 10s)
[INFO] ✓ Successfully registered with ConnLog
[INFO] Heartbeat #1 sent successfully, next in 60s
[INFO] Heartbeat #2 sent successfully, next in 60s
```

### Dashboard View

- Agent card shows **DEV** badge next to name
- Status shows **ONLINE**
- Agent detail page shows **🔧 DEV MODE** badge
- Metrics update in real-time

## Testing Scenarios

### 1. Basic Connectivity

```bash
# Start agent
cargo run --features dev-mode -- dev --token agent_xxx

# Verify in dashboard:
# - Status: ONLINE
# - Last seen: updates every 10s
# - Metrics showing system data
```

### 2. Failure Recovery

```bash
# Start with offline simulation
cargo run --features dev-mode -- dev --token agent_xxx --simulate-offline

# Watch dashboard for:
# - ONLINE → OFFLINE transitions
# - Alert triggers
# - Recovery to ONLINE
```

### 3. High Load Alerts

```bash
# Simulate high CPU
cargo run --features dev-mode -- dev --token agent_xxx --simulate-high-cpu

# Verify dashboard shows:
# - CPU at 95%
# - Alert conditions
```

### 4. Network Interruption

```bash
# Start agent
cargo run --features dev-mode -- dev --token agent_xxx --simulate-heartbeat-drop 2

# Every 2nd heartbeat drops
# Watch for OFFLINE transition after threshold
```

## Fake Metrics

When using `--fake-metrics`, the agent generates realistic but fake system data:

- **CPU**: ~25% ± 5% (or 95% with `--simulate-high-cpu`)
- **Memory**: ~60% of 16GB
- **Disk**: ~40% of 512GB
- **Load average**: ~1.5 ± 0.5
- **Hostname**: `dev-agent-<pid>`
- **OS/Arch**: From build system

Benefits:
- Test UI without needing real servers
- Consistent, predictable values
- No dependency on host machine stats
- Safe for CI/testing environments

## Differences from Production

| Feature | Dev Mode | Production |
|---------|----------|------------|
| **Availability** | Source builds with `--features dev-mode` | NOT available |
| Endpoint | http://localhost:3000 | https://connlog.com |
| Interval | 10s | 60s |
| Process | Foreground | Systemd service |
| User | Your user | `connlog-agent` |
| Config | In-memory | `/etc/connlog/agent.conf` |
| Logging | Stdout | Journald |
| Root | Not required | Required for install |
| Badge | Shows "DEV" | No badge |

**CRITICAL:** Production release binaries are built WITHOUT the `dev-mode` feature, so dev mode code is completely excluded.

## Troubleshooting

### Agent won't connect

```bash
# Agent won't connect

# Check platform is running
curl http://localhost:3000/api/health

# Verify token format
echo $TOKEN  # Should start with agent_

# Check logs
cargo run --features dev-mode -- dev --token agent_xxx
# Look for connection errors
```

### Metrics not updating

```bash
# Verify heartbeat interval
# Default is 10s

# Check dashboard polling
# Should auto-refresh every 10s

# Force refresh browser
```

### "Invalid token" error

```bash
# Token must start with "agent_"
# Get new token from dashboard:
# /dashboard/agents → Add Agent
```

### Platform database not ready

```bash
cd connlog-platform

# Run migrations
pnpm prisma migrate dev

# Seed data if needed
pnpm prisma db seed
```

## Development Workflow

### Typical Flow

```bash
# 1. Start platform
cd connlog-platform
pnpm dev

# 2. Create agent via UI
# http://localhost:3000/dashboard/agents

# 3. Run agent
cd ../connlog-agent
cargo run --features dev-mode -- dev --token agent_xxx --fake-metrics

# 4. Watch dashboard
# http://localhost:3000/dashboard/agents

# 5. Make changes, Ctrl+C agent, restart
```

### Testing Changes

**Agent changes:**
```bash
# Edit src/dev.rs or other files
cargo run --features dev-mode -- dev --token agent_xxx
# Agent restarts with changes
```

**Platform changes:**
```bash
# Edit API or UI components
# Next.js hot-reloads automatically
# Refresh dashboard to see changes
```

### Multiple Agents

```bash
# Terminal 1
cargo run --features dev-mode -- dev --token agent_111 --fake-metrics

# Terminal 2
cargo run --features dev-mode -- dev --token agent_222 --simulate-high-cpu

# Terminal 3
cargo run --features dev-mode -- dev --token agent_333 --simulate-offline

# Watch all 3 in dashboard
```

## CI/Testing Usage

### Automated Tests

```bash
#!/bin/bash
# test-agent-flow.sh

# Start platform (background)
cd connlog-platform
pnpm dev &
PLATFORM_PID=$!

# Wait for ready
sleep 5

# Create agent programmatically
TOKEN=$(curl -X POST http://localhost:3000/api/agents \
  -H "Content-Type: application/json" \
  -d '{"name":"test-agent"}' | jq -r '.authToken')

# Run agent with fake metrics
cd ../connlog-agent
cargo run --features dev-mode -- dev --token $TOKEN --fake-metrics &
AGENT_PID=$!

# Test expectations
sleep 15
STATUS=$(curl http://localhost:3000/api/agents/$AGENT_ID | jq -r '.status')

if [ "$STATUS" == "ONLINE" ]; then
  echo "✓ Test passed"
  exit 0
else
  echo "✗ Test failed"
  exit 1
fi

# Cleanup
kill $AGENT_PID $PLATFORM_PID
```

## Best Practices

1. **Use fake metrics for UI testing** - Consistent, fast
2. **Use real metrics for integration testing** - Validates collection
3. **Always use dev command for local work** - Never confuse with prod
4. **One agent per token** - Create new agent for each test
5. **Clean up after testing** - Delete test agents from dashboard

## Security Notes

- Dev mode tokens are **real tokens**
- They work in production if endpoint is changed
- **Never** commit tokens to git
- Use different tokens for dev/staging/prod
- Dev mode badge prevents confusion

## Next Steps

After dev mode works:
1. Test production install: `sudo connlog-agent install --token agent_xxx`
2. Deploy platform to staging
3. Test cross-platform (Linux, macOS, etc.)
4. Set up monitoring alerts
5. Configure email notifications

## Support

If you encounter issues:
1. Check platform logs: `pnpm dev` output
2. Check agent logs: stdout
3. Verify migrations: `pnpm prisma migrate status`
4. Check PostgreSQL: `psql connlog_dev`
5. Review API responses: Browser network tab
