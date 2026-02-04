# ConnLog Agent System - Complete Implementation

## Overview

This implementation provides a **production-grade heartbeat and system monitoring pipeline** for ConnLog. The agent requires only a token to become operational - no manual registration, no extra configuration.

## Architecture

```
┌─────────────┐
│  Dashboard  │  1. User creates agent, gets token
│     UI      │  2. Views live metrics
└──────┬──────┘
       │
       │ HTTPS
       ▼
┌─────────────┐
│  Platform   │  3. Receives heartbeats
│     API     │  4. Updates agent status
└──────┬──────┘  5. Stores metrics
       │
       │ Database
       ▼
┌─────────────┐
│  PostgreSQL │  Agent status, metrics
└─────────────┘
       ▲
       │ Bearer Auth
       │
┌─────────────┐
│ Rust Agent  │  Sends heartbeat + metrics
│  (Server)   │  Every 60s (configurable)
└─────────────┘
```

## Components

### 1. Database Schema

**Agent Status Flow:**
```
PENDING → ONLINE → OFFLINE
   ↓         ↓        ↓
DISABLED  DISABLED  DISABLED
```

**Fields:**
- Identity: `id`, `workspaceId`, `name`, `authToken`
- Status: `status`, `lastHeartbeatAt`
- Metrics: `cpuPercent`, `memoryUsedMb`, `memoryTotalMb`, `diskUsedMb`, `diskTotalMb`, `load1m`
- System Info: `hostname`, `os`, `arch`, `uptimeSeconds`
- Versioning: `agentVersion`, `protocolVersion`
- Configuration: `checkIntervalSecs`, `missedThreshold`

### 2. Heartbeat API Endpoint

**Endpoint:** `POST /api/agents/heartbeat`

**Authentication:**
```
Authorization: Bearer agent_xxx
```

**Request:**
```json
{
  "agent_version": "0.1.0",
  "protocol_version": 1,
  "hostname": "server-01",
  "os": "linux",
  "arch": "x86_64",
  "uptime_seconds": 123456,
  "metrics": {
    "cpu_percent": 12.3,
    "memory_used_mb": 2048,
    "memory_total_mb": 8192,
    "disk_used_mb": 120000,
    "disk_total_mb": 256000,
    "load_1m": 0.42
  }
}
```

**Response:**
```json
{
  "ok": true,
  "server_time": "2026-02-04T23:00:00Z",
  "expected_interval_seconds": 60,
  "update": null
}
```

**Behavior:**
1. Validates bearer token
2. Looks up agent by token
3. Rejects disabled agents or disabled workspaces
4. Transitions `PENDING` → `ONLINE` on first heartbeat
5. Transitions `OFFLINE` → `ONLINE` on recovery
6. Updates `lastHeartbeatAt`, metrics, system info
7. Returns expected interval for next heartbeat

### 3. Rust Agent

**Location:** `/connlog-agent`

**Dependencies:**
- `reqwest` - HTTP client
- `sysinfo` - System metrics collection
- `serde/serde_json` - Serialization
- `clap` - CLI argument parsing
- `anyhow` - Error handling
- `log/env_logger` - Logging

**Usage:**
```bash
# Basic
connlog-agent --token agent_xxx

# Custom platform
connlog-agent --token agent_xxx --platform-url https://connlog.example.com

# Environment variables
export CONNLOG_TOKEN=agent_xxx
export CONNLOG_PLATFORM_URL=https://connlog.example.com
connlog-agent
```

**Features:**
- ✅ Token-only setup
- ✅ Auto-detects hostname, OS, architecture
- ✅ Collects CPU, memory, disk, load metrics
- ✅ Sends heartbeat every 60s (or server-configured interval)
- ✅ Exponential backoff on failures (30s retry)
- ✅ Never logs tokens (security)
- ✅ Fail-fast on invalid tokens

### 4. Agent Detail UI

**Route:** `/dashboard/agents/[id]`

**Features:**
- Live status badge (ONLINE/OFFLINE/PENDING/DISABLED)
- Last seen timestamp
- System information (hostname, OS, arch)
- Agent version & protocol version
- Uptime
- Real-time metrics with progress bars:
  - CPU usage (%)
  - Memory usage (used/total)
  - Disk usage (used/total)
  - Load average (1m)
- Configuration display
- Auto-refresh every 10 seconds

## Security

1. **Token Format Validation**
   - Must start with `agent_`
   - Validated on both agent and platform

2. **Bearer Authentication**
   - Tokens sent as `Authorization: Bearer agent_xxx`
   - No cookies, no sessions
   - No user context

3. **Token Protection**
   - Never logged by agent
   - Never displayed in platform logs
   - Shown once in UI with copy button

4. **Workspace Isolation**
   - Agents scoped to workspaces
   - Users can only view agents in their workspace
   - Admin console can see all agents

## Status Transitions

```
User creates agent in UI
  ↓
Agent created with status=PENDING
  ↓
User copies token → starts Rust agent
  ↓
First heartbeat received
  ↓
status: PENDING → ONLINE
  ↓
Continuous heartbeats every 60s
  ↓
If heartbeats stop (silence detection)
  ↓
status: ONLINE → OFFLINE
  ↓
When heartbeats resume
  ↓
status: OFFLINE → ONLINE
```

## Deployment

### Agent Deployment (Systemd)

```bash
# 1. Build agent
cd connlog-agent
cargo build --release

# 2. Copy binary
sudo cp target/release/connlog-agent /usr/local/bin/

# 3. Create service file
sudo nano /etc/systemd/system/connlog-agent.service
```

```ini
[Unit]
Description=ConnLog Monitoring Agent
After=network.target

[Service]
Type=simple
User=connlog
Environment="CONNLOG_TOKEN=agent_xxx"
Environment="CONNLOG_PLATFORM_URL=https://connlog.example.com"
ExecStart=/usr/local/bin/connlog-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# 4. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable connlog-agent
sudo systemctl start connlog-agent

# 5. Check status
sudo systemctl status connlog-agent
sudo journalctl -u connlog-agent -f
```

### Platform Deployment

Standard Next.js deployment with:
1. PostgreSQL database
2. Environment variables configured
3. `/api/agents/heartbeat` endpoint accessible

## Testing

### Manual Testing

1. **Create Agent:**
   ```bash
   # In platform UI
   - Go to /dashboard/agents
   - Click "Create Agent"
   - Name: "test-agent"
   - Copy token
   ```

2. **Start Agent:**
   ```bash
   connlog-agent --token agent_xxx --platform-url http://localhost:3000
   ```

3. **Verify:**
   - Agent status changes from PENDING → ONLINE
   - `/dashboard/agents/[id]` shows live metrics
   - Metrics update every 10s in UI
   - Agent logs show successful heartbeats

### API Testing

```bash
# Test heartbeat endpoint
curl -X POST http://localhost:3000/api/agents/heartbeat \
  -H "Authorization: Bearer agent_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_version": "0.1.0",
    "protocol_version": 1,
    "hostname": "test-server",
    "os": "linux",
    "arch": "x86_64",
    "uptime_seconds": 12345,
    "metrics": {
      "cpu_percent": 25.5,
      "memory_used_mb": 4096,
      "memory_total_mb": 16384,
      "disk_used_mb": 50000,
      "disk_total_mb": 500000,
      "load_1m": 1.23
    }
  }'
```

Expected response:
```json
{
  "ok": true,
  "server_time": "2026-02-04T23:00:00.000Z",
  "expected_interval_seconds": 60,
  "update": null
}
```

## Future Enhancements (Not Implemented)

1. **Silence Detection Worker**
   - Background job checking `lastHeartbeatAt`
   - Transitions ONLINE → OFFLINE when threshold exceeded
   - Creates alerts

2. **Agent Updates**
   - Platform serves update info in heartbeat response
   - Agent can self-update (optional)

3. **Enhanced Metrics**
   - Network I/O
   - Process count
   - Detailed disk per-mount
   - Custom metrics

4. **Charts & History**
   - Time-series metrics storage
   - Historical charts
   - Anomaly detection

5. **Agent Fingerprinting**
   - UUID based on hostname + boot ID
   - Detects agent reinstalls

## Commits

1. ✅ `feat(api): add heartbeat + metrics ingestion endpoint`
2. ✅ `feat(agent): add rust agent with metrics collection`
3. ✅ `ui(agent): add agent detail page with live metrics`

## Key Design Decisions

1. **Token-only setup** - Simplicity is critical for adoption
2. **Blocking runtime** - No async complexity in agent
3. **Direct metric storage** - Values on Agent table for fast reads
4. **No historical data yet** - Keep scope focused
5. **10s UI polling** - Good enough without websockets
6. **Explicit status transitions** - Predictable behavior
7. **Bearer auth only** - No session complexity

## Success Criteria

✅ User creates agent in UI
✅ Copies token
✅ Runs `connlog-agent --token agent_xxx`
✅ Agent immediately goes ONLINE
✅ Dashboard shows live metrics
✅ System works unattended
✅ Production-quality code
✅ Clear error messages
✅ Secure token handling
✅ Graceful failure modes

This implementation provides **the foundation for real infrastructure monitoring**.
