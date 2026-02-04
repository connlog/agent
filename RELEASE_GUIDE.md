# Next Steps: Agent Release & Testing

## Prerequisites

Before creating the first release, you need to:

1. **Create the GitHub repository** at `github.com/connlog/connlog-agent`
2. **Push the agent code** to that repository
3. **Tag a release** to trigger the build workflow

## Step-by-Step Release Process

### 1. Create GitHub Repository

Go to https://github.com/organizations/connlog/repositories/new and create:
- **Repository name:** `connlog-agent`
- **Description:** "Lightweight system monitoring agent for ConnLog platform"
- **Visibility:** Public
- **Initialize:** Don't initialize (we have code already)

### 2. Configure Git Remote

```bash
cd /home/mmi/business/connlog/connlog-agent

# Add the GitHub remote
git remote add origin git@github.com:connlog/connlog-agent.git

# Push the canary branch
git push -u origin canary
```

### 3. Create First Release

```bash
# Tag the current commit
git tag -a v0.1.0 -m "Initial release

Features:
- Token-only setup with auto-detection
- System metrics collection (CPU, memory, disk, load)
- Heartbeat protocol with bearer auth
- Systemd self-install mode
- One-liner installation script
- Cross-platform Linux support (x86_64, aarch64)"

# Push the tag
git push origin v0.1.0
```

### 4. Monitor Build

1. Go to https://github.com/connlog/connlog-agent/actions
2. Watch the "Release" workflow run
3. Wait for builds to complete (~5-10 minutes)
4. Check that release was created with binaries

### 5. Test Installation

**Option A: Test with install.sh**

```bash
# On a fresh Ubuntu VM:
curl -fsSL https://raw.githubusercontent.com/connlog/connlog-agent/canary/install.sh | sh

# Run the agent
connlog-agent --token agent_xxx
```

**Option B: Test systemd install**

```bash
# Download and install
curl -fsSL https://raw.githubusercontent.com/connlog/connlog-agent/canary/install.sh | sh

# Install as service
sudo connlog-agent install --token agent_xxx

# Verify
sudo systemctl status connlog-agent
sudo journalctl -u connlog-agent -f
```

### 6. Verify on Platform

1. Go to ConnLog dashboard
2. Navigate to Agents section
3. Should see new agent with status: ONLINE
4. Click agent to view metrics
5. Metrics should update every 60 seconds

## Testing Checklist

- [ ] Install script downloads and installs binary
- [ ] `connlog-agent --version` shows correct version
- [ ] `connlog-agent --token <token>` runs and connects
- [ ] Agent appears in dashboard as PENDING
- [ ] First heartbeat transitions to ONLINE
- [ ] Metrics display correctly in dashboard
- [ ] `sudo connlog-agent install` creates service
- [ ] Service starts and runs successfully
- [ ] `systemctl status connlog-agent` shows active
- [ ] Logs appear in journalctl
- [ ] Agent survives reboot
- [ ] `sudo connlog-agent status` shows status
- [ ] `sudo connlog-agent uninstall` removes service
- [ ] Invalid token shows clear error

## Troubleshooting Build Issues

### Build fails on GitHub Actions

Check the Actions logs:
```
https://github.com/connlog/connlog-agent/actions
```

Common issues:
- **Rust compilation error:** Check Cargo.toml dependencies
- **Cross-compilation error:** Verify cross targets are correct
- **Permission error:** Check GitHub Actions permissions in repo settings

### Install script fails

Test manually:
```bash
# Download install script
curl -fsSL https://raw.githubusercontent.com/connlog/connlog-agent/canary/install.sh -o install.sh
chmod +x install.sh

# Run with debug
bash -x install.sh
```

### Agent doesn't connect

Check logs:
```bash
# If running manually
connlog-agent --token <token>

# If running as service
sudo journalctl -u connlog-agent -f
```

Common issues:
- **Invalid token format:** Token must start with `agent_`
- **Network connectivity:** Check firewall, DNS
- **Platform URL:** Verify platform is running and accessible

## Repository Structure

After setup, you should have:

```
GitHub Organization: connlog
├── connlog-agent        (this repo)
│   └── Branches: canary (default)
│   └── Releases: v0.1.0
│       ├── connlog-agent-v0.1.0-linux-x86_64.tar.gz
│       ├── connlog-agent-v0.1.0-linux-x86_64.tar.gz.sha256
│       ├── connlog-agent-v0.1.0-linux-aarch64.tar.gz
│       └── connlog-agent-v0.1.0-linux-aarch64.tar.gz.sha256
│
└── connlog-platform     (separate repo)
    └── ...
```

## Platform Requirements

The platform must have:
- [x] Migration: `20260204230042_add_agent_metrics_and_update_status_enum`
- [x] API endpoint: `POST /api/agents/heartbeat`
- [x] Agent status enum: PENDING, ONLINE, OFFLINE, DISABLED
- [x] Agent detail page: `/dashboard/agents/[id]`
- [x] Metrics display with live polling

All prerequisites are complete ✅

## Success Criteria

The installation is successful when:
1. User can install agent in < 1 minute
2. Only input required is token
3. Agent appears in dashboard as ONLINE
4. Metrics update every 60 seconds
5. Service survives reboots
6. Clean uninstall works properly

## Support Documentation

After release, update these locations:
- [ ] Add install instructions to platform dashboard
- [ ] Create "Add Agent" wizard in UI
- [ ] Update docs.connlog.com with installation guide
- [ ] Add troubleshooting section to support docs

## Monitoring After Release

Watch for:
- Download counts on GitHub releases
- Agent connection errors in platform logs
- Support requests about installation
- OS/architecture compatibility issues

Track metrics:
- Time to first successful connection
- Installation failure rate
- Average install duration
- Most common errors
