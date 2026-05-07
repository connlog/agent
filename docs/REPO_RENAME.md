# GitHub Repository Rename

The public GitHub repository was renamed from `connlog/connlog-agent` to `connlog/agent`.

## What changed

- GitHub repository URL: `github.com/connlog/connlog-agent` → `github.com/connlog/agent`
- `src/update.rs`: auto-update release check URL updated to new repo path
- `Cargo.toml`: added `repository` and `homepage` metadata fields

## What did NOT change

The installed agent identity is **stable**:

| Attribute            | Value                              |
| -------------------- | ---------------------------------- |
| Binary               | `connlog-agent`                    |
| Systemd service      | `connlog-agent`                    |
| Install path         | `/usr/local/bin/connlog-agent`     |
| Config dir           | `/etc/connlog/`                    |
| State dir            | `/var/lib/connlog/`                |
| Release artifacts    | `connlog-agent-linux-x86_64`, etc. |
| Cargo crate name     | `connlog-agent`                    |
| Update protocol      | Unchanged                          |
| Signing/verification | Unchanged                          |

## Compatibility

Agents on version ≤ 1.4.0 use the old update check URL
(`api.github.com/repos/connlog/connlog-agent/releases/latest`) and rely on
GitHub's repository redirect until they self-update to a version carrying the
new URL. GitHub redirects the old repository URL automatically.

Agents on version ≥ 1.4.1 use the new URL directly.

Platform-pushed updates (the primary update path) are always constructed with
the correct URL by the platform, regardless of the URL compiled into the agent.

## Manual step required

The actual rename must be done in GitHub:
```
github.com/connlog/connlog-agent → Settings → General → Repository name → agent → Rename
```

See full rename report: `connlog-platform/docs/reports/agent-repo-rename.md`
