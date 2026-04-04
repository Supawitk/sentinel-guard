# Sentinel Guard

Lightweight file access monitor that protects sensitive files from AI coding agents.

Watches for `.env`, API keys, SSH keys, crypto wallets, and other secrets being accessed by tools like OpenClaw, Cursor, or Copilot. Logs everything, alerts in real-time, and can block access via agent hooks.

## Install

```bash
cargo install --path .
```

Or download the binary from [Releases](https://github.com/Supawitk/sentinel-guard/releases).

## Commands

### Setup
```bash
sentinel init                    # Generate config file
sentinel check                   # Verify installation
```

### Scanning
```bash
sentinel scan .                  # Find sensitive files
sentinel scan . --deep           # + check file contents for secrets
sentinel skill-scan .            # Scan AI agent skills for malicious patterns
sentinel skill-scan --file X.md  # Scan a specific skill file
```

### Monitoring
```bash
sentinel watch .                 # Real-time file access monitoring
sentinel hook                    # Run as AI agent PreToolUse hook (stdin/stdout JSON)
```

### Integrity
```bash
sentinel baseline .              # Hash sensitive files
sentinel verify .                # Check for changes since baseline
```

### Reporting
```bash
sentinel log                     # View activity log
sentinel log --sensitive         # Sensitive events only
sentinel stats                   # Event statistics
sentinel dashboard               # Interactive TUI dashboard
sentinel report . -o report.csv  # Export to CSV
sentinel report . -t log -o x.csv  # Export activity log
```

### Protection
```bash
sentinel agents                  # Show running AI agents (Claude, Cursor, Copilot...)
sentinel honeypot .              # Plant fake .env/wallet/key decoy files
sentinel honeypot . --remove     # Remove planted honeypots
sentinel vault <file>            # Quarantine a sensitive file
sentinel vault list              # Show vault contents
sentinel vault-restore <name>    # Restore from vault
sentinel auto-vault .            # Auto-quarantine all sensitive files
```

### Maintenance
```bash
sentinel cleanup --days 7        # Remove old log entries
sentinel check                   # Verify installation
```

## Config

Generate with `sentinel init`, customize `sentinel.toml`:

```toml
[watch]
paths = ["."]
recursive = true

[protect]
sensitive_patterns = ["**/.env", "**/*.pem", "**/id_rsa", "**/wallet.dat"]

[alert]
mode = "all"                     # "log", "terminal", "all"
action = "warn"                  # "warn" or "block"
desktop_notifications = false

[log]
db_path = "~/.sentinel-guard/activity.db"
retention_days = 30

# Optional webhooks
[[webhooks.endpoints]]
name = "slack"
url = "https://hooks.slack.com/services/..."
format = "slack"                 # "slack", "discord", "generic"
enabled = false
```

## What It Detects

**Files:** `.env`, SSH keys, certificates, AWS/GCloud configs, crypto wallets, OpenClaw secrets, package manager configs

**Secrets in code:** API keys (AWS, OpenAI, Anthropic, GitHub, GitLab, Slack, Stripe), private keys, database URLs, crypto wallet keys, seed phrases

**Malicious AI skills:** Data exfiltration commands, RCE patterns, credential harvesting, persistence mechanisms, browser data access

## Architecture

```
src/
├── core/       Config, database, shared types
├── detect/     Scanner, skills, integrity, vault, honeypot
├── monitor/    Watcher, rules, agent detection, hooks
├── output/     Alerts, dashboard, notifications, webhooks, reports
└── main.rs     18 CLI commands
```

## License

MIT
