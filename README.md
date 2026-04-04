# Sentinel Guard

Lightweight file access monitor that protects sensitive files from AI coding agents.

Detects and alerts when `.env`, API keys, SSH keys, crypto wallets, or credentials are accessed by tools like OpenClaw, Cursor, or Copilot.

## Install

```bash
cargo install --path .
```

Or download from [Releases](https://github.com/Supawitk/sentinel-guard/releases).

## Usage

Run `sentinel` to open the interactive grid launcher, or use commands directly:

```
┌─ Setup ──────┬─ Scan ────────┬─ Monitor ─────┐
│ init         │ scan .        │ watch .       │
│ check        │ scan . --deep │ agents        │
├─ Integrity ──┼─ Protect ─────┼─ Report ──────┤
│ baseline .   │ honeypot .    │ dashboard     │
│ verify .     │ auto-vault .  │ log           │
│              │ vault list    │ stats         │
│              │               │ report -o x   │
│              │               │ cleanup       │
└──────────────┴───────────────┴───────────────┘
```

## Commands

| Command | Description |
|---------|-------------|
| `sentinel` | Interactive grid launcher |
| `sentinel scan . --deep` | Find sensitive files + secrets in content |
| `sentinel watch .` | Real-time monitoring with AI agent detection |
| `sentinel agents` | Show running AI agents (Claude, Cursor, Copilot...) |
| `sentinel dashboard` | Interactive TUI with live events and alerts |
| `sentinel honeypot .` | Plant fake .env/wallet/key decoy files |
| `sentinel auto-vault .` | Quarantine all sensitive files to vault |
| `sentinel baseline .` | Hash sensitive files for integrity checks |
| `sentinel verify .` | Detect tampering since baseline |
| `sentinel skill-scan .` | Scan AI agent skills for malicious patterns |
| `sentinel report . -o r.csv` | Export findings to CSV |
| `sentinel init` | Generate config |
| `sentinel check` | Verify installation |

## What It Detects

**Sensitive files** — `.env`, SSH keys, certificates, AWS/GCloud configs, crypto wallets, OpenClaw secrets, package manager tokens

**Secrets in code** — API keys (AWS, OpenAI, Anthropic, GitHub, Slack, Stripe), private keys, database URLs, seed phrases

**Malicious AI skills** — data exfiltration, RCE, credential harvesting, persistence, browser data theft

**Running AI agents** — Claude Code, Cursor, VS Code/Copilot, OpenClaw, Windsurf, Cody, Aider, Codex, Gemini

## Config

```bash
sentinel init  # creates sentinel.toml
```

```toml
[watch]
paths = ["."]
recursive = true

[protect]
sensitive_patterns = ["**/.env", "**/*.pem", "**/id_rsa", "**/wallet.dat"]

[alert]
mode = "all"
action = "warn"
desktop_notifications = false

[[webhooks.endpoints]]
name = "slack"
url = "https://hooks.slack.com/services/..."
format = "slack"
enabled = false
```

## Architecture

```
src/
├── core/       Config, database, shared types
├── detect/     Scanner, skills, integrity, vault, honeypot
├── monitor/    Watcher, rules, agent detection, hooks
├── output/     Launcher, dashboard, alerts, notifications, webhooks
└── main.rs     CLI entry (18 commands)
```

## License

MIT
