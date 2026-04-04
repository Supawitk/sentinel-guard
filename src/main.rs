mod core;
mod detect;
mod monitor;
mod output;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sentinel", version, about = "Sentinel Guard - AI Agent File Access Monitor")]
struct Cli {
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    // ── Setup ───────────────────────────────
    /// Generate default config file
    Init { #[arg(default_value = "sentinel.toml")] path: String },

    // ── Scanning ────────────────────────────
    /// Scan for sensitive files and secrets
    Scan {
        #[arg(default_value = ".")] path: String,
        #[arg(short = 'd', long)] deep: bool,
    },
    /// Scan AI agent skills for malicious patterns
    SkillScan {
        #[arg(default_value = ".")] path: String,
        #[arg(short, long)] file: Option<String>,
    },

    // ── Monitoring ──────────────────────────
    /// Watch directories for file access in real-time
    Watch { #[arg(default_value = ".")] paths: Vec<String> },
    /// Run as a PreToolUse hook for AI agents
    Hook,

    // ── Integrity ───────────────────────────
    /// Create baseline hashes of sensitive files
    Baseline { #[arg(default_value = ".")] path: String },
    /// Verify file integrity against baseline
    Verify { #[arg(default_value = ".")] path: String },

    // ── Reporting ───────────────────────────
    /// View activity log
    Log {
        #[arg(short, long, default_value = "50")] limit: u32,
        #[arg(short, long)] sensitive: bool,
    },
    /// Show activity statistics
    Stats,
    /// Open interactive terminal dashboard
    Dashboard,
    /// Export scan results or log to CSV/TXT
    Report {
        #[arg(default_value = ".")] path: String,
        #[arg(short, long, default_value = "sentinel-report.csv")] output: String,
        #[arg(short = 't', long, default_value = "scan")] report_type: String,
        #[arg(short = 'd', long)] deep: bool,
    },

    // ── Protection ───────────────────────────
    /// Show which AI agents are currently running
    Agents,
    /// Plant honeypot/canary files to detect unauthorized access
    Honeypot {
        #[arg(default_value = ".")] path: String,
        #[arg(long)] remove: bool,
    },
    /// Move sensitive files to a protected vault
    Vault { #[arg(default_value = "list")] action: String },
    /// Restore a file from the vault
    VaultRestore { name: String },
    /// Auto-quarantine all sensitive files in a directory
    AutoVault { #[arg(default_value = ".")] path: String },

    // ── Maintenance ─────────────────────────
    /// Clean up old log entries
    Cleanup { #[arg(short, long)] days: Option<u32> },
    /// Run self-check to verify installation
    Check,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).without_time().init();

    match cli.command {
        Some(cmd) => {
            // Direct CLI mode: run once and exit
            run_command(&cmd, &cli.config)?;
        }
        None => {
            // Interactive mode: launcher loop
            run_interactive_loop(&cli.config)?;
        }
    }

    Ok(())
}

/// Interactive launcher loop — keeps returning to the launcher after each command
fn run_interactive_loop(config_path: &Option<PathBuf>) -> Result<()> {
    loop {
        // Show launcher, get selected command
        let cmd_str = match output::launcher::run_launcher()? {
            Some(s) => s,
            None => return Ok(()), // user pressed q
        };

        // Parse the selected command string into a Commands enum
        let parsed = parse_command_str(&cmd_str);

        // Run the command (launcher is already exited, normal terminal now)
        if let Some(cmd) = parsed {
            print_banner();
            if let Err(e) = run_command(&cmd, config_path) {
                println!("\n  {} {}\n", "Error:".red().bold(), e);
            }

            // Wait for user to press Enter before returning to launcher
            // (except for dashboard/watch which have their own exit)
            if !matches!(cmd, Commands::Dashboard | Commands::Watch { .. } | Commands::Hook) {
                println!("\n  {}", "Press Enter to return to menu...".dimmed());
                let mut buf = String::new();
                let _ = std::io::stdin().read_line(&mut buf);
            }
        }
    }
}

/// Parse a command string like "scan . --deep" into Commands
fn parse_command_str(cmd_str: &str) -> Option<Commands> {
    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    if parts.is_empty() { return None; }

    match parts[0] {
        "init" => Some(Commands::Init { path: parts.get(1).unwrap_or(&"sentinel.toml").to_string() }),
        "check" => Some(Commands::Check),
        "scan" => Some(Commands::Scan {
            path: parts.get(1).unwrap_or(&".").to_string(),
            deep: parts.contains(&"--deep"),
        }),
        "skill-scan" => {
            let file = parts.iter().position(|&p| p == "--file" || p == "-f")
                .and_then(|i| parts.get(i + 1).map(|s| s.to_string()));
            Some(Commands::SkillScan { path: parts.get(1).unwrap_or(&".").to_string(), file })
        }
        "watch" => Some(Commands::Watch { paths: parts[1..].iter().map(|s| s.to_string()).collect() }),
        "hook" => Some(Commands::Hook),
        "baseline" => Some(Commands::Baseline { path: parts.get(1).unwrap_or(&".").to_string() }),
        "verify" => Some(Commands::Verify { path: parts.get(1).unwrap_or(&".").to_string() }),
        "log" => Some(Commands::Log {
            limit: 50,
            sensitive: parts.contains(&"--sensitive"),
        }),
        "stats" => Some(Commands::Stats),
        "dashboard" => Some(Commands::Dashboard),
        "report" => Some(Commands::Report {
            path: parts.get(1).unwrap_or(&".").to_string(),
            output: parts.iter().position(|&p| p == "-o").and_then(|i| parts.get(i + 1).map(|s| s.to_string())).unwrap_or("sentinel-report.csv".into()),
            report_type: parts.iter().position(|&p| p == "-t").and_then(|i| parts.get(i + 1).map(|s| s.to_string())).unwrap_or("scan".into()),
            deep: parts.contains(&"--deep"),
        }),
        "agents" => Some(Commands::Agents),
        "honeypot" => Some(Commands::Honeypot {
            path: parts.get(1).unwrap_or(&".").to_string(),
            remove: parts.contains(&"--remove"),
        }),
        "vault" => Some(Commands::Vault { action: parts.get(1).unwrap_or(&"list").to_string() }),
        "vault-restore" => parts.get(1).map(|n| Commands::VaultRestore { name: n.to_string() }),
        "auto-vault" => Some(Commands::AutoVault { path: parts.get(1).unwrap_or(&".").to_string() }),
        "cleanup" => Some(Commands::Cleanup {
            days: parts.iter().position(|&p| p == "--days").and_then(|i| parts.get(i + 1).and_then(|s| s.parse().ok())),
        }),
        _ => None,
    }
}

/// Execute a single command
fn run_command(command: &Commands, config_path: &Option<PathBuf>) -> Result<()> {
    // Skip banner for hook and check
    if matches!(command, Commands::Hook | Commands::Check) {
        // no banner
    }

    match command {
        Commands::Init { path } => {
            let p = PathBuf::from(path);
            if p.exists() {
                println!("  {} Config already exists: {}", "!".yellow().bold(), p.display());
            } else {
                core::config::Config::save_default(&p)?;
                println!("  {} Created: {}", "OK".green().bold(), p.display());
            }
        }

        Commands::Scan { path, deep } => {
            let config = load_config(config_path);
            let scanner = detect::scanner::Scanner::new(&config.protect.sensitive_patterns)?;
            println!("  Scanning {} {}...\n", path.white().bold(), if *deep { "(deep)" } else { "(patterns only)" });
            let findings = scanner.scan_directory(&PathBuf::from(path), *deep);
            output::report::print_findings(&findings);
            log_findings(&config, &findings);
        }

        Commands::SkillScan { path, file } => {
            let skill_scanner = detect::skills::SkillScanner::new()?;
            if let Some(f) = file {
                println!("  Scanning skill file: {}\n", f.white().bold());
                output::report::print_skill_findings(&skill_scanner.scan_file(&PathBuf::from(f)));
            } else {
                println!("  Scanning for AI agent skills in: {}\n", path.white().bold());
                output::report::print_skill_findings(&skill_scanner.scan_directory(&PathBuf::from(path)));
            }
        }

        Commands::Watch { paths } => {
            let mut config = load_config(config_path);
            if !paths.is_empty() && paths[0] != "." { config.watch.paths = paths.clone(); }
            monitor::watcher::watch(&config)?;
        }

        Commands::Hook => {
            let config = load_config(config_path);
            monitor::hooks::run_hook(&config)?;
        }

        Commands::Baseline { path } => {
            let config = load_config(config_path);
            let dir = PathBuf::from(path);
            println!("  Creating baseline in {}...\n", path.white().bold());
            let db = detect::integrity::create_baseline(&dir, &config.protect.sensitive_patterns)?;
            let count = db.files.len();
            detect::integrity::save_baseline(&dir, &db)?;
            println!("  {} Baseline: {} file(s) hashed", "OK".green().bold(), count);
        }

        Commands::Verify { path } => {
            let config = load_config(config_path);
            let dir = PathBuf::from(path);
            println!("  Verifying integrity in {}...\n", path.white().bold());
            let changes = detect::integrity::verify(&dir, &config.protect.sensitive_patterns)?;
            output::report::print_integrity_changes(&changes);
        }

        Commands::Log { limit, sensitive } => {
            let config = load_config(config_path);
            let db = core::db::ActivityDb::open(&config.db_path())?;
            let entries = if *sensitive { db.get_sensitive_only(*limit)? } else { db.get_recent(*limit)? };
            if entries.is_empty() {
                println!("  {}", "No activity logged yet.".dimmed());
            } else {
                println!("  {} (last {})\n", "Activity Log".white().bold(), entries.len());
                for e in &entries {
                    let mark = if e.is_sensitive { " !!".red().bold().to_string() } else { String::new() };
                    println!("  {} [{}]{} {}", e.timestamp.dimmed(), e.event_type.cyan(), mark, e.path);
                    if !e.detail.is_empty() { println!("           {}", e.detail.dimmed()); }
                }
            }
        }

        Commands::Stats => {
            let config = load_config(config_path);
            let db = core::db::ActivityDb::open(&config.db_path())?;
            let (total, sensitive, today) = db.get_stats()?;
            println!("  {}\n", "Statistics".white().bold());
            println!("  Total events:     {}", total.to_string().cyan());
            println!("  Sensitive events: {}", sensitive.to_string().red().bold());
            println!("  Events today:     {}", today.to_string().green());
            println!("  Database:         {}", config.db_path().display().to_string().dimmed());
        }

        Commands::Dashboard => {
            let config = load_config(config_path);
            output::dashboard::run(&config)?;
        }

        Commands::Report { path, output: out, report_type, deep } => {
            let config = load_config(config_path);
            match report_type.as_str() {
                "scan" => {
                    let scanner = detect::scanner::Scanner::new(&config.protect.sensitive_patterns)?;
                    let findings = scanner.scan_directory(&PathBuf::from(path), *deep);
                    output::report::export_findings(&findings, out)?;
                    println!("  {} Exported {} findings to {}", "OK".green().bold(), findings.len(), out.white().bold());
                }
                "log" => {
                    let db = core::db::ActivityDb::open(&config.db_path())?;
                    let entries = db.get_sensitive_only(10000)?;
                    output::report::export_log(&entries, out)?;
                    println!("  {} Exported {} entries to {}", "OK".green().bold(), entries.len(), out.white().bold());
                }
                _ => println!("  {} Unknown report type. Use 'scan' or 'log'.", "!".yellow().bold()),
            }
        }

        Commands::Agents => {
            let mut detector = monitor::agents::AgentDetector::new();
            let agents = detector.detect();
            if agents.is_empty() {
                println!("  {}", "No AI agents detected running.".dimmed());
            } else {
                println!("  {} ({} found)\n", "Running AI Agents".white().bold(), agents.len());
                for a in &agents {
                    println!("  {} {} (PID: {})", "->".green(), a.name.cyan().bold(), a.pid);
                    println!("     Process: {}", a.process_name.dimmed());
                }
            }
        }

        Commands::Honeypot { path, remove } => {
            let dir = PathBuf::from(path);
            if *remove { detect::honeypot::cleanup(&dir)?; }
            else { detect::honeypot::plant(&dir, None)?; }
        }

        Commands::Vault { action } => {
            if action == "list" { detect::vault::list_vault(); }
            else { detect::vault::quarantine(&PathBuf::from(action))?; }
        }

        Commands::VaultRestore { name } => {
            detect::vault::restore(name)?;
        }

        Commands::AutoVault { path } => {
            let config = load_config(config_path);
            println!("  Auto-quarantining sensitive files in {}...\n", path.white().bold());
            let count = detect::vault::auto_quarantine(&PathBuf::from(path), &config.protect.sensitive_patterns)?;
            println!("\n  {} {} file(s) moved to vault", "Done.".green().bold(), count);
        }

        Commands::Cleanup { days } => {
            let config = load_config(config_path);
            let db = core::db::ActivityDb::open(&config.db_path())?;
            let retention = days.unwrap_or(config.log.retention_days);
            let deleted = db.cleanup_old(retention)?;
            println!("  {} Cleaned {} entries (>{} days old)", "OK".green().bold(), deleted, retention);
        }

        Commands::Check => {
            run_self_check();
        }
    }

    Ok(())
}

fn load_config(path: &Option<PathBuf>) -> core::config::Config {
    core::config::Config::load_or_default(path.as_deref())
}

fn log_findings(config: &core::config::Config, findings: &[crate::core::types::Finding]) {
    if let Ok(db) = core::db::ActivityDb::open(&config.db_path()) {
        for f in findings {
            let _ = db.log_event("scan", &f.path.to_string_lossy(), true, &f.detail);
        }
    }
}

fn print_banner() {
    println!("\n  {} v{}\n", "Sentinel Guard".cyan().bold(), env!("CARGO_PKG_VERSION"));
}

fn run_self_check() {
    println!("  Sentinel Guard Self-Check\n");
    let checks = [
        ("Binary", true),
        ("Config loading", core::config::Config::load_or_default(None).watch.recursive),
        ("SQLite", { let p = core::config::Config::default().db_path(); core::db::ActivityDb::open(&p).is_ok() }),
        ("Scanner", detect::scanner::Scanner::new(&core::config::Config::default().protect.sensitive_patterns).is_ok()),
        ("Skill scanner", detect::skills::SkillScanner::new().is_ok()),
    ];
    for (name, ok) in &checks {
        let status = if *ok { "PASS".green().bold() } else { "FAIL".red().bold() };
        println!("  [{}] {}", status, name);
    }
    println!();
}
