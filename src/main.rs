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

#[derive(Subcommand)]
enum Commands {
    // ── Setup ───────────────────────────────
    /// Generate default config file
    Init { #[arg(default_value = "sentinel.toml")] path: String },

    // ── Scanning ────────────────────────────
    /// Scan for sensitive files and secrets
    Scan {
        #[arg(default_value = ".")] path: String,
        /// Deep scan file contents for secrets
        #[arg(short = 'd', long)] deep: bool,
    },
    /// Scan AI agent skills for malicious patterns
    SkillScan {
        #[arg(default_value = ".")] path: String,
        #[arg(short, long)] file: Option<String>,
    },

    // ── Monitoring ──────────────────────────
    /// Watch directories for file access in real-time
    Watch {
        #[arg(default_value = ".")] paths: Vec<String>,
    },
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

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            print_banner();
            println!("  {}\n", "Commands:".white().bold());
            println!("  {}   sentinel init              Generate config file", "Setup".cyan());
            println!("  {}   sentinel check             Verify installation", "     ".cyan());
            println!("  {} sentinel scan . --deep      Find secrets in files", "Scan ".cyan());
            println!("  {}   sentinel skill-scan .       Scan AI agent skills", "     ".cyan());
            println!("  {} sentinel watch .             Real-time monitoring", "Watch".cyan());
            println!("  {}   sentinel hook               AI agent hook mode", "     ".cyan());
            println!("  {} sentinel baseline .          Hash sensitive files", "Guard".cyan());
            println!("  {}   sentinel verify .            Check for changes", "     ".cyan());
            println!("  {}  sentinel log                 View activity log", "View ".cyan());
            println!("  {}   sentinel stats               Event statistics", "     ".cyan());
            println!("  {}   sentinel dashboard            TUI dashboard", "     ".cyan());
            println!("  {}   sentinel report . -o x.csv   Export report", "     ".cyan());
            println!();
            println!("  Run {} for more details on any command.", "sentinel <command> --help".yellow());
            println!();

            // If launched by double-click, wait for Enter so window doesn't close
            if atty::is(atty::Stream::Stdin) {
                print!("  Press Enter to exit...");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut buf = String::new();
                std::io::stdin().read_line(&mut buf)?;
            }
            return Ok(());
        }
    };

    // Skip banner for hook mode and check mode
    if !matches!(command, Commands::Hook | Commands::Check) {
        print_banner();
    }

    match command {
        // ── Setup ─────────────────────
        Commands::Init { path } => {
            let p = PathBuf::from(&path);
            if p.exists() {
                println!("  {} Config already exists: {}", "!".yellow().bold(), p.display());
            } else {
                core::config::Config::save_default(&p)?;
                println!("  {} Created: {}", "OK".green().bold(), p.display());
            }
        }

        // ── Scanning ──────────────────
        Commands::Scan { path, deep } => {
            let config = load_config(&cli.config);
            let scanner = detect::scanner::Scanner::new(&config.protect.sensitive_patterns)?;
            println!("  Scanning {} {}...\n", path.white().bold(), if deep { "(deep)" } else { "(patterns only)" });
            let findings = scanner.scan_directory(&PathBuf::from(&path), deep);
            output::report::print_findings(&findings);
            log_findings(&config, &findings);
        }

        Commands::SkillScan { path, file } => {
            let skill_scanner = detect::skills::SkillScanner::new()?;
            if let Some(f) = file {
                println!("  Scanning skill file: {}\n", f.white().bold());
                output::report::print_skill_findings(&skill_scanner.scan_file(&PathBuf::from(&f)));
            } else {
                println!("  Scanning for AI agent skills in: {}\n", path.white().bold());
                output::report::print_skill_findings(&skill_scanner.scan_directory(&PathBuf::from(&path)));
            }
        }

        // ── Monitoring ────────────────
        Commands::Watch { paths } => {
            let mut config = load_config(&cli.config);
            if !paths.is_empty() && paths[0] != "." { config.watch.paths = paths; }
            monitor::watcher::watch(&config)?;
        }

        Commands::Hook => {
            let config = load_config(&cli.config);
            monitor::hooks::run_hook(&config)?;
            return Ok(());
        }

        // ── Integrity ─────────────────
        Commands::Baseline { path } => {
            let config = load_config(&cli.config);
            let dir = PathBuf::from(&path);
            println!("  Creating baseline in {}...\n", path.white().bold());
            let db = detect::integrity::create_baseline(&dir, &config.protect.sensitive_patterns)?;
            let count = db.files.len();
            detect::integrity::save_baseline(&dir, &db)?;
            println!("  {} Baseline: {} file(s) hashed", "OK".green().bold(), count);
        }

        Commands::Verify { path } => {
            let config = load_config(&cli.config);
            let dir = PathBuf::from(&path);
            println!("  Verifying integrity in {}...\n", path.white().bold());
            let changes = detect::integrity::verify(&dir, &config.protect.sensitive_patterns)?;
            output::report::print_integrity_changes(&changes);
        }

        // ── Reporting ─────────────────
        Commands::Log { limit, sensitive } => {
            let config = load_config(&cli.config);
            let db = core::db::ActivityDb::open(&config.db_path())?;
            let entries = if sensitive { db.get_sensitive_only(limit)? } else { db.get_recent(limit)? };
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
            let config = load_config(&cli.config);
            let db = core::db::ActivityDb::open(&config.db_path())?;
            let (total, sensitive, today) = db.get_stats()?;
            println!("  {}\n", "Statistics".white().bold());
            println!("  Total events:     {}", total.to_string().cyan());
            println!("  Sensitive events: {}", sensitive.to_string().red().bold());
            println!("  Events today:     {}", today.to_string().green());
            println!("  Database:         {}", config.db_path().display().to_string().dimmed());
        }

        Commands::Dashboard => {
            let config = load_config(&cli.config);
            output::dashboard::run(&config)?;
            return Ok(());
        }

        Commands::Report { path, output: out, report_type, deep } => {
            let config = load_config(&cli.config);
            match report_type.as_str() {
                "scan" => {
                    let scanner = detect::scanner::Scanner::new(&config.protect.sensitive_patterns)?;
                    let findings = scanner.scan_directory(&PathBuf::from(&path), deep);
                    output::report::export_findings(&findings, &out)?;
                    println!("  {} Exported {} findings to {}", "OK".green().bold(), findings.len(), out.white().bold());
                }
                "log" => {
                    let db = core::db::ActivityDb::open(&config.db_path())?;
                    let entries = db.get_sensitive_only(10000)?;
                    output::report::export_log(&entries, &out)?;
                    println!("  {} Exported {} entries to {}", "OK".green().bold(), entries.len(), out.white().bold());
                }
                _ => println!("  {} Unknown report type. Use 'scan' or 'log'.", "!".yellow().bold()),
            }
        }

        // ── Maintenance ───────────────
        Commands::Cleanup { days } => {
            let config = load_config(&cli.config);
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
