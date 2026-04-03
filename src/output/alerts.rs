use crate::core::types::{Action, RuleResult};
use colored::Colorize;
use std::path::Path;

pub struct AlertManager {
    mode: AlertMode,
}

enum AlertMode { Log, Terminal, All }

impl AlertManager {
    pub fn new(mode_str: &str) -> Self {
        let mode = match mode_str {
            "log" => AlertMode::Log,
            "terminal" => AlertMode::Terminal,
            _ => AlertMode::All,
        };
        Self { mode }
    }

    pub fn alert(&self, path: &Path, event_type: &str, result: &RuleResult) {
        match self.mode {
            AlertMode::Log => self.log_alert(path, event_type, result),
            AlertMode::Terminal => self.terminal_alert(path, event_type, result),
            AlertMode::All => { self.log_alert(path, event_type, result); self.terminal_alert(path, event_type, result); }
        }
    }

    fn log_alert(&self, path: &Path, event_type: &str, result: &RuleResult) {
        match result.action {
            Action::Block => tracing::error!("BLOCKED: {} on {} - {}", event_type, path.display(), result.reason),
            Action::Warn => tracing::warn!("WARNING: {} on {} - {}", event_type, path.display(), result.reason),
            Action::Allow => tracing::debug!("{} on {}", event_type, path.display()),
        }
    }

    fn terminal_alert(&self, path: &Path, event_type: &str, result: &RuleResult) {
        let ts = chrono::Local::now().format("%H:%M:%S");
        match result.action {
            Action::Block => {
                eprintln!("  {} [{}] {} {} {}", format!("[{ts}]").dimmed(), "BLOCKED".red().bold(), event_type.yellow(), "->".dimmed(), path.display().to_string().white().bold());
                eprintln!("           {}", result.reason.red());
            }
            Action::Warn => {
                eprintln!("  {} [{}] {} {} {}", format!("[{ts}]").dimmed(), "WARNING".yellow().bold(), event_type.cyan(), "->".dimmed(), path.display().to_string().white().bold());
                eprintln!("           {}", result.reason.yellow());
            }
            Action::Allow => {}
        }
    }
}
