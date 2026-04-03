use crate::core::types::{Action, RuleResult};
use crate::detect::scanner::Scanner;
use std::path::Path;

pub struct RulesEngine {
    scanner: Scanner,
    default_action: Action,
}

impl RulesEngine {
    pub fn new(scanner: Scanner, default_action_str: &str) -> Self {
        let default_action = match default_action_str {
            "block" => Action::Block,
            "warn" => Action::Warn,
            _ => Action::Allow,
        };
        Self { scanner, default_action }
    }

    pub fn evaluate(&self, path: &Path, event_type: &str) -> RuleResult {
        if self.scanner.is_sensitive_path(path) {
            return RuleResult {
                action: self.default_action.clone(),
                reason: format!("'{}' matches sensitive pattern (event: {})", path.display(), event_type),
            };
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "pem" | "key" | "pfx" | "p12" | "jks" | "keystore") {
                return RuleResult {
                    action: self.default_action.clone(),
                    reason: format!("'{}' has sensitive extension .{} (event: {})", path.display(), ext, event_type),
                };
            }
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_lowercase();
            let sensitive = [".env", "id_rsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc",
                ".htpasswd", "wp-config.php", "credentials", "wallet.dat", "seed.txt"];
            if sensitive.iter().any(|s| lower == *s || lower.starts_with(s)) {
                return RuleResult {
                    action: self.default_action.clone(),
                    reason: format!("'{}' is a known sensitive filename (event: {})", path.display(), event_type),
                };
            }
        }
        RuleResult { action: Action::Allow, reason: String::new() }
    }
}
