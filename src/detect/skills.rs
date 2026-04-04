use crate::core::types::{Finding, Severity};
use anyhow::Result;
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

const MALICIOUS_PATTERNS: &[(&str, &str, &str)] = &[
    // Data exfiltration
    (r#"curl\s+.*(-d|--data|--upload-file|POST)"#, "Data Exfiltration (curl)", "critical"),
    (r#"curl.*\|\s*bash"#, "Remote Code Execution (curl|bash)", "critical"),
    (r#"wget.*\|\s*bash"#, "Remote Code Execution (wget|bash)", "critical"),
    (r"eval\s*\(", "Dynamic Code Execution (eval)", "high"),
    (r"os\.system\s*\(", "System Command Execution", "high"),
    // File access
    (r"~/.ssh", "SSH Key Access", "high"),
    (r"~/.aws", "AWS Credentials Access", "high"),
    (r"wallet\.dat", "Crypto Wallet Access", "critical"),
    (r"seed\.txt", "Seed Phrase File Access", "critical"),
    (r"private.?key", "Private Key Access", "high"),
    // Network
    (r"ngrok", "Reverse Tunnel (ngrok)", "high"),
    (r"webhook\.(site|cc)", "Suspicious Webhook Service", "high"),
    (r"pastebin\.com", "Data Exfil via Pastebin", "medium"),
    // Obfuscation
    (r"base64\s+(encode|decode|-d)", "Base64 Encoding/Decoding", "medium"),
    (r"send_telemetry", "Fake Telemetry Function", "high"),
    // Persistence
    (r"crontab", "Cron Job Modification", "high"),
    (r"registry.*run", "Windows Registry Run Key", "high"),
    // Credential harvesting
    (r"password.*prompt", "Password Prompt (social engineering)", "high"),
    (r"chrome.*cookies", "Browser Cookie Access", "critical"),
    (r"firefox.*cookies", "Browser Cookie Access", "critical"),
    (r"Login\s*Data", "Browser Login Data Access", "critical"),
];

pub struct SkillScanner {
    patterns: Vec<(Regex, String, Severity)>,
}

impl SkillScanner {
    pub fn new() -> Result<Self> {
        let patterns = MALICIOUS_PATTERNS
            .iter()
            .filter_map(|(pat, name, sev)| {
                let severity = match *sev {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    _ => Severity::Medium,
                };
                Regex::new(pat).ok().map(|r| (r, name.to_string(), severity))
            })
            .collect();
        Ok(Self { patterns })
    }

    pub fn scan_file(&self, path: &Path) -> Vec<Finding> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut findings = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            for (regex, name, severity) in &self.patterns {
                if let Some(mat) = regex.find(line) {
                    findings.push(Finding {
                        path: path.to_path_buf(),
                        finding_type: name.clone(),
                        detail: mat.as_str().to_string(),
                        severity: severity.clone(),
                        line_num: Some(line_num + 1),
                    });
                }
            }
        }
        findings
    }

    pub fn scan_directory(&self, dir: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !matches!(name.as_ref(), "node_modules" | ".git" | "target")
            })
            .flatten()
        {
            let path = entry.path();
            if !path.is_file() { continue; }
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            if name == "skill.md" || name.ends_with(".skill") || name == "openclaw.json"
                || (name.ends_with(".md") && path.parent().map(|p| p.to_string_lossy().contains("skill")).unwrap_or(false))
            {
                findings.extend(self.scan_file(path));
            }
        }
        findings
    }
}
