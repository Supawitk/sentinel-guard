use crate::core::types::{Finding, Severity};
use crate::detect::secrets;
use anyhow::Result;
use globset::Glob;
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

/// A sensitive pattern with its category label
struct LabeledPattern {
    glob: globset::GlobMatcher,
    pattern: String,
    category: &'static str,
}

/// Maps a glob pattern to a human-readable category
fn categorize(pattern: &str) -> &'static str {
    match pattern {
        p if p.contains(".env") => "Environment file — may contain API keys, DB passwords, secrets",
        p if p.contains(".pem") => "PEM certificate/key — private key or SSL certificate",
        p if p.contains(".key") && !p.contains("keystore") => "Private key file",
        p if p.contains(".pfx") || p.contains(".p12") => "PKCS#12 certificate bundle (contains private key)",
        p if p.contains(".jks") => "Java KeyStore — contains certificates and private keys",
        p if p.contains("id_rsa") => "SSH private key (RSA) — grants server access",
        p if p.contains("id_ed25519") => "SSH private key (Ed25519) — grants server access",
        p if p.contains(".ssh") => "SSH config/known hosts — contains server connection data",
        p if p.contains("credentials") => "Credentials file — likely contains passwords or tokens",
        p if p.contains("secrets") && !p.contains("openclaw") => "Secrets file — contains sensitive configuration",
        p if p.contains(".aws") => "AWS credentials/config — contains access keys for cloud services",
        p if p.contains(".gcloud") => "Google Cloud config — contains service account credentials",
        p if p.contains(".npmrc") => "npm config — may contain registry auth tokens",
        p if p.contains(".pypirc") => "PyPI config — contains package registry credentials",
        p if p.contains(".netrc") => "Netrc file — contains login credentials for remote hosts",
        p if p.contains("wp-config") => "WordPress config — contains database password and auth keys",
        p if p.contains(".htpasswd") => "Apache password file — contains hashed user credentials",
        p if p.contains("wallet.dat") => "Bitcoin wallet file — contains private keys and funds",
        p if p.contains(".wallet") => "Cryptocurrency wallet file",
        p if p.contains("keystore") => "Crypto keystore — contains encrypted private keys",
        p if p.contains(".ethereum") => "Ethereum keystore — contains encrypted wallet keys",
        p if p.contains(".bitcoin") => "Bitcoin wallet data",
        p if p.contains(".solana") => "Solana keypair — contains wallet private key",
        p if p.contains("seed.txt") => "Seed phrase file — wallet recovery words (critical!)",
        p if p.contains("mnemonic") => "Mnemonic/seed phrase — wallet recovery words (critical!)",
        p if p.contains("recovery") => "Recovery phrase file — wallet backup words",
        p if p.contains(".openclaw") => "OpenClaw agent config — may contain API keys and tokens",
        p if p.contains("MEMORY.md") => "AI agent memory file — contains conversation/context data",
        p if p.contains("SOUL.md") => "AI agent personality file — contains system prompts",
        p if p.contains("token") => "Token file — may contain auth/API tokens",
        _ => "Sensitive file",
    }
}

pub struct Scanner {
    patterns: Vec<LabeledPattern>,
    glob_set: globset::GlobSet, // fast check for is_sensitive_path
    secret_regexes: Vec<(Regex, String)>,
}

impl Scanner {
    pub fn new(raw_patterns: &[String]) -> Result<Self> {
        let mut patterns = Vec::new();
        let mut builder = globset::GlobSetBuilder::new();

        for pat in raw_patterns {
            let glob = Glob::new(pat)?.compile_matcher();
            builder.add(Glob::new(pat)?);
            patterns.push(LabeledPattern {
                glob,
                pattern: pat.clone(),
                category: categorize(pat),
            });
        }

        Ok(Self {
            patterns,
            glob_set: builder.build()?,
            secret_regexes: secrets::compile_patterns(),
        })
    }

    pub fn is_sensitive_path(&self, path: &Path) -> bool {
        self.glob_set.is_match(path)
    }

    /// Get the category for a path (first matching pattern)
    fn describe_match(&self, path: &Path) -> (String, &str) {
        for lp in &self.patterns {
            if lp.glob.is_match(path) {
                return (lp.pattern.clone(), lp.category);
            }
        }
        (String::new(), "Sensitive file")
    }

    pub fn scan_directory(&self, dir: &Path, check_content: bool) -> Vec<Finding> {
        let mut findings = Vec::new();
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !matches!(name.as_ref(), "node_modules" | ".git" | "target" | "__pycache__" | ".venv" | "venv")
            })
            .flatten()
        {
            let path = entry.path();

            if self.glob_set.is_match(path) {
                let (matched_pattern, category) = self.describe_match(path);
                findings.push(Finding {
                    path: path.to_path_buf(),
                    finding_type: "SENSITIVE FILE".into(),
                    detail: format!("{} (pattern: {})", category, matched_pattern),
                    severity: if category.contains("critical") || category.contains("private key") || category.contains("wallet") || category.contains("seed") || category.contains("mnemonic") {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    line_num: None,
                });
            }

            if check_content && path.is_file() {
                if let Ok(meta) = path.metadata() {
                    if meta.len() > 1_048_576 { continue; }
                }
                if let Ok(content) = std::fs::read_to_string(path) {
                    for (regex, name) in &self.secret_regexes {
                        if regex.is_match(&content) {
                            findings.push(Finding {
                                path: path.to_path_buf(),
                                finding_type: "SECRET FOUND".into(),
                                detail: format!("{name} detected in file content"),
                                severity: Severity::Critical,
                                line_num: None,
                            });
                        }
                    }
                }
            }
        }
        findings
    }
}
