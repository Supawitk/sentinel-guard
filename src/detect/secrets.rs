use regex::Regex;

/// Secret detection patterns with categories
pub const SECRET_PATTERNS: &[(&str, &str)] = &[
    // API Keys
    (r#"(?i)api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}"#, "API Key"),
    (r#"(?i)secret[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}"#, "Secret Key"),
    (r#"(?i)password\s*[:=]\s*['"]?[^\s'"]{8,}"#, "Password"),
    (r#"(?i)token\s*[:=]\s*['"]?[a-zA-Z0-9_\-\.]{20,}"#, "Token"),
    // Cloud providers
    (r#"(?i)aws_access_key_id\s*[:=]\s*['"]?AKIA[A-Z0-9]{16}"#, "AWS Access Key"),
    (r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?[a-zA-Z0-9/+=]{40}"#, "AWS Secret Key"),
    // AI services
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI/Stripe Secret Key"),
    (r"sk-ant-[a-zA-Z0-9\-]{20,}", "Anthropic API Key"),
    // Source control
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
    (r"glpat-[a-zA-Z0-9\-]{20,}", "GitLab Personal Access Token"),
    // Chat platforms
    (r"xoxb-[0-9]{10,}-[a-zA-Z0-9]+", "Slack Bot Token"),
    (r"xoxp-[0-9]{10,}-[a-zA-Z0-9]+", "Slack User Token"),
    // Certificates
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate"),
    // Database connections
    (r#"(?i)mongodb\+srv://[^\s]+"#, "MongoDB Connection String"),
    (r#"(?i)postgres://[^\s]+"#, "PostgreSQL Connection String"),
    (r#"(?i)mysql://[^\s]+"#, "MySQL Connection String"),
    (r#"(?i)redis://[^\s]+"#, "Redis Connection String"),
    // Firebase
    (r"AAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{140,}", "Firebase Cloud Messaging Key"),
    // Crypto
    (r"5[HJK][1-9A-HJ-NP-Za-km-z]{49}", "Bitcoin WIF Private Key"),
    (r#"(?i)(?:private.?key|secret)\s*[:=]\s*['"]?[0-9a-fA-F]{64}"#, "Hex Private Key (ETH/BTC)"),
    (r#"(?i)mnemonic\s*[:=]\s*['"]?[a-z]+"#, "Mnemonic/Seed Phrase Reference"),
    (r"xprv[a-zA-Z0-9]{100,}", "Extended Private Key (xprv)"),
    (r"xpub[a-zA-Z0-9]{100,}", "Extended Public Key (xpub)"),
];

pub fn compile_patterns() -> Vec<(Regex, String)> {
    SECRET_PATTERNS
        .iter()
        .filter_map(|(pattern, name)| {
            Regex::new(pattern).ok().map(|r| (r, name.to_string()))
        })
        .collect()
}
