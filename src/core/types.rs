use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity levels for findings
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    #[allow(dead_code)]
    Low,
    #[allow(dead_code)]
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Rule evaluation result
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Warn,
    Block,
}

#[derive(Debug)]
pub struct RuleResult {
    pub action: Action,
    pub reason: String,
}

/// A single finding from any scanner
#[derive(Debug, Clone)]
pub struct Finding {
    pub path: PathBuf,
    pub finding_type: String,
    pub detail: String,
    pub severity: Severity,
    pub line_num: Option<usize>,
}

/// Activity log entry from database
#[derive(Debug, Clone)]
pub struct ActivityEntry {
    #[allow(dead_code)]
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub path: String,
    pub is_sensitive: bool,
    pub detail: String,
}

/// Webhook endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub name: String,
    pub url: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub enabled: bool,
}

fn default_format() -> String {
    "generic".to_string()
}

/// Webhook config section
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebhookConfig {
    #[serde(default)]
    pub endpoints: Vec<WebhookEndpoint>,
}
