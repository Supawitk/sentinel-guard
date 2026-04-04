use crate::core::types::WebhookConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub watch: WatchConfig,
    pub protect: ProtectConfig,
    pub alert: AlertConfig,
    pub log: LogConfig,
    #[serde(default)]
    pub webhooks: WebhookConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    pub paths: Vec<String>,
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectConfig {
    pub sensitive_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub mode: String,
    pub action: String,
    #[serde(default)]
    pub desktop_notifications: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub db_path: String,
    pub retention_days: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            watch: WatchConfig {
                paths: vec![".".to_string()],
                recursive: true,
            },
            protect: ProtectConfig {
                sensitive_patterns: vec![
                    // Environment & config
                    "**/.env", "**/.env.*",
                    // Certificates & keys
                    "**/*.pem", "**/*.key", "**/*.pfx", "**/*.p12", "**/*.jks",
                    // SSH
                    "**/id_rsa", "**/id_ed25519", "**/.ssh/*",
                    // Credentials
                    "**/credentials*", "**/secrets*",
                    // Cloud
                    "**/.aws/*", "**/.gcloud/*",
                    // Package managers
                    "**/.npmrc", "**/.pypirc", "**/.netrc",
                    // Web
                    "**/wp-config.php", "**/.htpasswd",
                    // Crypto wallets
                    "**/wallet.dat", "**/*.wallet", "**/keystore/*",
                    "**/.ethereum/keystore/*", "**/.bitcoin/wallet.dat",
                    "**/.solana/id.json", "**/.solana/*.json",
                    "**/seed.txt", "**/mnemonic*", "**/recovery*phrase*",
                    // AI agent files
                    "**/.openclaw/secrets*", "**/.openclaw/*.json",
                    "**/MEMORY.md", "**/SOUL.md",
                    // Misc
                    "**/token*",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
            },
            alert: AlertConfig {
                mode: "all".to_string(),
                action: "warn".to_string(),
                desktop_notifications: false,
            },
            log: LogConfig {
                db_path: default_db_path(),
                retention_days: 30,
            },
            webhooks: WebhookConfig::default(),
        }
    }
}

fn default_db_path() -> String {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sentinel-guard")
        .join("activity.db")
        .to_string_lossy()
        .to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_or_default(path: Option<&Path>) -> Self {
        match path {
            Some(p) if p.exists() => Self::load(p).unwrap_or_default(),
            _ => {
                let candidates = [
                    PathBuf::from("sentinel.toml"),
                    PathBuf::from(".sentinel.toml"),
                    dirs::config_dir()
                        .unwrap_or_default()
                        .join("sentinel-guard")
                        .join("config.toml"),
                ];
                for candidate in &candidates {
                    if candidate.exists() {
                        if let Ok(config) = Self::load(candidate) {
                            tracing::info!("Loaded config from {}", candidate.display());
                            return config;
                        }
                    }
                }
                Self::default()
            }
        }
    }

    pub fn save_default(path: &Path) -> Result<()> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn db_path(&self) -> PathBuf {
        let expanded = shellexpand_simple(&self.log.db_path);
        PathBuf::from(expanded)
    }
}

fn shellexpand_simple(path: &str) -> String {
    if path.starts_with("~/") || path.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    path.to_string()
}
