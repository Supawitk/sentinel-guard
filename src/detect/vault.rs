use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const VAULT_DIR: &str = ".sentinel-vault";
const VAULT_INDEX: &str = "vault-index.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultIndex {
    pub files: HashMap<String, VaultEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultEntry {
    pub original_path: String,
    pub vault_name: String,
    pub moved_at: String,
    pub size: u64,
}

fn vault_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sentinel-guard")
        .join(VAULT_DIR)
}

fn load_index() -> VaultIndex {
    let path = vault_dir().join(VAULT_INDEX);
    if path.exists() {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(index) = serde_json::from_str(&content) {
                return index;
            }
        }
    }
    VaultIndex { files: HashMap::new() }
}

fn save_index(index: &VaultIndex) -> Result<()> {
    let dir = vault_dir();
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(VAULT_INDEX), serde_json::to_string_pretty(index)?)?;
    Ok(())
}

/// Move a sensitive file to the vault
pub fn quarantine(file_path: &Path) -> Result<()> {
    if !file_path.exists() {
        anyhow::bail!("File not found: {}", file_path.display());
    }

    let dir = vault_dir();
    fs::create_dir_all(&dir)?;

    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
    let vault_name = format!("{}_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"), file_name);
    let vault_path = dir.join(&vault_name);

    let metadata = fs::metadata(file_path)?;
    fs::copy(file_path, &vault_path)?;
    fs::remove_file(file_path)?;

    let mut index = load_index();
    index.files.insert(
        vault_name.clone(),
        VaultEntry {
            original_path: file_path.to_string_lossy().to_string(),
            vault_name,
            moved_at: chrono::Utc::now().to_rfc3339(),
            size: metadata.len(),
        },
    );
    save_index(&index)?;

    println!(
        "  {} Quarantined: {} -> vault",
        "OK".green().bold(),
        file_path.display().to_string().white().bold()
    );
    Ok(())
}

/// Restore a file from the vault
pub fn restore(vault_name: &str) -> Result<()> {
    let mut index = load_index();
    let entry = match index.files.remove(vault_name) {
        Some(e) => e,
        None => anyhow::bail!("Not found in vault: {}", vault_name),
    };

    let vault_path = vault_dir().join(&entry.vault_name);
    if !vault_path.exists() {
        anyhow::bail!("Vault file missing: {}", vault_path.display());
    }

    let orig = PathBuf::from(&entry.original_path);
    if let Some(parent) = orig.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::copy(&vault_path, &orig)?;
    fs::remove_file(&vault_path)?;
    save_index(&index)?;

    println!(
        "  {} Restored: {} -> {}",
        "OK".green().bold(),
        vault_name,
        entry.original_path.white().bold()
    );
    Ok(())
}

/// Auto-quarantine: scan directory and move all sensitive files to vault
pub fn auto_quarantine(dir: &Path, patterns: &[String]) -> Result<u32> {
    let scanner = crate::detect::scanner::Scanner::new(patterns)?;
    let findings = scanner.scan_directory(dir, false);
    let mut count = 0;

    for finding in &findings {
        if finding.path.is_file() {
            match quarantine(&finding.path) {
                Ok(()) => count += 1,
                Err(e) => tracing::warn!("Failed to quarantine {}: {}", finding.path.display(), e),
            }
        }
    }
    Ok(count)
}

/// List all files in vault
pub fn list_vault() {
    let index = load_index();
    if index.files.is_empty() {
        println!("  {}", "Vault is empty.".dimmed());
        return;
    }

    println!("  {} ({} file(s))\n", "Vault Contents".white().bold(), index.files.len());
    for (name, entry) in &index.files {
        println!(
            "  {} {}",
            name.cyan(),
            format!("(from: {})", entry.original_path).dimmed()
        );
        println!(
            "        Size: {} bytes  |  Moved: {}",
            entry.size,
            entry.moved_at.split('T').next().unwrap_or(&entry.moved_at)
        );
    }
    println!("\n  Restore with: {}", "sentinel vault-restore <name>".yellow());
}
