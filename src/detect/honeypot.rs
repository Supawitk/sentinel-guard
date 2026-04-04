use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

/// Fake sensitive files to plant as honeypots
const HONEYPOT_FILES: &[(&str, &str)] = &[
    (".env.production", "# DO NOT EDIT - Production Environment\nDATABASE_URL=postgres://admin:CHANGE_ME@prod-db:5432/app\nAPI_KEY=sk-fake-honeypot-sentinel-guard-trap\nSECRET_KEY=sentinel-honeypot-do-not-touch\n"),
    (".aws/credentials.bak", "[default]\naws_access_key_id = AKIAFAKEHONEYPOT00000\naws_secret_access_key = sentinel/honeypot/fake/key/do+not+use\n"),
    ("wallet-backup.dat", "# Sentinel Guard Honeypot\n# This is a fake wallet file used to detect unauthorized access.\n# If you see this content, an AI agent or malware accessed this file.\nFAKE_SEED=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n"),
    ("id_rsa.bak", "-----BEGIN FAKE RSA PRIVATE KEY-----\nThis is a Sentinel Guard honeypot file.\nAny access to this file is logged and flagged.\n-----END FAKE RSA PRIVATE KEY-----\n"),
];

/// Plant honeypot files in a directory
pub fn plant(dir: &Path, names: Option<Vec<String>>) -> Result<Vec<PathBuf>> {
    let mut planted = Vec::new();

    let files_to_plant: Vec<(&str, &str)> = match &names {
        Some(specific) => HONEYPOT_FILES
            .iter()
            .filter(|(name, _)| specific.iter().any(|s| name.contains(s.as_str())))
            .copied()
            .collect(),
        None => HONEYPOT_FILES.to_vec(),
    };

    for (name, content) in &files_to_plant {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        if path.exists() {
            println!("  {} Skipped (exists): {}", "!".yellow().bold(), path.display());
            continue;
        }

        fs::write(&path, content)?;

        // Make read-only to look more "real"
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        }

        #[cfg(windows)]
        {
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_readonly(true);
            fs::set_permissions(&path, perms)?;
        }

        println!(
            "  {} Planted honeypot: {}",
            "OK".green().bold(),
            path.display().to_string().cyan()
        );
        planted.push(path);
    }

    if planted.is_empty() {
        println!("  {}", "No new honeypots planted (all already exist).".dimmed());
    } else {
        println!(
            "\n  Planted {} honeypot(s). Any access will trigger an alert.",
            planted.len().to_string().green().bold()
        );
    }

    Ok(planted)
}

/// Remove all honeypot files from a directory
pub fn cleanup(dir: &Path) -> Result<u32> {
    let mut count = 0;
    for (name, _) in HONEYPOT_FILES {
        let path = dir.join(name);
        if path.exists() {
            // Remove read-only first
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_readonly(false);
            fs::set_permissions(&path, perms)?;

            fs::remove_file(&path)?;
            println!("  {} Removed: {}", "OK".green().bold(), path.display());
            count += 1;
        }
    }
    if count == 0 {
        println!("  {}", "No honeypots found to remove.".dimmed());
    }
    Ok(count)
}

/// List available honeypot templates
#[allow(dead_code)]
pub fn list_templates() {
    println!("  {}\n", "Available Honeypot Templates:".white().bold());
    for (name, _) in HONEYPOT_FILES {
        println!("  - {}", name.cyan());
    }
    println!("\n  Plant with: {}", "sentinel honeypot .".yellow());
}
