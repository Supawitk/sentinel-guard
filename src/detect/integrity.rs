use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

const HASH_DB_FILENAME: &str = ".sentinel-hashes.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct HashDatabase {
    pub created: String,
    pub updated: String,
    pub files: HashMap<String, FileHash>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileHash {
    pub hash: String,
    pub size: u64,
}

pub enum ChangeType { Modified, Deleted, New }

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Modified => write!(f, "MODIFIED"), Self::Deleted => write!(f, "DELETED"), Self::New => write!(f, "NEW") }
    }
}

pub struct IntegrityChange {
    pub path: String,
    pub change_type: ChangeType,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let mut h1: u64 = 0xcbf29ce484222325;
    let mut h2: u64 = 0x100000001b3;
    for &b in &buf {
        h1 ^= b as u64; h1 = h1.wrapping_mul(0x100000001b3);
        h2 ^= b as u64; h2 = h2.wrapping_mul(0xcbf29ce484222325);
    }
    Ok(format!("{:016x}{:016x}", h1, h2))
}

pub fn create_baseline(dir: &Path, patterns: &[String]) -> Result<HashDatabase> {
    let scanner = crate::detect::scanner::Scanner::new(patterns)?;
    let mut files = HashMap::new();
    for entry in walkdir::WalkDir::new(dir).follow_links(false).into_iter()
        .filter_entry(|e| !matches!(e.file_name().to_string_lossy().as_ref(), "node_modules" | ".git" | "target"))
        .flatten()
    {
        let path = entry.path();
        if path.is_file() && scanner.is_sensitive_path(path) {
            if let (Ok(h), Ok(m)) = (hash_file(path), fs::metadata(path)) {
                files.insert(path.to_string_lossy().to_string(), FileHash { hash: h, size: m.len() });
            }
        }
    }
    let now = chrono::Utc::now().to_rfc3339();
    Ok(HashDatabase { created: now.clone(), updated: now, files })
}

pub fn verify(dir: &Path, patterns: &[String]) -> Result<Vec<IntegrityChange>> {
    let hash_path = dir.join(HASH_DB_FILENAME);
    if !hash_path.exists() { anyhow::bail!("No baseline found. Run 'sentinel baseline' first."); }
    let baseline: HashDatabase = serde_json::from_str(&fs::read_to_string(&hash_path)?)?;
    let current = create_baseline(dir, patterns)?;
    let mut changes = Vec::new();
    for (path, old) in &baseline.files {
        match current.files.get(path) {
            Some(new) if old.hash != new.hash => changes.push(IntegrityChange { path: path.clone(), change_type: ChangeType::Modified, old_hash: Some(old.hash.clone()), new_hash: Some(new.hash.clone()) }),
            None => changes.push(IntegrityChange { path: path.clone(), change_type: ChangeType::Deleted, old_hash: Some(old.hash.clone()), new_hash: None }),
            _ => {}
        }
    }
    for path in current.files.keys() {
        if !baseline.files.contains_key(path) {
            changes.push(IntegrityChange { path: path.clone(), change_type: ChangeType::New, old_hash: None, new_hash: current.files.get(path).map(|h| h.hash.clone()) });
        }
    }
    Ok(changes)
}

pub fn save_baseline(dir: &Path, db: &HashDatabase) -> Result<()> {
    fs::write(dir.join(HASH_DB_FILENAME), serde_json::to_string_pretty(db)?)?;
    Ok(())
}
