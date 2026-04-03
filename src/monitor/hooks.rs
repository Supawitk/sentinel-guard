use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub tool_name: Option<String>,
    pub tool_input: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct HookOutput {
    pub decision: String,
    pub reason: Option<String>,
}

pub fn run_hook(config: &crate::core::config::Config) -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(h) => h,
        Err(_) => {
            let out = HookOutput { decision: "allow".into(), reason: None };
            println!("{}", serde_json::to_string(&out)?);
            return Ok(());
        }
    };

    let scanner = crate::detect::scanner::Scanner::new(&config.protect.sensitive_patterns)?;
    let file_path = extract_file_path(&hook_input);

    let decision = if let Some(path) = &file_path {
        if scanner.is_sensitive_path(&PathBuf::from(path)) {
            HookOutput { decision: "deny".into(), reason: Some(format!("Sentinel Guard: Access to '{}' blocked", path)) }
        } else {
            HookOutput { decision: "allow".into(), reason: None }
        }
    } else {
        HookOutput { decision: "allow".into(), reason: None }
    };

    if let Ok(db) = crate::core::db::ActivityDb::open(&config.db_path()) {
        let tool = hook_input.tool_name.as_deref().unwrap_or("unknown");
        let path_str = file_path.as_deref().unwrap_or("N/A");
        let _ = db.log_event(&format!("hook:{tool}"), path_str, decision.decision == "deny", decision.reason.as_deref().unwrap_or(""));
    }

    println!("{}", serde_json::to_string(&decision)?);
    Ok(())
}

fn extract_file_path(input: &HookInput) -> Option<String> {
    let tool_input = input.tool_input.as_ref()?;
    for field in &["file_path", "path", "filename", "file", "target"] {
        if let Some(s) = tool_input.get(field).and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }
    if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
        for s in &[".env", "id_rsa", ".ssh", ".aws", "wallet.dat", ".pem", "credentials"] {
            if cmd.contains(s) { return Some(s.to_string()); }
        }
    }
    None
}
