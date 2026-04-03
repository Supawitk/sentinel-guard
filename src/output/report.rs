use crate::core::types::Finding;
use colored::Colorize;

pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("  {}", "No issues found.".green());
        return;
    }
    println!("\n{}", format!("  Found {} issue(s):\n", findings.len()).yellow().bold());
    for f in findings {
        let icon = match f.finding_type.as_str() {
            "SENSITIVE FILE" => "FILE".red().bold(),
            _ => "SECRET".red().bold(),
        };
        println!("  [{}] {}", icon, f.path.display().to_string().white().bold());
        println!("        {}", f.detail.dimmed());
        if let Some(line) = f.line_num {
            println!("        Line: {}", line);
        }
    }
    println!();
}

pub fn print_skill_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("  {}", "No suspicious patterns found.".green());
        return;
    }
    println!("\n{}", format!("  Found {} suspicious pattern(s):\n", findings.len()).yellow().bold());
    for f in findings {
        let sev = match f.severity {
            crate::core::types::Severity::Critical => f.severity.to_string().red().bold(),
            crate::core::types::Severity::High => f.severity.to_string().red(),
            _ => f.severity.to_string().yellow(),
        };
        println!("  [{}] {} (line {})", sev, f.finding_type.white().bold(), f.line_num.unwrap_or(0));
        println!("        File: {}", f.path.display().to_string().dimmed());
        println!("        Match: {}\n", f.detail.cyan());
    }
}

pub fn export_findings(findings: &[Finding], output: &str) -> anyhow::Result<()> {
    let is_csv = output.ends_with(".csv");
    let mut content = if is_csv {
        String::from("Type,Path,Detail,Severity\n")
    } else {
        String::from("Sentinel Guard - Security Report\n================================\n\n")
    };
    for f in findings {
        if is_csv {
            content.push_str(&format!("{},{},{},{}\n", f.finding_type, f.path.display(), f.detail.replace(',', ";"), f.severity));
        } else {
            content.push_str(&format!("[{}] {}\n  {}\n\n", f.finding_type, f.path.display(), f.detail));
        }
    }
    if findings.is_empty() { content.push_str("No issues found.\n"); }
    std::fs::write(output, &content)?;
    Ok(())
}

pub fn export_log(entries: &[crate::core::types::ActivityEntry], output: &str) -> anyhow::Result<()> {
    let is_csv = output.ends_with(".csv");
    let mut content = if is_csv {
        String::from("Timestamp,EventType,Path,Sensitive,Detail\n")
    } else {
        String::from("Sentinel Guard - Activity Log\n=============================\n\n")
    };
    for e in entries {
        if is_csv {
            content.push_str(&format!("{},{},{},{},{}\n", e.timestamp, e.event_type, e.path.replace(',', ";"), e.is_sensitive, e.detail.replace(',', ";")));
        } else {
            content.push_str(&format!("[{}] {} - {}\n  {}\n\n", e.timestamp, e.event_type, e.path, e.detail));
        }
    }
    std::fs::write(output, &content)?;
    Ok(())
}

pub fn print_integrity_changes(changes: &[crate::detect::integrity::IntegrityChange]) {
    if changes.is_empty() {
        println!("  {}", "All files intact. No changes.".green());
        return;
    }
    println!("\n{}", format!("  Found {} change(s):\n", changes.len()).yellow().bold());
    for c in changes {
        let icon = match c.change_type {
            crate::detect::integrity::ChangeType::Modified => "MODIFIED".yellow().bold(),
            crate::detect::integrity::ChangeType::Deleted => "DELETED".red().bold(),
            crate::detect::integrity::ChangeType::New => "NEW".cyan().bold(),
        };
        println!("  [{}] {}", icon, c.path.white().bold());
        if let Some(h) = &c.old_hash { println!("        Old: {}", h.dimmed()); }
        if let Some(h) = &c.new_hash { println!("        New: {}", h.dimmed()); }
        println!();
    }
}
