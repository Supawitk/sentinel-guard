use crate::core::types::{Finding, Severity};
use crate::detect::secrets;
use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

pub struct Scanner {
    sensitive_globs: GlobSet,
    secret_regexes: Vec<(Regex, String)>,
}

impl Scanner {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            builder.add(Glob::new(pattern)?);
        }
        Ok(Self {
            sensitive_globs: builder.build()?,
            secret_regexes: secrets::compile_patterns(),
        })
    }

    pub fn is_sensitive_path(&self, path: &Path) -> bool {
        self.sensitive_globs.is_match(path)
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
            if self.sensitive_globs.is_match(path) {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    finding_type: "SENSITIVE FILE".into(),
                    detail: "Matches sensitive file pattern".into(),
                    severity: Severity::High,
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
