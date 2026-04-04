use sysinfo::System;
use std::collections::HashSet;

/// Known AI agent process names (lowercase for matching)
const KNOWN_AGENTS: &[(&str, &str)] = &[
    ("claude", "Claude Code"),
    ("claude-code", "Claude Code"),
    ("cursor", "Cursor"),
    ("code", "VS Code (Copilot)"),
    ("code - insiders", "VS Code Insiders (Copilot)"),
    ("openclaw", "OpenClaw"),
    ("windsurf", "Windsurf"),
    ("copilot-agent", "GitHub Copilot"),
    ("copilot", "GitHub Copilot"),
    ("cody", "Sourcegraph Cody"),
    ("aider", "Aider"),
    ("continue", "Continue.dev"),
    ("codex", "OpenAI Codex"),
    ("gemini", "Google Gemini"),
];

pub struct AgentDetector {
    sys: System,
}

#[derive(Debug, Clone)]
pub struct DetectedAgent {
    pub name: String,
    pub process_name: String,
    pub pid: u32,
}

impl AgentDetector {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        Self { sys }
    }

    /// Refresh process list and return currently running AI agents
    pub fn detect(&mut self) -> Vec<DetectedAgent> {
        self.sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let mut seen = HashSet::new();
        let mut agents = Vec::new();

        for (pid, process) in self.sys.processes() {
            let proc_name = process.name().to_string_lossy().to_lowercase();
            let proc_name_no_ext = proc_name.trim_end_matches(".exe");

            for &(pattern, display_name) in KNOWN_AGENTS {
                if proc_name_no_ext == pattern && seen.insert(display_name.to_string()) {
                    agents.push(DetectedAgent {
                        name: display_name.to_string(),
                        process_name: process.name().to_string_lossy().to_string(),
                        pid: pid.as_u32(),
                    });
                }
            }
        }
        agents
    }

    /// Get a formatted string of running agents for logging
    pub fn running_agents_str(&mut self) -> String {
        let agents = self.detect();
        if agents.is_empty() {
            "none detected".to_string()
        } else {
            agents.iter().map(|a| format!("{}({})", a.name, a.pid)).collect::<Vec<_>>().join(", ")
        }
    }
}
