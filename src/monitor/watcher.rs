use crate::core::config::Config;
use crate::core::db::ActivityDb;
use crate::core::types::Action;
use crate::monitor::rules::RulesEngine;
use crate::output::{alerts, notifier, webhook};
use anyhow::Result;
use notify_crate::{Event, EventKind, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;

// Rename to avoid clash with output::notifier
use notify as notify_crate;

pub fn watch(config: &Config) -> Result<()> {
    let scanner = crate::detect::scanner::Scanner::new(&config.protect.sensitive_patterns)?;
    let rules = RulesEngine::new(scanner, &config.alert.action);
    let alert_mgr = alerts::AlertManager::new(&config.alert.mode);
    let webhook_mgr = webhook::WebhookManager::new(&config.webhooks);
    let desktop = notifier::Notifier::new(config.alert.desktop_notifications);
    let mut agent_detector = crate::monitor::agents::AgentDetector::new();
    let db = ActivityDb::open(&config.db_path())?;

    // Show running AI agents at startup
    let agents = agent_detector.running_agents_str();
    tracing::info!("Active AI agents: {}", agents);

    let (tx, rx) = mpsc::channel::<notify_crate::Result<Event>>();
    let mut watcher = notify_crate::recommended_watcher(tx)?;

    let mode = if config.watch.recursive { RecursiveMode::Recursive } else { RecursiveMode::NonRecursive };

    for watch_path in &config.watch.paths {
        let path = Path::new(watch_path);
        if !path.exists() { tracing::warn!("Watch path does not exist: {}", watch_path); continue; }
        watcher.watch(path, mode)?;
        tracing::info!("Watching: {}", path.canonicalize()?.display());
    }

    println!("\n  {} Sentinel Guard is watching for file access...\n  Press Ctrl+C to stop.\n", colored::Colorize::green(">>>"));

    for event in rx {
        match event {
            Ok(event) => handle_event(&event, &rules, &alert_mgr, &webhook_mgr, &desktop, &mut agent_detector, &db),
            Err(e) => tracing::error!("Watch error: {}", e),
        }
    }
    Ok(())
}

fn handle_event(
    event: &Event,
    rules: &RulesEngine,
    alert_mgr: &alerts::AlertManager,
    webhook_mgr: &webhook::WebhookManager,
    desktop: &notifier::Notifier,
    agent_detector: &mut crate::monitor::agents::AgentDetector,
    db: &ActivityDb,
) {
    let event_type = match event.kind {
        EventKind::Access(_) => "access",
        EventKind::Create(_) => "create",
        EventKind::Modify(_) => "modify",
        EventKind::Remove(_) => "remove",
        EventKind::Any => "any",
        EventKind::Other => "other",
    };
    for path in &event.paths {
        let result = rules.evaluate(path, event_type);
        let is_sensitive = result.action != Action::Allow;
        let agents = if is_sensitive { agent_detector.running_agents_str() } else { String::new() };
        let detail = if agents.is_empty() || agents == "none detected" {
            result.reason.clone()
        } else {
            format!("{} [agents: {}]", result.reason, agents)
        };
        let _ = db.log_event(event_type, &path.to_string_lossy(), is_sensitive, &detail);
        if is_sensitive {
            alert_mgr.alert(path, event_type, &result);
            desktop.notify(path, event_type, &result);
            webhook_mgr.send_alert(event_type, &path.to_string_lossy(), &result.reason, is_sensitive);
        }
    }
}
