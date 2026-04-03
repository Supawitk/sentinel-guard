use crate::core::types::WebhookConfig;
use serde::Serialize;

#[derive(Serialize)] struct SlackPayload { text: String, username: String }
#[derive(Serialize)] struct DiscordPayload { content: String, username: String }
#[derive(Serialize)] struct GenericPayload { tool: String, event_type: String, path: String, detail: String, timestamp: String }

pub struct WebhookManager {
    config: WebhookConfig,
    client: ureq::Agent,
}

impl WebhookManager {
    pub fn new(config: &WebhookConfig) -> Self {
        Self { config: config.clone(), client: ureq::Agent::new_with_defaults() }
    }

    pub fn send_alert(&self, event_type: &str, path: &str, detail: &str, is_sensitive: bool) {
        if !is_sensitive { return; }
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        for ep in self.config.endpoints.iter().filter(|e| e.enabled) {
            let result = match ep.format.as_str() {
                "slack" => self.client.post(&ep.url).send_json(&SlackPayload {
                    text: format!(":warning: *Sentinel Guard*\n`{}` `{}` {}", event_type, path, detail),
                    username: "Sentinel Guard".into(),
                }),
                "discord" => self.client.post(&ep.url).send_json(&DiscordPayload {
                    content: format!("**Sentinel Guard** `{}` `{}` {}", event_type, path, detail),
                    username: "Sentinel Guard".into(),
                }),
                _ => self.client.post(&ep.url).send_json(&GenericPayload {
                    tool: "sentinel-guard".into(), event_type: event_type.into(),
                    path: path.into(), detail: detail.into(), timestamp: ts.clone(),
                }),
            };
            if let Err(e) = result { tracing::error!("Webhook '{}' failed: {}", ep.name, e); }
        }
    }
}
