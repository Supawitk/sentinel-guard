use crate::core::types::RuleResult;
use std::path::Path;

pub struct Notifier { enabled: bool }

impl Notifier {
    pub fn new(enabled: bool) -> Self { Self { enabled } }

    pub fn notify(&self, path: &Path, event_type: &str, _result: &RuleResult) {
        if !self.enabled { return; }
        let title = format!("Sentinel Guard - {}", event_type.to_uppercase());
        let body = format!("Sensitive file access: {}", path.display());
        let _ = self.send(&title, &body);
    }

    #[cfg(target_os = "windows")]
    fn send(&self, title: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        let script = format!(
            r#"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(0); $n = $t.GetElementsByTagName("text"); $n.Item(0).AppendChild($t.CreateTextNode("{}")) > $null; $n.Item(1).AppendChild($t.CreateTextNode("{}")) > $null; [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Sentinel Guard").Show([Windows.UI.Notifications.ToastNotification]::new($t))"#,
            title.replace('"', "'"), body.replace('"', "'")
        );
        std::process::Command::new("powershell").args(["-Command", &script]).output()?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn send(&self, title: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        std::process::Command::new("osascript").args(["-e", &format!(r#"display notification "{}" with title "{}""#, body.replace('"', "'"), title.replace('"', "'"))]).output()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn send(&self, title: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        std::process::Command::new("notify-send").args(["--urgency", "critical", title, body]).output()?;
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    fn send(&self, _: &str, _: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
}
