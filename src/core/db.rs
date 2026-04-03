use crate::core::types::ActivityEntry;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;

pub struct ActivityDb {
    conn: Connection,
}

impl ActivityDb {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                is_sensitive INTEGER NOT NULL DEFAULT 0,
                detail TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity(timestamp);
            CREATE INDEX IF NOT EXISTS idx_activity_path ON activity(path);
            CREATE INDEX IF NOT EXISTS idx_activity_sensitive ON activity(is_sensitive);",
        )?;
        Ok(Self { conn })
    }

    pub fn log_event(&self, event_type: &str, path: &str, is_sensitive: bool, detail: &str) -> Result<()> {
        let now: DateTime<Utc> = Utc::now();
        self.conn.execute(
            "INSERT INTO activity (timestamp, event_type, path, is_sensitive, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now.to_rfc3339(), event_type, path, is_sensitive as i32, detail],
        )?;
        Ok(())
    }

    pub fn get_recent(&self, limit: u32) -> Result<Vec<ActivityEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, path, is_sensitive, detail FROM activity ORDER BY id DESC LIMIT ?1",
        )?;
        let entries = stmt.query_map(params![limit], |row| {
            Ok(ActivityEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event_type: row.get(2)?,
                path: row.get(3)?,
                is_sensitive: row.get::<_, i32>(4)? != 0,
                detail: row.get(5)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    pub fn get_sensitive_only(&self, limit: u32) -> Result<Vec<ActivityEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, path, is_sensitive, detail FROM activity WHERE is_sensitive = 1 ORDER BY id DESC LIMIT ?1",
        )?;
        let entries = stmt.query_map(params![limit], |row| {
            Ok(ActivityEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event_type: row.get(2)?,
                path: row.get(3)?,
                is_sensitive: row.get::<_, i32>(4)? != 0,
                detail: row.get(5)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    pub fn get_stats(&self) -> Result<(u64, u64, u64)> {
        let total: u64 = self.conn.query_row("SELECT COUNT(*) FROM activity", [], |row| row.get(0))?;
        let sensitive: u64 = self.conn.query_row("SELECT COUNT(*) FROM activity WHERE is_sensitive = 1", [], |row| row.get(0))?;
        let today: u64 = self.conn.query_row("SELECT COUNT(*) FROM activity WHERE timestamp >= date('now')", [], |row| row.get(0))?;
        Ok((total, sensitive, today))
    }

    pub fn cleanup_old(&self, retention_days: u32) -> Result<u64> {
        let deleted = self.conn.execute(
            "DELETE FROM activity WHERE timestamp < datetime('now', ?1)",
            params![format!("-{retention_days} days")],
        )?;
        Ok(deleted as u64)
    }
}
