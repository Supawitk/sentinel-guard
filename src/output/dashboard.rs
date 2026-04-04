use crate::core::config::Config;
use crate::core::db::ActivityDb;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io::stdout;
use std::time::Duration;

pub fn run(config: &Config) -> Result<()> {
    let db = ActivityDb::open(&config.db_path())?;
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let result = run_ui(&mut terminal, &db);
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    result
}

fn run_ui(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>, db: &ActivityDb) -> Result<()> {
    loop {
        let (total, sensitive, today) = db.get_stats().unwrap_or((0, 0, 0));
        let recent = db.get_recent(30).unwrap_or_default();
        let sensitive_events = db.get_sensitive_only(20).unwrap_or_default();

        terminal.draw(|frame| {
            let chunks = Layout::default().direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Length(5), Constraint::Min(10), Constraint::Length(2)])
                .split(frame.area());

            let title = Paragraph::new(Line::from(vec![
                Span::styled(" Sentinel Guard ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("v0.7 ", Style::default().fg(Color::DarkGray)),
                Span::styled("AI Agent File Access Monitor", Style::default().fg(Color::White)),
            ])).block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, chunks[0]);

            let stats = Paragraph::new(vec![Line::from(vec![
                Span::raw("  Total: "), Span::styled(total.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("  |  Sensitive: "), Span::styled(sensitive.to_string(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::raw("  |  Today: "), Span::styled(today.to_string(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ])]).block(Block::default().title(" Statistics ").borders(Borders::ALL));
            frame.render_widget(stats, chunks[1]);

            let cols = Layout::default().direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(chunks[2]);

            let recent_items: Vec<ListItem> = recent.iter().map(|e| {
                let style = if e.is_sensitive { Style::default().fg(Color::Red) } else { Style::default().fg(Color::White) };
                let ts = e.timestamp.split('T').nth(1).unwrap_or(&e.timestamp).chars().take(8).collect::<String>();
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("[{}] ", e.event_type), Style::default().fg(Color::Yellow)),
                    Span::styled(truncate(&e.path, 40), style),
                ]))
            }).collect();
            frame.render_widget(List::new(recent_items).block(Block::default().title(" Recent ").borders(Borders::ALL)), cols[0]);

            let alert_items: Vec<ListItem> = sensitive_events.iter().map(|e| {
                let ts = e.timestamp.split('T').nth(1).unwrap_or(&e.timestamp).chars().take(8).collect::<String>();
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("[{}] ", e.event_type), Style::default().fg(Color::Red)),
                    Span::styled(truncate(&e.path, 35), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                ]))
            }).collect();
            frame.render_widget(List::new(alert_items).block(Block::default().title(" Alerts ").borders(Borders::ALL).border_style(Style::default().fg(Color::Red))), cols[1]);

            frame.render_widget(Paragraph::new(Line::from(vec![
                Span::styled(" q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" quit  "),
                Span::styled("r", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" refresh  "),
                Span::raw("Auto-refreshes every 2s"),
            ])), chunks[3]);
        })?;

        if event::poll(Duration::from_secs(2))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("...{}", &s[s.len() - max + 3..]) }
}
