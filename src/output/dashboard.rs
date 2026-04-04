use crate::core::config::Config;
use crate::core::db::ActivityDb;
use crate::core::types::ActivityEntry;
use crate::monitor::agents::{AgentDetector, DetectedAgent};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Terminal,
};
use std::io::stdout;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq)]
enum Tab { Events, Agents, Alerts, Detail }

struct AppState {
    tab: Tab,
    list_state: ListState,
    alert_state: ListState,
    filter: String,
    filter_mode: bool,
    show_detail: bool,
    recent: Vec<ActivityEntry>,
    sensitive: Vec<ActivityEntry>,
    agents: Vec<DetectedAgent>,
    total: u64,
    sensitive_count: u64,
    today: u64,
    status_msg: String,
}

impl AppState {
    fn new() -> Self {
        let mut ls = ListState::default();
        ls.select(Some(0));
        Self {
            tab: Tab::Events,
            list_state: ls,
            alert_state: ListState::default(),
            filter: String::new(),
            filter_mode: false,
            show_detail: false,
            recent: vec![],
            sensitive: vec![],
            agents: vec![],
            total: 0,
            sensitive_count: 0,
            today: 0,
            status_msg: String::new(),
        }
    }

    fn refresh(&mut self, db_path: &std::path::Path, agent_detector: &mut AgentDetector) {
        // Reopen DB each refresh to see writes from other processes (scan, watch, etc.)
        if let Ok(db) = ActivityDb::open(db_path) {
            let (t, s, d) = db.get_stats().unwrap_or((0, 0, 0));
            self.total = t;
            self.sensitive_count = s;
            self.today = d;
            self.recent = db.get_recent(100).unwrap_or_default();
            self.sensitive = db.get_sensitive_only(50).unwrap_or_default();
        }
        self.agents = agent_detector.detect();
    }

    fn filtered_recent(&self) -> Vec<&ActivityEntry> {
        if self.filter.is_empty() {
            self.recent.iter().collect()
        } else {
            let f = self.filter.to_lowercase();
            self.recent.iter().filter(|e| {
                e.path.to_lowercase().contains(&f)
                    || e.event_type.to_lowercase().contains(&f)
                    || e.detail.to_lowercase().contains(&f)
            }).collect()
        }
    }

    fn selected_entry(&self) -> Option<&ActivityEntry> {
        let items = self.filtered_recent();
        self.list_state.selected().and_then(|i| items.get(i).copied())
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.filtered_recent().len();
        if len == 0 { return; }
        let current = self.list_state.selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, len as isize - 1) as usize;
        self.list_state.select(Some(next));
    }
}

pub fn run(config: &Config) -> Result<()> {
    let db_path = config.db_path();
    // Ensure DB exists
    let _ = ActivityDb::open(&db_path)?;
    let mut agent_detector = AgentDetector::new();

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut state = AppState::new();
    state.refresh(&db_path, &mut agent_detector);

    let result = run_loop(&mut terminal, &db_path, &mut agent_detector, &mut state);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    db_path: &std::path::Path,
    agent_detector: &mut AgentDetector,
    state: &mut AppState,
) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, state))?;

        if event::poll(Duration::from_secs(2))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }

                // Filter mode captures all typing
                if state.filter_mode {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            state.filter_mode = false;
                            state.status_msg = if state.filter.is_empty() {
                                String::new()
                            } else {
                                format!("Filter: {}", state.filter)
                            };
                        }
                        KeyCode::Backspace => { state.filter.pop(); }
                        KeyCode::Char(c) => { state.filter.push(c); }
                        _ => {}
                    }
                    state.list_state.select(Some(0));
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if state.show_detail {
                            state.show_detail = false;
                        } else {
                            break;
                        }
                    }
                    // Tab switching
                    KeyCode::Char('1') => { state.tab = Tab::Events; state.status_msg.clear(); }
                    KeyCode::Char('2') => { state.tab = Tab::Agents; state.status_msg.clear(); }
                    KeyCode::Char('3') => { state.tab = Tab::Alerts; state.status_msg.clear(); }
                    KeyCode::Tab => {
                        state.tab = match state.tab {
                            Tab::Events => Tab::Agents,
                            Tab::Agents => Tab::Alerts,
                            Tab::Alerts => Tab::Events,
                            Tab::Detail => Tab::Events,
                        };
                    }
                    // Navigation
                    KeyCode::Up | KeyCode::Char('k') => state.move_selection(-1),
                    KeyCode::Down | KeyCode::Char('j') => state.move_selection(1),
                    KeyCode::Home => state.list_state.select(Some(0)),
                    KeyCode::End => {
                        let len = state.filtered_recent().len();
                        if len > 0 { state.list_state.select(Some(len - 1)); }
                    }
                    KeyCode::PageUp => state.move_selection(-10),
                    KeyCode::PageDown => state.move_selection(10),
                    // Actions
                    KeyCode::Enter => {
                        if state.selected_entry().is_some() {
                            state.show_detail = !state.show_detail;
                        }
                    }
                    KeyCode::Char('/') => {
                        state.filter_mode = true;
                        state.filter.clear();
                        state.status_msg = "Type to filter, Enter to confirm, Esc to cancel".into();
                    }
                    KeyCode::Char('c') => {
                        state.filter.clear();
                        state.list_state.select(Some(0));
                        state.status_msg = "Filter cleared".into();
                    }
                    KeyCode::Char('r') => {
                        state.refresh(db_path, agent_detector);
                        state.status_msg = "Refreshed".into();
                    }
                    _ => {}
                }
            }
        } else {
            // Auto-refresh on timeout
            state.refresh(db_path, agent_detector);
        }
    }
    Ok(())
}

fn draw(frame: &mut ratatui::Frame, state: &AppState) {
    let chunks = Layout::default().direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header + tabs
            Constraint::Length(3),  // Stats bar
            Constraint::Min(8),    // Main content
            Constraint::Length(2),  // Footer
        ])
        .split(frame.area());

    // ── Header with tabs ──
    let tab_titles = vec!["1:Events", "2:Agents", "3:Alerts"];
    let selected_tab = match state.tab {
        Tab::Events | Tab::Detail => 0,
        Tab::Agents => 1,
        Tab::Alerts => 2,
    };
    let tabs = Tabs::new(tab_titles)
        .block(Block::default()
            .title(" Sentinel Guard v0.8 ")
            .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL))
        .select(selected_tab)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, chunks[0]);

    // ── Stats bar ──
    let agent_count = state.agents.len();
    let agent_names: String = if agent_count == 0 {
        "none".into()
    } else {
        state.agents.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", ")
    };
    let stats = Paragraph::new(Line::from(vec![
        Span::raw("  Events: "),
        Span::styled(state.total.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  Sensitive: "),
        Span::styled(state.sensitive_count.to_string(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw("  Today: "),
        Span::styled(state.today.to_string(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw("  Agents: "),
        Span::styled(
            format!("{agent_count} ({agent_names})"),
            if agent_count > 0 { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) }
            else { Style::default().fg(Color::DarkGray) },
        ),
    ])).block(Block::default().borders(Borders::ALL));
    frame.render_widget(stats, chunks[1]);

    // ── Main content area ──
    match state.tab {
        Tab::Events | Tab::Detail => draw_events(frame, state, chunks[2]),
        Tab::Agents => draw_agents(frame, state, chunks[2]),
        Tab::Alerts => draw_alerts(frame, state, chunks[2]),
    }

    // ── Detail overlay ──
    if state.show_detail {
        if let Some(entry) = state.selected_entry() {
            draw_detail_popup(frame, entry);
        }
    }

    // ── Footer ──
    let footer_text = if state.filter_mode {
        Line::from(vec![
            Span::styled(" / ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&state.filter, Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" quit "),
            Span::styled("Tab/1-3", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" switch "),
            Span::styled("↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" scroll "),
            Span::styled("Enter", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" detail "),
            Span::styled("/", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" filter "),
            Span::styled("c", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" clear "),
            Span::styled("r", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" refresh "),
            if !state.status_msg.is_empty() {
                Span::styled(format!(" | {}", state.status_msg), Style::default().fg(Color::DarkGray))
            } else {
                Span::raw("")
            },
        ])
    };
    frame.render_widget(Paragraph::new(footer_text), chunks[3]);
}

fn draw_events(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let filtered = state.filtered_recent();
    let title = if state.filter.is_empty() {
        format!(" Events ({}) ", filtered.len())
    } else {
        format!(" Events ({}) [filter: {}] ", filtered.len(), state.filter)
    };

    let items: Vec<ListItem> = filtered.iter().map(|e| {
        let style = if e.is_sensitive { Style::default().fg(Color::Red) } else { Style::default().fg(Color::White) };
        let ts = e.timestamp.split('T').nth(1).unwrap_or(&e.timestamp).chars().take(8).collect::<String>();
        ListItem::new(Line::from(vec![
            Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("[{:6}] ", e.event_type), Style::default().fg(Color::Yellow)),
            Span::styled(truncate(&e.path, 60), style),
            if e.is_sensitive { Span::styled(" !!", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)) }
            else { Span::raw("") },
        ]))
    }).collect();

    let mut list_state = state.list_state.clone();
    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn draw_agents(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    if state.agents.is_empty() {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::styled("  No AI agents detected running.", Style::default().fg(Color::DarkGray)),
            Line::raw(""),
            Line::styled("  Detected agents: Claude Code, Cursor, VS Code (Copilot),", Style::default().fg(Color::DarkGray)),
            Line::styled("  OpenClaw, Windsurf, Cody, Aider, Codex, Gemini", Style::default().fg(Color::DarkGray)),
        ]).block(Block::default().title(" AI Agents (0) ").borders(Borders::ALL));
        frame.render_widget(msg, area);
        return;
    }

    let items: Vec<ListItem> = state.agents.iter().map(|a| {
        ListItem::new(Line::from(vec![
            Span::styled(format!("  {} ", a.name), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(format!("(PID: {}) ", a.pid), Style::default().fg(Color::Yellow)),
            Span::styled(format!("[{}]", a.process_name), Style::default().fg(Color::DarkGray)),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .title(format!(" AI Agents ({}) ", state.agents.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)));
    frame.render_widget(list, area);
}

fn draw_alerts(frame: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let items: Vec<ListItem> = state.sensitive.iter().map(|e| {
        let ts = e.timestamp.split('T').nth(1).unwrap_or(&e.timestamp).chars().take(8).collect::<String>();
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("[{}] ", e.event_type), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::styled(truncate(&e.path, 55), Style::default().fg(Color::Red)),
            ]),
            Line::from(vec![
                Span::raw("         "),
                Span::styled(truncate(&e.detail, 65), Style::default().fg(Color::DarkGray)),
            ]),
        ])
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .title(format!(" Sensitive Alerts ({}) ", state.sensitive.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)));
    frame.render_widget(list, area);
}

fn draw_detail_popup(frame: &mut ratatui::Frame, entry: &ActivityEntry) {
    let area = frame.area();
    let popup_width = (area.width as f32 * 0.7) as u16;
    let popup_height = 12;
    let x = (area.width - popup_width) / 2;
    let y = (area.height - popup_height) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let sensitive_str = if entry.is_sensitive { "YES" } else { "no" };
    let sensitive_style = if entry.is_sensitive {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };

    let text = vec![
        Line::raw(""),
        Line::from(vec![Span::raw("  Event:     "), Span::styled(&entry.event_type, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::raw("  Path:      "), Span::styled(&entry.path, Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::raw("  Time:      "), Span::styled(&entry.timestamp, Style::default().fg(Color::Cyan))]),
        Line::from(vec![Span::raw("  Sensitive: "), Span::styled(sensitive_str, sensitive_style)]),
        Line::raw(""),
        Line::from(vec![Span::raw("  Detail:    "), Span::styled(truncate(&entry.detail, popup_width as usize - 14), Style::default().fg(Color::DarkGray))]),
        Line::raw(""),
        Line::styled("  Press Esc or Enter to close", Style::default().fg(Color::DarkGray)),
    ];

    let popup = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(Block::default()
            .title(" Event Detail ")
            .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)));
    frame.render_widget(popup, popup_area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("...{}", &s[s.len().saturating_sub(max - 3)..]) }
}
