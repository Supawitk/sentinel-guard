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
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use std::io::stdout;

struct Command {
    name: &'static str,
    args: &'static str,
    group: &'static str,
    desc: &'static str,
    warning: &'static str,
    needs_confirm: bool,
}

const COMMANDS: &[Command] = &[
    // Setup
    Command { name: "init", args: "", group: "Setup", desc: "Generate a default sentinel.toml config file in current directory", warning: "", needs_confirm: false },
    Command { name: "check", args: "", group: "Setup", desc: "Run self-check to verify binary, config, database, and scanner are working", warning: "", needs_confirm: false },
    // Scanning
    Command { name: "scan", args: ".", group: "Scan", desc: "Scan current directory for sensitive files matching known patterns (.env, keys, wallets, etc.)", warning: "Pattern-only scan. Use --deep to also check file contents for secrets.", needs_confirm: false },
    Command { name: "scan", args: ". --deep", group: "Scan", desc: "Deep scan — checks filenames AND file contents for 26+ secret patterns (API keys, tokens, passwords, crypto keys)", warning: "Reads file contents. May be slow on large directories.", needs_confirm: false },
    Command { name: "skill-scan", args: ".", group: "Scan", desc: "Scan for AI agent SKILL.md files and check for malicious patterns (data exfil, RCE, credential theft)", warning: "", needs_confirm: false },
    // Monitoring
    Command { name: "watch", args: ".", group: "Monitor", desc: "Start real-time file monitoring. Alerts when sensitive files are accessed, created, or modified", warning: "Runs continuously until Ctrl+C. Logs which AI agents are active during events.", needs_confirm: false },
    Command { name: "agents", args: "", group: "Monitor", desc: "Show which AI coding agents are currently running (Claude Code, Cursor, VS Code, OpenClaw, etc.)", warning: "", needs_confirm: false },
    // Integrity
    Command { name: "baseline", args: ".", group: "Integrity", desc: "Create hash snapshot of all sensitive files. Used to detect tampering later with 'verify'", warning: "Creates .sentinel-hashes.json in the target directory.", needs_confirm: false },
    Command { name: "verify", args: ".", group: "Integrity", desc: "Compare current sensitive files against baseline hashes. Shows modified, deleted, and new files", warning: "Requires a baseline to exist. Run 'baseline' first.", needs_confirm: false },
    // Protection
    Command { name: "honeypot", args: ".", group: "Protect", desc: "Plant fake .env, wallet, SSH key, and AWS credential files as tripwires. Any access triggers alerts", warning: "Creates decoy files in your directory. Use --remove to clean up.", needs_confirm: true },
    Command { name: "auto-vault", args: ".", group: "Protect", desc: "Automatically find and quarantine ALL sensitive files to a protected vault", warning: "THIS MOVES FILES! They will be removed from their original location. Use 'vault-restore' to recover.", needs_confirm: true },
    Command { name: "vault", args: "list", group: "Protect", desc: "Show all files currently stored in the quarantine vault", warning: "", needs_confirm: false },
    // Reporting
    Command { name: "dashboard", args: "", group: "Report", desc: "Open interactive TUI with live events, agent detection, and alert panels", warning: "", needs_confirm: false },
    Command { name: "log", args: "", group: "Report", desc: "View recent activity log entries from the SQLite database", warning: "", needs_confirm: false },
    Command { name: "log", args: "--sensitive", group: "Report", desc: "View only sensitive/alert events from the activity log", warning: "", needs_confirm: false },
    Command { name: "stats", args: "", group: "Report", desc: "Show total events, sensitive events, and today's event count", warning: "", needs_confirm: false },
    Command { name: "report", args: ". -o report.csv", group: "Report", desc: "Export scan results to CSV or TXT file for sharing or compliance", warning: "", needs_confirm: false },
    // Maintenance
    Command { name: "cleanup", args: "--days 7", group: "Maintain", desc: "Remove activity log entries older than specified days", warning: "Deletes log data permanently.", needs_confirm: true },
];

struct LauncherState {
    list_state: ListState,
    filter: String,
    filter_mode: bool,
    show_confirm: bool,
    selected_cmd: Option<String>,
}

impl LauncherState {
    fn new() -> Self {
        let mut ls = ListState::default();
        ls.select(Some(0));
        Self { list_state: ls, filter: String::new(), filter_mode: false, show_confirm: false, selected_cmd: None }
    }

    fn filtered_commands(&self) -> Vec<&Command> {
        if self.filter.is_empty() {
            COMMANDS.iter().collect()
        } else {
            let f = self.filter.to_lowercase();
            COMMANDS.iter().filter(|c| {
                c.name.to_lowercase().contains(&f) || c.group.to_lowercase().contains(&f)
                    || c.desc.to_lowercase().contains(&f)
            }).collect()
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.filtered_commands().len();
        if len == 0 { return; }
        let cur = self.list_state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, len as isize - 1) as usize;
        self.list_state.select(Some(next));
    }

    fn selected(&self) -> Option<&Command> {
        let cmds = self.filtered_commands();
        self.list_state.selected().and_then(|i| cmds.get(i).copied())
    }
}

/// Returns the command string to execute, or None if user quit
pub fn run_launcher() -> Result<Option<String>> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut state = LauncherState::new();

    let result = run_loop(&mut terminal, &mut state);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    state: &mut LauncherState,
) -> Result<Option<String>> {
    loop {
        terminal.draw(|frame| draw_launcher(frame, state))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press { continue; }

            // Confirm dialog
            if state.show_confirm {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Enter => {
                        let cmd = state.selected_cmd.take();
                        state.show_confirm = false;
                        return Ok(cmd);
                    }
                    _ => {
                        state.show_confirm = false;
                        state.selected_cmd = None;
                    }
                }
                continue;
            }

            // Filter mode
            if state.filter_mode {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => state.filter_mode = false,
                    KeyCode::Backspace => { state.filter.pop(); state.list_state.select(Some(0)); }
                    KeyCode::Char(c) => { state.filter.push(c); state.list_state.select(Some(0)); }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
                KeyCode::Up | KeyCode::Char('k') => state.move_selection(-1),
                KeyCode::Down | KeyCode::Char('j') => state.move_selection(1),
                KeyCode::Home => state.list_state.select(Some(0)),
                KeyCode::End => {
                    let len = state.filtered_commands().len();
                    if len > 0 { state.list_state.select(Some(len - 1)); }
                }
                KeyCode::PageUp => state.move_selection(-5),
                KeyCode::PageDown => state.move_selection(5),
                KeyCode::Char('/') => { state.filter_mode = true; state.filter.clear(); }
                KeyCode::Char('c') => { state.filter.clear(); state.list_state.select(Some(0)); }
                KeyCode::Enter => {
                    if let Some(cmd) = state.selected() {
                        let full_cmd = if cmd.args.is_empty() {
                            cmd.name.to_string()
                        } else {
                            format!("{} {}", cmd.name, cmd.args)
                        };
                        if cmd.needs_confirm {
                            state.show_confirm = true;
                            state.selected_cmd = Some(full_cmd);
                        } else {
                            return Ok(Some(full_cmd));
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn draw_launcher(frame: &mut ratatui::Frame, state: &LauncherState) {
    let chunks = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8), Constraint::Length(8), Constraint::Length(2)])
        .split(frame.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Sentinel Guard ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("— Select a command to run", Style::default().fg(Color::DarkGray)),
    ])).block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // Command list
    let cmds = state.filtered_commands();
    let mut last_group = "";
    let items: Vec<ListItem> = cmds.iter().map(|cmd| {
        let group_label = if cmd.group != last_group {
            last_group = cmd.group;
            format!("[{}] ", cmd.group)
        } else {
            "       ".to_string()
        };

        let warn_indicator = if cmd.needs_confirm {
            Span::styled(" ⚠", Style::default().fg(Color::Yellow))
        } else {
            Span::raw("")
        };

        ListItem::new(Line::from(vec![
            Span::styled(group_label, Style::default().fg(Color::Cyan)),
            Span::styled(cmd.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(if cmd.args.is_empty() { String::new() } else { format!(" {}", cmd.args) }, Style::default().fg(Color::DarkGray)),
            warn_indicator,
        ]))
    }).collect();

    let title = if state.filter_mode {
        format!(" Commands [/{}] ", state.filter)
    } else if !state.filter.is_empty() {
        format!(" Commands ({}) [filter: {}] ", items.len(), state.filter)
    } else {
        format!(" Commands ({}) ", items.len())
    };

    let mut ls = state.list_state.clone();
    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(list, chunks[1], &mut ls);

    // Detail panel for selected command
    if let Some(cmd) = state.selected() {
        let mut detail_lines = vec![
            Line::from(vec![
                Span::styled("  Command: ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("sentinel {} {}", cmd.name, cmd.args), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(cmd.desc, Style::default().fg(Color::White)),
            ]),
        ];

        if !cmd.warning.is_empty() {
            detail_lines.push(Line::raw(""));
            detail_lines.push(Line::from(vec![
                Span::styled("  Warning: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(cmd.warning, Style::default().fg(Color::Yellow)),
            ]));
        }

        let detail = Paragraph::new(detail_lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().title(" Details ").borders(Borders::ALL));
        frame.render_widget(detail, chunks[2]);
    }

    // Footer
    let footer = if state.filter_mode {
        Line::from(vec![
            Span::styled(" /", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&state.filter, Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(Color::Yellow)),
            Span::styled("  (Enter to confirm, Esc to cancel)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" navigate  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" run  "),
            Span::styled("/", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" search  "),
            Span::styled("c", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" clear  "),
            Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" quit"),
        ])
    };
    frame.render_widget(Paragraph::new(footer), chunks[3]);

    // Confirm dialog
    if state.show_confirm {
        let area = frame.area();
        let w = 50.min(area.width - 4);
        let h = 7;
        let popup = Rect::new((area.width - w) / 2, (area.height - h) / 2, w, h);
        frame.render_widget(Clear, popup);
        let confirm = Paragraph::new(vec![
            Line::raw(""),
            Line::styled("  This action may modify files.", Style::default().fg(Color::Yellow)),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Press ", Style::default().fg(Color::White)),
                Span::styled("y", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(" to confirm, any other key to cancel", Style::default().fg(Color::White)),
            ]),
        ]).block(Block::default().title(" Confirm? ").borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)));
        frame.render_widget(confirm, popup);
    }
}
