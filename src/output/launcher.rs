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

// ── Command definitions ──

struct Cmd {
    name: &'static str,
    args: &'static str,
    short_desc: &'static str,
    desc: &'static str,
    warning: &'static str,
    needs_confirm: bool,
}

struct Group {
    name: &'static str,
    icon: &'static str,
    color: Color,
    commands: &'static [Cmd],
}

const GROUPS: &[Group] = &[
    Group { name: "Setup", icon: ">", color: Color::Green, commands: &[
        Cmd { name: "init", args: "", short_desc: "Generate config", desc: "Generate a default sentinel.toml config file", warning: "", needs_confirm: false },
        Cmd { name: "check", args: "", short_desc: "Self-check", desc: "Verify binary, config, database, and scanner", warning: "", needs_confirm: false },
    ]},
    Group { name: "Scan", icon: "#", color: Color::Cyan, commands: &[
        Cmd { name: "scan", args: ".", short_desc: "Quick scan", desc: "Find sensitive files by pattern (.env, keys, wallets)", warning: "", needs_confirm: false },
        Cmd { name: "scan", args: ". --deep", short_desc: "Deep scan", desc: "Scan filenames + file contents for 26+ secret types", warning: "May be slow on large directories", needs_confirm: false },
        Cmd { name: "skill-scan", args: ".", short_desc: "Skill scan", desc: "Check AI agent skills for malicious patterns", warning: "", needs_confirm: false },
    ]},
    Group { name: "Monitor", icon: "~", color: Color::Yellow, commands: &[
        Cmd { name: "watch", args: ".", short_desc: "Watch files", desc: "Real-time monitoring with AI agent attribution", warning: "Runs until Ctrl+C", needs_confirm: false },
        Cmd { name: "agents", args: "", short_desc: "AI agents", desc: "Show running AI agents (Claude, Cursor, Copilot...)", warning: "", needs_confirm: false },
    ]},
    Group { name: "Integrity", icon: "=", color: Color::Blue, commands: &[
        Cmd { name: "baseline", args: ".", short_desc: "Baseline", desc: "Hash sensitive files for later verification", warning: "Creates .sentinel-hashes.json", needs_confirm: false },
        Cmd { name: "verify", args: ".", short_desc: "Verify", desc: "Check files against baseline for tampering", warning: "Run 'baseline' first", needs_confirm: false },
    ]},
    Group { name: "Protect", icon: "!", color: Color::Red, commands: &[
        Cmd { name: "honeypot", args: ".", short_desc: "Honeypot", desc: "Plant decoy .env/wallet/key files as tripwires", warning: "Creates fake files in directory", needs_confirm: true },
        Cmd { name: "auto-vault", args: ".", short_desc: "Auto-vault", desc: "Quarantine ALL sensitive files to vault", warning: "MOVES files from original location!", needs_confirm: true },
        Cmd { name: "vault", args: "list", short_desc: "Vault list", desc: "Show quarantined files", warning: "", needs_confirm: false },
    ]},
    Group { name: "Report", icon: "*", color: Color::Magenta, commands: &[
        Cmd { name: "dashboard", args: "", short_desc: "Dashboard", desc: "Interactive TUI with live events and agents", warning: "", needs_confirm: false },
        Cmd { name: "log", args: "--sensitive", short_desc: "Alerts log", desc: "View sensitive/alert events only", warning: "", needs_confirm: false },
        Cmd { name: "stats", args: "", short_desc: "Statistics", desc: "Event counts and database info", warning: "", needs_confirm: false },
        Cmd { name: "report", args: ". -o report.csv", short_desc: "Export CSV", desc: "Export findings to CSV/TXT", warning: "", needs_confirm: false },
        Cmd { name: "cleanup", args: "--days 7", short_desc: "Cleanup", desc: "Remove old log entries", warning: "Deletes log data", needs_confirm: true },
    ]},
];

// ── State ──

struct State {
    group_idx: usize,
    cmd_idx: usize,
    filter: String,
    filter_mode: bool,
    show_confirm: bool,
    selected_cmd: Option<String>,
}

impl State {
    fn new() -> Self {
        Self { group_idx: 0, cmd_idx: 0, filter: String::new(), filter_mode: false, show_confirm: false, selected_cmd: None }
    }

    fn current_group(&self) -> &'static Group { &GROUPS[self.group_idx] }
    fn current_cmd(&self) -> &'static Cmd { &self.current_group().commands[self.cmd_idx] }

    fn cmd_string(&self) -> String {
        let cmd = self.current_cmd();
        if cmd.args.is_empty() { cmd.name.to_string() } else { format!("{} {}", cmd.name, cmd.args) }
    }

    fn move_group(&mut self, delta: isize) {
        let len = GROUPS.len() as isize;
        self.group_idx = ((self.group_idx as isize + delta).rem_euclid(len)) as usize;
        self.cmd_idx = 0;
    }

    fn move_cmd(&mut self, delta: isize) {
        let len = self.current_group().commands.len() as isize;
        self.cmd_idx = ((self.cmd_idx as isize + delta).rem_euclid(len)) as usize;
    }
}

// ── Entry point ──

pub fn run_launcher() -> Result<Option<String>> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut state = State::new();

    let result = run_loop(&mut terminal, &mut state);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    result
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>, state: &mut State) -> Result<Option<String>> {
    loop {
        terminal.draw(|frame| draw(frame, state))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press { continue; }

            if state.show_confirm {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Enter => { state.show_confirm = false; return Ok(state.selected_cmd.take()); }
                    _ => { state.show_confirm = false; state.selected_cmd = None; }
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
                // Navigate between groups
                KeyCode::Tab | KeyCode::Right => state.move_group(1),
                KeyCode::BackTab | KeyCode::Left => state.move_group(-1),
                // Navigate within group
                KeyCode::Up | KeyCode::Char('k') => state.move_cmd(-1),
                KeyCode::Down | KeyCode::Char('j') => state.move_cmd(1),
                // Quick jump to group by number
                KeyCode::Char('1') => { state.group_idx = 0; state.cmd_idx = 0; }
                KeyCode::Char('2') => { state.group_idx = 1; state.cmd_idx = 0; }
                KeyCode::Char('3') => { state.group_idx = 2; state.cmd_idx = 0; }
                KeyCode::Char('4') => { state.group_idx = 3; state.cmd_idx = 0; }
                KeyCode::Char('5') => { state.group_idx = 4; state.cmd_idx = 0; }
                KeyCode::Char('6') => { state.group_idx = 5; state.cmd_idx = 0; }
                // Run
                KeyCode::Enter => {
                    let cmd = state.current_cmd();
                    let full = state.cmd_string();
                    if cmd.needs_confirm {
                        state.show_confirm = true;
                        state.selected_cmd = Some(full);
                    } else {
                        return Ok(Some(full));
                    }
                }
                _ => {}
            }
        }
    }
}

// ── Drawing ──

fn draw(frame: &mut ratatui::Frame, state: &State) {
    let main_chunks = Layout::default().direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // Header
            Constraint::Min(10),    // Grid
            Constraint::Length(7),   // Detail panel
            Constraint::Length(2),   // Footer
        ])
        .split(frame.area());

    // ── Header ──
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Sentinel Guard ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("v0.8", Style::default().fg(Color::DarkGray)),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        Span::styled("←→/Tab", Style::default().fg(Color::Yellow)),
        Span::styled(" group  ", Style::default().fg(Color::DarkGray)),
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::styled(" command  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::styled(" run  ", Style::default().fg(Color::DarkGray)),
        Span::styled("1-6", Style::default().fg(Color::Yellow)),
        Span::styled(" jump  ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::styled(" quit", Style::default().fg(Color::DarkGray)),
    ])).block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, main_chunks[0]);

    // ── Grid: 2 rows x 3 columns ──
    let rows = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    let top_cols = Layout::default().direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(34), Constraint::Percentage(33)])
        .split(rows[0]);

    let bot_cols = Layout::default().direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(34), Constraint::Percentage(33)])
        .split(rows[1]);

    let grid_areas = [top_cols[0], top_cols[1], top_cols[2], bot_cols[0], bot_cols[1], bot_cols[2]];

    for (i, group) in GROUPS.iter().enumerate() {
        let is_active = i == state.group_idx;
        let border_style = if is_active {
            Style::default().fg(group.color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let title = format!(" {}:{} {} ", i + 1, group.icon, group.name);
        let block = Block::default()
            .title(title)
            .title_style(if is_active { Style::default().fg(group.color).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::DarkGray) })
            .borders(Borders::ALL)
            .border_style(border_style);

        let items: Vec<ListItem> = group.commands.iter().enumerate().map(|(j, cmd)| {
            let is_selected = is_active && j == state.cmd_idx;
            let prefix = if is_selected { "▶ " } else { "  " };
            let warn = if cmd.needs_confirm { " !" } else { "" };

            let style = if is_selected {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            ListItem::new(Line::from(vec![
                Span::styled(prefix, if is_selected { Style::default().fg(group.color) } else { Style::default() }),
                Span::styled(cmd.short_desc, style),
                Span::styled(warn, Style::default().fg(Color::Yellow)),
            ]))
        }).collect();

        let list = List::new(items).block(block);
        frame.render_widget(list, grid_areas[i]);
    }

    // ── Detail panel ──
    let cmd = state.current_cmd();
    let group = state.current_group();
    let mut lines = vec![
        Line::from(vec![
            Span::styled("  $ ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("sentinel {}", state.cmd_string()), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(cmd.desc, Style::default().fg(Color::White)),
        ]),
    ];

    if !cmd.warning.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("  Warning: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(cmd.warning, Style::default().fg(Color::Yellow)),
        ]));
    }

    let detail = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::default()
            .title(format!(" {} > {} ", group.name, cmd.short_desc))
            .title_style(Style::default().fg(group.color))
            .borders(Borders::ALL));
    frame.render_widget(detail, main_chunks[2]);

    // ── Footer ──
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ←→", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" group  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" cmd  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" run  "),
        Span::styled("1-6", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" jump  "),
        Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" quit"),
    ]));
    frame.render_widget(footer, main_chunks[3]);

    // ── Confirm popup ──
    if state.show_confirm {
        let area = frame.area();
        let w = 55.min(area.width - 4);
        let h = 7;
        let popup = Rect::new((area.width - w) / 2, (area.height - h) / 2, w, h);
        frame.render_widget(Clear, popup);
        frame.render_widget(Paragraph::new(vec![
            Line::raw(""),
            Line::styled("  This action may modify or move files.", Style::default().fg(Color::Yellow)),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Press ", Style::default()),
                Span::styled("y", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(" to confirm, any other key to cancel", Style::default()),
            ]),
        ]).block(Block::default().title(" Confirm? ").borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow))), popup);
    }
}
