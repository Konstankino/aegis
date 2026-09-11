//! The interactive, colored TUI (`ratatui` + `crossterm`) — the primary "easy" front-end.
//!
//! The UI holds **no policy logic**: it renders the engine's data and calls the same load/validate/
//! test/write functions the CLI does. `App::on_key` (state transitions) and [`ui`] (rendering) are
//! pure and headless-testable; only [`run`]/`event_loop` touch a real terminal.

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::artifacts::Artifact;
use crate::domains::{broker, egress, honeypot, meter, sandbox, supply};
use crate::io::{self, PolicyDir};
use crate::validate::{self, Status};
use crate::{testrun, Format};

/// Screen mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Browse,
    Help,
    Test,
}

/// What the event loop should do after a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Continue,
    Quit,
    /// Suspend the TUI and edit this artifact in `$EDITOR`.
    Edit(Artifact),
}

/// The TUI application state (UI-only; all policy data comes from the engine).
pub struct App {
    dir: PolicyDir,
    no_color: bool,
    rows: Vec<(Artifact, Status, String)>,
    list: ListState,
    detail: String,
    status_line: String,
    mode: Mode,
    // test panel
    input: String,
    chain: Vec<(String, String, String)>,
    trace: Vec<(String, Status)>,
}

impl App {
    /// Build the app over `dir`, loading statuses + the first artifact's detail.
    pub fn new(dir: PolicyDir, no_color: bool) -> Self {
        let mut app = App {
            dir,
            no_color,
            rows: Vec::new(),
            list: ListState::default(),
            detail: String::new(),
            status_line: "↑/↓ select · v validate · t test · e edit · r reload · ? help · q quit"
                .into(),
            mode: Mode::Browse,
            input: String::new(),
            chain: Vec::new(),
            trace: Vec::new(),
        };
        app.list.select(Some(0));
        app.reload();
        app
    }

    /// Recompute per-artifact statuses and the selected detail from disk.
    pub fn reload(&mut self) {
        self.rows = validate::per_artifact(&self.dir);
        self.refresh_detail();
    }

    fn selected(&self) -> Artifact {
        let i = self
            .list
            .selected()
            .unwrap_or(0)
            .min(self.rows.len().saturating_sub(1));
        self.rows.get(i).map(|r| r.0).unwrap_or(Artifact::Tools)
    }

    fn refresh_detail(&mut self) {
        let a = self.selected();
        self.detail = detail_for(&self.dir, a)
            .unwrap_or_else(|e| format!("error rendering {}: {e}", a.filename()));
    }

    fn select_delta(&mut self, delta: i32) {
        if self.rows.is_empty() {
            return;
        }
        let n = self.rows.len() as i32;
        let cur = self.list.selected().unwrap_or(0) as i32;
        let next = (cur + delta).rem_euclid(n) as usize;
        self.list.select(Some(next));
        self.refresh_detail();
    }

    /// Handle one key. Pure state transition; returns what the event loop should do.
    pub fn on_key(&mut self, key: KeyCode) -> Action {
        match self.mode {
            Mode::Help => {
                self.mode = Mode::Browse;
                Action::Continue
            }
            Mode::Browse => match key {
                KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.select_delta(1);
                    Action::Continue
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.select_delta(-1);
                    Action::Continue
                }
                KeyCode::Tab => {
                    self.select_delta(1);
                    Action::Continue
                }
                KeyCode::Char('r') | KeyCode::Enter => {
                    self.reload();
                    self.status_line = "reloaded from disk".into();
                    Action::Continue
                }
                KeyCode::Char('v') => {
                    self.reload();
                    let (ok, warn, err) = self.tally();
                    self.status_line = format!("validate: {ok} ok · {warn} warn · {err} error");
                    Action::Continue
                }
                KeyCode::Char('t') => {
                    self.mode = Mode::Test;
                    self.input.clear();
                    self.chain.clear();
                    self.trace.clear();
                    self.status_line =
                        "test mediate — type  tool | args-json | provenance  then Enter · Esc back"
                            .into();
                    Action::Continue
                }
                KeyCode::Char('e') => Action::Edit(self.selected()),
                KeyCode::Char('?') => {
                    self.mode = Mode::Help;
                    Action::Continue
                }
                _ => Action::Continue,
            },
            Mode::Test => match key {
                KeyCode::Esc => {
                    self.mode = Mode::Browse;
                    Action::Continue
                }
                KeyCode::Char(c) => {
                    self.input.push(c);
                    Action::Continue
                }
                KeyCode::Backspace => {
                    self.input.pop();
                    Action::Continue
                }
                KeyCode::Enter => {
                    self.run_test_call();
                    Action::Continue
                }
                _ => Action::Continue,
            },
        }
    }

    fn tally(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut err = 0;
        for (_, s, _) in &self.rows {
            match s {
                Status::Error => err += 1,
                Status::Warn => warn += 1,
                _ => ok += 1,
            }
        }
        (ok, warn, err)
    }

    /// Parse the `tool | args | prov` input, append to the session chain, and re-run the whole
    /// chain through the real broker.
    fn run_test_call(&mut self) {
        let parts: Vec<String> = self
            .input
            .split('|')
            .map(|p| p.trim().to_string())
            .collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            self.status_line = "format:  tool | args-json | provenance  (e.g.  web.fetch | {\"url\":\"x\"} | untrusted)".into();
            return;
        }
        self.chain
            .push((parts[0].clone(), parts[1].clone(), parts[2].clone()));
        self.input.clear();
        match testrun::mediate(&self.dir, "tui", "tui-thread", &self.chain) {
            Ok(t) => {
                self.trace = t
                    .steps
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        let status = match s.decision.as_str() {
                            "allow" => Status::Ok,
                            "human_approve" => Status::Warn,
                            _ => Status::Error,
                        };
                        let legs = format!(
                            "A{} B{} C{}{}",
                            s.cap.reads_untrusted as u8,
                            s.cap.reads_sensitive as u8,
                            s.cap.external_effect as u8,
                            if s.cap.is_trifecta() { " TRIFECTA" } else { "" }
                        );
                        (
                            format!(
                                "{}. {:<18} {:<14} [{legs}]{}",
                                i + 1,
                                s.tool,
                                s.decision,
                                s.reason
                                    .as_deref()
                                    .map(|r| format!("  {r}"))
                                    .unwrap_or_default()
                            ),
                            status,
                        )
                    })
                    .collect();
                self.status_line =
                    "call added — taint accumulates across the chain · Esc back".into();
            }
            Err(e) => {
                self.chain.pop();
                self.status_line = format!("error: {e}");
            }
        }
    }

    fn color(&self, s: Status) -> Color {
        if self.no_color {
            return Color::Reset;
        }
        match s {
            Status::Ok => Color::Green,
            Status::Info => Color::Cyan,
            Status::Warn => Color::Yellow,
            Status::Error => Color::Red,
        }
    }
}

fn glyph(s: Status) -> &'static str {
    match s {
        Status::Ok => "●",
        Status::Info | Status::Warn => "◐",
        Status::Error => "✗",
    }
}

/// The detail text for an artifact (the domain's `show`, text format).
fn detail_for(dir: &PolicyDir, a: Artifact) -> Result<String> {
    Ok(match a {
        Artifact::Tools => broker::tools_list(dir, Format::Text)?,
        Artifact::BrokerCedar => {
            let src = broker::cedar_show(dir)?;
            if src.trim().is_empty() {
                "broker.cedar is empty (default-deny)".into()
            } else {
                src
            }
        }
        Artifact::Egress => egress::show(dir, Format::Text)?,
        Artifact::Meter => meter::show(dir, Format::Text)?,
        Artifact::Pins => supply::show(dir, Format::Text)?,
        Artifact::Honeypots => honeypot::show(dir, Format::Text)?,
        Artifact::Sandbox => sandbox::show(dir, Format::Text)?,
    })
}

/// Render the whole screen. Pure — testable with `ratatui::backend::TestBackend`.
pub fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Title.
    let title = Line::from(vec![
        Span::styled(
            "aegis",
            Style::default()
                .fg(app.color(Status::Info))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  policy manager  ·  "),
        Span::styled(
            app.dir.root().display().to_string(),
            Style::default().add_modifier(Modifier::DIM),
        ),
    ]);
    f.render_widget(Paragraph::new(title), chunks[0]);

    // Body: list | detail.
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(0)])
        .split(chunks[1]);

    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|(a, s, _)| {
            ListItem::new(Line::from(vec![
                Span::styled(glyph(*s), Style::default().fg(app.color(*s))),
                Span::raw(format!(" {}", a.filename())),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" policies "))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▎");
    let mut ls = app.list.clone();
    f.render_stateful_widget(list, body[0], &mut ls);

    if app.mode == Mode::Test {
        render_test(f, app, body[1]);
    } else {
        let a = app.selected();
        let (_, status, msg) =
            app.rows
                .iter()
                .find(|r| r.0 == a)
                .cloned()
                .unwrap_or((a, Status::Ok, String::new()));
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {}  [{}] ", a.filename(), msg))
            .border_style(Style::default().fg(app.color(status)));
        f.render_widget(
            Paragraph::new(app.detail.clone())
                .block(block)
                .wrap(Wrap { trim: false }),
            body[1],
        );
    }

    // Footer.
    let footer = match app.mode {
        Mode::Test => "type  tool | args | prov  · Enter run · Esc back",
        Mode::Help => "any key to close help",
        Mode::Browse => "↑/↓ select · v validate · t test · e edit · r reload · ? help · q quit",
    };
    let foot = Line::from(vec![
        Span::styled(
            format!(" {footer} "),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::raw("   "),
        Span::raw(app.status_line.clone()),
    ]);
    f.render_widget(Paragraph::new(foot), chunks[2]);

    if app.mode == Mode::Help {
        render_help(f, app);
    }
}

fn render_test(f: &mut Frame, app: &App, area: Rect) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);
    let lines: Vec<Line> = app
        .trace
        .iter()
        .map(|(t, s)| Line::from(Span::styled(t.clone(), Style::default().fg(app.color(*s)))))
        .collect();
    f.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" test mediate — taint accumulates across the chain "),
            )
            .wrap(Wrap { trim: false }),
        parts[0],
    );
    f.render_widget(
        Paragraph::new(format!("› {}", app.input)).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" call:  tool | args-json | provenance "),
        ),
        parts[1],
    );
}

fn render_help(f: &mut Frame, _app: &App) {
    let area = centered(64, 40, f.area());
    f.render_widget(Clear, area);
    let help = "\
aegis — keys

  ↑/↓ or j/k   select a policy
  Enter / r    reload from disk
  v            validate all (status bar)
  t            test panel — mediate a tool-call chain
  e            edit the selected policy in $EDITOR (validated on save)
  ?            this help
  q / Esc      quit

Local files only: aegis touches just the seven policy artifacts in the
chosen directory — never infrastructure, never anything remote.";
    f.render_widget(
        Paragraph::new(help)
            .block(Block::default().borders(Borders::ALL).title(" help "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn centered(w: u16, h: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}

/// Launch the interactive TUI over `dir`.
pub fn run(dir: PolicyDir, no_color: bool) -> Result<()> {
    let mut app = App::new(dir, no_color);
    let mut terminal = ratatui::init();
    let res = event_loop(&mut app, &mut terminal);
    ratatui::restore();
    res
}

fn event_loop(app: &mut App, terminal: &mut DefaultTerminal) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match app.on_key(key.code) {
            Action::Continue => {}
            Action::Quit => break,
            Action::Edit(artifact) => {
                let result = suspend_and_edit(terminal, app, artifact);
                app.reload();
                app.status_line = match result {
                    Ok(msg) => msg,
                    Err(e) => format!("edit failed: {e}"),
                };
            }
        }
    }
    Ok(())
}

/// Cleanly hand the terminal to an external editor: leave the alternate screen + raw mode so the
/// editor (vim, nano, …) draws on a NORMAL terminal — otherwise it renders onto the TUI's alternate
/// screen and can look blank — then run the edit and re-enter the TUI with a forced full redraw.
fn suspend_and_edit(
    terminal: &mut DefaultTerminal,
    app: &App,
    artifact: Artifact,
) -> Result<String> {
    use ratatui::crossterm::cursor::Show;
    use ratatui::crossterm::execute;
    use ratatui::crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };

    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen, Show)?;
    let result = edit_artifact(app, artifact);
    enable_raw_mode()?;
    execute!(std::io::stdout(), EnterAlternateScreen)?;
    terminal.clear()?; // discard stale cells so the TUI repaints cleanly
    result
}

/// Edit one artifact in `$EDITOR`, validate the result, and write it (or report why not). Absent
/// files are pre-filled with the current effective config (see `domains::edit_seed`) so the editor
/// is never a blank buffer.
fn edit_artifact(app: &App, artifact: Artifact) -> Result<String> {
    let current = crate::domains::edit_seed(&app.dir, artifact)?;
    let edited = io::edit_text_in_editor(&current)?;
    if edited == current {
        return Ok(format!("{} unchanged", artifact.filename()));
    }
    if let Err(e) = validate::validate_text(artifact, &edited) {
        return Ok(format!(
            "NOT saved — {} is invalid: {e}",
            artifact.filename()
        ));
    }
    app.dir.write(artifact, &edited, false)?;
    Ok(format!("saved {}", artifact.filename()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn seeded_app() -> App {
        let dir = crate::io::unique_temp_dir("tui");
        crate::scaffold::init(&dir, true, false).unwrap(); // blank starters; the test seeds its own
                                                           // Give the broker something to show/test.
        crate::domains::broker::cedar_write_validated(
            &dir,
            "permit ( principal, action == Action::\"invoke\", resource );\n",
            false,
        )
        .unwrap();
        App::new(dir, true)
    }

    fn render(app: &App) -> String {
        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        term.draw(|f| ui(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content().iter().map(|c| c.symbol()).collect::<String>()
    }

    #[test]
    fn renders_policy_list_and_status_glyphs() {
        let app = seeded_app();
        let screen = render(&app);
        assert!(screen.contains("policies"));
        assert!(screen.contains("tools.json"));
        assert!(screen.contains("sandbox.toml"));
        assert!(screen.contains("●"), "a valid glyph is drawn");
        std::fs::remove_dir_all(app.dir.root()).ok();
    }

    #[test]
    fn navigation_and_validate_key() {
        let mut app = seeded_app();
        let first = app.selected();
        assert_eq!(app.on_key(KeyCode::Down), Action::Continue);
        assert_ne!(app.selected(), first, "selection moved");
        assert_eq!(app.on_key(KeyCode::Char('v')), Action::Continue);
        assert!(app.status_line.contains("validate:"));
        std::fs::remove_dir_all(app.dir.root()).ok();
    }

    #[test]
    fn test_panel_runs_a_mediate_chain_to_trifecta() {
        let mut app = seeded_app();
        // Register the two tools the chain needs.
        crate::domains::broker::tools_add(
            &app.dir,
            &crate::domains::broker::NewTool {
                name: "web.fetch".into(),
                consequence: "low_reversible".into(),
                reaches_sensitive: false,
                external_effect: true,
                version: None,
                schema_json: Some(r#"{"type":"object"}"#.into()),
            },
            false,
        )
        .unwrap();
        crate::domains::broker::tools_add(
            &app.dir,
            &crate::domains::broker::NewTool {
                name: "db.read".into(),
                consequence: "low_reversible".into(),
                reaches_sensitive: true,
                external_effect: false,
                version: None,
                schema_json: Some(r#"{"type":"object"}"#.into()),
            },
            false,
        )
        .unwrap();

        app.on_key(KeyCode::Char('t'));
        assert_eq!(app.mode, Mode::Test);
        // Enter two calls.
        for c in "web.fetch | {} | untrusted".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        for c in "db.read | {} | user".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        // The rendered test panel shows the trifecta on the second step.
        let screen = render(&app);
        assert!(screen.contains("TRIFECTA"), "screen: {screen}");
        // Esc returns to browse.
        app.on_key(KeyCode::Esc);
        assert_eq!(app.mode, Mode::Browse);
        std::fs::remove_dir_all(app.dir.root()).ok();
    }

    #[test]
    fn help_overlay_toggles() {
        let mut app = seeded_app();
        app.on_key(KeyCode::Char('?'));
        assert_eq!(app.mode, Mode::Help);
        assert!(render(&app).contains("keys"));
        app.on_key(KeyCode::Char('x')); // any key closes
        assert_eq!(app.mode, Mode::Browse);
        std::fs::remove_dir_all(app.dir.root()).ok();
    }

    // Regression: the TUI `e` edit path must open the editor on the artifact's CURRENT content and
    // save the result — not present an empty buffer. (This is the only test in this binary that
    // mutates $EDITOR, so there is no env race.)
    #[test]
    fn tui_edit_hands_current_content_to_editor_and_saves() {
        let app = seeded_app();
        let current = app.dir.read(Artifact::BrokerCedar).unwrap().unwrap();
        assert!(!current.is_empty());
        let record = app.dir.root().join("seen.txt");
        let script = app.dir.root().join("ed.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncat \"$1\" > '{}'\nprintf '\\n// added\\n' >> \"$1\"\n",
                record.display()
            ),
        )
        .unwrap();
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&script)
            .status()
            .unwrap();
        std::env::set_var("EDITOR", script.to_str().unwrap());
        let msg = edit_artifact(&app, Artifact::BrokerCedar).unwrap();
        std::env::remove_var("EDITOR");

        // The editor received the CURRENT content (not an empty file), and the edit was saved.
        assert_eq!(std::fs::read_to_string(&record).unwrap(), current);
        assert!(msg.contains("saved"), "got: {msg}");
        assert!(app
            .dir
            .read(Artifact::BrokerCedar)
            .unwrap()
            .unwrap()
            .contains("// added"));
        std::fs::remove_dir_all(app.dir.root()).ok();
    }
}
