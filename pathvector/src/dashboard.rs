//! Live-updating TUI dashboard using [`ratatui`] and [`crossterm`].
//!
//! The dashboard renders two panes:
//!
//! ```text
//! ┌─ Peers ─────────────────────────────────────────────────────────┐
//! │ ADDRESS     REMOTE-AS  TYPE  STATE        UPTIME   RCV  ACC ADV │
//! │ 10.0.0.1    65001      eBGP  Established  00:03:45   5    4   3 │
//! └─────────────────────────────────────────────────────────────────┘
//! ┌─ Routes ────────────────────────────────────────────────────────┐
//! │ PREFIX           PEER       NEXT-HOP  AS-PATH   ORIGIN  MED    │
//! │ 192.168.1.0/24   10.0.0.1   10.0.0.1  65001     IGP     —     │
//! └─────────────────────────────────────────────────────────────────┘
//!  Daemon: http://127.0.0.1:50051 | Refreshed: 00:00:01 | q: quit
//! ```
//!
//! The daemon is polled every [`POLL_INTERVAL`] seconds.  Press `q` or
//! `Ctrl-C` to exit and restore the terminal.

use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use pathvector_client::{
    PathvectorClient,
    types::{PeerState, Route, SessionState},
};

use crate::{
    error::CliError,
    output::{format_as_path, format_opt_u32, format_uptime},
};

/// Polling interval between daemon queries.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Crossterm event polling timeout.  Shorter than `POLL_INTERVAL` so keypresses
/// feel responsive.
const EVENT_TIMEOUT: Duration = Duration::from_millis(100);

// ── Terminal guard ────────────────────────────────────────────────────────────

/// RAII guard that restores the terminal on drop, even if the dashboard panics.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self, CliError> {
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort; ignore errors during teardown.
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

// ── Dashboard state ───────────────────────────────────────────────────────────

struct DashboardState {
    peers: Vec<PeerState>,
    routes: Vec<Route>,
    last_refresh: Instant,
    /// Error message shown in the status bar when the last poll failed.
    last_error: Option<String>,
}

impl DashboardState {
    fn new() -> Self {
        Self {
            peers: Vec::new(),
            routes: Vec::new(),
            last_refresh: Instant::now(),
            last_error: None,
        }
    }

    async fn refresh(&mut self, client: &mut PathvectorClient) {
        match client.list_peers().await {
            Ok(peers) => self.peers = peers,
            Err(e) => self.last_error = Some(e.to_string()),
        }
        match client.list_routes(None).await {
            Ok(routes) => self.routes = routes,
            Err(e) => self.last_error = Some(e.to_string()),
        }
        if self.last_error.is_none() {
            self.last_refresh = Instant::now();
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the live dashboard.  Returns when the user presses `q` or `Ctrl-C`.
pub async fn run_dashboard(addr: String) -> Result<(), CliError> {
    let mut client = PathvectorClient::connect(&addr)?;
    let mut state = DashboardState::new();

    // Initial data fetch before entering raw mode so errors surface cleanly.
    state.refresh(&mut client).await;

    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut next_poll = Instant::now() + POLL_INTERVAL;

    loop {
        terminal.draw(|f| render(f, &state, &addr))?;

        // Poll for keyboard events with a short timeout so we can re-render
        // after `POLL_INTERVAL` without blocking indefinitely.
        if event::poll(EVENT_TIMEOUT)?
            && let Event::Key(key) = event::read()?
        {
            match (key.code, key.modifiers) {
                (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                _ => {}
            }
        }

        if Instant::now() >= next_poll {
            state.refresh(&mut client).await;
            next_poll = Instant::now() + POLL_INTERVAL;
        }
    }

    Ok(())
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn render(f: &mut Frame, state: &DashboardState, addr: &str) {
    let area = f.area();

    // Vertical split: peers (~30%), routes (~65%), status bar (1 line).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    render_peers(f, state, chunks[0]);
    render_routes(f, state, chunks[1]);
    render_status_bar(f, state, addr, chunks[2]);
}

fn render_peers(f: &mut Frame, state: &DashboardState, area: ratatui::layout::Rect) {
    let header_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

    let header = Row::new([
        Cell::from("ADDRESS"),
        Cell::from("REMOTE-AS"),
        Cell::from("TYPE"),
        Cell::from("STATE"),
        Cell::from("UPTIME"),
        Cell::from("RCV"),
        Cell::from("ACC"),
        Cell::from("ADV"),
    ])
    .style(header_style);

    let rows: Vec<Row> = state
        .peers
        .iter()
        .map(|p| {
            let state_style = if p.session_state == SessionState::Established {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Yellow)
            };
            Row::new([
                Cell::from(p.address.to_string()),
                Cell::from(p.remote_as.to_string()),
                Cell::from(peer_type_str(p)),
                Cell::from(session_state_str(p)).style(state_style),
                Cell::from(format_uptime(p.uptime_seconds)),
                Cell::from(p.prefixes_received.to_string()),
                Cell::from(p.prefixes_accepted.to_string()),
                Cell::from(p.prefixes_advertised.to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(5),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Peers "));

    f.render_widget(table, area);
}

fn render_routes(f: &mut Frame, state: &DashboardState, area: ratatui::layout::Rect) {
    let header_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

    let header = Row::new([
        Cell::from("PREFIX"),
        Cell::from("PEER"),
        Cell::from("NEXT-HOP"),
        Cell::from("AS-PATH"),
        Cell::from("ORIGIN"),
        Cell::from("MED"),
    ])
    .style(header_style);

    let rows: Vec<Row> = state
        .routes
        .iter()
        .map(|r| {
            let next_hop = r
                .next_hop
                .map_or_else(|| "\u{2014}".to_owned(), |ip| ip.to_string());
            Row::new([
                Cell::from(r.prefix.clone()),
                Cell::from(r.peer_address.to_string()),
                Cell::from(next_hop),
                Cell::from(format_as_path(&r.as_path)),
                Cell::from(format_origin(r.origin)),
                Cell::from(format_opt_u32(r.med)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Min(20),
            Constraint::Length(7),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Routes "));

    f.render_widget(table, area);
}

fn render_status_bar(
    f: &mut Frame,
    state: &DashboardState,
    addr: &str,
    area: ratatui::layout::Rect,
) {
    let elapsed = state.last_refresh.elapsed();
    let elapsed_str = format_uptime(elapsed.as_secs());

    let text = if let Some(err) = &state.last_error {
        Line::from(vec![
            Span::styled(" error: ", Style::default().fg(Color::Red)),
            Span::raw(err.as_str()),
            Span::raw(" | q: quit"),
        ])
    } else {
        Line::from(vec![
            Span::raw(format!(" Daemon: {addr} | Refreshed: {elapsed_str} ago | ")),
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(": quit"),
        ])
    };

    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(paragraph, area);
}

// ── Small helpers ─────────────────────────────────────────────────────────────

fn peer_type_str(p: &PeerState) -> &'static str {
    match p.peer_type {
        Some(pathvector_client::types::PeerType::External) => "eBGP",
        Some(pathvector_client::types::PeerType::Internal) => "iBGP",
        _ => "—",
    }
}

fn session_state_str(p: &PeerState) -> &'static str {
    match p.session_state {
        SessionState::Established => "Established",
        SessionState::Idle => "Idle",
        _ => "Unknown",
    }
}

fn format_origin(origin: pathvector_client::types::Origin) -> &'static str {
    match origin {
        pathvector_client::types::Origin::Igp => "IGP",
        pathvector_client::types::Origin::Egp => "EGP",
        _ => "?",
    }
}
