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
    client_trait::DaemonClient,
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

    pub(crate) async fn refresh(&mut self, client: &mut impl DaemonClient) {
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
    let elapsed_secs = state.last_refresh.elapsed().as_secs();
    let text = build_status_bar_line(addr, elapsed_secs, state.last_error.as_deref());
    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(paragraph, area);
}

// ── Small helpers ─────────────────────────────────────────────────────────────

/// Build the status-bar [`Line`] from pure inputs.
///
/// Extracted from `render_status_bar` so the render path can be tested without
/// a live [`Instant`].  Pass `elapsed_secs = 0` in tests; the live path calls
/// `state.last_refresh.elapsed().as_secs()`.
pub(crate) fn build_status_bar_line(
    addr: &str,
    elapsed_secs: u64,
    error: Option<&str>,
) -> Line<'static> {
    if let Some(err) = error {
        Line::from(vec![
            Span::styled(" error: ", Style::default().fg(Color::Red)),
            Span::raw(err.to_owned()),
            Span::raw(" | q: quit"),
        ])
    } else {
        let elapsed_str = format_uptime(elapsed_secs);
        Line::from(vec![
            Span::raw(format!(" Daemon: {addr} | Refreshed: {elapsed_str} ago | ")),
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(": quit"),
        ])
    }
}

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

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use pathvector_client::types::{Origin, PeerState, PeerType, SessionState};

    fn make_peer(session_state: SessionState, peer_type: Option<PeerType>) -> PeerState {
        PeerState {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote_as: 65001,
            local_as: 65002,
            session_state,
            peer_type,
            hold_time: 90,
            uptime_seconds: 0,
            prefixes_received: 0,
            prefixes_accepted: 0,
            prefixes_advertised: 0,
        }
    }

    #[test]
    fn peer_type_str_external() {
        let p = make_peer(SessionState::Established, Some(PeerType::External));
        assert_eq!(peer_type_str(&p), "eBGP");
    }

    #[test]
    fn peer_type_str_internal() {
        let p = make_peer(SessionState::Established, Some(PeerType::Internal));
        assert_eq!(peer_type_str(&p), "iBGP");
    }

    #[test]
    fn peer_type_str_none() {
        let p = make_peer(SessionState::Idle, None);
        assert_eq!(peer_type_str(&p), "\u{2014}");
    }

    #[test]
    fn session_state_str_established() {
        let p = make_peer(SessionState::Established, None);
        assert_eq!(session_state_str(&p), "Established");
    }

    #[test]
    fn session_state_str_idle() {
        let p = make_peer(SessionState::Idle, None);
        assert_eq!(session_state_str(&p), "Idle");
    }

    #[test]
    fn format_origin_variants() {
        assert_eq!(format_origin(Origin::Igp), "IGP");
        assert_eq!(format_origin(Origin::Egp), "EGP");
        assert_eq!(format_origin(Origin::Incomplete), "?");
    }

    #[test]
    fn dashboard_state_new_is_empty() {
        let s = DashboardState::new();
        assert!(s.peers.is_empty());
        assert!(s.routes.is_empty());
        assert!(s.last_error.is_none());
    }

    // ── DashboardState::refresh ───────────────────────────────────────────────

    use crate::client_trait::MockDaemonClient;
    use pathvector_client::types::{AsSegment, AsSegmentType, Route};
    use std::net::Ipv4Addr as V4;

    fn make_route() -> Route {
        Route {
            prefix: "192.0.2.0/24".to_owned(),
            peer_address: IpAddr::V4(V4::new(10, 0, 0, 1)),
            peer_type: PeerType::External,
            next_hop: None,
            as_path: vec![AsSegment {
                kind: AsSegmentType::Sequence,
                asns: vec![65001],
            }],
            origin: pathvector_client::types::Origin::Igp,
            local_pref: None,
            med: None,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            atomic_aggregate: false,
            aggregator: None,
        }
    }

    #[tokio::test]
    async fn refresh_populates_peers_and_routes() {
        let mut state = DashboardState::new();
        let mut mock = MockDaemonClient::new();
        mock.peers = vec![make_peer(
            SessionState::Established,
            Some(PeerType::External),
        )];
        mock.routes = vec![make_route()];

        state.refresh(&mut mock).await;

        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.routes.len(), 1);
        assert!(state.last_error.is_none());
    }

    #[tokio::test]
    async fn refresh_sets_last_error_on_peer_failure() {
        let mut state = DashboardState::new();
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(pathvector_client::error::ClientError::Rpc(
            tonic::Status::unavailable("daemon down"),
        ));

        state.refresh(&mut mock).await;

        assert!(
            state.last_error.is_some(),
            "last_error must be set on RPC failure"
        );
    }

    #[tokio::test]
    async fn refresh_clears_stale_data_on_successive_success() {
        let mut state = DashboardState::new();
        let mut mock = MockDaemonClient::new();
        mock.peers = vec![make_peer(
            SessionState::Established,
            Some(PeerType::External),
        )];

        // First refresh — populates peers.
        state.refresh(&mut mock).await;
        assert_eq!(state.peers.len(), 1);

        // Second refresh with empty mock — peers list clears.
        let mut empty = MockDaemonClient::new();
        state.refresh(&mut empty).await;
        assert_eq!(state.peers.len(), 0);
        assert!(state.last_error.is_none());
    }

    // ── build_status_bar_line unit tests ──────────────────────────────────────

    #[test]
    fn status_bar_ok_zero_elapsed() {
        let line = build_status_bar_line("http://localhost:50051", 0, None);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("Daemon: http://localhost:50051"),
            "addr present: {text}"
        );
        // 0 secs → format_uptime returns em-dash
        assert!(
            text.contains('\u{2014}'),
            "0 secs renders as em-dash: {text}"
        );
        assert!(text.contains('q'), "quit hint present: {text}");
    }

    #[test]
    fn status_bar_ok_nonzero_elapsed() {
        let line = build_status_bar_line("http://127.0.0.1:50051", 65, None);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("00:01:05"),
            "65 s renders as 00:01:05: {text}"
        );
    }

    #[test]
    fn status_bar_error_state() {
        let line = build_status_bar_line("http://localhost:50051", 0, Some("connection refused"));
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("error:"), "error label present: {text}");
        assert!(
            text.contains("connection refused"),
            "error message present: {text}"
        );
    }

    #[test]
    fn status_bar_error_style_first_span_is_red() {
        let line = build_status_bar_line("http://localhost:50051", 0, Some("oops"));
        assert_eq!(
            line.spans[0].style.fg,
            Some(Color::Red),
            "first span must carry red style"
        );
    }

    // ── Snapshot tests (ratatui TestBackend) ─────────────────────────────────
    //
    // Each test renders a private widget function into a fixed-size in-memory
    // terminal buffer and snapshots the text output.  On first run the snapshot
    // files are created in `src/snapshots/`; after that, any change to the
    // rendered output fails the test until `cargo insta review` accepts it.

    use ratatui::backend::TestBackend;

    /// Render `draw` into a `width × height` test buffer and return the
    /// rendered text as a string suitable for snapshot testing.
    fn render_to_string(width: u16, height: u16, draw: impl FnOnce(&mut ratatui::Frame)) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(draw).unwrap();
        terminal.backend().to_string()
    }

    // --- render_peers ---

    #[test]
    fn snapshot_render_peers_empty() {
        let state = DashboardState::new();
        let output = render_to_string(80, 6, |f| {
            let area = f.area();
            render_peers(f, &state, area);
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_peers_established() {
        let mut state = DashboardState::new();
        let mut peer = make_peer(SessionState::Established, Some(PeerType::External));
        peer.uptime_seconds = 3661;
        peer.prefixes_received = 5;
        peer.prefixes_accepted = 4;
        peer.prefixes_advertised = 3;
        state.peers = vec![peer];
        let output = render_to_string(80, 6, |f| {
            let area = f.area();
            render_peers(f, &state, area);
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_peers_idle() {
        let mut state = DashboardState::new();
        state.peers = vec![make_peer(SessionState::Idle, Some(PeerType::Internal))];
        let output = render_to_string(80, 6, |f| {
            let area = f.area();
            render_peers(f, &state, area);
        });
        insta::assert_snapshot!(output);
    }

    // --- render_routes ---

    #[test]
    fn snapshot_render_routes_empty() {
        let state = DashboardState::new();
        let output = render_to_string(90, 6, |f| {
            let area = f.area();
            render_routes(f, &state, area);
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_routes_with_route() {
        let mut state = DashboardState::new();
        state.routes = vec![make_route()];
        let output = render_to_string(90, 6, |f| {
            let area = f.area();
            render_routes(f, &state, area);
        });
        insta::assert_snapshot!(output);
    }

    // --- render_status_bar ---
    //
    // `render_status_bar` calls `state.last_refresh.elapsed().as_secs()`.
    // `DashboardState::new()` sets `last_refresh = Instant::now()`, so elapsed
    // is 0 for any synchronous test — the snapshot reliably shows "—".

    #[test]
    fn snapshot_render_status_bar_ok() {
        let state = DashboardState::new();
        let output = render_to_string(80, 1, |f| {
            let area = f.area();
            render_status_bar(f, &state, "http://127.0.0.1:50051", area);
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_status_bar_error() {
        let mut state = DashboardState::new();
        state.last_error = Some("connection refused".to_owned());
        let output = render_to_string(80, 1, |f| {
            let area = f.area();
            render_status_bar(f, &state, "http://127.0.0.1:50051", area);
        });
        insta::assert_snapshot!(output);
    }

    // --- render (full layout) ---
    //
    // Exercises the top-level `render` dispatcher which composes all three panes
    // via a `Layout` split.  This is the only test that calls `render()` directly
    // and therefore the one that covers the layout code path.

    #[test]
    fn snapshot_render_full_populated() {
        let mut state = DashboardState::new();
        let mut peer = make_peer(SessionState::Established, Some(PeerType::External));
        peer.uptime_seconds = 7322; // 02:02:02
        peer.prefixes_received = 10;
        peer.prefixes_accepted = 8;
        peer.prefixes_advertised = 6;
        state.peers = vec![peer];
        state.routes = vec![make_route()];

        let output = render_to_string(80, 20, |f| {
            render(f, &state, "http://127.0.0.1:50051");
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_full_empty() {
        let state = DashboardState::new();
        let output = render_to_string(80, 20, |f| {
            render(f, &state, "http://127.0.0.1:50051");
        });
        insta::assert_snapshot!(output);
    }
}
