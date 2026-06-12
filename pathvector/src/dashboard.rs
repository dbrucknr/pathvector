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
//!  Daemon: http://127.0.0.1:50051 | ● Live | q: quit
//! ```
//!
//! The dashboard subscribes to the daemon's `WatchPeers` and `WatchRoutes`
//! streaming RPCs and updates the TUI as events arrive — no polling.
//! Press `q` or `Ctrl-C` to exit and restore the terminal.

use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt as _;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use tokio::sync::mpsc;

use pathvector_client::{
    PathvectorClient,
    error::ClientError,
    types::{PeerEvent, PeerEventType, PeerState, Route, RouteEvent, RouteEventType, SessionState},
};

use crate::{
    client_trait::DaemonClient,
    error::CliError,
    output::{format_as_path, format_opt_u32, format_uptime},
};

/// Crossterm keyboard polling interval inside the blocking thread.
const KEY_POLL: Duration = Duration::from_millis(50);

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
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

// ── Dashboard state ───────────────────────────────────────────────────────────

pub(crate) struct DashboardState {
    pub(crate) peers: Vec<PeerState>,
    pub(crate) routes: Vec<Route>,
    /// Set when the last stream event was an error.
    pub(crate) last_error: Option<String>,
}

impl DashboardState {
    pub(crate) fn new() -> Self {
        Self {
            peers: Vec::new(),
            routes: Vec::new(),
            last_error: None,
        }
    }

    /// Apply a single event from the `WatchPeers` stream.
    ///
    /// - `Current` / `Changed` — upsert the peer by address.
    /// - `EndInitial` — no-op; the snapshot phase is complete.
    /// - `Err` — record the error message in `last_error`.
    pub(crate) fn apply_peer_event(&mut self, event: Result<PeerEvent, ClientError>) {
        match event {
            Err(e) => self.last_error = Some(e.to_string()),
            Ok(PeerEvent {
                event_type: PeerEventType::Current | PeerEventType::Changed,
                peer: Some(p),
            }) => {
                if let Some(slot) = self.peers.iter_mut().find(|x| x.address == p.address) {
                    *slot = p;
                } else {
                    self.peers.push(p);
                }
                self.last_error = None;
            }
            Ok(_) => {}
        }
    }

    /// Apply a single event from the `WatchRoutes` stream.
    ///
    /// - `Current` / `Announced` — upsert the route by prefix.
    /// - `Withdrawn` — remove the route with the matching prefix.
    /// - `EndInitial` — no-op; the snapshot phase is complete.
    /// - `Err` — record the error message in `last_error`.
    pub(crate) fn apply_route_event(&mut self, event: Result<RouteEvent, ClientError>) {
        match event {
            Err(e) => self.last_error = Some(e.to_string()),
            Ok(RouteEvent {
                event_type: RouteEventType::Current | RouteEventType::Announced,
                route: Some(r),
                ..
            }) => {
                if let Some(slot) = self.routes.iter_mut().find(|x| x.prefix == r.prefix) {
                    *slot = r;
                } else {
                    self.routes.push(r);
                }
                self.last_error = None;
            }
            Ok(RouteEvent {
                event_type: RouteEventType::Withdrawn,
                withdrawn_prefix: Some(prefix),
                ..
            }) => {
                self.routes.retain(|r| r.prefix != prefix);
                self.last_error = None;
            }
            Ok(_) => {}
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the live dashboard.  Returns when the user presses `q` or `Ctrl-C`.
///
/// Subscribes to `WatchPeers` and `WatchRoutes` before entering raw terminal
/// mode so that connection errors surface in the normal terminal rather than
/// corrupting the display.
pub async fn run_dashboard(addr: String) -> Result<(), CliError> {
    let mut client = PathvectorClient::connect(&addr)?;

    // Subscribe before raw mode — errors are visible in the normal terminal.
    let mut peer_stream = client.watch_peers().await?;
    let mut route_stream = client.watch_routes(None).await?;

    let mut state = DashboardState::new();

    // Keyboard events arrive from a dedicated blocking thread via a channel.
    let (key_tx, mut key_rx) = mpsc::channel::<event::KeyEvent>(16);
    tokio::task::spawn_blocking(move || {
        loop {
            if event::poll(KEY_POLL).is_ok_and(|ready| ready)
                && let Ok(Event::Key(k)) = event::read()
                && key_tx.blocking_send(k).is_err()
            {
                break;
            }
        }
    });

    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| render(f, &state, &addr))?;

        tokio::select! {
            Some(key) = key_rx.recv() => {
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _)
                    | (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                    _ => {}
                }
            }
            Some(event) = peer_stream.next() => state.apply_peer_event(event),
            Some(event) = route_stream.next() => state.apply_route_event(event),
        }
    }

    Ok(())
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn render(f: &mut Frame, state: &DashboardState, addr: &str) {
    let area = f.area();

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
                Cell::from(
                    r.peer_address
                        .map_or_else(|| "local".to_owned(), |a| a.to_string()),
                ),
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
    let text = build_status_bar_line(addr, state.last_error.as_deref());
    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(paragraph, area);
}

// ── Small helpers ─────────────────────────────────────────────────────────────

/// Build the status-bar [`Line`] from pure inputs.
///
/// Extracted from `render_status_bar` so the render path can be tested without
/// terminal I/O.
pub(crate) fn build_status_bar_line(addr: &str, error: Option<&str>) -> Line<'static> {
    if let Some(err) = error {
        Line::from(vec![
            Span::styled(" error: ", Style::default().fg(Color::Red)),
            Span::raw(err.to_owned()),
            Span::raw(" | q: quit"),
        ])
    } else {
        Line::from(vec![
            Span::raw(format!(" Daemon: {addr} | ")),
            Span::styled("● Live", Style::default().fg(Color::Green)),
            Span::raw(" | "),
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(": quit"),
        ])
    }
}

fn peer_type_str(p: &PeerState) -> &'static str {
    match p.peer_type {
        Some(pathvector_client::types::PeerType::External) => "eBGP",
        Some(pathvector_client::types::PeerType::Internal) => "iBGP",
        _ => "\u{2014}",
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

    use pathvector_client::types::{
        AsSegment, AsSegmentType, Origin, PeerEvent, PeerEventType, PeerState, PeerType,
        RouteEvent, RouteEventType, SessionState,
    };

    use super::*;

    // ── Fixture helpers ───────────────────────────────────────────────────────

    fn make_peer(
        address: Ipv4Addr,
        session_state: SessionState,
        peer_type: Option<PeerType>,
    ) -> PeerState {
        PeerState {
            address: IpAddr::V4(address),
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

    fn make_route(prefix: &str, peer: Ipv4Addr) -> Route {
        Route {
            prefix: prefix.to_owned(),
            peer_address: Some(IpAddr::V4(peer)),
            peer_type: PeerType::External,
            next_hop: None,
            as_path: vec![AsSegment {
                kind: AsSegmentType::Sequence,
                asns: vec![65001],
            }],
            origin: Origin::Igp,
            local_pref: None,
            med: None,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            atomic_aggregate: false,
            aggregator: None,
        }
    }

    // These helpers return Result<_, ClientError> to match the apply_* method
    // signatures exactly — the Ok wrapping is intentional.
    #[allow(clippy::unnecessary_wraps)]
    fn peer_event(kind: PeerEventType, peer: PeerState) -> Result<PeerEvent, ClientError> {
        Ok(PeerEvent {
            event_type: kind,
            peer: Some(peer),
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn end_initial_peer() -> Result<PeerEvent, ClientError> {
        Ok(PeerEvent {
            event_type: PeerEventType::EndInitial,
            peer: None,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn route_announced(r: Route) -> Result<RouteEvent, ClientError> {
        Ok(RouteEvent {
            event_type: RouteEventType::Announced,
            route: Some(r),
            withdrawn_prefix: None,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn route_current(r: Route) -> Result<RouteEvent, ClientError> {
        Ok(RouteEvent {
            event_type: RouteEventType::Current,
            route: Some(r),
            withdrawn_prefix: None,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn route_withdrawn(prefix: &str) -> Result<RouteEvent, ClientError> {
        Ok(RouteEvent {
            event_type: RouteEventType::Withdrawn,
            route: None,
            withdrawn_prefix: Some(prefix.to_owned()),
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn end_initial_route() -> Result<RouteEvent, ClientError> {
        Ok(RouteEvent {
            event_type: RouteEventType::EndInitial,
            route: None,
            withdrawn_prefix: None,
        })
    }

    fn rpc_error() -> ClientError {
        ClientError::Rpc(tonic::Status::unavailable("daemon down"))
    }

    // ── DashboardState::new ───────────────────────────────────────────────────

    #[test]
    fn dashboard_state_new_is_empty() {
        let s = DashboardState::new();
        assert!(s.peers.is_empty());
        assert!(s.routes.is_empty());
        assert!(s.last_error.is_none());
    }

    // ── apply_peer_event ─────────────────────────────────────────────────────

    #[test]
    fn apply_peer_current_inserts_new_peer() {
        let mut state = DashboardState::new();
        let p = make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Established,
            Some(PeerType::External),
        );
        state.apply_peer_event(peer_event(PeerEventType::Current, p));
        assert_eq!(state.peers.len(), 1);
        assert!(state.last_error.is_none());
    }

    #[test]
    fn apply_peer_changed_updates_existing_peer() {
        let mut state = DashboardState::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let p1 = make_peer(addr, SessionState::Idle, None);
        state.apply_peer_event(peer_event(PeerEventType::Current, p1));
        assert_eq!(state.peers[0].session_state, SessionState::Idle);

        let p2 = make_peer(addr, SessionState::Established, Some(PeerType::External));
        state.apply_peer_event(peer_event(PeerEventType::Changed, p2));
        // Same peer, not a second entry.
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].session_state, SessionState::Established);
    }

    #[test]
    fn apply_peer_changed_different_address_inserts() {
        let mut state = DashboardState::new();
        let p1 = make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Established,
            Some(PeerType::External),
        );
        let p2 = make_peer(
            Ipv4Addr::new(10, 0, 0, 2),
            SessionState::Established,
            Some(PeerType::Internal),
        );
        state.apply_peer_event(peer_event(PeerEventType::Current, p1));
        state.apply_peer_event(peer_event(PeerEventType::Changed, p2));
        assert_eq!(state.peers.len(), 2);
    }

    #[test]
    fn apply_peer_end_initial_is_noop() {
        let mut state = DashboardState::new();
        state.apply_peer_event(end_initial_peer());
        assert!(state.peers.is_empty());
        assert!(state.last_error.is_none());
    }

    #[test]
    fn apply_peer_error_sets_last_error() {
        let mut state = DashboardState::new();
        state.apply_peer_event(Err(rpc_error()));
        assert!(state.last_error.is_some());
        assert!(state.last_error.as_deref().unwrap().contains("daemon down"));
    }

    #[test]
    fn apply_peer_success_clears_last_error() {
        let mut state = DashboardState::new();
        state.apply_peer_event(Err(rpc_error()));
        assert!(state.last_error.is_some());

        let p = make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Established,
            Some(PeerType::External),
        );
        state.apply_peer_event(peer_event(PeerEventType::Current, p));
        assert!(state.last_error.is_none());
    }

    // ── apply_route_event ────────────────────────────────────────────────────

    #[test]
    fn apply_route_current_inserts_new_route() {
        let mut state = DashboardState::new();
        let r = make_route("10.0.0.0/8", Ipv4Addr::new(10, 0, 0, 1));
        state.apply_route_event(route_current(r));
        assert_eq!(state.routes.len(), 1);
        assert!(state.last_error.is_none());
    }

    #[test]
    fn apply_route_announced_inserts_new_route() {
        let mut state = DashboardState::new();
        let r = make_route("192.0.2.0/24", Ipv4Addr::new(10, 0, 0, 1));
        state.apply_route_event(route_announced(r));
        assert_eq!(state.routes.len(), 1);
    }

    #[test]
    fn apply_route_announced_updates_existing_prefix() {
        let mut state = DashboardState::new();
        let prefix = "10.0.0.0/8";
        let r1 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        state.apply_route_event(route_announced(r1));

        let mut r2 = make_route(prefix, Ipv4Addr::new(10, 0, 0, 2));
        r2.med = Some(100);
        state.apply_route_event(route_announced(r2));

        // Same prefix — updated in place, not duplicated.
        assert_eq!(state.routes.len(), 1);
        assert_eq!(state.routes[0].med, Some(100));
    }

    #[test]
    fn apply_route_withdrawn_removes_route() {
        let mut state = DashboardState::new();
        let prefix = "10.0.0.0/8";
        state.apply_route_event(route_announced(make_route(
            prefix,
            Ipv4Addr::new(10, 0, 0, 1),
        )));
        assert_eq!(state.routes.len(), 1);

        state.apply_route_event(route_withdrawn(prefix));
        assert!(state.routes.is_empty());
        assert!(state.last_error.is_none());
    }

    #[test]
    fn apply_route_withdrawn_unknown_prefix_is_noop() {
        let mut state = DashboardState::new();
        state.apply_route_event(route_announced(make_route(
            "10.0.0.0/8",
            Ipv4Addr::new(10, 0, 0, 1),
        )));
        state.apply_route_event(route_withdrawn("192.0.2.0/24")); // not present
        assert_eq!(state.routes.len(), 1); // original route untouched
    }

    #[test]
    fn apply_route_withdrawn_only_removes_matching_prefix() {
        let mut state = DashboardState::new();
        state.apply_route_event(route_announced(make_route(
            "10.0.0.0/8",
            Ipv4Addr::new(10, 0, 0, 1),
        )));
        state.apply_route_event(route_announced(make_route(
            "172.16.0.0/12",
            Ipv4Addr::new(10, 0, 0, 1),
        )));
        state.apply_route_event(route_withdrawn("10.0.0.0/8"));
        assert_eq!(state.routes.len(), 1);
        assert_eq!(state.routes[0].prefix, "172.16.0.0/12");
    }

    #[test]
    fn apply_route_end_initial_is_noop() {
        let mut state = DashboardState::new();
        state.apply_route_event(end_initial_route());
        assert!(state.routes.is_empty());
        assert!(state.last_error.is_none());
    }

    #[test]
    fn apply_route_error_sets_last_error() {
        let mut state = DashboardState::new();
        state.apply_route_event(Err(rpc_error()));
        assert!(state.last_error.is_some());
    }

    #[test]
    fn apply_route_success_clears_last_error() {
        let mut state = DashboardState::new();
        state.apply_route_event(Err(rpc_error()));
        state.apply_route_event(route_announced(make_route(
            "10.0.0.0/8",
            Ipv4Addr::new(10, 0, 0, 1),
        )));
        assert!(state.last_error.is_none());
    }

    // ── Helper functions ─────────────────────────────────────────────────────

    #[test]
    fn peer_type_str_external() {
        let p = make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Established,
            Some(PeerType::External),
        );
        assert_eq!(peer_type_str(&p), "eBGP");
    }

    #[test]
    fn peer_type_str_internal() {
        let p = make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Established,
            Some(PeerType::Internal),
        );
        assert_eq!(peer_type_str(&p), "iBGP");
    }

    #[test]
    fn peer_type_str_none() {
        let p = make_peer(Ipv4Addr::new(10, 0, 0, 1), SessionState::Idle, None);
        assert_eq!(peer_type_str(&p), "\u{2014}");
    }

    #[test]
    fn session_state_str_established() {
        let p = make_peer(Ipv4Addr::new(10, 0, 0, 1), SessionState::Established, None);
        assert_eq!(session_state_str(&p), "Established");
    }

    #[test]
    fn session_state_str_idle() {
        let p = make_peer(Ipv4Addr::new(10, 0, 0, 1), SessionState::Idle, None);
        assert_eq!(session_state_str(&p), "Idle");
    }

    #[test]
    fn format_origin_variants() {
        assert_eq!(format_origin(Origin::Igp), "IGP");
        assert_eq!(format_origin(Origin::Egp), "EGP");
        assert_eq!(format_origin(Origin::Incomplete), "?");
    }

    // ── build_status_bar_line ────────────────────────────────────────────────

    #[test]
    fn status_bar_live_contains_addr_and_live_indicator() {
        let line = build_status_bar_line("http://localhost:50051", None);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("Daemon: http://localhost:50051"),
            "addr: {text}"
        );
        assert!(text.contains("Live"), "live indicator: {text}");
        assert!(text.contains('q'), "quit hint: {text}");
    }

    #[test]
    fn status_bar_live_indicator_is_green() {
        let line = build_status_bar_line("http://127.0.0.1:50051", None);
        let live_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("Live"))
            .unwrap();
        assert_eq!(live_span.style.fg, Some(Color::Green));
    }

    #[test]
    fn status_bar_error_shows_message() {
        let line = build_status_bar_line("http://localhost:50051", Some("connection refused"));
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("error:"), "error label: {text}");
        assert!(text.contains("connection refused"), "error message: {text}");
    }

    #[test]
    fn status_bar_error_first_span_is_red() {
        let line = build_status_bar_line("http://localhost:50051", Some("oops"));
        assert_eq!(line.spans[0].style.fg, Some(Color::Red));
    }

    // ── Snapshot tests (ratatui TestBackend) ─────────────────────────────────

    use ratatui::backend::TestBackend;

    fn render_to_string(width: u16, height: u16, draw: impl FnOnce(&mut ratatui::Frame)) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(draw).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn snapshot_render_peers_empty() {
        let state = DashboardState::new();
        let output = render_to_string(80, 6, |f| {
            render_peers(f, &state, f.area());
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_peers_established() {
        let mut state = DashboardState::new();
        let mut peer = make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Established,
            Some(PeerType::External),
        );
        peer.uptime_seconds = 3661;
        peer.prefixes_received = 5;
        peer.prefixes_accepted = 4;
        peer.prefixes_advertised = 3;
        state.peers = vec![peer];
        let output = render_to_string(80, 6, |f| {
            render_peers(f, &state, f.area());
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_peers_idle() {
        let mut state = DashboardState::new();
        state.peers = vec![make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Idle,
            Some(PeerType::Internal),
        )];
        let output = render_to_string(80, 6, |f| {
            render_peers(f, &state, f.area());
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_routes_empty() {
        let state = DashboardState::new();
        let output = render_to_string(90, 6, |f| {
            render_routes(f, &state, f.area());
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_routes_with_route() {
        let mut state = DashboardState::new();
        state.routes = vec![make_route("192.0.2.0/24", Ipv4Addr::new(10, 0, 0, 1))];
        let output = render_to_string(90, 6, |f| {
            render_routes(f, &state, f.area());
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_status_bar_live() {
        let state = DashboardState::new();
        let output = render_to_string(80, 1, |f| {
            render_status_bar(f, &state, "http://127.0.0.1:50051", f.area());
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_status_bar_error() {
        let mut state = DashboardState::new();
        state.last_error = Some("connection refused".to_owned());
        let output = render_to_string(80, 1, |f| {
            render_status_bar(f, &state, "http://127.0.0.1:50051", f.area());
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_render_full_populated() {
        let mut state = DashboardState::new();
        let mut peer = make_peer(
            Ipv4Addr::new(10, 0, 0, 1),
            SessionState::Established,
            Some(PeerType::External),
        );
        peer.uptime_seconds = 7322;
        peer.prefixes_received = 10;
        peer.prefixes_accepted = 8;
        peer.prefixes_advertised = 6;
        state.peers = vec![peer];
        state.routes = vec![make_route("192.0.2.0/24", Ipv4Addr::new(10, 0, 0, 1))];
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
