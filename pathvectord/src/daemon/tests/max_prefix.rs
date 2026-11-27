//! ── RFC 4486 §4: Maximum Prefix Limits ───────────────────────────────────────

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use pathvector_session::fsm::SessionInfo;
use pathvector_session::message::{CeaseError, NotificationError, PathAttribute, UpdateMessage};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AsPath, Asn, Nlri, Origin, PeerType};

use crate::config;
use crate::daemon::*;

const LOCAL_AS: u32 = 65001;
const PEER_AS: u32 = 65002;
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn make_state_with_limit(
    limit: u32,
    restart_secs: u16,
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let (tx, rx) = mpsc::channel::<UpdateMessage>(256);
    let mut receivers = HashMap::new();
    receivers.insert(IpAddr::V4(PEER_IP), rx);
    let peer_configs = vec![config::PeerConfig {
        address: IpAddr::V4(PEER_IP),
        port: 179,
        remote_as: PEER_AS,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: Some(limit),
        max_prefixes_v6: None,
        max_prefixes_restart: if restart_secs > 0 {
            Some(restart_secs)
        } else {
            None
        },
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }];
    let mut senders = HashMap::new();
    senders.insert(IpAddr::V4(PEER_IP), tx);
    let state = DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    (state, receivers)
}

fn establish(state: &mut DaemonState) {
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &[],
        None,
    );
}

fn announce(prefixes: &[&str]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
            PathAttribute::NextHop(PEER_IP),
        ],
        announced: prefixes.iter().map(|s| nlri(s)).collect(),
    }
}

/// Under the limit — no CEASE returned.
#[test]
fn no_cease_when_under_limit() {
    let (mut state, _rxs) = make_state_with_limit(5, 0);
    establish(&mut state);
    let result = state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["10.0.0.0/8", "192.168.0.0/24"]),
    );
    assert!(
        result.is_none(),
        "no notification expected when prefix count is below the limit"
    );
}

/// Exactly at the limit — no CEASE.
#[test]
fn no_cease_at_exact_limit() {
    let (mut state, _rxs) = make_state_with_limit(2, 0);
    establish(&mut state);
    let result = state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["10.0.0.0/8", "192.168.0.0/24"]),
    );
    assert!(
        result.is_none(),
        "no notification expected when prefix count equals the limit"
    );
}

/// One prefix over the limit — CEASE/MaximumNumberOfPrefixesReached returned.
#[test]
fn cease_when_limit_exceeded() {
    let (mut state, _rxs) = make_state_with_limit(2, 0);
    establish(&mut state);
    let result = state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12"]),
    );
    let notification = result.expect("CEASE notification must be returned when limit is exceeded");
    assert!(
        matches!(
            notification.error,
            NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
        ),
        "error code must be CEASE/MaximumNumberOfPrefixesReached (RFC 4486 §4)"
    );
}

/// With restart configured, idle-hold deadline is set after CEASE.
#[test]
fn idle_hold_inserted_when_restart_configured() {
    let (mut state, _rxs) = make_state_with_limit(1, 60);
    establish(&mut state);
    let result = state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["10.0.0.0/8", "192.168.0.0/24"]),
    );
    assert!(result.is_some(), "CEASE must be returned");
    assert!(
        state.max_prefix_idle.contains_key(&IpAddr::V4(PEER_IP)),
        "max_prefix_idle must be set for the peer when restart_secs > 0"
    );
    let deadline = state.max_prefix_idle[&IpAddr::V4(PEER_IP)];
    assert!(deadline > Instant::now(), "deadline must be in the future");
}

/// Without restart, no idle-hold deadline is set and the peer is latched.
#[test]
fn no_idle_hold_without_restart() {
    let (mut state, _rxs) = make_state_with_limit(1, 0);
    establish(&mut state);
    let result = state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["10.0.0.0/8", "192.168.0.0/24"]),
    );
    assert!(result.is_some(), "CEASE must be returned");
    assert!(
        !state.max_prefix_idle.contains_key(&IpAddr::V4(PEER_IP)),
        "max_prefix_idle must NOT be set when max_prefixes_restart is not configured"
    );
    assert!(state.max_prefix_latched.contains(&IpAddr::V4(PEER_IP)));
    // Removing the peer is what clears the latch.
    state.remove_peer(IpAddr::V4(PEER_IP));
    assert!(!state.max_prefix_latched.contains(&IpAddr::V4(PEER_IP)));
}

/// Peer with no max_prefixes configured is never subject to the limit.
#[test]
fn no_limit_when_unconfigured() {
    let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
    let peer_configs = vec![config::PeerConfig {
        address: IpAddr::V4(PEER_IP),
        port: 179,
        remote_as: PEER_AS,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }];
    let mut senders = HashMap::new();
    senders.insert(IpAddr::V4(PEER_IP), tx);
    let mut state = DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    establish(&mut state);
    // Send 100 prefixes — no limit should fire.
    let prefixes: Vec<String> = (0u8..100).map(|i| format!("10.{i}.0.0/24")).collect();
    let prefix_strs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let result = state.on_route_update(IpAddr::V4(PEER_IP), announce(&prefix_strs));
    assert!(
        result.is_none(),
        "no limit when max_prefixes is not configured"
    );
}

/// `add_peer` wires max_prefixes into the runtime maps.
#[test]
fn add_peer_populates_max_prefix_maps() {
    let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
    let peer_cfg = config::PeerConfig {
        address: IpAddr::V4(PEER_IP),
        port: 179,
        remote_as: PEER_AS,
        import_default: None,
        export_default: None,
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: Some(50),
        max_prefixes_v6: Some(200),
        max_prefixes_restart: Some(30),
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    let mut state = DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[],
        HashMap::new(),
        vec![],
    );
    state.add_peer(&peer_cfg, tx);
    assert_eq!(
        state
            .peer_max_prefixes_v4
            .get(&IpAddr::V4(PEER_IP))
            .copied(),
        Some(50)
    );
    assert_eq!(
        state
            .peer_max_prefixes_v6
            .get(&IpAddr::V4(PEER_IP))
            .copied(),
        Some(200)
    );
    assert_eq!(
        state
            .peer_max_prefixes_restart
            .get(&IpAddr::V4(PEER_IP))
            .copied(),
        Some(30)
    );
}

/// `remove_peer` clears all three max-prefix maps.
#[test]
fn remove_peer_clears_max_prefix_maps() {
    let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
    let (mut state, _rxs) = make_state_with_limit(10, 60);
    establish(&mut state);
    // Trigger idle-hold by exceeding limit.
    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&[
            "10.0.0.0/8",
            "192.168.0.0/24",
            "172.16.0.0/12",
            "10.1.0.0/16",
            "10.2.0.0/16",
            "10.3.0.0/16",
            "10.4.0.0/16",
            "10.5.0.0/16",
            "10.6.0.0/16",
            "10.7.0.0/16",
            "10.8.0.0/16",
        ]),
    );
    // max_prefix_idle should now be set.
    assert!(state.max_prefix_idle.contains_key(&IpAddr::V4(PEER_IP)));

    state.remove_peer(IpAddr::V4(PEER_IP));

    assert!(
        !state
            .peer_max_prefixes_v4
            .contains_key(&IpAddr::V4(PEER_IP)),
        "peer_max_prefixes_v4 cleared"
    );
    assert!(
        !state
            .peer_max_prefixes_v6
            .contains_key(&IpAddr::V4(PEER_IP)),
        "peer_max_prefixes_v6 cleared"
    );
    assert!(
        !state
            .peer_max_prefixes_restart
            .contains_key(&IpAddr::V4(PEER_IP)),
        "peer_max_prefixes_restart cleared"
    );
    assert!(
        !state.max_prefix_idle.contains_key(&IpAddr::V4(PEER_IP)),
        "max_prefix_idle cleared"
    );
    drop(tx); // silence unused variable warning
}

// ── Event-loop integration tests ──────────────────────────────────────────
//
// These tests drive `run_event_loop` directly to verify the end-to-end
// behaviour of the max-prefix feature: CEASE delivery, idle-hold blocking,
// and idle-hold expiry.

fn peer_established_info(peer_as: u32) -> SessionInfo {
    SessionInfo {
        peer_as,
        peer_bgp_id: PEER_IP,
        hold_time: 90,
        peer_capabilities: vec![],
        peer_type: PeerType::External,
        local_addr: None,
    }
}

type EventLoopFixture = (
    Arc<RwLock<DaemonState>>,
    Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    mpsc::Receiver<SessionCommand>,
);

fn make_state_for_loop(
    peer_ip: IpAddr,
    peer_as: u32,
    limit: u32,
    restart_secs: u16,
) -> EventLoopFixture {
    // Keep the receiver alive: a closed outbound channel marks the peer
    // stalled, and its reset would be mistaken for the idle-hold one.
    let (update_tx, mut update_rx) = mpsc::channel::<UpdateMessage>(64);
    tokio::spawn(async move { while update_rx.recv().await.is_some() {} });
    let (stop_tx, stop_rx) = mpsc::channel::<SessionCommand>(8);
    let peer_cfg = config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: peer_as,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: Some(limit),
        max_prefixes_v6: None,
        max_prefixes_restart: if restart_secs > 0 {
            Some(restart_secs)
        } else {
            None
        },
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    let mut senders = HashMap::new();
    senders.insert(peer_ip, update_tx);
    let state = Arc::new(RwLock::new(DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[peer_cfg],
        senders,
        vec![],
    )));
    let mut stop_map = HashMap::new();
    stop_map.insert(peer_ip, stop_tx);
    let stop_senders = Arc::new(Mutex::new(stop_map));
    (state, stop_senders, stop_rx)
}

/// RFC 4486 §4 MUST: exceeding the limit causes the event loop to send
/// CEASE/MaximumNumberOfPrefixesReached to the peer's session.
#[tokio::test]
async fn event_loop_sends_cease_when_limit_exceeded() {
    let peer_ip = PEER_IP;
    let (state, stop_senders, mut stop_rx) =
        make_state_for_loop(IpAddr::V4(peer_ip), PEER_AS, 2, 0);

    state.write().await.on_established(
        IpAddr::V4(peer_ip),
        peer_ip,
        PeerType::External,
        PEER_AS,
        90,
        &[],
        None,
    );

    let (event_tx, event_rx) = mpsc::channel(8);
    // 3 prefixes exceed limit of 2.
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::RouteUpdate(announce(&["10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12"])),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    )
    .await;

    let cmd = stop_rx
        .try_recv()
        .expect("peer must receive a SessionCommand when limit is exceeded");
    let is_max_prefix_cease = matches!(
        &cmd,
        SessionCommand::Notification(n)
            if matches!(
                n.error,
                NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
            )
    );
    assert!(
        is_max_prefix_cease,
        "command must be CEASE/MaximumNumberOfPrefixesReached (RFC 4486 §4), got: {cmd:?}"
    );
}

/// RFC 4486 §4 — after a CEASE the session terminates. The subsequent
/// Terminated event must flush the peer's routes from Loc-RIB so no stale
/// routes from the over-limit UPDATE persist.
#[tokio::test]
async fn over_limit_routes_flushed_after_termination() {
    let peer_ip = PEER_IP;
    let (state, stop_senders, _stop_rx) = make_state_for_loop(IpAddr::V4(peer_ip), PEER_AS, 2, 0);

    state.write().await.on_established(
        IpAddr::V4(peer_ip),
        peer_ip,
        PeerType::External,
        PEER_AS,
        90,
        &[],
        None,
    );

    let (event_tx, event_rx) = mpsc::channel(8);
    // 3 prefixes exceed limit of 2.
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::RouteUpdate(announce(&["10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12"])),
        ))
        .await
        .unwrap();
    // Session layer responds to CEASE with a Terminated event.
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::Terminated(TerminationReason::OperatorStop),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    )
    .await;

    let s = state.read().await;
    assert_eq!(
        s.rib.loc_rib.len(),
        0,
        "Loc-RIB must be empty after over-limit update + termination"
    );
}

/// Idle-hold: a reconnect attempt during the hold window must be rejected
/// with a stop; the peer must NOT be established.
#[tokio::test]
async fn event_loop_idle_hold_blocks_reconnect() {
    let peer_ip = PEER_IP;
    // 300-second idle-hold so it does not expire during the test.
    let (state, stop_senders, mut stop_rx) =
        make_state_for_loop(IpAddr::V4(peer_ip), PEER_AS, 1, 300);

    state.write().await.on_established(
        IpAddr::V4(peer_ip),
        peer_ip,
        PeerType::External,
        PEER_AS,
        90,
        &[],
        None,
    );

    let (event_tx, event_rx) = mpsc::channel(16);
    // 2 prefixes exceed limit of 1 → CEASE + idle-hold inserted.
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::RouteUpdate(announce(&["10.0.0.0/8", "192.168.0.0/24"])),
        ))
        .await
        .unwrap();
    // Session terminates.
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::Terminated(TerminationReason::OperatorStop),
        ))
        .await
        .unwrap();
    // Peer reconnects immediately — must be blocked.
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::Established(peer_established_info(PEER_AS)),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    )
    .await;

    // First command: CEASE for the over-limit UPDATE.
    let first = stop_rx.try_recv().expect("first command must be CEASE");
    assert!(
        matches!(
            first,
            SessionCommand::Notification(n)
                if matches!(
                    n.error,
                    NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
                )
        ),
        "first command must be CEASE/MaximumNumberOfPrefixesReached"
    );

    // Next, apart from the post-teardown capability refresh: stop the
    // blocked reconnect.
    let second = std::iter::from_fn(|| stop_rx.try_recv().ok())
        .find(|c| !matches!(c, SessionCommand::SetCapabilities(_)))
        .expect("second command must stop the blocked reconnect");
    assert!(
        matches!(
            &second,
            SessionCommand::Notification(n)
                if n.error == NotificationError::Cease(CeaseError::ConnectionRejected)
        ),
        "reconnect during idle-hold must be stopped, got: {second:?}"
    );

    // Peer must not be established (no peer_type entry).
    let s = state.read().await;
    assert!(
        !s.rib.peer_types.contains_key(&IpAddr::V4(peer_ip)),
        "peer must not be established while idle-hold is active"
    );
}

/// Idle-hold expiry: the timer branch in the event loop removes a deadline
/// that has already passed, allowing the next reconnect to succeed.
///
/// Strategy: bypass the RouteUpdate/Terminated path (tested elsewhere) and
/// insert an already-expired deadline directly into `max_prefix_idle`. This
/// makes the timer arm fire on the first `select!` iteration without needing
/// `start_paused` or time-advance coordination.
#[tokio::test]
async fn event_loop_idle_hold_timer_clears_expired_deadline() {
    let peer_ip = PEER_IP;
    let (state, stop_senders, _stop_rx) = make_state_for_loop(IpAddr::V4(peer_ip), PEER_AS, 100, 0);

    // Insert an idle-hold deadline that is already in the past.
    let expired = Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap();
    state
        .write()
        .await
        .max_prefix_idle
        .insert(IpAddr::V4(peer_ip), expired);

    // Run the event loop with a single no-op event then close the channel.
    // The loop will see both the expired timer and the closed channel on
    // the first select! iteration.  We send a Terminated for a peer that
    // was never established (on_terminated is a no-op in that case) so
    // the loop also processes something and doesn't immediately break —
    // the timer branch wins the select! race at least once.
    let (event_tx, event_rx) = mpsc::channel(4);
    let loop_handle = tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    ));

    // Give the spawned loop time to enter select! and fire the timer.
    for _ in 0..20 {
        tokio::task::yield_now().await;
        if !state
            .read()
            .await
            .max_prefix_idle
            .contains_key(&IpAddr::V4(peer_ip))
        {
            break;
        }
    }

    assert!(
        !state
            .read()
            .await
            .max_prefix_idle
            .contains_key(&IpAddr::V4(peer_ip)),
        "timer branch must remove an expired idle-hold deadline"
    );

    drop(event_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), loop_handle).await;
}

/// Idle-hold blocks reconnects arriving in the coalesced drain loop
/// (try_recv path), not just the primary await path.
#[tokio::test]
async fn event_loop_idle_hold_blocks_reconnect_in_drain_loop() {
    let peer_ip = PEER_IP;
    let (state, stop_senders, mut stop_rx) =
        make_state_for_loop(IpAddr::V4(peer_ip), PEER_AS, 1, 300);

    state.write().await.on_established(
        IpAddr::V4(peer_ip),
        peer_ip,
        PeerType::External,
        PEER_AS,
        90,
        &[],
        None,
    );

    let (event_tx, event_rx) = mpsc::channel(16);

    // Pre-fill channel: first event wakes the loop, subsequent events land
    // in the try_recv drain. The Established arrives in the drain loop.
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::RouteUpdate(announce(&["10.0.0.0/8", "192.168.0.0/24"])),
        ))
        .await
        .unwrap();
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::Terminated(TerminationReason::OperatorStop),
        ))
        .await
        .unwrap();
    event_tx
        .send((
            IpAddr::V4(peer_ip),
            SessionEvent::Established(peer_established_info(PEER_AS)),
        ))
        .await
        .unwrap();

    // Yield before dropping so all three events are in the channel before
    // the loop wakes, maximising the chance the Established is seen during drain.
    tokio::task::yield_now().await;
    drop(event_tx);

    run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    )
    .await;

    // Collect all commands sent to the peer.
    let mut cmds = Vec::new();
    while let Ok(cmd) = stop_rx.try_recv() {
        cmds.push(cmd);
    }

    let has_cease = cmds.iter().any(|c| {
        matches!(
            c,
            SessionCommand::Notification(n)
                if matches!(
                    n.error,
                    NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
                )
        )
    });
    let has_stop = cmds.iter().any(|c| {
        matches!(
            c,
            SessionCommand::Notification(n)
                if n.error == NotificationError::Cease(CeaseError::ConnectionRejected)
        )
    });

    assert!(has_cease, "peer must receive CEASE for over-limit update");
    assert!(
        has_stop,
        "reconnect during idle-hold must be stopped (drain-loop path)"
    );
    assert!(
        !state
            .read()
            .await
            .rib
            .peer_types
            .contains_key(&IpAddr::V4(peer_ip)),
        "peer must not be established while idle-hold is active"
    );
}

// ── Two-peer displaced best-path test ─────────────────────────────────────
//
// Scenario: Peer A holds 10.0.0.0/8. Peer B (limit=1) sends 10.0.0.0/8
// plus 192.168.0.0/24, exceeding the limit. handle_update runs fully —
// AdjRibIn_B gets both routes and LocRib may temporarily prefer Peer B's
// route — but FIB changes are NOT applied (we return CEASE early). After
// on_terminated(B) the LocRib must revert to Peer A's 10.0.0.0/8, and
// 192.168.0.0/24 must be absent (Peer B was the only contributor).

const PEER_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const AS_A: u32 = 65100;
const AS_B: u32 = 65200;

fn announce_from(peer_ip: IpAddr, peer_as: u32, prefixes: &[&str]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(peer_as)])),
            PathAttribute::NextHop(must_v4(peer_ip)),
        ],
        announced: prefixes.iter().map(|s| nlri(s)).collect(),
    }
}

fn peer_cfg(address: IpAddr, remote_as: u32, v4_limit: Option<u32>) -> config::PeerConfig {
    config::PeerConfig {
        address,
        port: 179,
        remote_as,
        import_default: Some(config::ImportDefault::Accept),
        import_default_v6: None,
        export_default: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: v4_limit,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }
}

fn make_two_peer_state() -> (
    DaemonState,
    tokio::sync::mpsc::Receiver<UpdateMessage>,
    tokio::sync::mpsc::Receiver<UpdateMessage>,
) {
    let (tx_a, rx_a) = tokio::sync::mpsc::channel::<UpdateMessage>(256);
    let (tx_b, rx_b) = tokio::sync::mpsc::channel::<UpdateMessage>(256);
    let mut senders = HashMap::new();
    senders.insert(IpAddr::V4(PEER_A), tx_a);
    senders.insert(IpAddr::V4(PEER_B), tx_b);

    let mut state = DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[
            peer_cfg(IpAddr::V4(PEER_A), AS_A, None),
            peer_cfg(IpAddr::V4(PEER_B), AS_B, Some(1)),
        ],
        senders,
        vec![],
    );
    state.on_established(
        IpAddr::V4(PEER_A),
        PEER_A,
        PeerType::External,
        AS_A,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(PEER_B),
        PEER_B,
        PeerType::External,
        AS_B,
        90,
        &[],
        None,
    );
    (state, rx_a, rx_b)
}

/// When Peer B exceeds the limit and sends a CEASE, Peer B's routes (including
/// one that displaced Peer A's best path) must be fully withdrawn from the
/// LocRib after on_terminated. The FIB was never updated to Peer B's route,
/// so on_terminated reverts cleanly without exposing a transient state.
#[test]
fn displaced_best_path_reverts_after_termination() {
    use pathvector_rib::PeerId;
    use std::net::IpAddr;
    let (mut state, _rx_a, _rx_b) = make_two_peer_state();

    let shared: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    let b_only: Nlri<Ipv4Addr> = "192.168.0.0/24".parse().unwrap();
    let peer_a_id = PeerId::new(IpAddr::V4(PEER_A));

    // Step 1: Peer A owns 10.0.0.0/8.
    let r = state.on_route_update(
        IpAddr::V4(PEER_A),
        announce_from(IpAddr::V4(PEER_A), AS_A, &["10.0.0.0/8"]),
    );
    assert!(r.is_none(), "Peer A must not trigger a CEASE");
    assert_eq!(
        state.rib.loc_rib.best_peer(&shared),
        Some(peer_a_id),
        "Peer A must be best for 10.0.0.0/8 before Peer B arrives"
    );

    // Step 2: Peer B exceeds limit (1) by sending 2 prefixes.
    // handle_update runs fully — LocRib may swap best path to Peer B —
    // but on_route_update returns CEASE without applying FIB changes.
    let r = state.on_route_update(
        IpAddr::V4(PEER_B),
        announce_from(IpAddr::V4(PEER_B), AS_B, &["10.0.0.0/8", "192.168.0.0/24"]),
    );
    assert!(
        r.as_ref().is_some_and(|n| matches!(
            n.error,
            NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
        )),
        "Peer B must receive CEASE/MaximumNumberOfPrefixesReached"
    );

    // Step 3: Terminate Peer B. LocRib must revert fully to Peer A's world.
    state.on_terminated(IpAddr::V4(PEER_B), TerminationReason::OperatorStop, true);

    assert_eq!(
        state.rib.loc_rib.best_peer(&shared),
        Some(peer_a_id),
        "Peer A must be best for 10.0.0.0/8 after Peer B termination"
    );
    assert!(
        state.rib.loc_rib.best_peer(&b_only).is_none(),
        "192.168.0.0/24 must be absent — Peer B was the only contributor"
    );
    let adj_b = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_B))
        .map_or(0, AdjRibIn::len);
    assert_eq!(adj_b, 0, "Peer B AdjRibIn must be empty after termination");
}

/// IPv6-limit fires independently of the IPv4 limit.
#[test]
fn cease_when_v6_limit_exceeded() {
    use pathvector_session::message::{MpReachNlri, Prefix};
    use pathvector_types::AfiSafi;
    use pathvector_types::NextHop;

    let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
    let (tx, _rx) = tokio::sync::mpsc::channel::<UpdateMessage>(256);
    let mut senders = HashMap::new();
    senders.insert(IpAddr::V4(peer_ip), tx);

    let cfg = config::PeerConfig {
        address: IpAddr::V4(peer_ip),
        port: 179,
        remote_as: 65099,
        import_default: None,
        import_default_v6: None,
        export_default: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: Some(1),
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    let mut state = DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[cfg],
        senders,
        vec![],
    );
    state.on_established(
        IpAddr::V4(peer_ip),
        peer_ip,
        PeerType::External,
        65099,
        90,
        &[],
        None,
    );

    let v6_nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let pfx1: Nlri<std::net::Ipv6Addr> = "2001:db8::/32".parse().unwrap();
    let pfx2: Nlri<std::net::Ipv6Addr> = "2001:db8:1::/48".parse().unwrap();

    let update = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65099)])),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(v6_nh),
                prefixes: vec![Prefix::V6(pfx1), Prefix::V6(pfx2)],
            }),
        ],
        announced: vec![],
    };

    let result = state.on_route_update(IpAddr::V4(peer_ip), update);
    assert!(
        result.as_ref().is_some_and(|n| matches!(
            n.error,
            NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
        )),
        "must CEASE when IPv6 limit exceeded; got: {result:?}"
    );
    // The UPDATE carried no IPv4 NLRI, so the IPv4 Adj-RIB-In must be
    // empty — confirming the limits are checked independently, not combined.
    let v4_count = state
        .adj_ribs_in
        .get(&IpAddr::V4(peer_ip))
        .map_or(0, AdjRibIn::len);
    assert_eq!(
        v4_count, 0,
        "IPv4 Adj-RIB-In must be empty when only IPv6 prefixes were sent"
    );
}
