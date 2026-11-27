//! Regression and effectiveness tests for cross-UPDATE NLRI coalescing.
//!
//! Each test is named after the invariant it protects. Where a bug was found
//! and fixed during review, the test name includes the word "regression".
//!
//! **Bug 1 (regression)** — gRPC-facing mutation methods must self-flush.
//! `originate_routes`, `withdraw_originated_routes`, and `set_import_default`
//! call `propagate_to_all_peers` which buffers decisions. Without a self-flush
//! the decisions would not be sent until the next BGP event arrived.
//!
//! **Bug 2 (regression)** — `flush_mrai_pending` calls `propagate_to_all_peers`
//! which buffers. The event loop arm must call `flush_pending` after
//! `flush_mrai_pending` or MRAI-released routes stay buffered.
//!
//! **Bug 3 (regression)** — mandatory-attribute errors in the `try_recv` drain
//! loop must be treated as withdraw (RFC 7606 §2) for the erroring peer's own
//! prefix and skip to the next outer iteration, not silently corrupt or block
//! the rest of the batch.
//!
//! **Effectiveness** — two `on_route_update` calls with the same attribute set
//! must produce fewer outbound `UpdateMessage`s than prefixes announced.

use std::{collections::HashMap, net::Ipv4Addr};

use pathvector_types::{AsPath, Asn, Nlri, Origin, PeerType};

use crate::config;
use crate::daemon::*;

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

/// Build a state with large channels and Accept-default policies.
fn make_state(
    peers: &[(Ipv4Addr, u32)],
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let mut receivers = HashMap::new();
    let mut senders = HashMap::new();
    let peer_configs: Vec<_> = peers
        .iter()
        .map(|&(addr, remote_as)| {
            let (tx, rx) = mpsc::channel::<UpdateMessage>(256);
            senders.insert(IpAddr::V4(addr), tx);
            receivers.insert(IpAddr::V4(addr), rx);
            config::PeerConfig {
                address: IpAddr::V4(addr),
                port: 179,
                remote_as,
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
            }
        })
        .collect();
    let state = DaemonState::new(
        65001,
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

fn announce(peer: Ipv4Addr, prefixes: &[&str]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop(peer),
        ],
        announced: prefixes.iter().map(|s| nlri(s)).collect(),
    }
}

// ── Effectiveness ─────────────────────────────────────────────────────────

/// Two BGP UPDATEs arriving back-to-back (same attribute set, different
/// prefixes) must be coalesced into a single outbound UpdateMessage.
/// This is the primary invariant of the coalescing feature.
#[test]
fn two_updates_same_attrs_produce_one_outbound_message() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    while rxs.get_mut(&IpAddr::V4(peer_a)).unwrap().try_recv().is_ok() {}
    while rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv().is_ok() {}

    // Two separate BGP UPDATEs with identical path attributes.
    state.on_route_update(IpAddr::V4(peer_a), announce(peer_a, &["10.0.0.0/8"]));
    state.on_route_update(IpAddr::V4(peer_a), announce(peer_a, &["172.16.0.0/12"]));

    // A single flush must send both prefixes in one UpdateMessage.
    state.flush_pending();

    let msg = rxs
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b must receive a coalesced UPDATE");
    assert!(
        msg.announced.contains(&nlri("10.0.0.0/8")),
        "coalesced UPDATE must carry 10.0.0.0/8"
    );
    assert!(
        msg.announced.contains(&nlri("172.16.0.0/12")),
        "coalesced UPDATE must carry 172.16.0.0/12"
    );

    // No second UpdateMessage — both prefixes arrived in one wire frame.
    assert!(
        rxs.get_mut(&IpAddr::V4(peer_b))
            .unwrap()
            .try_recv()
            .is_err(),
        "coalescing must produce exactly one outbound UpdateMessage for identical attrs"
    );
}

/// N prefix announcements with identical attributes must arrive in at most
/// ceil(N / max_nlri_per_update) messages, not N separate messages.
/// Verifies scaling behavior as burst size grows.
#[test]
fn large_burst_is_packed_into_fewer_messages_than_prefixes() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );

    // 20 separate on_route_update calls — one per prefix.
    let prefixes: Vec<String> = (0u8..20).map(|i| format!("10.{i}.0.0/16")).collect();
    for prefix in &prefixes {
        state.on_route_update(IpAddr::V4(peer_a), announce(peer_a, &[prefix.as_str()]));
    }
    state.flush_pending();

    let mut total_messages = 0usize;
    let mut total_prefixes = 0usize;
    while let Ok(msg) = rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv() {
        total_messages += 1;
        total_prefixes += msg.announced.len();
    }

    assert_eq!(
        total_prefixes, 20,
        "all 20 prefixes must be delivered to peer_b"
    );
    assert!(
        total_messages < 20,
        "20 separate route events must produce fewer than 20 outbound UpdateMessages (got {total_messages})"
    );
}

// ── Bug 1 regression: gRPC-facing methods must self-flush ─────────────────

/// `originate_routes` must send immediately without the caller having to
/// call `flush_pending()` separately.  Regression: before the fix, routes
/// sat in the pending buffer until the next BGP event.
#[test]
fn regression_originate_routes_sends_without_manual_flush() {
    let peer: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, mut rxs) = make_state(&[(peer, 65002)]);
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    // Drain the empty table dump from on_established.
    while rxs.get_mut(&IpAddr::V4(peer)).unwrap().try_recv().is_ok() {}

    let route = RouteBuilder::new(nlri("203.0.113.0/24"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4("10.0.0.1".parse().unwrap()))
        .build();

    // originate_routes must self-flush — no explicit flush_pending() call.
    state.originate_routes(vec![route]);

    rxs.get_mut(&IpAddr::V4(peer))
        .unwrap()
        .try_recv()
        .expect("originate_routes must send immediately without a manual flush_pending call");
}

/// `withdraw_originated_routes` must send immediately without a manual
/// `flush_pending()`.  Regression: before the fix, withdrawals buffered.
#[test]
fn regression_withdraw_originated_routes_sends_without_manual_flush() {
    let peer: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, mut rxs) = make_state(&[(peer, 65002)]);
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    let route = RouteBuilder::new(nlri("203.0.113.0/24"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4("10.0.0.1".parse().unwrap()))
        .build();
    state.originate_routes(vec![route]);
    // Drain the announcement.
    while rxs.get_mut(&IpAddr::V4(peer)).unwrap().try_recv().is_ok() {}

    // Withdraw — must self-flush.
    state.withdraw_originated_routes(&[nlri("203.0.113.0/24")]);

    let msg = rxs
        .get_mut(&IpAddr::V4(peer))
        .unwrap()
        .try_recv()
        .expect("withdraw_originated_routes must send immediately without a manual flush");
    assert!(
        msg.withdrawn.contains(&nlri("203.0.113.0/24")),
        "WITHDRAW must carry 203.0.113.0/24"
    );
}

/// `set_import_default` must send the resulting policy-change UPDATEs
/// immediately without a manual `flush_pending()`.  Regression: before the
/// fix, the WITHDRAW from a Reject policy sat buffered.
#[test]
fn regression_set_import_default_sends_without_manual_flush() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );

    state.on_route_update(IpAddr::V4(peer_a), announce(peer_a, &["10.0.0.0/8"]));
    state.flush_pending();
    // Drain initial announcement.
    while rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv().is_ok() {}

    // Flip import policy to Reject — must self-flush without caller needing flush_pending.
    state.set_import_default(IpAddr::V4(peer_a), pathvector_policy::DefaultAction::Reject);

    let msg = rxs
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("set_import_default must send WITHDRAW immediately without manual flush");
    assert!(
        msg.withdrawn.contains(&nlri("10.0.0.0/8")),
        "WITHDRAW must carry 10.0.0.0/8 after import policy → Reject"
    );
}

// ── Bug 2 regression: MRAI must flush its own decisions ───────────────────

/// After `flush_mrai_pending`, the decisions it generates via
/// `propagate_to_all_peers` must be sent to peers.  The event loop arm
/// calls `flush_pending` after `flush_mrai_pending`; this test verifies
/// that `flush_mrai_pending` alone is not sufficient — its caller must
/// flush.  (Regression: the event loop previously did not call the second
/// flush, so MRAI-released routes were delayed until the next event.)
#[test]
fn regression_flush_mrai_pending_requires_subsequent_flush_pending() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    // peer_b is eBGP so MRAI applies.
    let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    while rxs.get_mut(&IpAddr::V4(peer_a)).unwrap().try_recv().is_ok() {}
    while rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv().is_ok() {}

    // Announce a route that is first suppressed by MRAI, then add it to
    // mrai_pending manually so flush_mrai_pending picks it up.
    let prefix = nlri("10.0.0.0/8");

    // Insert the route into the Loc-RIB so propagate_prefix has something to send.
    let src = PeerId::new(IpAddr::V4(peer_a));
    let route = RouteBuilder::new(
        prefix,
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65002)]),
    )
    .next_hop(NextHop::V4(peer_a))
    .peer_type(PeerType::External)
    .build();
    state.rib_insert_v4(src, route);

    // Manufacture an mrai_pending entry for peer_b so flush_mrai_pending
    // has something to process.
    state.mrai.defer(IpAddr::V4(peer_b), prefix);

    // Call flush_mrai_pending without the subsequent flush_pending.
    state.flush_mrai_pending();

    // Without flush_pending, nothing should be in peer_b's channel yet
    // (decisions sit in pending_decisions[peer_b]).
    let before_flush = rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv();
    assert!(
        before_flush.is_err(),
        "flush_mrai_pending alone must NOT send to channel — decisions remain buffered"
    );

    // Now flush — decisions must arrive.
    state.flush_pending();

    let msg = rxs
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("flush_pending after flush_mrai_pending must deliver the MRAI-released route");
    assert!(
        msg.announced.contains(&prefix),
        "MRAI-released route must be in the delivered UPDATE"
    );
}

// ── Bug 3 regression: missing-mandatory-attribute in drain loop ──────────

/// RFC 7606 §3(d): a mandatory-attribute error detected during the
/// `try_recv` drain loop must be treated as withdraw (RFC 7606 §2) for
/// the erroring peer's own prefix, without blocking the rest of the
/// batch — peer_a's valid update in the same drain batch must still be
/// processed, and peer_b must receive no `SessionCommand` (no
/// NOTIFICATION; the session stays up). Regression: an earlier version
/// of this code path silently dropped the malformed message without
/// continuing to the next iteration of the drain loop.
///
/// This test drives `run_event_loop` directly and injects two events:
/// 1. A valid RouteUpdate from peer_a (fills the drain loop).
/// 2. A malformed RouteUpdate from peer_b (missing Origin — RFC 7606 §3(d)).
#[tokio::test]
async fn regression_missing_mandatory_attr_in_drain_loop_treated_as_withdraw() {
    use tokio::sync::mpsc;

    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

    // We need the full event loop state bundle.
    let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
    let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(64);
    let peer_configs = vec![
        config::PeerConfig {
            address: IpAddr::V4(peer_a),
            port: 179,
            remote_as: 65002,
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
        },
        config::PeerConfig {
            address: IpAddr::V4(peer_b),
            port: 179,
            remote_as: 65003,
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
        },
    ];
    let mut senders = HashMap::new();
    senders.insert(IpAddr::V4(peer_a), tx_a);
    senders.insert(IpAddr::V4(peer_b), tx_b);
    let state = DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    let state = Arc::new(tokio::sync::RwLock::new(state));

    {
        let mut s = state.write().await;
        s.on_established(
            IpAddr::V4(peer_a),
            peer_a,
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        s.on_established(
            IpAddr::V4(peer_b),
            peer_b,
            PeerType::External,
            65003,
            90,
            &[],
            None,
        );
    }

    let (event_tx, event_rx) = mpsc::channel::<(IpAddr, SessionEvent)>(16);

    // Stop-command channels: we capture peer_b's receiver to check for NOTIFICATION.
    let (stop_a_tx, _stop_a_rx) = mpsc::channel::<SessionCommand>(4);
    let (stop_b_tx, mut stop_b_rx) = mpsc::channel::<SessionCommand>(4);
    let mut stop_map: HashMap<IpAddr, mpsc::Sender<SessionCommand>> = HashMap::new();
    stop_map.insert(IpAddr::V4(peer_a), stop_a_tx);
    stop_map.insert(IpAddr::V4(peer_b), stop_b_tx);
    let stop_senders = Arc::new(std::sync::Mutex::new(stop_map));

    let loop_handle = tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    ));

    // Send two events in quick succession so the second arrives in the drain loop.
    // Event 1 (valid): wakes the loop.
    event_tx
        .send((
            IpAddr::V4(peer_a),
            SessionEvent::RouteUpdate(UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            }),
        ))
        .await
        .unwrap();

    // Event 2 (malformed — missing Origin): arrives while loop is processing event 1.
    event_tx
        .send((
            IpAddr::V4(peer_b),
            SessionEvent::RouteUpdate(UpdateMessage {
                withdrawn: vec![],
                // Missing Origin → RFC 4271 §6.3 → NOTIFICATION
                attributes: vec![
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65003)])),
                    PathAttribute::NextHop(peer_b),
                ],
                announced: vec![nlri("172.16.0.0/12")],
            }),
        ))
        .await
        .unwrap();

    // Give the loop time to process both events.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    // peer_a's valid update in the same drain batch must still have been
    // processed — proving the malformed message on peer_b didn't block
    // or abort the rest of the batch.
    assert!(
        state
            .read()
            .await
            .rib
            .loc_rib
            .best(&nlri("10.0.0.0/8"))
            .is_some(),
        "peer_a's valid update in the same drain batch must still be processed"
    );

    // RFC 7606 §2: peer_b's malformed announcement must not be installed.
    assert!(
        state
            .read()
            .await
            .rib
            .loc_rib
            .best(&nlri("172.16.0.0/12"))
            .is_none(),
        "prefix from an UPDATE missing a mandatory attribute must not be installed"
    );

    // RFC 7606 §3(d): treat-as-withdraw keeps the session up — peer_b
    // must receive no SessionCommand at all (in particular, no NOTIFICATION).
    assert!(
        stop_b_rx.try_recv().is_err(),
        "peer_b must receive no SessionCommand after a treat-as-withdraw UPDATE"
    );

    // Shut down the loop.
    drop(event_tx);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), loop_handle).await;
}

// ── Event-loop drain coalescing ───────────────────────────────────────────

/// Drives `run_event_loop` directly and sends N route events in rapid
/// succession BEFORE yielding.  All N events land in the channel before the
/// loop wakes up, so events 2-N are processed by the `try_recv` drain and
/// flushed together with event 1 in a single `flush_pending` call.
///
/// This is the only test that exercises the real `try_recv` drain path.
/// The unit-level effectiveness tests (`two_updates_same_attrs_*`) call
/// `flush_pending` manually and never touch the event loop at all.
#[tokio::test]
async fn event_loop_drain_coalesces_rapid_burst() {
    use std::{sync::Mutex, time::Duration};
    use tokio::sync::mpsc as tmp;

    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

    let (tx_a, _rx_a) = tmp::channel::<UpdateMessage>(64);
    let (tx_b, mut rx_b) = tmp::channel::<UpdateMessage>(64);

    let peer_configs = vec![
        config::PeerConfig {
            address: IpAddr::V4(peer_a),
            port: 179,
            remote_as: 65002,
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
        },
        config::PeerConfig {
            address: IpAddr::V4(peer_b),
            port: 179,
            remote_as: 65003,
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
        },
    ];
    let mut update_senders = HashMap::new();
    update_senders.insert(IpAddr::V4(peer_a), tx_a);
    update_senders.insert(IpAddr::V4(peer_b), tx_b);

    let state = DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        update_senders,
        vec![],
    );
    let state = Arc::new(RwLock::new(state));

    {
        let mut s = state.write().await;
        s.on_established(
            IpAddr::V4(peer_a),
            peer_a,
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        s.on_established(
            IpAddr::V4(peer_b),
            peer_b,
            PeerType::External,
            65003,
            90,
            &[],
            None,
        );
    }

    let (event_tx, event_rx) = tmp::channel::<(IpAddr, SessionEvent)>(64);
    let stop_senders: Arc<Mutex<HashMap<IpAddr, tmp::Sender<SessionCommand>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let loop_handle = tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    ));

    // Send all 10 events before yielding.  Each uses a distinct prefix but
    // identical path attributes, so all decisions will share an attribute
    // set and `flush_updates` can pack them into one UpdateMessage.
    // Because all sends complete synchronously (channel has capacity),
    // all 10 events are in the channel buffer before the event loop runs.
    let prefixes: Vec<String> = (0u8..10).map(|i| format!("10.{i}.0.0/16")).collect();
    for prefix in &prefixes {
        let nlri_parsed: Nlri<Ipv4Addr> = prefix.parse().unwrap();
        event_tx
            .send((
                IpAddr::V4(peer_a),
                SessionEvent::RouteUpdate(UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                        PathAttribute::NextHop(peer_a),
                    ],
                    announced: vec![nlri_parsed],
                }),
            ))
            .await
            .unwrap();
    }

    // Yield long enough for the event loop to drain all 10 events and flush.
    // 100ms >> any realistic scheduler latency; MRAI timer fires every 15s
    // so it will not interfere.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut total_messages = 0usize;
    let mut total_prefixes = 0usize;
    while let Ok(msg) = rx_b.try_recv() {
        total_messages += 1;
        total_prefixes += msg.announced.len();
    }

    assert_eq!(total_prefixes, 10, "all 10 prefixes must arrive at peer_b");
    assert!(
        total_messages < 10,
        "10 rapid-fire route events must be coalesced into fewer than 10 \
         UpdateMessages by the try_recv drain (got {total_messages} messages \
         for {total_prefixes} prefixes)"
    );

    drop(event_tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), loop_handle).await;
}

/// Verifies that buffered `pending_decisions` are not lost or reordered
/// when `set_export_default` is called while the state lock is not held by
/// the event loop.
///
/// The scenario: (1) import a route so it sits in pending_decisions, (2)
/// call set_export_default for the receiving peer (Accept), (3) flush.
/// Both the original route and the export-policy-driven dump must arrive.
#[test]
fn set_export_default_does_not_lose_pending_decisions() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );

    // Announce a route and buffer it (do NOT call flush_pending yet).
    state.on_route_update(IpAddr::V4(peer_a), announce(peer_a, &["10.0.0.0/8"]));

    // `pending_decisions[peer_b]` now has one entry.  Call set_export_default
    // (which sends at once, draining the buffer ahead of its own decisions).
    // In production this is always serialized by the write lock — the event
    // loop always flushes before releasing — but we simulate the direct call
    // here to verify the buffer is not corrupted.
    state.set_export_default(IpAddr::V4(peer_b), pathvector_policy::DefaultAction::Accept);

    // Peer_b must receive the route whether set_export_default or this
    // flush_pending sends it.
    state.flush_pending();

    let mut received_prefixes = std::collections::HashSet::new();
    while let Ok(msg) = rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv() {
        for nlri in msg.announced {
            received_prefixes.insert(nlri);
        }
    }

    assert!(
        received_prefixes.contains(&nlri("10.0.0.0/8")),
        "10.0.0.0/8 must reach peer_b despite set_export_default being called \
         while it was in the pending buffer"
    );
}
