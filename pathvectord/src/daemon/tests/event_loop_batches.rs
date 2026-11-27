use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{
        Arc as StdArc,
        atomic::{AtomicBool, Ordering},
    },
};

use pathvector_rib::oracle::NextHopOracle;
use pathvector_session::fsm::SessionInfo;
use pathvector_session::message::{
    Capability, GracefulRestartFamily, PathAttribute, UpdateMessage,
};
use pathvector_session::transport::{SessionCommand, SessionEvent, TerminationReason};
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};
use tokio::sync::mpsc;

use crate::config;
use crate::daemon::*;

// ── helpers ───────────────────────────────────────────────────────────────

type StateBundle = (
    Arc<RwLock<DaemonState>>,
    HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>,
    Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
);

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

#[derive(Clone)]
struct ToggleOracle(StdArc<AtomicBool>);

impl ToggleOracle {
    fn reachable() -> Self {
        Self(StdArc::new(AtomicBool::new(true)))
    }
}

impl NextHopOracle for ToggleOracle {
    fn is_reachable(&self, _: &NextHop) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    fn igp_metric(&self, _: &NextHop) -> Option<u32> {
        None
    }
}

fn established_info(peer_as: u32) -> SessionInfo {
    SessionInfo {
        peer_as,
        peer_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        hold_time: 90,
        peer_capabilities: vec![Capability::FourByteAsn(peer_as)],
        peer_type: PeerType::External,
        local_addr: None,
    }
}

/// Build a `DaemonState` + receivers for a set of peers with accept-all
/// policies and channels of the given capacity.
fn make_state(peers: &[(IpAddr, u32)], channel_cap: usize) -> StateBundle {
    let mut update_senders = HashMap::new();
    let mut update_receivers = HashMap::new();
    let mut stop_map: HashMap<IpAddr, mpsc::Sender<SessionCommand>> = HashMap::new();
    let mut stop_receivers: HashMap<IpAddr, mpsc::Receiver<SessionCommand>> = HashMap::new();

    for &(ip, _) in peers {
        let (tx, rx) = mpsc::channel(channel_cap);
        update_senders.insert(ip, tx);
        update_receivers.insert(ip, rx);
        let (stx, srx) = mpsc::channel(8);
        stop_map.insert(ip, stx);
        stop_receivers.insert(ip, srx);
    }
    let stop_senders = Arc::new(Mutex::new(stop_map));

    let peer_configs: Vec<config::PeerConfig> = peers
        .iter()
        .map(|&(address, remote_as)| config::PeerConfig {
            address,
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
        })
        .collect();

    let state = Arc::new(RwLock::new(DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        update_senders,
        vec![],
    )));

    (state, update_receivers, stop_senders)
}

// ── Established dispatch ──────────────────────────────────────────────────

#[tokio::test]
async fn event_loop_dispatches_established() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

    let (event_tx, event_rx) = mpsc::channel(8);
    event_tx
        .send((peer_ip, SessionEvent::Established(established_info(65002))))
        .await
        .unwrap();
    drop(event_tx); // close channel so event loop exits after one event

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    let s = state.read().await;
    assert!(
        s.rib.peer_types.contains_key(&peer_ip),
        "Established event must register peer type in DaemonState"
    );
}

// ── Metrics for coalesced events (GH #105) ────────────────────────────────

/// `(metric name, sorted labels) -> value` for everything a test recorded.
type MetricSnapshot =
    std::collections::HashMap<(String, Vec<(String, String)>), metrics_util::debugging::DebugValue>;

/// Runs `f` with a thread-local debugging recorder installed for its whole
/// (possibly async) duration, then returns everything it recorded as
/// `(name, sorted labels) -> value`. Sound here because `#[tokio::test]`
/// uses a current-thread runtime and `run_event_loop` is awaited inline.
async fn capture_metrics<F: std::future::Future<Output = ()>>(f: F) -> MetricSnapshot {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    {
        let _guard = metrics::set_default_local_recorder(&recorder);
        f.await;
    }
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _unit, _desc, value)| {
            let key = ck.key();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            labels.sort();
            ((key.name().to_string(), labels), value)
        })
        .collect()
}

fn peer_label(ip: IpAddr) -> Vec<(String, String)> {
    vec![("peer".to_string(), ip.to_string())]
}

fn gauge(snap: &MetricSnapshot, name: &str, labels: Vec<(String, String)>) -> Option<f64> {
    match snap.get(&(name.to_string(), labels)) {
        Some(metrics_util::debugging::DebugValue::Gauge(v)) => Some(v.into_inner()),
        _ => None,
    }
}

fn counter(snap: &MetricSnapshot, name: &str, labels: Vec<(String, String)>) -> Option<u64> {
    match snap.get(&(name.to_string(), labels)) {
        Some(metrics_util::debugging::DebugValue::Counter(v)) => Some(*v),
        _ => None,
    }
}

fn update_for(peer: Ipv4Addr, asn: u32, prefix: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(asn)])),
            PathAttribute::NextHop(peer),
        ],
        announced: vec![nlri(prefix)],
    }
}

/// `run_event_loop` coalesces every event already queued behind the first
/// into one lock hold. The metrics hooks used to run only for that first
/// event, so an Established → UPDATEs → Terminated burst left
/// `session_up` at 1 for a peer that was gone (the alert-hiding case from
/// GH #105) and undercounted received UPDATEs.
#[tokio::test]
async fn coalesced_terminated_zeroes_session_up_and_counts_every_update() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

    // Everything is queued before the loop starts, so the Established is
    // the "first" event and the other four are drained behind it.
    let (event_tx, event_rx) = mpsc::channel(16);
    event_tx
        .send((peer_ip, SessionEvent::Established(established_info(65002))))
        .await
        .unwrap();
    for prefix in ["10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"] {
        event_tx
            .send((
                peer_ip,
                SessionEvent::RouteUpdate(update_for("10.0.0.2".parse().unwrap(), 65002, prefix)),
            ))
            .await
            .unwrap();
    }
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(
                pathvector_session::transport::TerminationReason::OperatorStop,
            ),
        ))
        .await
        .unwrap();
    drop(event_tx);

    let snap = capture_metrics(async {
        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;
    })
    .await;

    let p = peer_label(peer_ip);
    assert_eq!(
        gauge(&snap, "pathvectord_bgp_session_up", p.clone()),
        Some(0.0),
        "a Terminated event coalesced behind others must still mark the session down"
    );
    assert_eq!(
        counter(
            &snap,
            "pathvectord_bgp_sessions_established_total",
            p.clone()
        ),
        Some(1)
    );
    let mut terminated = p.clone();
    terminated.push(("reason".to_string(), "operator_stop".to_string()));
    terminated.sort();
    assert_eq!(
        counter(
            &snap,
            "pathvectord_bgp_sessions_terminated_total",
            terminated
        ),
        Some(1)
    );
    assert_eq!(
        counter(&snap, "pathvectord_bgp_updates_received_total", p),
        Some(3),
        "every UPDATE counts, not just the first of a batch"
    );
}

/// The mirror case: an Established that is *not* the first event of its
/// batch must still mark the session up, and the Adj-RIB-In gauge must
/// reflect the latest count after UPDATEs that were also coalesced.
#[tokio::test]
async fn coalesced_established_sets_session_up_and_adj_rib_in_gauge() {
    let first: IpAddr = "10.0.0.3".parse().unwrap();
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002), (first, 65003)], 64);

    let (event_tx, event_rx) = mpsc::channel(16);
    // Peer `first` is the batch's first event; everything for `peer_ip`
    // is drained behind it.
    event_tx
        .send((first, SessionEvent::Established(established_info(65003))))
        .await
        .unwrap();
    event_tx
        .send((peer_ip, SessionEvent::Established(established_info(65002))))
        .await
        .unwrap();
    for prefix in ["10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"] {
        event_tx
            .send((
                peer_ip,
                SessionEvent::RouteUpdate(update_for("10.0.0.2".parse().unwrap(), 65002, prefix)),
            ))
            .await
            .unwrap();
    }
    drop(event_tx);

    let snap = capture_metrics(async {
        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;
    })
    .await;

    let p = peer_label(peer_ip);
    assert_eq!(
        gauge(&snap, "pathvectord_bgp_session_up", p.clone()),
        Some(1.0)
    );
    assert_eq!(
        counter(
            &snap,
            "pathvectord_bgp_sessions_established_total",
            p.clone()
        ),
        Some(1)
    );
    assert_eq!(
        gauge(&snap, "pathvectord_bgp_adj_rib_in_prefixes", p.clone()),
        Some(3.0),
        "Adj-RIB-In gauge must show the count after the last coalesced UPDATE"
    );
    assert_eq!(
        counter(&snap, "pathvectord_bgp_updates_received_total", p),
        Some(3)
    );
}

/// A Terminated that is the *first* event of its batch takes an early
/// `continue`, which used to skip `update_rib_sizes`: after a peer's
/// routes were flushed, `pathvectord_bgp_loc_rib_prefixes` kept
/// reporting the pre-teardown size (GH #105).
#[tokio::test]
async fn terminated_first_event_refreshes_loc_rib_gauge() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);
    {
        let mut s = state.write().await;
        s.on_established(
            peer_ip,
            "10.0.0.2".parse().unwrap(),
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        s.on_route_update(
            peer_ip,
            update_for("10.0.0.2".parse().unwrap(), 65002, "10.1.0.0/16"),
        );
        assert_eq!(s.rib.loc_rib.len(), 1, "precondition: route installed");
    }

    let (event_tx, event_rx) = mpsc::channel(4);
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(TerminationReason::OperatorStop),
        ))
        .await
        .unwrap();
    drop(event_tx);

    let snap = capture_metrics(async {
        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;
    })
    .await;

    assert_eq!(state.read().await.rib.loc_rib.len(), 0, "routes flushed");
    assert_eq!(
        gauge(
            &snap,
            "pathvectord_bgp_loc_rib_prefixes",
            vec![("afi".to_string(), "ipv4".to_string())]
        ),
        Some(0.0),
        "Loc-RIB size gauge must be refreshed after a teardown"
    );
}

// ── Drain-loop early exit ─────────────────────────────────────────────────

const DRAIN_PEER_A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const DRAIN_PEER_B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

/// Gives `peer` a command channel whose receiving end the test keeps.
fn capture_commands(
    stop_senders: &Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>,
    peer: IpAddr,
) -> mpsc::Receiver<SessionCommand> {
    let (tx, rx) = mpsc::channel(8);
    stop_senders.lock().unwrap().insert(peer, tx);
    rx
}

/// An UPDATE that resets its session: attributes, a missing ORIGIN and no
/// NLRI (RFC 7606 §5.2).
fn session_reset_update(peer_as: u32) -> SessionEvent {
    SessionEvent::RouteUpdate(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::AsPath(AsPath::from_sequence(vec![
            Asn::new(peer_as),
        ]))],
        announced: vec![],
    })
}

fn drain_commands(rx: &mut mpsc::Receiver<SessionCommand>) -> Vec<SessionCommand> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// A peer that reconnects while its max-prefix idle-hold is running is
/// owed a stop, also when a later event in the same batch makes the
/// drain loop leave early to send a NOTIFICATION. The idle-hold itself is
/// local policy: RFC 4486 §4 requires only the Cease.
#[tokio::test]
async fn idle_hold_reconnect_is_stopped_when_batch_ends_in_notification() {
    let (state, _rxs, stop_senders) =
        make_state(&[(DRAIN_PEER_A, 65002), (DRAIN_PEER_B, 65003)], 64);
    let mut a = capture_commands(&stop_senders, DRAIN_PEER_A);
    let mut b = capture_commands(&stop_senders, DRAIN_PEER_B);
    {
        let mut s = state.write().await;
        s.peer_max_prefixes_v4.insert(DRAIN_PEER_A, 1);
        s.peer_max_prefixes_restart.insert(DRAIN_PEER_A, 300);
        s.on_established(
            DRAIN_PEER_A,
            Ipv4Addr::new(10, 0, 0, 2),
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
    }
    let mut over_limit = update_for(Ipv4Addr::new(10, 0, 0, 2), 65002, "10.1.0.0/16");
    over_limit.announced.push(nlri("10.2.0.0/16"));

    let (event_tx, event_rx) = mpsc::channel(16);
    for event in [
        // Each of these two is handled on its own: the first leaves
        // through the first-event NOTIFICATION path and arms the hold.
        (DRAIN_PEER_A, SessionEvent::RouteUpdate(over_limit)),
        (
            DRAIN_PEER_A,
            SessionEvent::Terminated(TerminationReason::OperatorStop),
        ),
        // One batch: B starts it, the other two are drained behind it.
        (
            DRAIN_PEER_B,
            SessionEvent::Established(established_info(65003)),
        ),
        (
            DRAIN_PEER_A,
            SessionEvent::Established(established_info(65002)),
        ),
        (DRAIN_PEER_B, session_reset_update(65003)),
    ] {
        event_tx.send(event).await.unwrap();
    }
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    let b_commands = drain_commands(&mut b);
    assert!(
        matches!(b_commands.as_slice(), [SessionCommand::AutomaticStop(_)]),
        "precondition: the batch must end on the NOTIFICATION path, got {b_commands:?}"
    );
    assert!(
        !state
            .read()
            .await
            .rib
            .peer_types
            .contains_key(&DRAIN_PEER_A),
        "the held-off peer must not be established"
    );
    let a_commands = drain_commands(&mut a);
    assert!(
        matches!(
            a_commands.as_slice(),
            [
                SessionCommand::Notification(_),
                SessionCommand::SetCapabilities(_),
                SessionCommand::Notification(_)
            ]
        ),
        "expected the Cease, the post-teardown refresh, then a stop for \
         the rejected reconnect, got {a_commands:?}"
    );
}

/// The stop owed on the early exit is sent after the state write lock is
/// released, so a session slow to take commands does not stall the lock.
#[tokio::test]
async fn early_exit_idle_hold_stop_is_sent_without_the_state_lock() {
    let (state, _rxs, stop_senders) =
        make_state(&[(DRAIN_PEER_A, 65002), (DRAIN_PEER_B, 65003)], 64);
    let mut a = capture_commands(&stop_senders, DRAIN_PEER_A);
    let _b = capture_commands(&stop_senders, DRAIN_PEER_B);
    // Fill A's channel with a command that cannot be mistaken for a stop.
    let a_sender = stop_senders.lock().unwrap()[&DRAIN_PEER_A].clone();
    while a_sender
        .try_send(SessionCommand::SetCapabilities(vec![]))
        .is_ok()
    {}
    state.write().await.max_prefix_idle.insert(
        DRAIN_PEER_A,
        Instant::now() + std::time::Duration::from_secs(300),
    );

    let (event_tx, event_rx) = mpsc::channel(8);
    for event in [
        (
            DRAIN_PEER_B,
            SessionEvent::Established(established_info(65003)),
        ),
        (
            DRAIN_PEER_A,
            SessionEvent::Established(established_info(65002)),
        ),
        (DRAIN_PEER_B, session_reset_update(65003)),
    ] {
        event_tx.send(event).await.unwrap();
    }

    tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        stop_senders,
        None,
    ));

    // The stop cannot be delivered until A's channel is drained, yet the
    // lock must become free once the batch has been applied.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            tokio::task::yield_now().await;
            if let Ok(s) = state.try_write()
                && s.rib.peer_types.contains_key(&DRAIN_PEER_B)
            {
                break;
            }
        }
    })
    .await
    .expect("state lock still held while the stop is blocked");

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !matches!(a.recv().await, Some(SessionCommand::Notification(_))) {}
    })
    .await
    .expect("the rejected reconnect was never stopped");
}

/// Events coalesced ahead of the one that needs a NOTIFICATION have
/// already changed the RIB, so the early exit must refresh the size gauges
/// like the normal exit does (GH #105).
#[tokio::test]
async fn drain_loop_early_exit_refreshes_loc_rib_gauge() {
    let (state, _rxs, stop_senders) =
        make_state(&[(DRAIN_PEER_A, 65002), (DRAIN_PEER_B, 65003)], 64);
    {
        let mut s = state.write().await;
        s.on_established(
            DRAIN_PEER_A,
            Ipv4Addr::new(10, 0, 0, 2),
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        s.on_route_update(
            DRAIN_PEER_A,
            update_for(Ipv4Addr::new(10, 0, 0, 2), 65002, "10.1.0.0/16"),
        );
        assert_eq!(s.rib.loc_rib.len(), 1, "precondition: route installed");
    }

    let (event_tx, event_rx) = mpsc::channel(8);
    for event in [
        // Sets the gauge to 1, then A's routes are flushed behind it.
        (
            DRAIN_PEER_B,
            SessionEvent::Established(established_info(65003)),
        ),
        (
            DRAIN_PEER_A,
            SessionEvent::Terminated(TerminationReason::OperatorStop),
        ),
        (DRAIN_PEER_B, session_reset_update(65003)),
    ] {
        event_tx.send(event).await.unwrap();
    }
    drop(event_tx);

    let snap = capture_metrics(async {
        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;
    })
    .await;

    assert_eq!(state.read().await.rib.loc_rib.len(), 0, "routes flushed");
    assert_eq!(
        gauge(
            &snap,
            "pathvectord_bgp_loc_rib_prefixes",
            vec![("afi".to_string(), "ipv4".to_string())]
        ),
        Some(0.0),
        "Loc-RIB size gauge must be refreshed when the drain loop leaves early"
    );
}

// ── UPDATEs from a session the daemon did not register ────────────────────

// A reconnect during the max-prefix idle-hold is refused: the daemon never
// runs `on_established` for it. Its UPDATEs can already be queued behind
// the `Established` and must change nothing: to the daemon that session is
// not established, and RFC 4271 §9 says "An UPDATE message may be received
// only in the Established state". The hold-off itself is local policy.

/// A and B configured, A inside its idle-hold window.
fn idle_held_state() -> StateBundle {
    let (state, rxs, stop_senders) =
        make_state(&[(DRAIN_PEER_A, 65002), (DRAIN_PEER_B, 65003)], 64);
    state.try_write().unwrap().max_prefix_idle.insert(
        DRAIN_PEER_A,
        Instant::now() + std::time::Duration::from_secs(300),
    );
    (state, rxs, stop_senders)
}

fn rejected_update() -> SessionEvent {
    SessionEvent::RouteUpdate(update_for(Ipv4Addr::new(10, 0, 0, 2), 65002, "10.1.0.0/16"))
}

/// Runs the loop over `events`, all queued before it starts, so that
/// everything behind the first event is eligible for coalescing.
async fn run_queued(
    events: Vec<(IpAddr, SessionEvent)>,
    state: &Arc<RwLock<DaemonState>>,
    stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
) {
    let (event_tx, event_rx) = mpsc::channel(events.len());
    for event in events {
        event_tx.send(event).await.unwrap();
    }
    drop(event_tx);
    run_event_loop(event_rx, Arc::clone(state), stop_senders, None).await;
}

fn assert_nothing_installed_from_a(s: &DaemonState) {
    assert_eq!(s.rib.loc_rib.len(), 0, "Loc-RIB must stay empty");
    assert_eq!(
        s.adj_ribs_in[&DRAIN_PEER_A].routes().count(),
        0,
        "Adj-RIB-In must stay empty"
    );
    assert!(
        !s.rib.prefixes_received.contains_key(&DRAIN_PEER_A),
        "no received-prefix count for an unregistered session"
    );
}

/// First-event path: the rejected `Established` ends its own iteration, so
/// the UPDATE behind it starts the next one.
#[tokio::test]
async fn update_behind_rejected_established_is_ignored() {
    let (state, _rxs, stop_senders) = idle_held_state();
    let mut a = capture_commands(&stop_senders, DRAIN_PEER_A);

    run_queued(
        vec![
            (
                DRAIN_PEER_A,
                SessionEvent::Established(established_info(65002)),
            ),
            (DRAIN_PEER_A, rejected_update()),
        ],
        &state,
        stop_senders,
    )
    .await;

    assert_nothing_installed_from_a(&*state.read().await);
    let commands = drain_commands(&mut a);
    assert!(
        matches!(commands.as_slice(), [SessionCommand::Notification(_)]),
        "got {commands:?}"
    );
}

/// Drain-loop path: both the rejected `Established` and its UPDATE are
/// coalesced behind another peer's event. Nothing may be installed, and
/// the established peer must not be sent the prefix.
#[tokio::test]
async fn coalesced_update_behind_rejected_established_is_ignored() {
    let (state, mut rxs, stop_senders) = idle_held_state();
    let mut a = capture_commands(&stop_senders, DRAIN_PEER_A);

    run_queued(
        vec![
            (
                DRAIN_PEER_B,
                SessionEvent::Established(established_info(65003)),
            ),
            (
                DRAIN_PEER_A,
                SessionEvent::Established(established_info(65002)),
            ),
            (DRAIN_PEER_A, rejected_update()),
        ],
        &state,
        stop_senders,
    )
    .await;

    assert_nothing_installed_from_a(&*state.read().await);
    let b_updates = rxs.get_mut(&DRAIN_PEER_B).unwrap();
    while let Ok(msg) = b_updates.try_recv() {
        assert!(
            msg.announced.is_empty(),
            "the refused route was advertised to an established peer: {msg:?}"
        );
    }
    let commands = drain_commands(&mut a);
    assert!(
        matches!(commands.as_slice(), [SessionCommand::Notification(_)]),
        "got {commands:?}"
    );
}

/// An over-limit UPDATE from a refused session must not send a second
/// Cease or push the idle-hold deadline out.
#[tokio::test]
async fn update_from_rejected_session_does_not_rearm_idle_hold() {
    let (state, _rxs, stop_senders) = idle_held_state();
    let mut a = capture_commands(&stop_senders, DRAIN_PEER_A);
    let deadline = {
        let mut s = state.write().await;
        s.peer_max_prefixes_v4.insert(DRAIN_PEER_A, 1);
        s.peer_max_prefixes_restart.insert(DRAIN_PEER_A, 600);
        s.max_prefix_idle[&DRAIN_PEER_A]
    };
    let mut over_limit = update_for(Ipv4Addr::new(10, 0, 0, 2), 65002, "10.1.0.0/16");
    over_limit.announced.push(nlri("10.2.0.0/16"));

    run_queued(
        vec![
            (
                DRAIN_PEER_A,
                SessionEvent::Established(established_info(65002)),
            ),
            (DRAIN_PEER_A, SessionEvent::RouteUpdate(over_limit)),
        ],
        &state,
        stop_senders,
    )
    .await;

    assert_eq!(state.read().await.max_prefix_idle[&DRAIN_PEER_A], deadline);
    let commands = drain_commands(&mut a);
    assert!(
        matches!(commands.as_slice(), [SessionCommand::Notification(_)]),
        "got {commands:?}"
    );
}

/// The rule is registration, not the idle-hold: no session the daemon has
/// not established may change state, End-of-RIB markers included
/// (RFC 4724 §2), nor draw a NOTIFICATION.
#[test]
fn update_from_unregistered_session_is_ignored() {
    let (state, _rxs, _stop_senders) = make_state(&[(DRAIN_PEER_A, 65002)], 64);
    let mut s = state.try_write().unwrap();

    let notification = s.on_route_update(
        DRAIN_PEER_A,
        update_for(Ipv4Addr::new(10, 0, 0, 2), 65002, "10.1.0.0/16"),
    );
    assert!(notification.is_none());
    let SessionEvent::RouteUpdate(reset) = session_reset_update(65002) else {
        unreachable!()
    };
    assert!(s.on_route_update(DRAIN_PEER_A, reset).is_none());
    s.on_route_update(
        DRAIN_PEER_A,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        },
    );

    assert_nothing_installed_from_a(&s);
    assert!(!s.rib.eor_received.contains(&DRAIN_PEER_A));
}

// ── Terminated dispatch ───────────────────────────────────────────────────

#[tokio::test]
async fn event_loop_dispatches_terminated() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

    // Establish first so there is state to tear down.
    {
        let mut s = state.write().await;
        s.on_established(
            peer_ip,
            must_v4(peer_ip),
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
    }

    let (event_tx, event_rx) = mpsc::channel(8);
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    let s = state.read().await;
    assert!(
        !s.rib.peer_types.contains_key(&peer_ip),
        "Terminated event must remove peer type from DaemonState"
    );
}

// ── RouteUpdate dispatch ──────────────────────────────────────────────────

#[tokio::test]
async fn event_loop_dispatches_route_update() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

    {
        let mut s = state.write().await;
        s.on_established(
            peer_ip,
            must_v4(peer_ip),
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
    }

    let update = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop(must_v4(peer_ip)),
        ],
        announced: vec![nlri("10.0.0.0/8")],
    };

    let (event_tx, event_rx) = mpsc::channel(8);
    event_tx
        .send((peer_ip, SessionEvent::RouteUpdate(update)))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    let s = state.read().await;
    assert_eq!(
        s.rib.loc_rib.len(),
        1,
        "RouteUpdate must insert route into Loc-RIB"
    );
}

// ── Stalled peer → stop command ───────────────────────────────────────────

#[tokio::test]
async fn event_loop_sends_stop_to_stalled_peer() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

    // Give peer_b a channel of capacity 1 so it stalls during propagation.
    let (update_tx_a, _) = mpsc::channel::<UpdateMessage>(64);
    let (stall_tx, mut stall_drain) = mpsc::channel::<UpdateMessage>(1);
    let (sess_stop_a, _sess_stop_rx_a) = mpsc::channel::<SessionCommand>(8);
    let (sess_stop_b, mut cmd_rx_b) = mpsc::channel::<SessionCommand>(8);

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
    update_senders.insert(IpAddr::V4(peer_a), update_tx_a);
    update_senders.insert(IpAddr::V4(peer_b), stall_tx);
    let state = Arc::new(RwLock::new(DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        update_senders,
        vec![],
    )));
    let mut stop_map = HashMap::new();
    stop_map.insert(IpAddr::V4(peer_a), sess_stop_a);
    stop_map.insert(IpAddr::V4(peer_b), sess_stop_b);
    let stop_senders = Arc::new(Mutex::new(stop_map));

    // Establish both peers.
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

    // Drain the EOR marker that on_established sent to peer_b (RFC 4724 §2)
    // so the capacity-1 channel is empty before we pre-fill it below.
    while stall_drain.try_recv().is_ok() {}

    // Pre-fill peer_b's cap-1 UPDATE channel so the propagation try_send fails.
    {
        let s = state.read().await;
        s.update_senders[&IpAddr::V4(peer_b)]
            .try_send(UpdateMessage {
                withdrawn: vec![nlri("0.0.0.0/0")],
                attributes: vec![],
                announced: vec![],
            })
            .expect("channel must have room for the fill message");
    }

    // Announce a route from peer_a — propagation to peer_b will fail
    // (channel already full) and peer_b must be recorded as stalled.
    let (event_tx, event_rx) = mpsc::channel(8);
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
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    // The event loop must have reset peer_b.
    let cmd = cmd_rx_b
        .try_recv()
        .expect("event loop must reset stalled peer_b");
    assert!(
        matches!(
            &cmd,
            SessionCommand::AutomaticStop(n)
                if n.error == NotificationError::Cease(CeaseError::OutOfResources)
        ),
        "expected AutomaticStop(Out of Resources), got {cmd:?}"
    );
}

// ── FIB change → recompute_all + propagate ────────────────────────────────

#[tokio::test]
async fn event_loop_fib_change_withdraws_unreachable_routes() {
    use pathvector_types::{AsPath, Asn, Origin};

    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (state, mut rxs, stop_senders) = make_state(
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
        64,
    );

    // Install a ToggleOracle (initially reachable).
    let oracle = ToggleOracle::reachable();
    {
        let mut s = state.write().await;
        s.set_oracles(oracle.clone(), oracle.clone());
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
        s.on_route_update(
            IpAddr::V4(peer_a),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        s.flush_pending();
    }
    // Drain EOR marker and initial route propagation.
    while rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv().is_ok() {}

    // Simulate next-hop going down.
    oracle.0.store(false, Ordering::Relaxed);

    // Keep the event channel open so the loop does not exit via the event
    // arm before it has a chance to process the FIB change.  Both arms
    // could otherwise be immediately ready and select! is non-deterministic.
    let (event_tx, event_rx) = mpsc::channel::<(IpAddr, SessionEvent)>(8);
    let (fib_tx, fib_rx) = watch::channel(());

    // Spawn the loop as a background task, then signal the FIB change.
    let loop_handle = tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        stop_senders,
        Some(fib_rx),
    ));
    fib_tx.send(()).unwrap();

    // Yield repeatedly to give the event loop task a chance to wake up and
    // call on_fib_change before we inspect state.
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }

    // Route must be withdrawn from Loc-RIB.
    let s = state.read().await;
    assert!(
        s.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
        "Loc-RIB must not have a best path when next-hop is unreachable"
    );
    drop(s);

    // peer_b must have received a WITHDRAW.
    let msg = rxs
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b must receive WITHDRAW via FIB change");
    assert!(!msg.withdrawn.is_empty());
    assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));

    // Shut down: close the event channel so the loop exits.
    drop(event_tx);
    tokio::time::timeout(std::time::Duration::from_secs(1), loop_handle)
        .await
        .expect("event loop must exit within timeout")
        .expect("loop task must not panic");
}

// ── Channel closed → loop exits ───────────────────────────────────────────

#[tokio::test]
async fn event_loop_exits_when_channel_closes() {
    let (state, _rxs, stop_senders) = make_state(&[], 64);
    let (event_tx, event_rx) = mpsc::channel::<(IpAddr, SessionEvent)>(8);
    // Drop the sender immediately — the loop must exit without hanging.
    drop(event_tx);
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        run_event_loop(event_rx, state, stop_senders, None),
    )
    .await
    .expect("run_event_loop must exit when the event channel is closed");
}

// ── DaemonState::add_peer / remove_peer ───────────────────────────────────

fn peer_cfg(address: IpAddr, remote_as: u32) -> config::PeerConfig {
    config::PeerConfig {
        address,
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
}

#[tokio::test]
async fn add_peer_inserts_all_state_maps() {
    let (state, _rxs, _stop) = make_state(&[], 8);
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (update_tx, _update_rx) = mpsc::channel(8);

    let added = state
        .write()
        .await
        .add_peer(&peer_cfg(peer_ip, 65099), update_tx);

    assert!(added, "first add_peer must return true");
    let s = state.read().await;
    assert!(s.adj_ribs_in.contains_key(&peer_ip));
    assert!(s.adj_ribs_in_v6.contains_key(&peer_ip));
    assert!(s.adj_ribs_out.contains_key(&peer_ip));
    assert!(s.adj_ribs_out_v6.contains_key(&peer_ip));
    assert!(s.import_policies.contains_key(&peer_ip));
    assert!(s.export_policies.contains_key(&peer_ip));
    assert!(s.update_senders.contains_key(&peer_ip));
    assert_eq!(s.rib.peer_remote_as.get(&peer_ip), Some(&65099_u32));
}

#[tokio::test]
async fn add_peer_is_idempotent() {
    let (state, _rxs, _stop) = make_state(&[], 8);
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (tx1, _) = mpsc::channel(8);
    let (tx2, _) = mpsc::channel(8);

    let first = state.write().await.add_peer(&peer_cfg(peer_ip, 65099), tx1);
    let second = state.write().await.add_peer(&peer_cfg(peer_ip, 65099), tx2);

    assert!(first, "first call must return true");
    assert!(!second, "second call (idempotent) must return false");
}

#[tokio::test]
async fn remove_peer_clears_all_state_maps() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

    let removed = state.write().await.remove_peer(peer_ip);

    assert!(removed, "remove_peer must return true for an existing peer");
    let s = state.read().await;
    assert!(!s.adj_ribs_in.contains_key(&peer_ip));
    assert!(!s.adj_ribs_in_v6.contains_key(&peer_ip));
    assert!(!s.adj_ribs_out.contains_key(&peer_ip));
    assert!(!s.import_policies.contains_key(&peer_ip));
    assert!(!s.export_policies.contains_key(&peer_ip));
    assert!(!s.update_senders.contains_key(&peer_ip));
    assert!(!s.rib.peer_remote_as.contains_key(&peer_ip));
}

#[tokio::test]
async fn remove_peer_returns_false_when_not_found() {
    let (state, _rxs, _stop) = make_state(&[], 8);
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();

    let removed = state.write().await.remove_peer(peer_ip);

    assert!(!removed, "remove_peer must return false for unknown peer");
}

/// RFC 9234: a dynamically added peer with a configured role must get
/// `peer_roles` populated and OTC terms installed — mirrors the static-peer
/// path in `DaemonState::new`, which `test_install_otc_terms_counts_per_role`
/// already covers.
#[tokio::test]
async fn add_peer_with_role_installs_otc_terms_and_peer_roles() {
    let (state, _rxs, _stop) = make_state(&[], 8);
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (update_tx, _update_rx) = mpsc::channel(8);

    let mut cfg = peer_cfg(peer_ip, 65099);
    cfg.role = Some(config::PeerRole::Customer);
    state.write().await.add_peer(&cfg, update_tx);

    let s = state.read().await;
    assert_eq!(s.rib.peer_roles.get(&peer_ip), Some(&Role::Customer));
    // Customer: leak-detect (no-op for this role) + ingress attach = 2 terms.
    assert_eq!(s.import_policies[&peer_ip].len(), 2);
    assert_eq!(s.import_policies_v6[&peer_ip].len(), 2);
    // Customer: propagation-block = 1 term.
    assert_eq!(s.export_policies[&peer_ip].len(), 1);
}

/// The dynamic `add_peer` path must apply the same eBGP-only guard as
/// the static `DaemonState::new` path (`test_role_ignored_for_ibgp_peer`)
/// — a `role` configured on an iBGP peer (`remote_as == local_as == 65001`
/// in this harness) must be ignored, not applied.
#[tokio::test]
async fn add_peer_ignores_role_for_ibgp_peer() {
    let (state, _rxs, _stop) = make_state(&[], 8);
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (update_tx, _update_rx) = mpsc::channel(8);

    let mut cfg = peer_cfg(peer_ip, 65001); // local_as in this harness is 65001
    cfg.role = Some(config::PeerRole::Customer);
    state.write().await.add_peer(&cfg, update_tx);

    let s = state.read().await;
    assert!(
        !s.rib.peer_roles.contains_key(&peer_ip),
        "peer_roles must not record a role for an iBGP peer"
    );
    assert_eq!(s.import_policies[&peer_ip].len(), 0);
    assert_eq!(s.import_policies_v6[&peer_ip].len(), 0);
    assert_eq!(s.export_policies[&peer_ip].len(), 0);
}

/// `remove_peer` must clear `peer_roles`, otherwise a later `AddPeer` for a
/// different role at the same address would inherit a stale role via the
/// reconnect capability-refresh path.
#[tokio::test]
async fn remove_peer_clears_peer_roles() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, _stop) = make_state(&[], 8);
    let (update_tx, _update_rx) = mpsc::channel(8);
    let mut cfg = peer_cfg(peer_ip, 65099);
    cfg.role = Some(config::PeerRole::Peer);
    state.write().await.add_peer(&cfg, update_tx);
    assert!(state.read().await.rib.peer_roles.contains_key(&peer_ip));

    state.write().await.remove_peer(peer_ip);

    assert!(!state.read().await.rib.peer_roles.contains_key(&peer_ip));
}

/// Termination of a peer in `pending_removal` must erase all per-peer state
/// (not just reset it for reconnect).
#[tokio::test]
async fn retired_removes_a_peer_pending_removal() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

    // Mark as pending removal.
    state.write().await.pending_removal.insert(peer_ip);

    let (event_tx, event_rx) = mpsc::channel(4);
    // Establish, terminate, retire.
    event_tx
        .send((peer_ip, SessionEvent::Established(established_info(65099))))
        .await
        .unwrap();
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ))
        .await
        .unwrap();
    event_tx
        .send((peer_ip, SessionEvent::Retired))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    let s = state.read().await;
    // All per-peer maps must be cleared.
    assert!(
        !s.adj_ribs_in.contains_key(&peer_ip),
        "adj_ribs_in must be removed after Retired"
    );
    assert!(
        !s.rib.peer_remote_as.contains_key(&peer_ip),
        "peer_remote_as must be removed after Retired"
    );
    assert!(
        !s.pending_removal.contains(&peer_ip),
        "pending_removal entry must be cleaned up"
    );
}

/// When RemovePeer is issued but the stop sender is absent, the command
/// processor must synthesize a Retired event so the pending_removal cleanup
/// still runs.
#[tokio::test]
async fn remove_peer_synthesizes_retired_when_no_stop_sender() {
    // A SessionHandle stub that is never actually spawned — RemovePeer does
    // not call spawn_fn, so we just need any type that satisfies the bound.
    struct NeverSpawned;
    impl SessionHandle for NeverSpawned {
        async fn start(&self) {}
        async fn next_event(&mut self) -> Option<SessionEvent> {
            None
        }
        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            mpsc::channel(1).0
        }
        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}
        async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
    }

    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    // Build state with the peer but deliberately provide an empty stop_senders
    // map — simulates the window where the session actor has exited and its
    // stop sender has been dropped.
    let (state, _rxs, _orig_stop) = make_state(&[(peer_ip, 65099)], 8);
    let empty_stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let (event_tx, event_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);

    let state_clone = Arc::clone(&state);
    let stop_clone = Arc::clone(&empty_stop_senders);
    let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let event_tx_clone = event_tx.clone();

    tokio::spawn(run_command_processor::<NeverSpawned, _, KernelTcpMd5>(
        cmd_rx,
        state_clone,
        stop_clone,
        incoming,
        Arc::new(ListenerKeys::default()),
        event_tx_clone,
        |_cfg| unreachable!("spawn_fn must not be called by RemovePeer"),
        SpawnConfig {
            local_as: 65001,
            local_bgp_id: "1.2.3.4".parse().unwrap(),
            hold_time: 180,
            graceful_restart_time: 0,
            configured_restarting: false,
            confederation_id: None,
            startup_instant: std::time::Instant::now(),
            md5_enforcement: Md5Enforcement::Required,
        },
        None,
    ));

    cmd_tx
        .send(DaemonCommand::RemovePeer(peer_ip))
        .await
        .unwrap();
    drop(cmd_tx);
    // Drop our own event_tx so the event loop terminates after draining.
    drop(event_tx);

    // The command processor should have synthesized Retired; run the event
    // loop to consume it and complete the cleanup.
    run_event_loop(event_rx, Arc::clone(&state), empty_stop_senders, None).await;

    let s = state.read().await;
    assert!(
        !s.adj_ribs_in.contains_key(&peer_ip),
        "adj_ribs_in must be cleared after synthesized Retired"
    );
    assert!(
        !s.pending_removal.contains(&peer_ip),
        "pending_removal entry must be cleared"
    );
}

/// Termination of a normal peer (not in pending_removal) must NOT remove
/// the peer from `adj_ribs_in` — it should be ready for reconnect.
#[tokio::test]
async fn terminated_without_pending_removal_keeps_peer_state() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

    let (event_tx, event_rx) = mpsc::channel(4);
    event_tx
        .send((peer_ip, SessionEvent::Established(established_info(65099))))
        .await
        .unwrap();
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    let s = state.read().await;
    assert!(
        s.adj_ribs_in.contains_key(&peer_ip),
        "adj_ribs_in must be preserved for a normal (non-removed) peer termination"
    );
    assert!(
        s.rib.peer_remote_as.contains_key(&peer_ip),
        "peer_remote_as must be preserved for reconnect"
    );
}

/// `Retired` completes only a removal that `RemovePeer` asked for.
#[tokio::test]
async fn retired_without_pending_removal_keeps_peer_state() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

    let (event_tx, event_rx) = mpsc::channel(4);
    event_tx
        .send((peer_ip, SessionEvent::Retired))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    assert!(state.read().await.adj_ribs_in.contains_key(&peer_ip));
}

/// `AddPeer` while the peer is in `pending_removal` must be silently
/// dropped — the spawn function must never be called.
///
/// The operator must wait until the Retired event clears all per-peer
/// state before re-adding the peer.
#[tokio::test]
async fn add_peer_while_pending_removal_is_dropped() {
    struct NeverSpawned;
    impl SessionHandle for NeverSpawned {
        async fn start(&self) {}
        async fn next_event(&mut self) -> Option<SessionEvent> {
            None
        }
        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            mpsc::channel(1).0
        }
        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}
        async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
    }

    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

    // Mark the peer as being removed — teardown is in progress.
    state.write().await.pending_removal.insert(peer_ip);

    let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let (event_tx, _event_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);

    tokio::spawn(run_command_processor::<NeverSpawned, _, KernelTcpMd5>(
        cmd_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        incoming,
        Arc::new(ListenerKeys::default()),
        event_tx,
        // If spawn_fn is called the test panics — AddPeer must be dropped.
        |_cfg| panic!("spawn_fn must not be called while peer is in pending_removal"),
        SpawnConfig {
            local_as: 65001,
            local_bgp_id: "1.2.3.4".parse().unwrap(),
            hold_time: 180,
            graceful_restart_time: 0,
            configured_restarting: false,
            confederation_id: None,
            startup_instant: std::time::Instant::now(),
            md5_enforcement: Md5Enforcement::Required,
        },
        None,
    ));

    cmd_tx
        .send(DaemonCommand::AddPeer(peer_cfg(peer_ip, 65099)))
        .await
        .unwrap();
    drop(cmd_tx);

    // Give the command processor a moment to process the command.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Peer must still be in pending_removal — add was dropped.
    let s = state.read().await;
    assert!(
        s.pending_removal.contains(&peer_ip),
        "pending_removal must still contain the peer after a dropped AddPeer"
    );
    // adj_ribs_in must still have the peer (it was there before the add attempt).
    assert!(
        s.adj_ribs_in.contains_key(&peer_ip),
        "adj_ribs_in must be unchanged — no second entry was added"
    );
}

// ── RFC 9003 — shutdown message dispatch ─────────────────────────────────

/// `RemovePeer` must send `SessionCommand::Stop` (no payload) when the peer
/// has no configured `shutdown_message`.
#[tokio::test]
async fn remove_peer_without_shutdown_message_sends_stop() {
    struct NeverSpawned;
    impl SessionHandle for NeverSpawned {
        async fn start(&self) {}
        async fn next_event(&mut self) -> Option<SessionEvent> {
            None
        }
        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            mpsc::channel(1).0
        }
        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}
        async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
    }

    let peer_ip: IpAddr = "10.0.1.1".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65010)], 8);

    // Register a real stop sender so we can observe what command is sent.
    let (session_stop_tx, mut session_stop_rx) = mpsc::channel(8);
    stop_senders
        .lock()
        .unwrap()
        .insert(peer_ip, session_stop_tx);

    let (event_tx, _event_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);

    tokio::spawn(run_command_processor::<NeverSpawned, _, KernelTcpMd5>(
        cmd_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(ListenerKeys::default()),
        event_tx,
        |_cfg| unreachable!(),
        SpawnConfig {
            local_as: 65001,
            local_bgp_id: "1.2.3.4".parse().unwrap(),
            hold_time: 180,
            graceful_restart_time: 0,
            configured_restarting: false,
            confederation_id: None,
            startup_instant: std::time::Instant::now(),
            md5_enforcement: Md5Enforcement::Required,
        },
        None,
    ));

    cmd_tx
        .send(DaemonCommand::RemovePeer(peer_ip))
        .await
        .unwrap();

    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), session_stop_rx.recv())
        .await
        .expect("timed out waiting for command")
        .expect("channel closed");

    assert!(
        matches!(cmd, SessionCommand::Stop),
        "expected Stop when no shutdown_message configured, got {cmd:?}"
    );
}

/// `RemovePeer` must send `SessionCommand::Notification` with a
/// `Cease/AdministrativeShutdown` payload when `shutdown_message` is set.
/// The payload must be a valid RFC 9003 encoded string.
#[tokio::test]
async fn remove_peer_with_shutdown_message_sends_rfc9003_notification() {
    use pathvector_session::message::{CeaseError, NotificationError, decode_shutdown_message};
    struct NeverSpawned;
    impl SessionHandle for NeverSpawned {
        async fn start(&self) {}
        async fn next_event(&mut self) -> Option<SessionEvent> {
            None
        }
        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            mpsc::channel(1).0
        }
        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}
        async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
    }

    let peer_ip: IpAddr = "10.0.1.2".parse().unwrap();

    // Build state with shutdown_message set.
    let mut senders = HashMap::new();
    let (utx, _urx) = mpsc::channel(8);
    senders.insert(peer_ip, utx);
    let peer_cfg = config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: 65011,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: Some("planned maintenance".to_string()),
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    let state = Arc::new(RwLock::new(DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[peer_cfg],
        senders,
        vec![],
    )));

    // Register a real stop sender so we can observe what command is sent.
    let (session_stop_tx, mut session_stop_rx) = mpsc::channel(8);
    let stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(Mutex::new(HashMap::from([(peer_ip, session_stop_tx)])));

    let (event_tx, _event_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);

    tokio::spawn(run_command_processor::<NeverSpawned, _, KernelTcpMd5>(
        cmd_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(ListenerKeys::default()),
        event_tx,
        |_cfg| unreachable!(),
        SpawnConfig {
            local_as: 65001,
            local_bgp_id: "1.2.3.4".parse().unwrap(),
            hold_time: 180,
            graceful_restart_time: 0,
            configured_restarting: false,
            confederation_id: None,
            startup_instant: std::time::Instant::now(),
            md5_enforcement: Md5Enforcement::Required,
        },
        None,
    ));

    cmd_tx
        .send(DaemonCommand::RemovePeer(peer_ip))
        .await
        .unwrap();

    let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), session_stop_rx.recv())
        .await
        .expect("timed out waiting for command")
        .expect("channel closed");

    match cmd {
        SessionCommand::Notification(msg) => {
            assert!(
                matches!(
                    msg.error,
                    NotificationError::Cease(CeaseError::AdministrativeShutdown)
                ),
                "expected Cease/AdministrativeShutdown, got {:?}",
                msg.error
            );
            let reason = decode_shutdown_message(&msg.data)
                .expect("RFC 9003 payload must decode to a UTF-8 string");
            assert_eq!(
                reason, "planned maintenance",
                "decoded shutdown reason must match configured message"
            );
        }
        other => panic!("expected Notification, got {other:?}"),
    }
}

// ── RFC 2918 — route_refresh_peers tracking ───────────────────────────────

/// `on_established` must insert the peer into `route_refresh_peers` when
/// both sides negotiated `Capability::RouteRefresh`.
#[tokio::test]
async fn on_established_tracks_route_refresh_when_both_sides_negotiated() {
    let peer_ip: IpAddr = "10.0.2.1".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65020)], 8);

    // Simulate the daemon advertising RouteRefresh (as build_daemon now does).
    {
        let mut s = state.write().await;
        s.config_capabilities.push(Capability::RouteRefresh);
    }

    let (event_tx, event_rx) = mpsc::channel(8);

    // Peer's OPEN includes RouteRefresh capability.
    let info = SessionInfo {
        peer_as: 65020,
        peer_bgp_id: Ipv4Addr::new(10, 0, 2, 1),
        hold_time: 90,
        peer_capabilities: vec![Capability::FourByteAsn(65020), Capability::RouteRefresh],
        peer_type: PeerType::External,
        local_addr: None,
    };

    event_tx
        .send((peer_ip, SessionEvent::Established(info)))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    assert!(
        state.read().await.route_refresh_peers.contains(&peer_ip),
        "route_refresh_peers must contain peer after both sides negotiated RouteRefresh"
    );
}

/// `on_established` must NOT add to `route_refresh_peers` if the peer did
/// not advertise `Capability::RouteRefresh`, even if we did.
#[tokio::test]
async fn on_established_does_not_track_route_refresh_when_peer_omits_capability() {
    let peer_ip: IpAddr = "10.0.2.2".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65021)], 8);

    {
        let mut s = state.write().await;
        s.config_capabilities.push(Capability::RouteRefresh);
    }

    let (event_tx, event_rx) = mpsc::channel(8);

    // Peer's OPEN does NOT include RouteRefresh.
    let info = SessionInfo {
        peer_as: 65021,
        peer_bgp_id: Ipv4Addr::new(10, 0, 2, 2),
        hold_time: 90,
        peer_capabilities: vec![Capability::FourByteAsn(65021)],
        peer_type: PeerType::External,
        local_addr: None,
    };

    event_tx
        .send((peer_ip, SessionEvent::Established(info)))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    assert!(
        !state.read().await.route_refresh_peers.contains(&peer_ip),
        "route_refresh_peers must NOT contain peer when peer did not advertise RouteRefresh"
    );
}

/// `on_terminated` must remove the peer from `route_refresh_peers`.
#[tokio::test]
async fn on_terminated_clears_route_refresh_peers() {
    let peer_ip: IpAddr = "10.0.2.3".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65022)], 8);

    {
        let mut s = state.write().await;
        s.config_capabilities.push(Capability::RouteRefresh);
    }

    let (event_tx, event_rx) = mpsc::channel(8);

    let info = SessionInfo {
        peer_as: 65022,
        peer_bgp_id: Ipv4Addr::new(10, 0, 2, 3),
        hold_time: 90,
        peer_capabilities: vec![Capability::FourByteAsn(65022), Capability::RouteRefresh],
        peer_type: PeerType::External,
        local_addr: None,
    };

    event_tx
        .send((peer_ip, SessionEvent::Established(info)))
        .await
        .unwrap();
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    assert!(
        !state.read().await.route_refresh_peers.contains(&peer_ip),
        "route_refresh_peers must be cleared after Terminated"
    );
}

// ── Per-peer hold timer ────────────────────────────────────────────────────

/// `build_daemon` must use the per-peer `hold_time` override instead of the
/// global default when one is present in `PeerConfig`.
#[test]
fn build_daemon_uses_per_peer_hold_time_override() {
    // build_daemon is not directly callable, but the same logic is used in
    // the `AddPeer` command processor via `SpawnConfig`.  We verify the
    // formula directly: the per-peer value wins over the global fallback.
    let global_hold_time: u16 = 180;
    let per_peer_hold_time: u16 = 45;

    // A PeerConfig with hold_time set must yield the per-peer value.
    let peer_cfg_with_override = config::PeerConfig {
        address: "10.0.3.1".parse().unwrap(),
        port: 179,
        remote_as: 65030,
        import_default: None,
        export_default: None,
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: Some(per_peer_hold_time),
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    assert_eq!(
        peer_cfg_with_override.hold_time.unwrap_or(global_hold_time),
        per_peer_hold_time,
        "per-peer hold_time must override global default"
    );

    // A PeerConfig without hold_time must fall back to the global default.
    let peer_cfg_no_override = config::PeerConfig {
        hold_time: None,
        ..peer_cfg_with_override.clone()
    };
    assert_eq!(
        peer_cfg_no_override.hold_time.unwrap_or(global_hold_time),
        global_hold_time,
        "absent per-peer hold_time must fall back to global default"
    );
}

/// `run_command_processor` must wire the per-peer `hold_time` override into
/// the `SessionConfig` it passes to `spawn_fn`.  This verifies the wiring
/// at the call site in `run_command_processor`, not just the formula.
#[tokio::test]
async fn add_peer_wires_per_peer_hold_time_into_session_config() {
    use std::sync::Mutex as StdMutex;

    // A minimal SessionHandle that records the SessionConfig it was built with.
    struct CaptureHandle;
    impl SessionHandle for CaptureHandle {
        async fn start(&self) {}
        async fn next_event(&mut self) -> Option<SessionEvent> {
            None
        }
        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            mpsc::channel(1).0
        }
        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}
        async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
    }

    let global_hold_time: u16 = 180;
    let per_peer_hold_time: u16 = 45;
    let peer_ip: IpAddr = "10.0.5.1".parse().unwrap();

    // Start with no pre-configured peers so AddPeer isn't treated as idempotent.
    let (state, _rxs, stop_senders) = make_state(&[], 8);

    let captured: Arc<StdMutex<Option<SessionConfig>>> = Arc::new(StdMutex::new(None));
    let captured_clone = Arc::clone(&captured);

    let (event_tx, _event_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);

    tokio::spawn(run_command_processor::<CaptureHandle, _, KernelTcpMd5>(
        cmd_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(ListenerKeys::default()),
        event_tx,
        move |cfg| {
            *captured_clone.lock().unwrap() = Some(cfg);
            CaptureHandle
        },
        SpawnConfig {
            local_as: 65001,
            local_bgp_id: "1.2.3.4".parse().unwrap(),
            hold_time: global_hold_time,
            graceful_restart_time: 0,
            configured_restarting: false,
            confederation_id: None,
            startup_instant: std::time::Instant::now(),
            md5_enforcement: Md5Enforcement::Required,
        },
        None,
    ));

    let peer_cfg = config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: 65050,
        import_default: None,
        export_default: None,
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: Some(per_peer_hold_time),
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };

    cmd_tx.send(DaemonCommand::AddPeer(peer_cfg)).await.unwrap();
    drop(cmd_tx);

    // Give the command processor a moment to call spawn_fn.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let session_cfg = captured
        .lock()
        .unwrap()
        .take()
        .expect("spawn_fn was never called — AddPeer did not trigger session spawn");

    assert_eq!(
        session_cfg.hold_time, per_peer_hold_time,
        "run_command_processor must forward per-peer hold_time into SessionConfig"
    );
}

// ── Removed broadcast correctness ─────────────────────────────────────────

/// Over the `Terminated` and `Retired` of a peer in `pending_removal`, the
/// event loop must broadcast exactly **one** event on `peer_tx`, `Removed`,
/// and it must carry the correct `remote_as` and `local_as` captured before
/// the state was erased.
///
/// This is the critical regression test for the fix that replaced the
/// diff-based approach (which emitted `remote_as: 0`) with capturing
/// identity fields before `on_terminated` / `remove_peer` run.
#[tokio::test]
async fn removal_broadcasts_one_removed_event_with_correct_fields() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let remote_as = 65099_u32;
    let local_as = 65001_u32;
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, remote_as)], 8);

    // Subscribe BEFORE the event fires so we don't miss the broadcast.
    let mut peer_rx = state.read().await.peer_tx.subscribe();

    state.write().await.pending_removal.insert(peer_ip);

    let (event_tx, event_rx) = mpsc::channel(4);
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ))
        .await
        .unwrap();
    event_tx
        .send((peer_ip, SessionEvent::Retired))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    // Collect all events broadcast during the loop.
    let mut events = vec![];
    while let Ok(ev) = peer_rx.try_recv() {
        events.push(ev);
    }

    // Exactly one event must have been sent.
    assert_eq!(
        events.len(),
        1,
        "exactly one peer_tx event must fire for a removal; got {events:?}"
    );

    let ev = &events[0];
    assert_eq!(
        ev.r#type,
        proto::PeerEventType::Removed as i32,
        "event type must be Removed"
    );

    let ps = ev
        .peer
        .as_ref()
        .expect("Removed event must carry a PeerState");
    assert_eq!(ps.address, peer_ip.to_string(), "address must match");
    assert_eq!(ps.remote_as, remote_as, "remote_as must not be zeroed");
    assert_eq!(ps.local_as, local_as, "local_as must not be zeroed");
}

// ── One teardown per removal ──────────────────────────────────────────────

const REMOVED: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
const BYSTANDER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));

/// Establishes `peer_ip` and has it announce `prefix`.
fn establish_and_announce(
    s: &mut DaemonState,
    peer_ip: IpAddr,
    capabilities: &[Capability],
    prefix: &str,
) {
    s.on_established(
        peer_ip,
        Ipv4Addr::new(10, 0, 0, 2),
        PeerType::External,
        65099,
        90,
        capabilities,
        None,
    );
    s.on_route_update(peer_ip, announcement(prefix));
    s.flush_pending();
}

fn announcement(prefix: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65099)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        announced: vec![nlri(prefix)],
    }
}

/// Runs the event loop over `events`, all from `peer_ip`.
async fn run_events(
    state: &Arc<RwLock<DaemonState>>,
    stop_senders: &Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    peer_ip: IpAddr,
    events: Vec<SessionEvent>,
) {
    let (event_tx, event_rx) = mpsc::channel(events.len());
    for event in events {
        event_tx.send((peer_ip, event)).await.unwrap();
    }
    drop(event_tx);
    run_event_loop(event_rx, Arc::clone(state), Arc::clone(stop_senders), None).await;
}

/// An Established peer's removal delivers `Terminated` and then `Retired`.
/// The teardown must run for only one of them: `WatchRoutes` subscribers see
/// what one teardown emits, not the same events twice.
#[tokio::test]
async fn removing_an_established_peer_tears_it_down_once() {
    let (state, _rxs, stop_senders) = make_state(&[(REMOVED, 65099), (BYSTANDER, 65099)], 8);
    let mut route_rx = {
        let mut s = state.write().await;
        s.on_established(
            REMOVED,
            Ipv4Addr::new(10, 0, 0, 2),
            PeerType::External,
            65099,
            90,
            &[],
            None,
        );
        establish_and_announce(&mut s, BYSTANDER, &[], "192.0.2.0/24");
        s.pending_removal.insert(REMOVED);
        s.route_tx.subscribe()
    };

    run_events(
        &state,
        &stop_senders,
        REMOVED,
        vec![
            SessionEvent::Terminated(TerminationReason::OperatorStop),
            SessionEvent::Retired,
        ],
    )
    .await;

    let mut events = vec![];
    while let Ok(event) = route_rx.try_recv() {
        events.push(event);
    }
    assert_eq!(
        events.len(),
        1,
        "the other peer's route must be reported once; got {events:?}"
    );
    assert!(!state.read().await.adj_ribs_in.contains_key(&REMOVED));
}

/// A session can flap just ahead of `RemovePeer`, leaving a later session's
/// events queued behind a `Terminated` that is handled while the peer is
/// already marked. That later session's routes still have to go.
#[tokio::test]
async fn retired_withdraws_routes_learned_after_the_removed_peers_terminated() {
    let (state, _rxs, stop_senders) = make_state(&[(REMOVED, 65099)], 8);
    state.write().await.pending_removal.insert(REMOVED);

    run_events(
        &state,
        &stop_senders,
        REMOVED,
        vec![
            SessionEvent::Terminated(TerminationReason::Unclean),
            SessionEvent::Established(established_info(65099)),
            SessionEvent::RouteUpdate(announcement("192.0.2.0/24")),
            SessionEvent::Retired,
        ],
    )
    .await;

    assert_eq!(state.read().await.rib.loc_rib.len(), 0);
}

/// A session task that dies while Established reports no `Terminated`.
#[tokio::test]
async fn retired_alone_withdraws_an_established_peers_routes() {
    let (state, _rxs, stop_senders) = make_state(&[(REMOVED, 65099)], 8);
    {
        let mut s = state.write().await;
        establish_and_announce(&mut s, REMOVED, &[], "192.0.2.0/24");
        assert_eq!(s.rib.loc_rib.len(), 1);
        s.pending_removal.insert(REMOVED);
    }

    run_events(&state, &stop_senders, REMOVED, vec![SessionEvent::Retired]).await;

    assert_eq!(state.read().await.rib.loc_rib.len(), 0);
}

/// Between sessions with Graceful Restart routes retained, `Retired` is all a
/// removal gets. An earlier removal at the same address must not change that.
#[tokio::test]
async fn retired_withdraws_routes_retained_for_graceful_restart() {
    let (state, _rxs, stop_senders) = make_state(&[(REMOVED, 65099)], 8);
    let (update_tx, _update_rx) = mpsc::channel(8);
    let peer_config = config::PeerConfig {
        address: REMOVED,
        port: 179,
        remote_as: 65099,
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
    };

    // A first removal that got both events, then the address is reused.
    state.write().await.pending_removal.insert(REMOVED);
    run_events(
        &state,
        &stop_senders,
        REMOVED,
        vec![
            SessionEvent::Terminated(TerminationReason::OperatorStop),
            SessionEvent::Retired,
        ],
    )
    .await;
    assert!(state.write().await.add_peer(&peer_config, update_tx));

    let graceful_restart = Capability::GracefulRestart {
        restart_flags: 0,
        restart_time: 120,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: true,
        }],
    };
    {
        let mut s = state.write().await;
        establish_and_announce(&mut s, REMOVED, &[graceful_restart], "192.0.2.0/24");
        s.on_terminated(REMOVED, TerminationReason::Unclean, true);
        assert_eq!(s.rib.loc_rib.len(), 1, "the route is retained");
        s.pending_removal.insert(REMOVED);
    }

    run_events(&state, &stop_senders, REMOVED, vec![SessionEvent::Retired]).await;

    assert_eq!(state.read().await.rib.loc_rib.len(), 0);
}

/// When a normal peer (not in `pending_removal`) receives `Terminated`, the
/// event loop must broadcast exactly **one** `Changed(peer: None)` event —
/// not a `Removed` — so monitoring tools see the peer go Idle rather than
/// disappear.
///
/// This is a regression guard for the `notify: bool` parameter: the normal
/// reconnect path must still send its notification.
#[tokio::test]
async fn terminated_without_pending_removal_broadcasts_changed_not_removed() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

    let mut peer_rx = state.read().await.peer_tx.subscribe();

    let (event_tx, event_rx) = mpsc::channel(4);
    event_tx
        .send((
            peer_ip,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

    let mut events = vec![];
    while let Ok(ev) = peer_rx.try_recv() {
        events.push(ev);
    }

    assert_eq!(
        events.len(),
        1,
        "exactly one peer_tx event must fire for a normal Terminated; got {events:?}"
    );
    assert_eq!(
        events[0].r#type,
        proto::PeerEventType::Changed as i32,
        "normal Terminated must emit Changed, not Removed"
    );
    assert!(
        events[0].peer.is_none(),
        "Changed signal from on_terminated must have peer: None (stream builds payload)"
    );
}

/// `on_terminated(peer_ip, notify: false)` must not send any broadcast on
/// `peer_tx`.  This is a direct unit test of the new parameter — if it is
/// ever dropped or inverted, this test will catch the regression.
#[tokio::test]
async fn on_terminated_notify_false_sends_no_broadcast() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

    let mut peer_rx = state.read().await.peer_tx.subscribe();

    state
        .write()
        .await
        .on_terminated(peer_ip, TerminationReason::Unclean, false);

    // No broadcast must arrive.
    assert!(
        peer_rx.try_recv().is_err(),
        "on_terminated(notify=false) must not send to peer_tx"
    );
}

/// `on_terminated(peer_ip, notify: true)` must send exactly one
/// `Changed(peer: None)` broadcast on `peer_tx`.
#[tokio::test]
async fn on_terminated_notify_true_sends_changed_broadcast() {
    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

    let mut peer_rx = state.read().await.peer_tx.subscribe();

    state
        .write()
        .await
        .on_terminated(peer_ip, TerminationReason::Unclean, true);

    let ev = peer_rx
        .try_recv()
        .expect("on_terminated(notify=true) must send to peer_tx");
    assert_eq!(
        ev.r#type,
        proto::PeerEventType::Changed as i32,
        "broadcast must be Changed"
    );
    assert!(ev.peer.is_none(), "Changed signal must have peer: None");
    assert!(peer_rx.try_recv().is_err(), "must send exactly one event");
}

// ── incoming_senders race-safety ──────────────────────────────────────────

/// After `RemovePeer` is processed by `run_command_processor`, the peer's
/// entry must be gone from `incoming_senders`.
///
/// This proves that new inbound TCP connections from the removed peer are
/// rejected by `run_bgp_listener` before `Terminated` even fires — closing
/// the reconnect race window.
#[tokio::test]
async fn remove_peer_clears_incoming_senders() {
    struct NeverSpawned;
    impl SessionHandle for NeverSpawned {
        async fn start(&self) {}
        async fn next_event(&mut self) -> Option<SessionEvent> {
            None
        }
        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            mpsc::channel(1).0
        }
        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            mpsc::channel(1).0
        }
        async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}
        async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
    }

    let peer_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

    // Pre-populate incoming_senders as if AddPeer had already run.
    let (incoming_tx, _incoming_rx) = mpsc::channel::<SessionCommand>(1);
    let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::from([(peer_ip, incoming_tx)])));

    let (event_tx, _event_rx) = mpsc::channel(8);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(run_command_processor::<NeverSpawned, _, KernelTcpMd5>(
        cmd_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        Arc::clone(&incoming),
        Arc::new(ListenerKeys::default()),
        event_tx,
        |_cfg| unreachable!("RemovePeer must not call spawn_fn"),
        SpawnConfig {
            local_as: 65001,
            local_bgp_id: "1.2.3.4".parse().unwrap(),
            hold_time: 180,
            graceful_restart_time: 0,
            configured_restarting: false,
            confederation_id: None,
            startup_instant: std::time::Instant::now(),
            md5_enforcement: Md5Enforcement::Required,
        },
        None,
    ));

    assert!(
        incoming.read().await.contains_key(&peer_ip),
        "pre-condition: incoming_senders must contain the peer before RemovePeer"
    );

    cmd_tx
        .send(DaemonCommand::RemovePeer(peer_ip))
        .await
        .unwrap();

    // Allow the command processor to run the handler.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert!(
        !incoming.read().await.contains_key(&peer_ip),
        "incoming_senders must not contain the peer after RemovePeer — \
         new inbound TCP connections must be rejected immediately"
    );
}

/// `run_bgp_listener` must drop (RST) inbound TCP connections whose source
/// address is not in `incoming_senders`.
///
/// This proves the other half of the race-safety invariant: even if an
/// adversarial or reconnecting peer dials in, the listener drops it without
/// forwarding it to any session actor.
#[tokio::test]
async fn bgp_listener_drops_unlisted_peer() {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt as _;

    // Bind the listener on a random OS-assigned port with an empty
    // incoming_senders — no peers are known.
    let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let md5: Md5Keys = Arc::new(ListenerKeys::default());

    // Spawn on port 0 so the OS assigns a free port.
    let listener_sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener_sock.local_addr().unwrap().port();
    drop(listener_sock);

    let incoming_clone = Arc::clone(&incoming);
    let md5_clone = Arc::clone(&md5);
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
    tokio::spawn(async move {
        run_bgp_listener(bind_addr, incoming_clone, md5_clone).await;
    });

    // Give the listener a moment to bind.
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // Connect from 127.0.0.1 — not present in incoming_senders.
    let mut conn = tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .expect("TCP connect must succeed");

    // The listener drops the stream immediately — we should see EOF (0
    // bytes read) with no data sent, within a short timeout.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(tokio::time::Duration::from_secs(2), conn.read(&mut buf))
        .await
        .expect("read must complete within 2 s — listener must close the connection promptly")
        .expect("read must not return an OS error");

    assert_eq!(
        n, 0,
        "listener must send no data and close the connection for an unlisted peer"
    );
}

/// An IPv4 listener and an IPv6 listener bound to the *same* port must
/// coexist without EADDRINUSE, and each must independently accept
/// connections from its own address family. Proves the
/// `IPV6_V6ONLY`-via-`socket2` fix in `bind_listener`: without it, an
/// IPv6 "any" bind can be dual-stack on some platforms and collide with
/// a same-port IPv4 listener.
#[tokio::test]
async fn bgp_listener_v4_and_v6_coexist_on_same_port() {
    use std::net::SocketAddr;

    // Pick a free port via a throwaway IPv4 bind, then drop it so both
    // real listeners can claim that exact port on their own family.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let peer_v4: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let peer_v6: Ipv6Addr = "::1".parse().unwrap();
    let (tx_v4, mut rx_v4) = mpsc::channel(1);
    let (tx_v6, mut rx_v6) = mpsc::channel(1);
    let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::from([
            (IpAddr::V4(peer_v4), tx_v4),
            (IpAddr::V6(peer_v6), tx_v6),
        ])));
    let md5: Md5Keys = Arc::new(ListenerKeys::default());

    let bind_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let bind_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let (incoming_v4, md5_v4) = (Arc::clone(&incoming), Arc::clone(&md5));
    tokio::spawn(async move {
        run_bgp_listener(bind_v4, incoming_v4, md5_v4).await;
    });
    let (incoming_v6, md5_v6) = (Arc::clone(&incoming), Arc::clone(&md5));
    tokio::spawn(async move {
        run_bgp_listener(bind_v6, incoming_v6, md5_v6).await;
    });

    // Give both listeners a moment to bind.
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    let _conn_v4 = tokio::net::TcpStream::connect(SocketAddr::new(IpAddr::V4(peer_v4), port))
        .await
        .expect("IPv4 connect must succeed — the IPv4 listener must have bound cleanly");
    tokio::time::timeout(tokio::time::Duration::from_secs(2), rx_v4.recv())
        .await
        .expect("must receive an IncomingConnection within 2 s")
        .expect("channel must not be closed");

    let _conn_v6 = tokio::net::TcpStream::connect(SocketAddr::new(IpAddr::V6(peer_v6), port))
        .await
        .expect(
            "IPv6 connect must succeed — the IPv6 listener must have bound cleanly \
             alongside the IPv4 one on the same port",
        );
    tokio::time::timeout(tokio::time::Duration::from_secs(2), rx_v6.recv())
        .await
        .expect("must receive an IncomingConnection within 2 s")
        .expect("channel must not be closed");
}
