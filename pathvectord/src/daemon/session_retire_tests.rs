// daemon/session_retire_tests.rs — `RemovePeer` must complete from any
// session state, and must leave no session or forwarding task behind.
//
// RFC 4271 §8.2.2: on a ManualStop (Event 2), a session that has sent its OPEN
// "sends the NOTIFICATION with a Cease"; in Connect and Active it drops the
// connection without one. Only a session that was Established has routes to
// delete, so only it reports a termination. A removal cannot depend on that
// report.
//
// These tests run real session tasks over loopback TCP. Each handle is wrapped
// to observe the two things a removal must end: the session task (its event
// stream closes) and the daemon's forwarding task (which owns the handle and
// drops it on exit).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use pathvector_session::message::{
    BgpMessage, Capability, CeaseError, GracefulRestartFamily, NotificationError, PathAttribute,
    RouteRefreshMessage, UpdateMessage,
};
use pathvector_session::transport::{
    self, SessionCommand, SessionConfig, SessionEvent, SessionHandle, SpawnedSessionHandle,
    TerminationReason,
    listener::ListenerKeys,
    tcp_md5::{KernelTcpMd5, Md5Enforcement},
};
use pathvector_types::{AfiSafi, AsPath, Asn, Origin, PeerType};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, broadcast, mpsc, watch};

use super::session_restart_tests::PeerConn;
use super::{
    DaemonCommand, DaemonState, SpawnConfig, build_daemon, run_command_processor, run_event_loop,
};
use crate::{config, proto};

const PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TIMEOUT: Duration = Duration::from_secs(5);

/// What has ended for one spawned session.
#[derive(Clone, Copy, Default)]
struct Lifetime {
    /// The session task has exited: its event stream closed.
    session_ended: bool,
    /// The forwarding task has exited: it dropped the handle it owned.
    handle_dropped: bool,
}

/// A real session handle that reports when its tasks end.
struct Tracked {
    inner: SpawnedSessionHandle,
    life: watch::Sender<Lifetime>,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.life.send_modify(|l| l.handle_dropped = true);
    }
}

impl SessionHandle for Tracked {
    async fn start(&self) {
        self.inner.start().await;
    }
    async fn next_event(&mut self) -> Option<SessionEvent> {
        let event = self.inner.next_event().await;
        if event.is_none() {
            self.life.send_modify(|l| l.session_ended = true);
        }
        event
    }
    fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
        self.inner.update_sender()
    }
    fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.inner.stop_sender()
    }
    fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.inner.incoming_sender()
    }
    async fn send_route_refresh(&self, rr: RouteRefreshMessage) {
        self.inner.send_route_refresh(rr).await;
    }
    async fn set_capabilities(&self, caps: Vec<Capability>) {
        self.inner.set_capabilities(caps).await;
    }
}

type Lives = Arc<Mutex<Vec<watch::Receiver<Lifetime>>>>;

fn peer_config(port: u16) -> config::PeerConfig {
    config::PeerConfig {
        address: PEER_IP,
        port,
        remote_as: 65002,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: Some(1),
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }
}

async fn wait_until(state: &RwLock<DaemonState>, done: impl Fn(&DaemonState) -> bool) {
    tokio::time::timeout(TIMEOUT, async {
        while !done(&*state.read().await) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("timed out waiting for the daemon state");
}

fn spawn_config() -> SpawnConfig {
    SpawnConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        graceful_restart_time: 0,
        configured_restarting: false,
        confederation_id: None,
        startup_instant: std::time::Instant::now(),
        md5_enforcement: Md5Enforcement::Required,
    }
}

fn config_with(static_peers: Vec<config::PeerConfig>) -> config::Config {
    config::Config {
        daemon: config::DaemonConfig {
            local_as: 65001,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            grpc_port: 0,
            bgp_port: 0,
            metrics_port: None,
            local_ipv6: None,
            cluster_id: None,
            confederation_id: None,
            fib_table: 254,
            fib_metric: 20,
            graceful_restart_time: 0,
            restarting: false,
            selection_deferral_time: 0,
            rpki: None,
            tcp_md5_enforcement: config::TcpMd5EnforcementConfig::Required,
        },
        peers: static_peers,
        sidecar_path: None,
    }
}

/// The daemon's startup wiring, command processor and event loop, spawning
/// real sessions.
struct Daemon {
    state: Arc<RwLock<DaemonState>>,
    commands: mpsc::Sender<DaemonCommand>,
    lives: Lives,
    peer_events: broadcast::Receiver<proto::PeerEvent>,
}

impl Daemon {
    async fn start(static_peers: Vec<config::PeerConfig>) -> Self {
        let lives: Lives = Arc::default();
        let spawned = Arc::clone(&lives);
        let spawn_fn = move |cfg: SessionConfig| {
            let (life, observed) = watch::channel(Lifetime::default());
            spawned.lock().unwrap().push(observed);
            Tracked {
                inner: transport::spawn(cfg),
                life,
            }
        };
        let cfg = config_with(static_peers);
        let (state, event_rx, event_tx, stop_senders, incoming_senders, keys) =
            build_daemon(&cfg, spawn_fn.clone()).await;
        let peer_events = state.read().await.peer_tx.subscribe();
        let (commands, command_rx) = mpsc::channel(4);
        tokio::spawn(run_command_processor(
            command_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            incoming_senders,
            keys,
            event_tx,
            spawn_fn,
            spawn_config(),
            None,
        ));
        tokio::spawn(run_event_loop(
            event_rx,
            Arc::clone(&state),
            stop_senders,
            None,
        ));
        Self {
            state,
            commands,
            lives,
            peer_events,
        }
    }

    async fn send(&self, command: DaemonCommand) {
        self.commands.send(command).await.ok().unwrap();
    }

    async fn add(&self, peer: config::PeerConfig) {
        self.send(DaemonCommand::AddPeer(peer)).await;
        wait_until(&self.state, |s| s.adj_ribs_in.contains_key(&PEER_IP)).await;
    }

    /// `RemovePeer`, waiting for the daemon to forget the peer and to say so.
    async fn remove(&mut self) {
        self.send(DaemonCommand::RemovePeer(PEER_IP)).await;
        wait_until(&self.state, |s| {
            !s.adj_ribs_in.contains_key(&PEER_IP) && !s.pending_removal.contains(&PEER_IP)
        })
        .await;
        tokio::time::timeout(TIMEOUT, async {
            loop {
                let event = self.peer_events.recv().await.unwrap();
                if event.r#type == proto::PeerEventType::Removed as i32 {
                    break;
                }
            }
        })
        .await
        .expect("no Removed event");
    }

    /// Waits for both tasks of the `index`th session spawned to end.
    async fn assert_tasks_end(&self, index: usize) {
        let mut life = self.lives.lock().unwrap()[index].clone();
        let ended = tokio::time::timeout(TIMEOUT, async {
            life.wait_for(|l| l.session_ended && l.handle_dropped)
                .await
                .is_ok()
        })
        .await;
        let last = *life.borrow();
        assert!(
            matches!(ended, Ok(true)),
            "session {index} outlived its removal: session task ended = {}, \
             forwarding task ended = {}",
            last.session_ended,
            last.handle_dropped,
        );
    }
}

async fn listen() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

async fn accept(listener: &TcpListener) -> tokio::net::TcpStream {
    let (stream, _): (_, SocketAddr) = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .expect("the session never dialled the peer")
        .unwrap();
    stream
}

const ADMIN_SHUTDOWN: NotificationError =
    NotificationError::Cease(CeaseError::AdministrativeShutdown);

#[tokio::test]
async fn removing_an_established_peer_ends_its_tasks() {
    let (listener, port) = listen().await;
    let mut daemon = Daemon::start(vec![peer_config(port)]).await;
    let mut conn = PeerConn::handshake(accept(&listener).await).await;
    wait_until(&daemon.state, |s| s.rib.peer_types.contains_key(&PEER_IP)).await;

    daemon.remove().await;

    assert_eq!(conn.notification().await.error, ADMIN_SHUTDOWN);
    daemon.assert_tasks_end(0).await;
}

/// The session has sent its OPEN, so the peer is owed a Cease, but it was never
/// Established, so it reports no termination.
#[tokio::test]
async fn removing_a_peer_in_open_sent_completes_and_ends_its_tasks() {
    let (listener, port) = listen().await;
    let mut daemon = Daemon::start(vec![]).await;
    daemon.add(peer_config(port)).await;
    let stream = accept(&listener).await;
    let mut conn =
        tokio_util::codec::FramedRead::new(stream, pathvector_session::framing::BgpCodec::new());
    assert!(matches!(conn.next().await, Some(Ok(BgpMessage::Open(_)))));

    daemon.remove().await;

    let Some(Ok(BgpMessage::Notification(n))) = conn.next().await else {
        panic!("no NOTIFICATION before the connection closed");
    };
    assert_eq!(n.error, ADMIN_SHUTDOWN);
    daemon.assert_tasks_end(0).await;
}

/// Nothing listens, so the session only ever sees failed dials. Repeating the
/// add and remove must not accumulate tasks.
#[tokio::test]
async fn repeatedly_removing_an_unreachable_peer_accumulates_nothing() {
    let (listener, port) = listen().await;
    drop(listener);
    let mut daemon = Daemon::start(vec![]).await;

    for index in 0..3 {
        daemon.add(peer_config(port)).await;
        daemon.remove().await;
        daemon.assert_tasks_end(index).await;
    }
    assert_eq!(daemon.lives.lock().unwrap().len(), 3);
}

/// Removing a peer that was Established but has since dropped and not come
/// back: its last termination was already handled.
#[tokio::test]
async fn removing_a_peer_between_sessions_completes_and_ends_its_tasks() {
    let (listener, port) = listen().await;
    let mut daemon = Daemon::start(vec![peer_config(port)]).await;
    let conn = PeerConn::handshake(accept(&listener).await).await;
    wait_until(&daemon.state, |s| s.rib.peer_types.contains_key(&PEER_IP)).await;
    drop(conn);
    drop(listener);
    wait_until(&daemon.state, |s| !s.rib.peer_types.contains_key(&PEER_IP)).await;

    daemon.remove().await;

    daemon.assert_tasks_end(0).await;
}

// ── Orderings real sessions cannot be made to produce on demand ──────────────

fn stop_map(
    tx: mpsc::Sender<SessionCommand>,
) -> Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> {
    Arc::new(Mutex::new(HashMap::from([(PEER_IP, tx)])))
}

fn state_with_peer() -> Arc<RwLock<DaemonState>> {
    let (update_tx, _) = mpsc::channel(1);
    Arc::new(RwLock::new(DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None,
        &[peer_config(179)],
        HashMap::from([(PEER_IP, update_tx)]),
        vec![],
    )))
}

/// The command processor over [`state_with_peer`], with the session played by
/// the test: it reads the commands and sends the events.
struct Processor {
    state: Arc<RwLock<DaemonState>>,
    stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    commands: mpsc::Sender<DaemonCommand>,
    session_rx: mpsc::Receiver<SessionCommand>,
    event_rx: mpsc::Receiver<(IpAddr, SessionEvent)>,
    task: tokio::task::JoinHandle<()>,
}

impl Processor {
    fn start(state: Arc<RwLock<DaemonState>>) -> Self {
        let (session_tx, session_rx) = mpsc::channel(8);
        let stop_senders = stop_map(session_tx);
        let (event_tx, event_rx) = mpsc::channel(8);
        let (commands, command_rx) = mpsc::channel(4);
        let task = tokio::spawn(run_command_processor::<Tracked, _, KernelTcpMd5>(
            command_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            Arc::default(),
            Arc::new(ListenerKeys::default()),
            event_tx,
            |_| panic!("a session was spawned for an address still in use"),
            spawn_config(),
            None,
        ));
        Self {
            state,
            stop_senders,
            commands,
            session_rx,
            event_rx,
            task,
        }
    }

    async fn send(&self, command: DaemonCommand) {
        self.commands.send(command).await.ok().unwrap();
    }

    async fn expect_commands(&mut self, expected: &[&str]) {
        for expected in expected {
            let command = tokio::time::timeout(TIMEOUT, self.session_rx.recv())
                .await
                .expect("the session was never told to end")
                .expect("the command channel closed first");
            assert_eq!(format!("{command:?}"), *expected);
        }
    }
}

fn establish(s: &mut DaemonState, capabilities: &[Capability]) {
    s.on_established(
        PEER_IP,
        Ipv4Addr::new(10, 0, 0, 2),
        PeerType::External,
        65002,
        90,
        capabilities,
        None,
    );
}

/// A session's `Retired` follows its `Terminated`, and may still be queued when
/// the latter is handled. The address must stay taken until then. A session
/// added in between would receive the old one's `Retired`, and that cannot be
/// told apart from its own: removing the new session would complete early, with
/// its events still on the way.
#[tokio::test]
async fn address_stays_taken_until_the_removed_session_is_retired() {
    let state = state_with_peer();
    establish(&mut *state.write().await, &[]);
    let mut p = Processor::start(Arc::clone(&state));
    p.send(DaemonCommand::RemovePeer(PEER_IP)).await;
    p.expect_commands(&["Stop", "Retire"]).await;

    let (event_tx, event_rx) = mpsc::channel(8);
    tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&p.stop_senders),
        None,
    ));
    event_tx
        .send((
            PEER_IP,
            SessionEvent::Terminated(TerminationReason::OperatorStop),
        ))
        .await
        .unwrap();
    wait_until(&state, |s| !s.rib.peer_types.contains_key(&PEER_IP)).await;
    {
        let s = state.read().await;
        assert!(s.adj_ribs_in.contains_key(&PEER_IP));
        assert!(s.pending_removal.contains(&PEER_IP));
    }

    p.send(DaemonCommand::AddPeer(peer_config(179))).await;
    drop(p.commands);
    p.task.await.expect("AddPeer was not ignored");

    event_tx
        .send((PEER_IP, SessionEvent::Retired))
        .await
        .unwrap();
    wait_until(&state, |s| {
        !s.adj_ribs_in.contains_key(&PEER_IP) && !s.pending_removal.contains(&PEER_IP)
    })
    .await;
    assert!(p.stop_senders.lock().unwrap().is_empty());
}

/// A retiring session closes its command channel before the daemon has taken
/// its last events. A second `RemovePeer` then must not complete the removal
/// ahead of them.
#[tokio::test]
async fn repeated_remove_peer_leaves_the_first_removal_to_finish() {
    let mut p = Processor::start(state_with_peer());
    p.send(DaemonCommand::RemovePeer(PEER_IP)).await;
    p.expect_commands(&["Stop", "Retire"]).await;
    p.session_rx.close();

    p.send(DaemonCommand::RemovePeer(PEER_IP)).await;
    drop(p.commands);
    p.task.await.unwrap();

    assert!(p.event_rx.try_recv().is_err(), "an event was made up");
    assert!(p.state.read().await.pending_removal.contains(&PEER_IP));
}

// ── A session task that dies ─────────────────────────────────────────────────
//
// It never emits `Retired`, and the daemon may still be holding events it did
// emit. The removal must complete, but not ahead of those events.

/// A handle whose session is played by the test.
struct Scripted {
    events: mpsc::Receiver<SessionEvent>,
    commands: mpsc::Sender<SessionCommand>,
}

/// The far end of a [`Scripted`]. Dropping `commands` is the session task dying;
/// the event stream ends when `events` is dropped.
struct Script {
    events: mpsc::Sender<SessionEvent>,
    commands: mpsc::Receiver<SessionCommand>,
}

fn scripted() -> (Scripted, Script) {
    let (event_tx, event_rx) = mpsc::channel(8);
    let (command_tx, command_rx) = mpsc::channel(8);
    (
        Scripted {
            events: event_rx,
            commands: command_tx,
        },
        Script {
            events: event_tx,
            commands: command_rx,
        },
    )
}

impl SessionHandle for Scripted {
    async fn start(&self) {}
    async fn next_event(&mut self) -> Option<SessionEvent> {
        self.events.recv().await
    }
    fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
        mpsc::channel(1).0
    }
    fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.commands.clone()
    }
    fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.commands.clone()
    }
    async fn send_route_refresh(&self, _rr: RouteRefreshMessage) {}
    async fn set_capabilities(&self, _caps: Vec<Capability>) {}
}

async fn next(events: &mut mpsc::Receiver<(IpAddr, SessionEvent)>) -> SessionEvent {
    tokio::time::timeout(TIMEOUT, events.recv())
        .await
        .expect("no event reached the daemon")
        .expect("the event channel closed")
        .1
}

/// The session task is gone, but its forwarding task has yet to hand over what
/// it emitted. `RemovePeer` must not get ahead of that: the address would be
/// free, and the old events would reach a replacement.
#[tokio::test]
async fn dead_session_is_retired_after_the_events_it_left_behind() {
    let (state, _, _, stop_senders, incoming, keys) =
        build_daemon(&config_with(vec![]), |_| -> Scripted { unreachable!() }).await;
    let (session, mut script) = scripted();
    let session = Mutex::new(Some(session));
    let (event_tx, mut event_rx) = mpsc::channel(8);
    let (commands, command_rx) = mpsc::channel(4);
    let processor = tokio::spawn(run_command_processor::<Scripted, _, KernelTcpMd5>(
        command_rx,
        Arc::clone(&state),
        stop_senders,
        incoming,
        keys,
        event_tx,
        move |_| session.lock().unwrap().take().expect("one session"),
        spawn_config(),
        None,
    ));
    commands
        .send(DaemonCommand::AddPeer(peer_config(179)))
        .await
        .ok()
        .unwrap();
    wait_until(&state, |s| s.adj_ribs_in.contains_key(&PEER_IP)).await;

    script.commands.close();
    commands
        .send(DaemonCommand::RemovePeer(PEER_IP))
        .await
        .ok()
        .unwrap();
    drop(commands);
    processor.await.unwrap();
    assert!(
        event_rx.try_recv().is_err(),
        "the removal was completed ahead of the session's events"
    );

    script
        .events
        .send(SessionEvent::Terminated(TerminationReason::Unclean))
        .await
        .unwrap();
    drop(script.events);
    assert!(matches!(
        next(&mut event_rx).await,
        SessionEvent::Terminated(_)
    ));
    assert!(matches!(next(&mut event_rx).await, SessionEvent::Retired));
}

/// The session task died some time before `RemovePeer`, and all it emitted has
/// been handled, so nothing more will come from it.
#[tokio::test]
async fn removing_a_peer_whose_session_died_earlier_completes() {
    let (session, script) = scripted();
    let session = Mutex::new(Some(session));
    let (state, event_rx, event_tx, stop_senders, incoming, keys) =
        build_daemon(&config_with(vec![peer_config(179)]), move |_| {
            session.lock().unwrap().take().expect("one session")
        })
        .await;
    tokio::spawn(run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::clone(&stop_senders),
        None,
    ));
    drop(script);
    tokio::time::timeout(TIMEOUT, async {
        while stop_senders.lock().unwrap().contains_key(&PEER_IP) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the end of the session was not noticed");
    assert!(state.read().await.adj_ribs_in.contains_key(&PEER_IP));

    let (commands, command_rx) = mpsc::channel(4);
    tokio::spawn(run_command_processor::<Scripted, _, KernelTcpMd5>(
        command_rx,
        Arc::clone(&state),
        stop_senders,
        incoming,
        keys,
        event_tx,
        |_| unreachable!("no peer is added"),
        spawn_config(),
        None,
    ));
    commands
        .send(DaemonCommand::RemovePeer(PEER_IP))
        .await
        .ok()
        .unwrap();
    wait_until(&state, |s| {
        !s.adj_ribs_in.contains_key(&PEER_IP) && !s.pending_removal.contains(&PEER_IP)
    })
    .await;
}

/// A Graceful Restart peer's connection can fail just before `RemovePeer`. That
/// termination must not open a restart window for a peer being removed: its
/// routes are withdrawn at once.
#[tokio::test]
async fn unclean_termination_of_a_peer_being_removed_withdraws_routes() {
    let state = state_with_peer();
    {
        let mut s = state.write().await;
        establish(
            &mut s,
            &[Capability::GracefulRestart {
                restart_flags: 0,
                restart_time: 120,
                families: vec![GracefulRestartFamily {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    forwarding_preserved: true,
                }],
            }],
        );
        s.on_route_update(
            PEER_IP,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec!["192.0.2.0/24".parse().unwrap()],
            },
        );
        s.flush_pending();
        assert_eq!(s.rib.loc_rib.len(), 1);
        s.pending_removal.insert(PEER_IP);
    }
    let (session_tx, _session_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(8);
    event_tx
        .send((
            PEER_IP,
            SessionEvent::Terminated(TerminationReason::Unclean),
        ))
        .await
        .unwrap();
    drop(event_tx);

    run_event_loop(event_rx, Arc::clone(&state), stop_map(session_tx), None).await;

    let s = state.read().await;
    assert_eq!(s.rib.loc_rib.len(), 0, "the removed peer's route remains");
    assert!(s.gr.deadlines.is_empty(), "a restart window opened");
}
