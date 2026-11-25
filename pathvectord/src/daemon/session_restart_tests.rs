// daemon/session_restart_tests.rs — which of the daemon's own resets bring a
// session back, and when.
//
// RFC 4271 §8.1.2 separates the two kinds of stop. Event 2 (ManualStop) is
// "Local system administrator manually stops the peer connection". Event 8
// (AutomaticStop) is "Local system automatically stops the BGP connection",
// and its example is "exceeding the number of prefixes for a given peer".
// §6.7 leaves terminating on a prefix limit "under control of local
// configuration" and requires the Cease. Whether and when the session starts
// again is local policy too: §8.1.1 `AllowAutomaticStart`, and the
// IdleHoldTimer that "keeps the BGP peer in Idle for a particular duration".
//
// pathvectord's policy for a prefix limit:
// - `max_prefixes_restart` absent or 0: the session stays down until an
//   operator acts (AllowAutomaticStart false).
// - positive N: it is started again N seconds after the Cease
//   (IdleHoldTimer, Event 13), whatever `connect_retry_time` is.
// Every other reset the daemon decides on reconnects after
// `connect_retry_time`, including a NOTIFICATION for an UPDATE error it
// detects (§8.2.2 Established, Event 28).
//
// These tests drive `run_event_loop` and `run_command_processor` with a real
// session task over loopback TCP and a hand-driven peer, because a mock command
// channel can only show which command was sent, not what the session does
// afterwards.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, CeaseError, NotificationError, NotificationMessage, OpenMessage,
    PathAttribute, UpdateMessage, UpdateMsgError,
};
use pathvector_session::transport::{
    self, SessionCommand, SessionConfig, SessionEvent, SpawnedSessionHandle,
};
use pathvector_types::{AsPath, Asn, Nlri, Origin};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::peer::run_command_processor;
use super::{DaemonCommand, DaemonState, SpawnConfig, build_daemon, run_event_loop};
use crate::config;

const LOCAL_AS: u32 = 65001;
const PEER_AS: u32 = 65002;
const LOCAL_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CONNECT_RETRY: Duration = Duration::from_millis(100);
/// Many `CONNECT_RETRY` intervals: long enough that no dial means none is due.
const QUIET: Duration = Duration::from_millis(1500);
const TIMEOUT: Duration = Duration::from_secs(5);

/// The remote end of one TCP connection from the session under test.
struct PeerConn {
    reader: FramedRead<OwnedReadHalf, BgpCodec>,
    writer: FramedWrite<OwnedWriteHalf, BgpCodec>,
}

impl PeerConn {
    /// Completes the OPEN/KEEPALIVE exchange on a connection the session dialled.
    async fn handshake(stream: TcpStream) -> Self {
        let (r, w) = stream.into_split();
        let mut conn = Self {
            reader: FramedRead::new(r, BgpCodec::new()),
            writer: FramedWrite::new(w, BgpCodec::new()),
        };
        assert!(matches!(conn.recv().await, BgpMessage::Open(_)));
        conn.send(BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: u16::try_from(PEER_AS).unwrap(),
            hold_time: 90,
            bgp_id: PEER_ID,
            capabilities: vec![Capability::FourByteAsn(PEER_AS)],
        }))
        .await;
        assert!(matches!(conn.recv().await, BgpMessage::Keepalive));
        conn.send(BgpMessage::Keepalive).await;
        conn
    }

    async fn recv(&mut self) -> BgpMessage {
        tokio::time::timeout(TIMEOUT, self.reader.next())
            .await
            .expect("timed out waiting for a message from the session")
            .expect("session closed the connection")
            .expect("decode error")
    }

    async fn send(&mut self, msg: BgpMessage) {
        self.writer.send(msg).await.expect("send to session");
    }

    /// The next NOTIFICATION, skipping anything else the session sends.
    async fn notification(&mut self) -> NotificationMessage {
        loop {
            if let BgpMessage::Notification(n) = self.recv().await {
                return n;
            }
        }
    }
}

struct Daemon {
    listener: TcpListener,
    peer_cfg: config::PeerConfig,
    state: Arc<RwLock<DaemonState>>,
    event_tx: mpsc::Sender<(IpAddr, SessionEvent)>,
    incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    commands: mpsc::Sender<DaemonCommand>,
}

impl Daemon {
    async fn start(max_prefixes_v4: Option<u32>, max_prefixes_restart: Option<u16>) -> Self {
        Self::start_with_retry(max_prefixes_v4, max_prefixes_restart, CONNECT_RETRY).await
    }

    /// The daemon as `run_with` assembles it, with one configured peer that
    /// dials this test's listener every `connect_retry`.
    async fn start_with_retry(
        max_prefixes_v4: Option<u32>,
        max_prefixes_restart: Option<u16>,
        connect_retry: Duration,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_cfg = config::PeerConfig {
            address: PEER_IP,
            port: listener.local_addr().unwrap().port(),
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
            max_prefixes_v4,
            max_prefixes_v6: None,
            max_prefixes_restart,
            role: None,
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        };
        let cfg = config::Config {
            daemon: config::DaemonConfig {
                local_as: LOCAL_AS,
                bgp_id: LOCAL_ID,
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
            peers: vec![peer_cfg.clone()],
            sidecar_path: None,
        };
        let spawn = move |mut session: SessionConfig| -> SpawnedSessionHandle {
            session.connect_retry_time = connect_retry;
            transport::spawn(session)
        };

        let (state, event_rx, event_tx, stop_senders, incoming, md5) =
            build_daemon(&cfg, spawn).await;
        tokio::spawn(run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        ));
        let (commands, command_rx) = mpsc::channel(4);
        tokio::spawn(run_command_processor(
            command_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            Arc::clone(&incoming),
            md5,
            event_tx.clone(),
            spawn,
            SpawnConfig {
                local_as: LOCAL_AS,
                local_bgp_id: LOCAL_ID,
                hold_time: 90,
                graceful_restart_time: 0,
                configured_restarting: false,
                confederation_id: None,
                startup_instant: Instant::now(),
                md5_enforcement: cfg.daemon.tcp_md5_enforcement.into(),
            },
            None,
        ));

        Self {
            listener,
            peer_cfg,
            state,
            event_tx,
            incoming,
            commands,
        }
    }

    /// Accepts the session's next dial and completes the handshake.
    async fn accept(&self) -> PeerConn {
        let (stream, _) = tokio::time::timeout(TIMEOUT, self.listener.accept())
            .await
            .expect("the session never dialled the peer again")
            .unwrap();
        PeerConn::handshake(stream).await
    }

    async fn assert_no_dial(&self, within: Duration) {
        assert!(
            tokio::time::timeout(within, self.listener.accept())
                .await
                .is_err(),
            "the session dialled the peer again"
        );
    }

    /// Hands the session a connection from the peer and requires it to be
    /// closed without a byte of BGP.
    async fn assert_inbound_refused(&self) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (peer, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let session = self.incoming.read().await[&PEER_IP].clone();
        session
            .send(SessionCommand::IncomingConnection(accepted.unwrap().0))
            .await
            .unwrap();
        let (read, _write) = peer.unwrap().into_split();
        let next = tokio::time::timeout(TIMEOUT, FramedRead::new(read, BgpCodec::new()).next())
            .await
            .expect("the inbound connection was left open");
        assert!(
            next.is_none(),
            "the inbound connection was answered: {next:?}"
        );
    }

    async fn is_registered(&self) -> bool {
        self.state
            .read()
            .await
            .rib
            .peer_types
            .contains_key(&PEER_IP)
    }

    async fn wait_until_registered(&self) {
        wait_for("the peer to be registered", async || {
            self.is_registered().await
        })
        .await;
    }

    async fn wait_until_unregistered(&self) {
        wait_for("the teardown to be processed", async || {
            !self.is_registered().await
        })
        .await;
    }

    /// Sends two prefixes to a peer limited to one, and returns after the
    /// Cease and its teardown.
    async fn exceed_limit(&self, mut conn: PeerConn) {
        self.wait_until_registered().await;
        conn.send(two_prefixes()).await;
        assert_eq!(
            conn.notification().await.error,
            NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached),
        );
        self.wait_until_unregistered().await;
    }

    async fn remove_peer(&self) {
        self.commands
            .send(DaemonCommand::RemovePeer(PEER_IP))
            .await
            .unwrap();
        wait_for("the peer to be removed", async || {
            !self.state.read().await.adj_ribs_in.contains_key(&PEER_IP)
        })
        .await;
    }

    async fn add_peer(&self) {
        self.commands
            .send(DaemonCommand::AddPeer(self.peer_cfg.clone()))
            .await
            .unwrap();
    }
}

async fn wait_for(what: &str, mut done: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(TIMEOUT, async {
        while !done().await {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn announce(prefixes: &[[u8; 4]]) -> BgpMessage {
    BgpMessage::Update(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
            PathAttribute::NextHop(PEER_ID),
        ],
        announced: prefixes
            .iter()
            .map(|o| Nlri::new(Ipv4Addr::from(*o), 24).unwrap())
            .collect(),
    })
}

fn two_prefixes() -> BgpMessage {
    announce(&[[192, 0, 2, 0], [198, 51, 100, 0]])
}

/// Absent or zero `max_prefixes_restart`: no dial, no inbound connection and no
/// repeated `AddPeer` brings the session back.
async fn assert_latched_down(max_prefixes_restart: Option<u16>) {
    let daemon = Daemon::start(Some(1), max_prefixes_restart).await;
    let conn = daemon.accept().await;
    daemon.exceed_limit(conn).await;

    daemon.assert_no_dial(QUIET).await;
    daemon.assert_inbound_refused().await;
    daemon.add_peer().await;
    daemon.assert_no_dial(QUIET).await;
    assert!(!daemon.is_registered().await);
}

#[tokio::test]
async fn max_prefix_without_restart_time_stays_down() {
    assert_latched_down(None).await;
}

#[tokio::test]
async fn max_prefix_with_zero_restart_time_stays_down() {
    assert_latched_down(Some(0)).await;
}

#[tokio::test]
async fn removing_and_adding_the_peer_clears_the_latch() {
    let daemon = Daemon::start(Some(1), None).await;
    let conn = daemon.accept().await;
    daemon.exceed_limit(conn).await;

    daemon.remove_peer().await;
    daemon.add_peer().await;

    let _conn = daemon.accept().await;
    daemon.wait_until_registered().await;
}

/// The restart follows `max_prefixes_restart`, not a longer ConnectRetry time.
#[tokio::test]
async fn max_prefix_restart_shorter_than_connect_retry() {
    let daemon = Daemon::start_with_retry(Some(1), Some(1), Duration::from_secs(60)).await;
    let conn = daemon.accept().await;
    daemon.wait_until_registered().await;
    let before_cease = Instant::now();
    daemon.exceed_limit(conn).await;

    let _conn = daemon.accept().await;
    let waited = before_cease.elapsed();
    assert!(
        (Duration::from_secs(1)..Duration::from_secs(3)).contains(&waited),
        "restarted after {waited:?}, expected 1 s"
    );
    daemon.wait_until_registered().await;
}

/// Nor is it brought forward by a shorter one: nothing happens before it.
#[tokio::test]
async fn max_prefix_restart_longer_than_connect_retry() {
    let daemon = Daemon::start(Some(1), Some(2)).await;
    let conn = daemon.accept().await;
    daemon.wait_until_registered().await;
    let before_cease = Instant::now();
    daemon.exceed_limit(conn).await;

    daemon.assert_inbound_refused().await;
    daemon.assert_no_dial(QUIET).await;

    let _conn = daemon.accept().await;
    let waited = before_cease.elapsed();
    assert!(
        (Duration::from_secs(2)..Duration::from_secs(4)).contains(&waited),
        "restarted after {waited:?}, expected 2 s"
    );
    daemon.wait_until_registered().await;
}

#[tokio::test]
async fn removing_a_peer_cancels_its_pending_restart() {
    let daemon = Daemon::start(Some(1), Some(1)).await;
    let conn = daemon.accept().await;
    daemon.exceed_limit(conn).await;

    daemon.remove_peer().await;

    daemon.assert_no_dial(QUIET).await;
}

fn over_limit_event() -> (IpAddr, SessionEvent) {
    let BgpMessage::Update(update) = two_prefixes() else {
        unreachable!()
    };
    (PEER_IP, SessionEvent::RouteUpdate(update))
}

/// The same peer is also marked stalled in the batch that exceeds its limit, so
/// the daemon queues a reconnecting reset behind the Cease. It must not undo
/// the latch. `earlier` is handled first, which puts the over-limit UPDATE on
/// the drain-loop path.
async fn assert_stays_down_with_stalled_reset(earlier: Option<BgpMessage>) {
    let daemon = Daemon::start(Some(1), None).await;
    let mut conn = daemon.accept().await;
    daemon.wait_until_registered().await;

    {
        // Held so that both events are queued before the loop handles either.
        let mut state = daemon.state.write().await;
        state.stalled_peers.push(PEER_IP);
        if let Some(BgpMessage::Update(update)) = earlier {
            daemon
                .event_tx
                .send((PEER_IP, SessionEvent::RouteUpdate(update)))
                .await
                .unwrap();
        }
        daemon.event_tx.send(over_limit_event()).await.unwrap();
    }

    assert_eq!(
        conn.notification().await.error,
        NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached),
    );
    daemon.assert_no_dial(QUIET).await;
}

#[tokio::test]
async fn stalled_reset_does_not_undo_the_latch_first_event_path() {
    assert_stays_down_with_stalled_reset(None).await;
}

#[tokio::test]
async fn stalled_reset_does_not_undo_the_latch_drain_loop_path() {
    assert_stays_down_with_stalled_reset(Some(announce(&[[192, 0, 2, 0]]))).await;
}

#[tokio::test]
async fn session_reconnects_after_stalled_outbound_reset() {
    let daemon = Daemon::start(None, None).await;
    let mut conn = daemon.accept().await;
    daemon.wait_until_registered().await;

    // Mark the peer as stalled, as a full outbound channel would, then send an
    // UPDATE so the event loop runs and drains the list.
    daemon.state.write().await.stalled_peers.push(PEER_IP);
    conn.send(announce(&[[192, 0, 2, 0]])).await;

    // RFC 4486 §4: a speaker that "runs out of resources ... and decides to
    // reset a session" MAY send "Out of Resources".
    assert_eq!(
        conn.notification().await.error,
        NotificationError::Cease(CeaseError::OutOfResources),
    );
    drop(conn);

    let _conn = daemon.accept().await;
    daemon.wait_until_registered().await;
}

#[tokio::test]
async fn session_reconnects_after_daemon_detected_update_error() {
    let daemon = Daemon::start(None, None).await;
    let mut conn = daemon.accept().await;
    daemon.wait_until_registered().await;

    // RFC 7606 §5.2: path attributes, no NLRI and no ORIGIN cannot be treated
    // as a withdrawal, so the session is reset.
    conn.send(BgpMessage::Update(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::AsPath(AsPath::from_sequence(vec![
            Asn::new(PEER_AS),
        ]))],
        announced: vec![],
    }))
    .await;
    assert_eq!(
        conn.notification().await.error,
        NotificationError::UpdateMessage(UpdateMsgError::MissingWellKnownAttribute),
    );
    drop(conn);

    let _conn = daemon.accept().await;
    daemon.wait_until_registered().await;
}
