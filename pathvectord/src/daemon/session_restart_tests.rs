// daemon/session_restart_tests.rs — a session the daemon resets on its own
// authority must come back without operator action.
//
// RFC 4271 §8.1.2 separates the two kinds of stop. Event 2 (ManualStop) is
// "Local system administrator manually stops the peer connection"; §8.2.2
// leaves it in Idle until a start event. Event 8 (AutomaticStop) is "Local
// system automatically stops the BGP connection", and its example is "exceeding
// the number of prefixes for a given peer". §8.1.1: "The term "automatic"
// refers to a start being issued to the BGP peer connection FSM when such logic
// determines that the BGP peer connection should be restarted." When to restart
// is local policy; pathvectord's documented policy is the ConnectRetry interval,
// held off further by `max_prefixes_restart`.
//
// A NOTIFICATION for an UPDATE error the daemon detects is §8.2.2 Established
// Event 28, which likewise ends in Idle with no operator involved.
//
// These tests drive `run_event_loop` with a real session task over loopback TCP
// and a hand-driven peer, because a mock command channel can only show which
// command was sent, not what the session does afterwards.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, CeaseError, NotificationError, NotificationMessage, OpenMessage,
    PathAttribute, UpdateMessage, UpdateMsgError,
};
use pathvector_session::transport::{self, SessionConfig, SessionHandle};
use pathvector_types::{AsPath, Asn, Nlri, Origin};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::{DaemonState, run_event_loop};
use crate::config;

const LOCAL_AS: u32 = 65001;
const PEER_AS: u32 = 65002;
const LOCAL_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CONNECT_RETRY: Duration = Duration::from_millis(100);
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

    /// A NOTIFICATION arriving within `within`, if any.
    async fn notification_within(&mut self, within: Duration) -> Option<NotificationMessage> {
        tokio::time::timeout(within, self.notification()).await.ok()
    }
}

struct Daemon {
    listener: TcpListener,
    state: Arc<RwLock<DaemonState>>,
}

impl Daemon {
    /// A daemon with one configured peer, a real session task dialling this
    /// test's listener, and `run_event_loop` consuming its events.
    async fn start(max_prefixes_v4: Option<u32>, max_prefixes_restart: Option<u16>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let peer_cfg = config::PeerConfig {
            address: PEER_IP,
            port: peer_addr.port(),
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

        let mut handle = transport::spawn(SessionConfig {
            local_as: LOCAL_AS,
            local_bgp_id: LOCAL_ID,
            hold_time: 90,
            connect_retry_time: CONNECT_RETRY,
            capabilities: vec![Capability::FourByteAsn(LOCAL_AS)],
            required_capabilities: vec![],
            peer_as: Some(PEER_AS),
            confederation_member: false,
            public_as: LOCAL_AS,
            peer_addr,
            tcp_md5: None,
        });
        handle.start().await;

        let state = Arc::new(RwLock::new(DaemonState::new(
            LOCAL_AS,
            LOCAL_ID,
            None,
            None,
            None,
            &[peer_cfg],
            HashMap::from([(PEER_IP, handle.update_sender())]),
            vec![],
        )));
        let stop_senders = Arc::new(Mutex::new(HashMap::from([(PEER_IP, handle.stop_sender())])));

        let (event_tx, event_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(event) = handle.next_event().await {
                if event_tx.send((PEER_IP, event)).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(run_event_loop(
            event_rx,
            Arc::clone(&state),
            stop_senders,
            None,
        ));

        Self { listener, state }
    }

    /// Accepts the session's next dial and completes the handshake.
    async fn accept(&self) -> PeerConn {
        let (stream, _) = tokio::time::timeout(TIMEOUT, self.listener.accept())
            .await
            .expect("the session never dialled the peer again")
            .unwrap();
        PeerConn::handshake(stream).await
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
        tokio::time::timeout(TIMEOUT, async {
            while !self.is_registered().await {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("peer never registered as established");
    }
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

#[tokio::test]
async fn session_reconnects_after_max_prefix_cease() {
    let daemon = Daemon::start(Some(1), None).await;
    let mut conn = daemon.accept().await;
    conn.send(two_prefixes()).await;
    assert_eq!(
        conn.notification().await.error,
        NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached),
    );
    drop(conn);

    // No `max_prefixes_restart`: back after the ConnectRetry interval.
    let _conn = daemon.accept().await;
    daemon.wait_until_registered().await;
}

#[tokio::test]
async fn session_is_rejected_during_idle_hold_and_accepted_after_it() {
    let daemon = Daemon::start(Some(1), Some(1)).await;
    let mut conn = daemon.accept().await;
    conn.send(two_prefixes()).await;
    assert_eq!(
        conn.notification().await.error,
        NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached),
    );
    drop(conn);
    let ceased_at = tokio::time::Instant::now();

    // Every reconnect inside the hold-off is refused, and the session keeps
    // retrying until one lands after it.
    let mut rejections = 0;
    let _conn = loop {
        let mut conn = daemon.accept().await;
        match conn.notification_within(Duration::from_millis(300)).await {
            Some(n) => {
                // RFC 4486 §4: "If a BGP speaker decides to disallow a BGP
                // connection ... the BGP speaker SHOULD send a NOTIFICATION
                // message with ... the Error Subcode "Connection Rejected"."
                assert_eq!(
                    n.error,
                    NotificationError::Cease(CeaseError::ConnectionRejected)
                );
                rejections += 1;
            }
            None => break conn,
        }
        assert!(
            ceased_at.elapsed() < TIMEOUT,
            "still rejected long after the idle-hold expired"
        );
    };

    assert!(rejections > 0, "no reconnect was attempted during the hold");
    assert!(
        ceased_at.elapsed() >= Duration::from_millis(900),
        "accepted before the idle-hold expired"
    );
    daemon.wait_until_registered().await;
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
