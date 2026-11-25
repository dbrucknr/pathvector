//! What a session does after it is stopped or reset, over real loopback TCP.
//!
//! RFC 4271 §8.2.2: after `ManualStop` (Event 2) the session is in Idle and
//! only a start event leaves it. After `AutomaticStop` (Event 8) it is in Idle
//! too, until the local system's own logic starts it again (§8.1.1), here the
//! `ConnectRetry` interval. In Idle, "BGP FSM refuses all incoming BGP
//! connections for this peer."

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite};

use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, CeaseError, NotificationError, NotificationMessage, OpenMessage,
};
use pathvector_session::transport::{
    SessionCommand, SessionConfig, SessionEvent, SessionHandle, SpawnedSessionHandle, spawn,
};

const CONNECT_RETRY: Duration = Duration::from_millis(100);
/// Many `ConnectRetry` intervals: long enough that "no redial" means none is due.
const QUIET: Duration = Duration::from_millis(800);
const TIMEOUT: Duration = Duration::from_secs(5);

type Reader = FramedRead<OwnedReadHalf, BgpCodec>;
type Writer = FramedWrite<OwnedWriteHalf, BgpCodec>;

async fn recv(reader: &mut Reader) -> Option<BgpMessage> {
    tokio::time::timeout(TIMEOUT, reader.next())
        .await
        .expect("timed out waiting for the session")
        .map(|m| m.expect("decode error"))
}

/// A session that has dialled `listener` and reached Established.
async fn established() -> (SpawnedSessionHandle, TcpListener, Reader, Writer) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut handle = spawn(SessionConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        capabilities: vec![Capability::FourByteAsn(65001)],
        required_capabilities: vec![],
        peer_as: Some(65002),
        confederation_member: false,
        public_as: 65001,
        peer_addr: listener.local_addr().unwrap(),
        tcp_md5: None,
        connect_retry_time: CONNECT_RETRY,
        send_hold_time: pathvector_session::fsm::SendHoldTime::default(),
    });
    handle.start().await;

    let (stream, _) = listener.accept().await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec::new());
    let mut writer = FramedWrite::new(w, BgpCodec::new());
    assert!(matches!(recv(&mut reader).await, Some(BgpMessage::Open(_))));
    writer
        .send(BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::FourByteAsn(65002)],
        }))
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut reader).await,
        Some(BgpMessage::Keepalive)
    ));
    writer.send(BgpMessage::Keepalive).await.unwrap();
    assert!(matches!(
        handle.next_event().await,
        Some(SessionEvent::Established(_))
    ));
    (handle, listener, reader, writer)
}

async fn assert_terminated(handle: &mut SpawnedSessionHandle) {
    let event = tokio::time::timeout(TIMEOUT, handle.next_event())
        .await
        .expect("timed out waiting for Terminated");
    assert!(
        matches!(event, Some(SessionEvent::Terminated(_))),
        "expected Terminated, got {event:?}"
    );
}

async fn assert_no_redial(listener: &TcpListener) {
    assert!(
        tokio::time::timeout(QUIET, listener.accept())
            .await
            .is_err(),
        "a stopped session dialled the peer again"
    );
}

/// Hands the session an inbound connection and returns the peer's end of it.
async fn deliver_inbound(handle: &SpawnedSessionHandle) -> Reader {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (peer, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    handle
        .incoming_sender()
        .send(SessionCommand::IncomingConnection(accepted.unwrap().0))
        .await
        .unwrap();
    let (r, w) = peer.unwrap().into_split();
    // Keep our write half open, so that only the session can end the stream.
    std::mem::forget(w);
    FramedRead::new(r, BgpCodec::new())
}

#[tokio::test]
async fn stopped_session_stays_down() {
    let (mut handle, listener, mut reader, _writer) = established().await;
    handle.stop().await;
    assert!(matches!(
        recv(&mut reader).await,
        Some(BgpMessage::Notification(_))
    ));
    assert_terminated(&mut handle).await;
    assert_no_redial(&listener).await;
}

/// `SessionCommand::Notification` is the administrative form: it is how a peer
/// is removed with an RFC 9003 shutdown message.
#[tokio::test]
async fn administrative_notification_stays_down() {
    let (mut handle, listener, mut reader, _writer) = established().await;
    handle
        .stop_sender()
        .send(SessionCommand::Notification(NotificationMessage {
            error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
            data: vec![],
        }))
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut reader).await,
        Some(BgpMessage::Notification(_))
    ));
    assert_terminated(&mut handle).await;
    assert_no_redial(&listener).await;
}

/// A second reset sent while the first one's restart is pending is ignored.
#[tokio::test]
async fn automatic_stop_reconnects() {
    let (mut handle, listener, mut reader, _writer) = established().await;
    let reset = NotificationMessage {
        error: NotificationError::Cease(CeaseError::OutOfResources),
        data: vec![],
    };
    for _ in 0..2 {
        handle
            .stop_sender()
            .send(SessionCommand::AutomaticStop(reset.clone()))
            .await
            .unwrap();
    }
    assert_eq!(
        recv(&mut reader).await,
        Some(BgpMessage::Notification(reset))
    );
    assert_terminated(&mut handle).await;
    tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .expect("a reset session never dialled again")
        .unwrap();
}

/// The session is already in Idle with a retry pending when the stop arrives.
#[tokio::test]
async fn stop_while_a_retry_is_pending_cancels_it() {
    let (mut handle, listener, reader, writer) = established().await;
    drop((reader, writer));
    assert_terminated(&mut handle).await;
    handle.stop().await;
    assert_no_redial(&listener).await;
}

#[tokio::test]
async fn inbound_connection_in_idle_is_closed() {
    let (mut handle, _listener, mut reader, _writer) = established().await;
    handle.stop().await;
    assert!(matches!(
        recv(&mut reader).await,
        Some(BgpMessage::Notification(_))
    ));
    assert_terminated(&mut handle).await;

    let mut inbound = deliver_inbound(&handle).await;
    assert_eq!(recv(&mut inbound).await, None);
}
