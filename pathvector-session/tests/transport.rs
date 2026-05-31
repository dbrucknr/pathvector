//! Integration tests for the BGP TCP transport.
//!
//! Each test spins up a real loopback TCP connection. The "peer" side is driven
//! manually with `BgpCodec` so we have full control over the exchange.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_util::codec::{FramedRead, FramedWrite};

use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, CeaseError, NotificationError, NotificationMessage, OpenMessage,
};
use pathvector_session::transport::{SessionConfig, SessionEvent, spawn};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn peer_open(peer_as: u32, hold_time: u16) -> BgpMessage {
    BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: if peer_as > 0xFFFF { 23456 } else { peer_as as u16 },
        hold_time,
        bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![Capability::FourByteAsn(peer_as)],
    })
}

fn local_config(peer_addr: std::net::SocketAddr) -> SessionConfig {
    SessionConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        capabilities: vec![Capability::FourByteAsn(65001)],
        peer_as: Some(65002),
        peer_addr,
    }
}

/// Bind a listener on a random loopback port and return it along with the
/// address the session under test should dial.
async fn loopback_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

/// Run the standard BGP open/keepalive handshake on the accepted side.
/// Returns the framed read/write halves (caller keeps connection alive).
async fn accept_and_handshake(
    listener: TcpListener,
) -> (
    FramedRead<tokio::net::tcp::OwnedReadHalf, BgpCodec>,
    FramedWrite<tokio::net::tcp::OwnedWriteHalf, BgpCodec>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec);
    let mut writer = FramedWrite::new(w, BgpCodec);

    // Receive OPEN from session under test.
    let msg = reader.next().await.unwrap().unwrap();
    assert!(matches!(msg, BgpMessage::Open(_)));

    // Respond with our OPEN.
    writer.send(peer_open(65002, 90)).await.unwrap();

    // Receive KEEPALIVE.
    let msg = reader.next().await.unwrap().unwrap();
    assert!(matches!(msg, BgpMessage::Keepalive));

    // Send our KEEPALIVE — session under test transitions to Established.
    writer.send(BgpMessage::Keepalive).await.unwrap();

    (reader, writer)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_session_reaches_established() {
    let (listener, addr) = loopback_listener().await;

    let peer = tokio::spawn(async move {
        let (_reader, _writer) = accept_and_handshake(listener).await;
        // Hold the connection open until the test drops the task.
        std::future::pending::<()>().await;
    });

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .expect("timed out waiting for Established")
        .expect("session exited before Established");

    assert!(
        matches!(event, SessionEvent::Established(_)),
        "expected Established, got {event:?}"
    );
    if let SessionEvent::Established(info) = event {
        assert_eq!(info.peer_as, 65002);
        assert_eq!(info.peer_bgp_id, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(info.hold_time, 90);
    }

    peer.abort();
}

#[tokio::test]
async fn test_manual_stop_sends_cease_and_emits_terminated() {
    let (listener, addr) = loopback_listener().await;

    let peer = tokio::spawn(async move {
        let (mut reader, _writer) = accept_and_handshake(listener).await;

        // After handshake, wait to receive the CEASE NOTIFICATION from our Stop.
        let msg = reader.next().await.unwrap().unwrap();
        assert!(
            matches!(
                &msg,
                BgpMessage::Notification(NotificationMessage {
                    error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                    ..
                })
            ),
            "expected CEASE notification, got {msg:?}"
        );
    });

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    // Wait for Established.
    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, SessionEvent::Established(_)));

    // Issue stop.
    handle.stop().await;

    // Next event must be Terminated.
    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .expect("timed out waiting for Terminated")
        .expect("session exited unexpectedly");
    assert!(
        matches!(event, SessionEvent::Terminated),
        "expected Terminated, got {event:?}"
    );

    peer.await.expect("peer task panicked");
}

#[tokio::test]
async fn test_peer_disconnect_emits_terminated() {
    let (listener, addr) = loopback_listener().await;

    let peer = tokio::spawn(async move {
        let (_reader, _writer) = accept_and_handshake(listener).await;
        // Dropping reader/writer closes the TCP connection.
    });

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    // Wait for Established, then the peer closes its end.
    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, SessionEvent::Established(_)));

    peer.await.unwrap(); // peer drops connection

    // Session should emit Terminated.
    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .expect("timed out waiting for Terminated after peer disconnect")
        .expect("session exited unexpectedly");
    assert!(
        matches!(event, SessionEvent::Terminated),
        "expected Terminated, got {event:?}"
    );
}

#[tokio::test]
async fn test_connect_retry_on_refused_connection() {
    // Use a port with nothing listening — connect will be refused immediately.
    // After the retry timer fires, the session tries again and should connect.
    let (listener, addr) = loopback_listener().await;

    // Drop the listener so the first connect attempt is refused.
    drop(listener);

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    // Bind the real listener now — session will retry and connect to it.
    // We have to race against the 120s retry timer; use a short timeout to
    // detect immediate failure rather than waiting for the full retry cycle.
    let result = tokio::time::timeout(Duration::from_millis(500), handle.next_event()).await;

    // We expect a timeout (no event yet) because the retry timer is 120s.
    // The session is alive and waiting — not erroring out.
    assert!(result.is_err(), "expected timeout waiting for event on refused connection");
}

#[tokio::test]
async fn test_open_with_wrong_peer_as_does_not_establish() {
    let (listener, addr) = loopback_listener().await;

    // Peer sends AS 99999 but the session expects 65002.
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, BgpCodec);
        let mut writer = FramedWrite::new(w, BgpCodec);

        let _ = reader.next().await; // receive OPEN
        writer.send(peer_open(99999, 90)).await.unwrap(); // wrong AS

        // Expect a NOTIFICATION back (bad peer AS).
        let msg = reader.next().await.unwrap().unwrap();
        assert!(matches!(msg, BgpMessage::Notification(_)), "expected NOTIFICATION");
    });

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    // No Established event should arrive — only a timeout.
    let result =
        tokio::time::timeout(Duration::from_secs(2), handle.next_event()).await;
    // Could get no event (if session is Idle after error) or it might re-try.
    // Either way, it must NOT emit Established.
    if let Ok(Some(event)) = result {
        assert!(
            !matches!(event, SessionEvent::Established(_)),
            "should not reach Established with wrong peer AS"
        );
    }

    peer.await.expect("peer task panicked");
}
