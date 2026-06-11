//! Integration tests for the BGP TCP transport.
//!
//! Each test spins up a real loopback TCP connection. The "peer" side is driven
//! manually with `BgpCodec` so we have full control over the exchange.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_util::codec::{FramedRead, FramedWrite};

use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, CeaseError, NotificationError, NotificationMessage, OpenMessage,
    UpdateMessage,
};
use pathvector_session::transport::{
    SessionCommand, SessionConfig, SessionEvent, SessionHandle, spawn,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn peer_open(peer_as: u32, hold_time: u16) -> BgpMessage {
    BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: u16::try_from(peer_as).unwrap_or(23456),
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
        required_capabilities: vec![],
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
    let mut reader = FramedRead::new(r, BgpCodec::new());
    let mut writer = FramedWrite::new(w, BgpCodec::new());

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
    assert!(
        result.is_err(),
        "expected timeout waiting for event on refused connection"
    );
}

// ── Short-timer config for timer-expiry tests ─────────────────────────────────
//
// Hold time = 3 s (minimum valid) → keepalive interval = 1 s.
// Tests that need timers to fire use this config and wait with real time.

fn short_timer_config(peer_addr: std::net::SocketAddr) -> SessionConfig {
    SessionConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 3,
        capabilities: vec![Capability::FourByteAsn(65001)],
        required_capabilities: vec![],
        peer_as: Some(65002),
        peer_addr,
    }
}

/// Handshake helper that sends `hold_time = 3` from the peer side.
async fn accept_and_handshake_short(
    listener: TcpListener,
) -> (
    FramedRead<tokio::net::tcp::OwnedReadHalf, BgpCodec>,
    FramedWrite<tokio::net::tcp::OwnedWriteHalf, BgpCodec>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec::new());
    let mut writer = FramedWrite::new(w, BgpCodec::new());

    let msg = reader.next().await.unwrap().unwrap();
    assert!(matches!(msg, BgpMessage::Open(_)));

    writer.send(peer_open(65002, 3)).await.unwrap();

    let msg = reader.next().await.unwrap().unwrap();
    assert!(matches!(msg, BgpMessage::Keepalive));

    writer.send(BgpMessage::Keepalive).await.unwrap();

    (reader, writer)
}

// ── RouteUpdate event ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_update_message_emits_route_update_event() {
    let (listener, addr) = loopback_listener().await;

    let peer = tokio::spawn(async move {
        let (mut _reader, mut writer) = accept_and_handshake(listener).await;
        let update = BgpMessage::Update(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        });
        writer.send(update).await.unwrap();
        std::future::pending::<()>().await;
    });

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, SessionEvent::Established(_)));

    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .expect("timed out waiting for RouteUpdate")
        .expect("session exited");
    assert!(
        matches!(event, SessionEvent::RouteUpdate(_)),
        "expected RouteUpdate, got {event:?}"
    );

    peer.abort();
}

// ── Keepalive timer fires ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_keepalive_timer_fires_sends_keepalive_to_peer() {
    // hold_time=3 → keepalive interval=1 s; wait up to 3 s for it to fire.
    let (listener, addr) = loopback_listener().await;

    let peer = tokio::spawn(async move {
        let (mut reader, _writer) = accept_and_handshake_short(listener).await;
        // First message after Established should be a KEEPALIVE from the session's
        // keepalive timer (fires after 1 s).
        let msg = tokio::time::timeout(Duration::from_secs(3), reader.next())
            .await
            .expect("timed out waiting for KEEPALIVE from session")
            .unwrap()
            .unwrap();
        assert!(
            matches!(msg, BgpMessage::Keepalive),
            "expected KEEPALIVE from session timer, got {msg:?}"
        );
    });

    let mut handle = spawn(short_timer_config(addr));
    handle.start().await;

    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, SessionEvent::Established(_)));

    peer.await.expect("peer task panicked");
}

// ── Hold timer fires ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_hold_timer_fires_terminates_session() {
    // hold_time=3 s; peer sends no KEEPALIVEs after the handshake, so the hold
    // timer fires at 3 s and the session sends a NOTIFICATION then terminates.
    let (listener, addr) = loopback_listener().await;

    let peer = tokio::spawn(async move {
        let (mut reader, _writer) = accept_and_handshake_short(listener).await;
        // Drain KEEPALIVEs (from session's keepalive timer), then wait for
        // NOTIFICATION when the hold timer fires.
        loop {
            match reader.next().await {
                Some(Ok(BgpMessage::Keepalive)) => {}
                Some(Ok(BgpMessage::Notification(_))) | None => break,
                other => panic!("unexpected: {other:?}"),
            }
        }
    });

    let mut handle = spawn(short_timer_config(addr));
    handle.start().await;

    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, SessionEvent::Established(_)));

    // Hold timer fires at 3 s (peer is not sending KEEPALIVEs).
    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .expect("timed out waiting for Terminated")
        .expect("session exited");
    assert!(
        matches!(event, SessionEvent::Terminated),
        "expected Terminated, got {event:?}"
    );

    peer.await.expect("peer task panicked");
}

// ── Stop while connecting (abort pending connect task, covers line 261) ───────

#[tokio::test]
async fn test_stop_while_connecting_aborts_pending_task() {
    let (listener, addr) = loopback_listener().await;
    drop(listener); // Nothing listening — first connect is refused quickly.

    let mut handle = spawn(local_config(addr));
    // Buffer both Start and Stop before the session processes either.
    // The biased select! ensures ManualStop is processed before recv_connect
    // (even if the TCP refusal is already ready), so drop_connection is called
    // while connect_task is still Some — covering the t.abort() path.
    handle.start().await;
    handle.stop().await;

    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let result = tokio::time::timeout(Duration::from_millis(300), handle.next_event()).await;
    if let Ok(Some(event)) = result {
        assert!(
            !matches!(event, SessionEvent::Established(_)),
            "should not establish after immediate stop"
        );
    }
}

// ── Codec error on received message (transport/mod.rs lines 184-185) ─────────
//
// When the peer sends a well-framed message whose payload fails BGP decode,
// `recv_message` returns `Some(Err(FramingError))`. The session logs a warning,
// drops the connection, and feeds TcpFailed back to the FSM.
//
// We trigger this by writing a raw frame with a valid 16-byte all-ones marker
// but a length field of 0 — the codec rejects it with `InvalidLength(0)`.

#[tokio::test]
async fn test_codec_error_emits_terminated() {
    let (listener, addr) = loopback_listener().await;

    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, BgpCodec::new());
        let mut writer = FramedWrite::new(w, BgpCodec::new());

        // Complete the normal handshake.
        let _ = reader.next().await.unwrap().unwrap();
        writer.send(peer_open(65002, 90)).await.unwrap();
        let _ = reader.next().await.unwrap().unwrap();
        writer.send(BgpMessage::Keepalive).await.unwrap();

        // Session is now Established. Send a malformed frame:
        // valid 16-byte all-ones marker, then length = 0 (invalid — must be ≥ 19).
        let mut raw_writer = writer.into_inner();
        let mut frame = [0u8; 19];
        frame[..16].fill(0xFF); // valid marker
        frame[16..18].copy_from_slice(&0u16.to_be_bytes()); // length = 0 → invalid
        raw_writer.write_all(&frame).await.unwrap();

        // Keep the peer side open while the session processes the error.
        std::future::pending::<()>().await;
    });

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, SessionEvent::Established(_)));

    // The codec error triggers TcpFailed → FSM teardown → Terminated.
    let event = tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .expect("timed out waiting for Terminated after codec error")
        .expect("session channel closed unexpectedly");
    assert!(
        matches!(event, SessionEvent::Terminated),
        "expected Terminated after codec error, got {event:?}"
    );

    peer.abort();
}

// ── Connect-retry timer fires (transport/mod.rs lines 204-205) ────────────────
//
// When TcpFailed arrives from Connect state the FSM arms the 120 s retry timer.
// With `start_paused = true` we advance the clock 121 s without waiting in real
// time; the timer arm in `wait_for_input` fires (lines 204-205) and the session
// initiates a fresh TCP connect.
//
// Lines 147-148 and 227-228 (TcpFailed recovery when a TCP *send* fails) are not
// covered here — they require injecting a broken writer, which needs the
// BgpTransport trait refactor documented in TODO.md.

#[tokio::test(start_paused = true)]
async fn test_connect_retry_timer_fires_initiates_reconnect() {
    // Bind a listener, capture its address, then drop it so the first connect
    // is immediately refused.
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = first.local_addr().unwrap();
    drop(first);

    let handle = spawn(local_config(addr));
    handle.start().await;

    // Give the runtime enough yields to process:
    //   ManualStart → spawn connect_task → ECONNREFUSED → recv_connect(Err)
    //   → TcpFailed → StartConnectRetryTimer(120 s) → retry_deadline set.
    // Real I/O (the refused connect) still completes even with time paused.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    // Bind the listener BEFORE advancing the clock so it is ready when the
    // session retries.
    let listener = TcpListener::bind(addr)
        .await
        .expect("port should be free after first drop");

    // Advance past the 120 s retry timer.  The `sleep_until` inside
    // `deadline_fut` resolves; the retry arm in `wait_for_input` fires
    // (lines 204-205) and feeds ConnectRetryTimerExpired to the FSM.
    tokio::time::advance(Duration::from_secs(121)).await;

    // Drive the new connect_task (spawned by the FSM response) to completion.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    // The session reconnected — accept it.
    // `listener.accept()` is real I/O so the runtime handles it without a
    // paused-time timeout; after the yields above the connect is already in
    // the kernel accept queue.
    let accept = listener.accept().await;
    assert!(
        accept.is_ok(),
        "session should have retried and connected after retry timer"
    );
}

#[tokio::test]
async fn test_open_with_wrong_peer_as_does_not_establish() {
    let (listener, addr) = loopback_listener().await;

    // Peer sends AS 99999 but the session expects 65002.
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, BgpCodec::new());
        let mut writer = FramedWrite::new(w, BgpCodec::new());

        let _ = reader.next().await; // receive OPEN
        writer.send(peer_open(99999, 90)).await.unwrap(); // wrong AS

        // Expect a NOTIFICATION back (bad peer AS).
        let msg = reader.next().await.unwrap().unwrap();
        assert!(
            matches!(msg, BgpMessage::Notification(_)),
            "expected NOTIFICATION"
        );
    });

    let mut handle = spawn(local_config(addr));
    handle.start().await;

    // No Established event should arrive — only a timeout.
    let result = tokio::time::timeout(Duration::from_secs(2), handle.next_event()).await;
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

// ── RFC 4271 §6.8 collision detection ─────────────────────────────────────────

/// Helper: complete the BGP open/keepalive handshake *from the peer side* over
/// an already-connected `TcpStream` (as opposed to `accept_and_handshake` which
/// waits for a listener accept first).
async fn peer_handshake_on_stream(
    stream: tokio::net::TcpStream,
    peer_as: u32,
    peer_bgp_id: Ipv4Addr,
) -> (
    FramedRead<tokio::net::tcp::OwnedReadHalf, BgpCodec>,
    FramedWrite<tokio::net::tcp::OwnedWriteHalf, BgpCodec>,
) {
    let (r, w) = stream.into_split();
    let mut reader = FramedRead::new(r, BgpCodec::new());
    let mut writer = FramedWrite::new(w, BgpCodec::new());

    // Receive OPEN from the session under test.
    let msg = reader.next().await.unwrap().unwrap();
    assert!(matches!(msg, BgpMessage::Open(_)), "expected OPEN");

    // Respond with our OPEN.
    writer
        .send(BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: u16::try_from(peer_as).unwrap_or(23456),
            hold_time: 90,
            bgp_id: peer_bgp_id,
            capabilities: vec![Capability::FourByteAsn(peer_as)],
        }))
        .await
        .unwrap();

    // Receive KEEPALIVE sent by the session.
    let msg = reader.next().await.unwrap().unwrap();
    assert!(matches!(msg, BgpMessage::Keepalive), "expected KEEPALIVE");

    // Send our KEEPALIVE to complete Established.
    writer.send(BgpMessage::Keepalive).await.unwrap();

    (reader, writer)
}

/// Collision where `local_bgp_id > peer_bgp_id`: the session must close its
/// outbound connection, adopt the incoming one, and still reach Established.
#[tokio::test]
async fn test_collision_local_wins_adopts_incoming() {
    // Session config: local BGP ID 10.0.0.2 (higher than peer 10.0.0.1).
    let (outbound_listener, outbound_addr) = loopback_listener().await;
    let config = SessionConfig {
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        peer_as: Some(65002),
        ..local_config(outbound_addr)
    };
    let mut handle = spawn(config);
    handle.start().await;

    // Simulate the outbound connection being accepted by the peer — drive it
    // far enough that the session reaches OpenConfirm (peer OPEN received).
    let peer_bgp_id = Ipv4Addr::new(10, 0, 0, 1); // lower than local
    let outbound_peer = tokio::spawn(async move {
        let (stream, _) = outbound_listener.accept().await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, BgpCodec::new());
        let mut writer = FramedWrite::new(w, BgpCodec::new());

        // Receive the OPEN the session sends.
        let msg = reader.next().await.unwrap().unwrap();
        assert!(matches!(msg, BgpMessage::Open(_)));

        // Send our OPEN — session enters OpenConfirm and stores peer_bgp_id.
        writer
            .send(BgpMessage::Open(OpenMessage {
                version: 4,
                my_as: 65002,
                hold_time: 90,
                bgp_id: peer_bgp_id,
                capabilities: vec![Capability::FourByteAsn(65002)],
            }))
            .await
            .unwrap();

        // Hold the connection open until the test tears it down.
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop((reader, writer));
    });

    // Wait until Established would normally happen OR give the session time
    // to reach OpenConfirm (peer OPEN received → peer_bgp_id is set).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now simulate the daemon delivering an inbound TCP connection from the peer.
    // This triggers collision detection: local (10.0.0.2) > peer (10.0.0.1),
    // so the session should close the outbound and adopt this incoming stream.
    let (incoming_listener, incoming_addr) = loopback_listener().await;
    let incoming_tx = handle.incoming_sender();

    // Simulate the peer dialling US: connect to a listener we control.
    let incoming_peer = tokio::spawn(async move {
        let stream = tokio::net::TcpStream::connect(incoming_addr).await.unwrap();
        // Complete the handshake on this new connection.
        peer_handshake_on_stream(stream, 65002, peer_bgp_id).await
    });

    // Accept the "incoming from peer" stream and deliver it to the session.
    let (incoming_stream, _) = incoming_listener.accept().await.unwrap();
    incoming_tx
        .send(SessionCommand::IncomingConnection(incoming_stream))
        .await
        .unwrap();

    // The session must reach Established (over the new connection).
    let event = tokio::time::timeout(Duration::from_secs(3), handle.next_event())
        .await
        .expect("timed out waiting for Established")
        .expect("session channel closed");
    assert!(
        matches!(event, SessionEvent::Established(_)),
        "expected Established, got {event:?}"
    );

    outbound_peer.abort();
    incoming_peer.abort();
}

/// Collision where `local_bgp_id < peer_bgp_id`: the session must keep its
/// outbound connection and discard the incoming one, then reach Established
/// normally over the outbound.
#[tokio::test]
async fn test_collision_peer_wins_keeps_outbound() {
    // Session config: local BGP ID 10.0.0.1 (lower than peer 10.0.0.2).
    let (outbound_listener, outbound_addr) = loopback_listener().await;
    let config = SessionConfig {
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        peer_as: Some(65002),
        ..local_config(outbound_addr)
    };
    let mut handle = spawn(config);
    handle.start().await;

    let peer_bgp_id = Ipv4Addr::new(10, 0, 0, 2); // higher than local

    // Accept the outbound connection and drive through full handshake.
    let outbound_peer = tokio::spawn(async move {
        let (stream, _) = outbound_listener.accept().await.unwrap();
        let (r, w) = stream.into_split();
        let mut reader = FramedRead::new(r, BgpCodec::new());
        let mut writer = FramedWrite::new(w, BgpCodec::new());

        // Receive OPEN.
        let msg = reader.next().await.unwrap().unwrap();
        assert!(matches!(msg, BgpMessage::Open(_)));

        // Send our OPEN (higher BGP ID — session should keep this connection).
        writer
            .send(BgpMessage::Open(OpenMessage {
                version: 4,
                my_as: 65002,
                hold_time: 90,
                bgp_id: peer_bgp_id,
                capabilities: vec![Capability::FourByteAsn(65002)],
            }))
            .await
            .unwrap();

        // Receive KEEPALIVE.
        let msg = reader.next().await.unwrap().unwrap();
        assert!(matches!(msg, BgpMessage::Keepalive));

        // Complete handshake.
        writer.send(BgpMessage::Keepalive).await.unwrap();

        // Hold the connection open.
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop((reader, writer));
    });

    // Give the session time to receive the peer OPEN (enter OpenConfirm).
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Deliver a spurious inbound connection — should be silently discarded.
    let (discard_listener, discard_addr) = loopback_listener().await;
    let incoming_tx = handle.incoming_sender();

    // "Peer" tries to open a second connection to us.
    let discard_peer = tokio::spawn(async move {
        // Just connect — the stream will be dropped by the session immediately.
        let _stream = tokio::net::TcpStream::connect(discard_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let (incoming_stream, _) = discard_listener.accept().await.unwrap();
    incoming_tx
        .send(SessionCommand::IncomingConnection(incoming_stream))
        .await
        .unwrap();

    // Session must still reach Established over the original outbound connection.
    let event = tokio::time::timeout(Duration::from_secs(3), handle.next_event())
        .await
        .expect("timed out waiting for Established")
        .expect("session channel closed");
    assert!(
        matches!(event, SessionEvent::Established(_)),
        "expected Established, got {event:?}"
    );

    outbound_peer.abort();
    discard_peer.abort();
}
