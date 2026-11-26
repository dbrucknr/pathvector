//! The RFC 9687 `SendHoldTimer` as the transport runs it.
//!
//! §3 describes the failure: a peer that keeps its side of the session alive
//! but advertises a zero TCP receive window, so nothing can be sent to it. §5:
//! "If the local system does not send any BGP messages within the period
//! specified in `SendHoldTime`, then a NOTIFICATION message with the "Send Hold
//! Timer Expired" Error Code MAY be sent and the BGP connection MUST be closed.
//! Additionally, an error MUST be logged". The log is asserted in
//! `send_hold_log.rs`.

mod supervision_support;

use std::time::Duration;

use tokio::time::Instant;

use pathvector_session::message::BgpMessage;
use pathvector_session::transport::{
    SendHoldTime, SessionEvent, SessionHandle, SpawnedSessionHandle, TerminationReason,
};
use supervision_support::*;

/// Keep the peer talking (KEEPALIVE every 10 s) for `secs`, stopping early if
/// the session reports an event.
async fn talk_for(
    handle: &mut SpawnedSessionHandle,
    peer: &MockPeer,
    secs: u64,
) -> Option<SessionEvent> {
    for _ in 0..secs / 10 {
        peer.push(BgpMessage::Keepalive);
        if let Ok(event) = tokio::time::timeout(Duration::from_secs(10), handle.next_event()).await
        {
            return event;
        }
    }
    None
}

fn expect_send_hold_expiry(event: Option<&SessionEvent>) {
    assert!(
        matches!(
            event,
            Some(SessionEvent::Terminated(
                TerminationReason::SendHoldTimerExpired
            ))
        ),
        "{event:?}"
    );
}

/// §6: enabled by default, 8 minutes for a 90 s `HoldTime`, counted from the
/// last message that was sent.
#[tokio::test(start_paused = true)]
async fn peer_that_stops_reading_is_closed_after_the_default_send_hold_time() {
    let (mut handle, peer) = established(config(90)).await;
    let last_send = Instant::now();
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();

    expect_send_hold_expiry(talk_for(&mut handle, &peer, 600).await.as_ref());
    let after = last_send.elapsed();
    assert!(
        (Duration::from_secs(480)..=Duration::from_secs(481)).contains(&after),
        "closed after {after:?}"
    );
    // §4.3: closing must not wait for the NOTIFICATION to be written.
    assert!(!peer.connection_open(), "still open after expiry");
    assert!(peer.aborted(), "unwritten data was not discarded");
}

/// A healthy session sends its KEEPALIVEs, which restart the timer (§4.3).
#[tokio::test(start_paused = true)]
async fn healthy_idle_session_never_expires() {
    let (mut handle, peer) = established(config(90)).await;
    assert!(talk_for(&mut handle, &peer, 7_200).await.is_none());
}

/// Every message sent restarts the timer, so a slow peer that still takes one
/// now and then stays up.
#[tokio::test(start_paused = true)]
async fn each_completed_send_restarts_the_send_hold_timer() {
    let (mut handle, peer) = established(config(90)).await;
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();

    for _ in 0..5 {
        assert!(talk_for(&mut handle, &peer, 470).await.is_none());
        peer.set_reading(true);
        settle().await;
        peer.set_reading(false);
        settle().await;
    }
    // And once it stops for good, the full period applies again.
    let stalled = Instant::now();
    expect_send_hold_expiry(talk_for(&mut handle, &peer, 600).await.as_ref());
    assert!(stalled.elapsed() >= Duration::from_secs(440));
}

#[tokio::test(start_paused = true)]
async fn configured_send_hold_time_applies() {
    let mut cfg = config(90);
    cfg.send_hold_time = SendHoldTime::from_secs(120, 90).unwrap();
    let (mut handle, peer) = established(cfg).await;
    let start = Instant::now();
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    expect_send_hold_expiry(talk_for(&mut handle, &peer, 600).await.as_ref());
    assert!(start.elapsed() <= Duration::from_secs(121));
}

#[tokio::test(start_paused = true)]
async fn disabled_send_hold_timer_never_closes() {
    let mut cfg = config(90);
    cfg.send_hold_time = SendHoldTime::DISABLED;
    let (mut handle, peer) = established(cfg).await;
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    assert!(talk_for(&mut handle, &peer, 7_200).await.is_none());
}

/// §4.3: with a negotiated `HoldTime` of zero the timer is stopped; an idle
/// session sends nothing and must stay up.
#[tokio::test(start_paused = true)]
async fn zero_hold_time_session_has_no_send_hold_timer() {
    let (mut handle, mut peer) = established(config(0)).await;
    peer.clear_sent();
    assert!(
        tokio::time::timeout(Duration::from_secs(7_200), handle.next_event())
            .await
            .is_err()
    );
    assert!(peer.sent().is_empty());
}

// ── Real TCP: an actual closed receive window ────────────────────────────────

mod zero_window {
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpSocket;

    use pathvector_session::message::{PathAttribute, UpdateMessage};
    use pathvector_session::transport::spawn;
    use pathvector_types::{Nlri, Origin};

    use super::*;

    /// About 4 KB on the wire.
    fn large_update() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            announced: (0..800u32)
                .map(|n| Nlri::new(Ipv4Addr::from(0x0b00_0000 + n), 32).unwrap())
                .collect(),
        }
    }

    /// The peer completes the handshake, keeps sending KEEPALIVEs, and never
    /// reads again, so the kernel's windows really do close. The session must
    /// close the connection itself, and the peer sees it end.
    #[tokio::test]
    async fn peer_with_a_closed_window_is_disconnected() {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(1).unwrap();

        let mut cfg = config(3);
        cfg.peer_addr = listener.local_addr().unwrap();
        cfg.send_hold_time = SendHoldTime::from_secs(4, 3).unwrap();
        let mut handle = spawn(cfg);
        handle.start().await;

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        assert!(stream.read(&mut buf).await.unwrap() > 0, "no OPEN");
        stream.write_all(&peer_open(3).encode()).await.unwrap();
        stream
            .write_all(&BgpMessage::Keepalive.encode())
            .await
            .unwrap();
        assert!(matches!(
            next_event(&mut handle).await,
            SessionEvent::Established(_)
        ));

        let updates = handle.update_sender();
        let feeder = tokio::spawn(async move {
            // Far more than the socket buffers hold.
            for _ in 0..4_000 {
                if updates.send(large_update()).await.is_err() {
                    break;
                }
            }
        });

        let started = std::time::Instant::now();
        let event = loop {
            stream
                .write_all(&BgpMessage::Keepalive.encode())
                .await
                .unwrap();
            if let Ok(event) =
                tokio::time::timeout(Duration::from_millis(500), handle.next_event()).await
            {
                break event;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the session never gave up on a closed window"
            );
        };
        expect_send_hold_expiry(event.as_ref());
        assert!(started.elapsed() >= Duration::from_secs(3));

        // The connection was reset or closed: reading ends instead of waiting.
        let ended = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(ended.is_ok(), "the connection was left open");
        feeder.abort();
    }
}
