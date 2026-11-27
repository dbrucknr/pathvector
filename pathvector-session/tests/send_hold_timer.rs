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

use pathvector_session::message::{BgpMessage, RouteRefreshMessage};
use pathvector_session::transport::{
    SendHoldTime, SessionEvent, SessionHandle, SpawnedSessionHandle, TerminationReason,
};
use pathvector_types::AfiSafi;
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

/// §4.3: "Each time the local system sends a BGP message, it restarts the
/// `SendHoldTimer`". That is each message, not each time the write buffer
/// empties: here a batch of five goes out one message per 100 s.
#[tokio::test(start_paused = true)]
async fn each_message_of_a_partly_written_batch_restarts_the_timer() {
    let (mut handle, mut peer) = established(config(90)).await;
    peer.clear_sent();
    peer.set_reading(false);
    for n in 1..=5 {
        handle.update_sender().send(update(n)).await.unwrap();
    }

    let mut last_send = Instant::now();
    for _ in 0..4 {
        let event = talk_for(&mut handle, &peer, 100).await;
        assert!(event.is_none(), "{event:?} while messages were being sent");
        last_send = Instant::now();
        peer.take(1);
        settle().await;
    }
    let sent: Vec<_> = peer.sent().into_iter().map(|s| s.msg).collect();
    assert_eq!(sent, (1..=4).map(update_msg).collect::<Vec<_>>());

    // The period then runs from the last message that was sent.
    expect_send_hold_expiry(talk_for(&mut handle, &peer, 600).await.as_ref());
    let after = last_send.elapsed();
    assert!(
        (Duration::from_secs(480)..=Duration::from_secs(481)).contains(&after),
        "closed {after:?} after the last message"
    );
}

/// A message that can be written when the timer comes due is sent, so it
/// restarts the timer although more are still waiting.
#[tokio::test(start_paused = true)]
async fn a_message_found_sendable_at_the_deadline_restarts_the_timer() {
    let mut cfg = config(90);
    cfg.send_hold_time = SendHoldTime::from_secs(125, 90).unwrap();
    let (mut handle, mut peer) = established(cfg).await;
    peer.clear_sent();
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    handle.update_sender().send(update(2)).await.unwrap();

    assert!(talk_for(&mut handle, &peer, 120).await.is_none());
    tokio::time::sleep(Duration::from_secs(4)).await;
    // Nothing else is due before the deadline at 125 s.
    peer.take_quietly(1);
    let event = talk_for(&mut handle, &peer, 20).await;
    assert!(event.is_none(), "{event:?}");
    let sent: Vec<_> = peer.sent().into_iter().map(|s| s.msg).collect();
    assert_eq!(sent, vec![update_msg(1)]);
}

/// A KEEPALIVE or ROUTE-REFRESH is dropped as a repeat only while an identical
/// one is still unsent. Once it has gone out, the next one is queued, although
/// messages behind the first are still waiting.
#[tokio::test(start_paused = true)]
async fn a_sent_keepalive_or_route_refresh_does_not_suppress_the_next() {
    let (handle, mut peer) = established(config(90)).await;
    peer.clear_sent();
    peer.set_reading(false);
    let refresh = RouteRefreshMessage::new(AfiSafi::IPV4_UNICAST);
    let other = RouteRefreshMessage::new(AfiSafi::IPV6_UNICAST);

    // Waiting: UPDATE, then the KEEPALIVE of the 30 s timer, then two
    // ROUTE-REFRESHes.
    handle.update_sender().send(update(1)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(31)).await;
    handle.send_route_refresh(refresh.clone()).await;
    handle.send_route_refresh(other.clone()).await;
    settle().await;
    // All but the last go out.
    peer.take(3);
    settle().await;

    handle.send_route_refresh(refresh.clone()).await;
    tokio::time::sleep(Duration::from_secs(30)).await;
    peer.set_reading(true);
    settle().await;

    let sent: Vec<_> = peer.sent().into_iter().map(|s| s.msg).collect();
    assert_eq!(
        sent,
        vec![
            update_msg(1),
            BgpMessage::Keepalive,
            BgpMessage::RouteRefresh(refresh.clone()),
            BgpMessage::RouteRefresh(other),
            BgpMessage::RouteRefresh(refresh),
            BgpMessage::Keepalive,
        ]
    );
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
