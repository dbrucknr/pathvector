//! Timer supervision under load and backpressure (issue #102).
//!
//! RFC 4271 §8.2.2 (Established): "If the `KeepaliveTimer_Expires` event occurs
//! (Event 11), the local system: sends a KEEPALIVE message", and "If the
//! `HoldTimer_Expires` event occurs (Event 10), the local system: sends a
//! NOTIFICATION message with the Error Code Hold Timer Expired, ... drops the
//! TCP connection". §4.4: KEEPALIVEs are exchanged "often enough not to cause
//! the Hold Timer to expire". None of that may depend on the session having
//! nothing else to do, on the peer reading, or on the local consumer keeping
//! up.
//!
//! Every test runs with paused tokio time over a mock transport.

mod supervision_support;

use std::time::Duration;

use tokio::time::Instant;

use pathvector_session::message::{
    BgpMessage, NotificationError, NotificationMessage, RouteRefreshMessage,
};
use pathvector_session::transport::{
    SessionCommand, SessionEvent, SessionHandle, TerminationReason,
};
use pathvector_types::AfiSafi;
use supervision_support::*;

/// How many ready inbound messages may be processed ahead of an overdue timer.
const SERVICE_BOUND: usize = 8;

/// Drain events in the background, returning the NLRI order seen.
fn drain_events(
    mut handle: pathvector_session::transport::SpawnedSessionHandle,
) -> tokio::sync::mpsc::UnboundedReceiver<SessionEvent> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = handle.next_event().await {
            if tx.send(event).is_err() {
                break;
            }
        }
    });
    rx
}

fn hold_expired(msg: &BgpMessage) -> bool {
    matches!(
        msg,
        BgpMessage::Notification(NotificationMessage {
            error: NotificationError::HoldTimerExpired,
            ..
        })
    )
}

// ── Sustained ready input ────────────────────────────────────────────────────

/// An overdue `KeepaliveTimer` is serviced while UPDATEs are continuously ready.
#[tokio::test(start_paused = true)]
async fn overdue_keepalive_is_sent_while_updates_stay_ready() {
    let (handle, mut peer) = established(config(90)).await;
    let mut events = drain_events(handle);
    let before = peer.consumed();
    peer.clear_sent();

    for n in 0..5_000 {
        peer.push(update_msg(n));
    }
    // Moves the clock past the 30 s KeepaliveTimer before the session runs.
    tokio::time::advance(Duration::from_secs(31)).await;
    settle().await;

    let keepalive = peer
        .sent()
        .into_iter()
        .rev()
        .find(|s| matches!(s.msg, BgpMessage::Keepalive))
        .expect("a KEEPALIVE was sent");
    assert!(
        keepalive.consumed - before <= SERVICE_BOUND,
        "KEEPALIVE sent only after {} of 5000 ready UPDATEs",
        keepalive.consumed - before
    );
    // Servicing the timer did not cost any input.
    let mut delivered = 0;
    while events.try_recv().is_ok() {
        delivered += 1;
    }
    assert_eq!(delivered, 5_000);
}

/// A flooded session and a quiet control session on the same runtime both keep
/// their KEEPALIVE cadence, the flooded one without first working through its
/// backlog.
#[tokio::test(start_paused = true)]
async fn flooded_and_control_sessions_both_keep_cadence() {
    let (flooded, mut flooded_peer) = established(config(90)).await;
    let (control, mut control_peer) = established(config(9)).await;
    let _flooded_events = drain_events(flooded);
    let _control_events = drain_events(control);
    flooded_peer.clear_sent();
    control_peer.clear_sent();
    let start = flooded_peer.consumed();

    let mut overdue_keepalives = 0;
    for round in 0..20u32 {
        let before = flooded_peer.consumed();
        let written = flooded_peer.sent().len();
        for n in 0..500 {
            flooded_peer.push(update_msg(round * 500 + n));
        }
        control_peer.push(BgpMessage::Keepalive);
        tokio::time::advance(Duration::from_secs(3)).await;
        settle().await;
        for s in flooded_peer.sent().into_iter().skip(written) {
            if matches!(s.msg, BgpMessage::Keepalive) {
                overdue_keepalives += 1;
                assert!(
                    s.consumed - before <= SERVICE_BOUND,
                    "round {round}: KEEPALIVE waited behind {} ready UPDATEs",
                    s.consumed - before
                );
            }
        }
    }

    assert!(overdue_keepalives >= 1, "no KEEPALIVE fell due in 60 s");
    let control_times = control_peer.keepalive_times();
    assert!(
        control_times.len() >= 19,
        "control: {}",
        control_times.len()
    );
    for pair in control_times.windows(2) {
        assert!(pair[1] - pair[0] <= Duration::from_secs(4));
    }
    assert_eq!(flooded_peer.consumed() - start, 10_000);
}

/// Well-formed ROUTE-REFRESH messages do not restart the `HoldTimer` (only
/// KEEPALIVE and UPDATE do, §8.2.2), so a peer that sends nothing else must be
/// timed out however fast it sends them.
#[tokio::test(start_paused = true)]
async fn hold_timer_expires_under_a_flood_of_non_restarting_messages() {
    let (handle, mut peer) = established(config(90)).await;
    let mut events = drain_events(handle);
    let before = peer.consumed();
    peer.clear_sent();

    for _ in 0..20_000 {
        peer.push(BgpMessage::RouteRefresh(RouteRefreshMessage::new(
            AfiSafi::IPV4_UNICAST,
        )));
    }
    tokio::time::advance(Duration::from_secs(91)).await;
    settle().await;

    let notification = peer
        .sent()
        .into_iter()
        .find(|s| hold_expired(&s.msg))
        .expect("Hold Timer Expired was never sent");
    assert!(
        notification.consumed - before <= 64 * 2,
        "HoldTimer serviced only after {} ready messages",
        notification.consumed - before
    );
    assert!(matches!(
        events.recv().await,
        Some(SessionEvent::Terminated(_))
    ));
}

// ── Peer stops reading ───────────────────────────────────────────────────────

/// A blocked write must not stop the `HoldTimer`.
#[tokio::test(start_paused = true)]
async fn hold_timer_runs_while_a_write_is_blocked() {
    let (mut handle, peer) = established(config(90)).await;
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    settle().await;

    let start = Instant::now();
    let event = tokio::time::timeout(Duration::from_secs(600), handle.next_event())
        .await
        .expect("the HoldTimer never fired while a write was blocked")
        .unwrap();
    assert!(matches!(event, SessionEvent::Terminated(_)), "{event:?}");
    assert!(start.elapsed() <= Duration::from_secs(91));
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(!peer.connection_open(), "the connection was not dropped");
}

/// A blocked write must not stop the session reading, or the peer's
/// KEEPALIVEs would go unprocessed.
#[tokio::test(start_paused = true)]
async fn inbound_messages_are_processed_while_a_write_is_blocked() {
    let (mut handle, peer) = established(config(90)).await;
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    settle().await;

    peer.push(update_msg(7));
    let event = next_event(&mut handle).await;
    assert!(matches!(event, SessionEvent::RouteUpdate(_)), "{event:?}");
}

/// Shutdown under write pressure: `Stop` takes effect at once.
#[tokio::test(start_paused = true)]
async fn stop_takes_effect_while_a_write_is_blocked() {
    let (mut handle, peer) = established(config(90)).await;
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    settle().await;

    handle
        .stop_sender()
        .send(SessionCommand::Stop)
        .await
        .unwrap();
    let event = next_event(&mut handle).await;
    assert!(
        matches!(
            event,
            SessionEvent::Terminated(TerminationReason::OperatorStop)
        ),
        "{event:?}"
    );
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(!peer.connection_open(), "the connection was not dropped");
}

/// Once the peer reads again everything queued is written, in order, and the
/// outbound queue stays bounded meanwhile.
#[tokio::test(start_paused = true)]
async fn outbound_updates_are_bounded_and_ordered_across_a_write_stall() {
    let (mut handle, mut peer) = established(config(90)).await;
    peer.clear_sent();
    peer.set_reading(false);

    let tx = handle.update_sender();
    let mut accepted = 0u32;
    for _ in 0..10 {
        while tx.try_send(update(accepted)).is_ok() {
            accepted += 1;
        }
        settle().await;
    }
    assert!(
        (256..2_000).contains(&accepted),
        "the session must stop taking UPDATEs while it cannot write: took {accepted}"
    );
    // The peer is still alive: its KEEPALIVEs keep the session up.
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(60)).await;
        peer.push(BgpMessage::Keepalive);
        settle().await;
    }

    peer.set_reading(true);
    settle().await;
    let written: Vec<_> = peer
        .sent()
        .into_iter()
        .filter_map(|s| match s.msg {
            BgpMessage::Update(u) => Some(u),
            _ => None,
        })
        .collect();
    let expected: Vec<_> = (0..accepted).map(update).collect();
    assert_eq!(written, expected);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), handle.next_event())
            .await
            .is_err(),
        "the session must still be up"
    );
}

// ── Consumer stalls (full event channel) ─────────────────────────────────────

/// KEEPALIVEs keep their cadence while the event consumer is stalled, and every
/// event is delivered, in order, once it resumes.
#[tokio::test(start_paused = true)]
async fn keepalives_continue_while_the_event_channel_is_full() {
    let (mut handle, mut peer) = established(config(9)).await;
    peer.clear_sent();

    for n in 0..1_000 {
        peer.push(update_msg(n));
    }
    // Nobody calls next_event() for 8 s: less than the peer's hold time.
    let start = Instant::now();
    for _ in 0..8 {
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
    }
    let times = peer.keepalive_times();
    let during: Vec<_> = times.iter().filter(|t| **t > start).collect();
    assert!(
        during.len() >= 2,
        "{} KEEPALIVEs in 8 s of consumer stall (cadence 3 s)",
        during.len()
    );
    assert!(
        peer.consumed() < 200,
        "the session must stop reading a peer it cannot deliver for"
    );

    for n in 0..1_000 {
        match next_event(&mut handle).await {
            SessionEvent::RouteUpdate(u) => assert_eq!(u, update(n)),
            other => panic!("expected UPDATE {n}, got {other:?}"),
        }
    }
}

/// A consumer stalled for longer than the `HoldTime` must not make the session
/// declare a talking peer dead: its messages are waiting to be read.
#[tokio::test(start_paused = true)]
async fn consumer_stall_longer_than_hold_time_keeps_a_talking_peer() {
    let (mut handle, mut peer) = established(config(9)).await;
    peer.clear_sent();

    for n in 0..1_000 {
        peer.push(update_msg(n));
    }
    for _ in 0..40 {
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
    }
    assert!(
        !peer.sent().iter().any(|s| hold_expired(&s.msg)),
        "peer declared dead while its messages were unread"
    );
    let times = peer.keepalive_times();
    assert!(times.len() >= 12, "{} KEEPALIVEs in 40 s", times.len());

    for n in 0..1_000 {
        match next_event(&mut handle).await {
            SessionEvent::RouteUpdate(u) => assert_eq!(u, update(n)),
            other => panic!("expected UPDATE {n}, got {other:?}"),
        }
    }
}

/// A consumer stall does not hide a dead peer: the `HoldTimer` still expires.
#[tokio::test(start_paused = true)]
async fn silent_peer_is_timed_out_while_the_event_channel_is_full() {
    let (mut handle, mut peer) = established(config(9)).await;
    peer.clear_sent();

    // Enough to fill the event channel, then silence.
    for n in 0..65 {
        peer.push(update_msg(n));
    }
    settle().await;
    for _ in 0..12 {
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
    }
    assert!(
        peer.sent().iter().any(|s| hold_expired(&s.msg)),
        "HoldTimer suspended by the full event channel"
    );
    assert!(!peer.connection_open());

    for n in 0..65 {
        match next_event(&mut handle).await {
            SessionEvent::RouteUpdate(u) => assert_eq!(u, update(n)),
            other => panic!("expected UPDATE {n}, got {other:?}"),
        }
    }
    assert!(matches!(
        next_event(&mut handle).await,
        SessionEvent::Terminated(_)
    ));
}

/// A consumer that never resumes cannot make the session buffer without bound:
/// the session is reset with Cease / Out of Resources.
#[tokio::test(start_paused = true)]
async fn permanent_consumer_stall_ends_in_a_bounded_overload_reset() {
    let (mut handle, mut peer) = established(config(9)).await;
    peer.clear_sent();

    for n in 0..5_000 {
        peer.push(update_msg(n));
    }
    for _ in 0..3_000 {
        tokio::time::advance(Duration::from_secs(1)).await;
        settle_briefly().await;
    }
    assert!(!peer.connection_open(), "the session never gave up");
    assert!(peer.sent().iter().any(|s| matches!(
        &s.msg,
        BgpMessage::Notification(NotificationMessage {
            error: NotificationError::Cease(
                pathvector_session::message::CeaseError::OutOfResources
            ),
            ..
        })
    )));
    assert!(peer.consumed() < 300, "consumed {}", peer.consumed());

    let mut events = 0;
    loop {
        match next_event(&mut handle).await {
            SessionEvent::RouteUpdate(_) => events += 1,
            SessionEvent::Terminated(_) => break,
            other @ SessionEvent::Established(_) => panic!("unexpected {other:?}"),
        }
    }
    assert!(events < 300, "{events} events were buffered");
}

/// A connection that closes while the backlog is full is a TCP failure
/// (`Unclean`, so Graceful Restart can apply), not a local overload reset.
#[tokio::test(start_paused = true)]
async fn close_behind_a_full_backlog_is_reported_as_a_tcp_failure() {
    let (mut handle, mut peer) = established(config(9)).await;
    peer.clear_sent();
    // Exactly fills the 64-entry channel and the 64-entry backlog.
    for n in 0..128 {
        peer.push(update_msg(n));
    }
    peer.close();
    for _ in 0..1_000 {
        tokio::time::advance(Duration::from_secs(1)).await;
        settle_briefly().await;
    }
    assert!(!peer.connection_open());

    for n in 0..128 {
        assert!(
            matches!(next_event(&mut handle).await, SessionEvent::RouteUpdate(u) if u == update(n))
        );
    }
    let event = next_event(&mut handle).await;
    assert!(
        matches!(event, SessionEvent::Terminated(TerminationReason::Unclean)),
        "{event:?}"
    );
}

async fn settle_briefly() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

/// Shutdown under consumer pressure: `Stop` takes effect at once.
#[tokio::test(start_paused = true)]
async fn stop_takes_effect_while_the_event_channel_is_full() {
    let (mut handle, mut peer) = established(config(90)).await;
    peer.clear_sent();
    for n in 0..1_000 {
        peer.push(update_msg(n));
    }
    settle().await;

    handle
        .stop_sender()
        .send(SessionCommand::Stop)
        .await
        .unwrap();
    settle().await;
    assert!(
        peer.sent()
            .iter()
            .any(|s| matches!(s.msg, BgpMessage::Notification(_))),
        "no Cease was sent while the event channel was full"
    );
    assert!(!peer.connection_open());

    let mut n = 0;
    loop {
        match next_event(&mut handle).await {
            SessionEvent::RouteUpdate(u) => {
                assert_eq!(u, update(n));
                n += 1;
            }
            SessionEvent::Terminated(TerminationReason::OperatorStop) => break,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Dropping the handle ends the session task rather than leaving it running.
#[tokio::test(start_paused = true)]
async fn session_task_exits_when_its_handle_is_dropped() {
    let (handle, peer) = established(config(90)).await;
    let tx = handle.update_sender();
    drop(handle);

    tokio::time::timeout(Duration::from_secs(30), tx.closed())
        .await
        .expect("session task is still running after its handle was dropped");
    assert!(!peer.connection_open());
}

// ── Teardown, closing and cadence details ────────────────────────────────────

/// §8.2.2 has the local system release its resources and drop the connection on
/// a stop whether or not the NOTIFICATION could be sent, so the consumer must
/// still learn that the session ended.
#[tokio::test(start_paused = true)]
async fn terminated_is_emitted_when_the_notification_cannot_be_written() {
    let (mut handle, peer) = established(config(90)).await;
    peer.break_writes();
    handle
        .stop_sender()
        .send(SessionCommand::Stop)
        .await
        .unwrap();
    let event = next_event(&mut handle).await;
    assert!(matches!(event, SessionEvent::Terminated(_)), "{event:?}");
    assert!(!peer.connection_open());
}

/// A peer that is only slow still gets what was queued, then the NOTIFICATION,
/// if it reads before the close deadline.
#[tokio::test(start_paused = true)]
async fn notification_follows_queued_data_to_a_peer_that_resumes_reading() {
    let (mut handle, mut peer) = established(config(90)).await;
    peer.clear_sent();
    peer.set_reading(false);
    handle.update_sender().send(update(1)).await.unwrap();
    settle().await;
    handle
        .stop_sender()
        .send(SessionCommand::Stop)
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut handle).await,
        SessionEvent::Terminated(_)
    ));

    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        peer.connection_open(),
        "closed without waiting for the peer"
    );
    peer.set_reading(true);
    settle().await;

    let sent: Vec<_> = peer.sent().into_iter().map(|s| s.msg).collect();
    assert!(matches!(sent[0], BgpMessage::Update(_)), "{sent:?}");
    assert!(matches!(sent[1], BgpMessage::Notification(_)), "{sent:?}");
    assert!(!peer.connection_open());
}

/// A stalled writer must not accumulate one KEEPALIVE per `KeepaliveTimer`
/// expiry.
#[tokio::test(start_paused = true)]
async fn keepalives_do_not_pile_up_behind_a_blocked_write() {
    let (_handle, mut peer) = established(config(9)).await;
    peer.clear_sent();
    peer.set_reading(false);
    for _ in 0..40 {
        tokio::time::advance(Duration::from_secs(3)).await;
        peer.push(BgpMessage::Keepalive);
        settle().await;
    }
    peer.set_reading(true);
    settle().await;
    let queued = peer.keepalive_times().len();
    assert!(queued <= 1, "{queued} KEEPALIVEs were buffered");
}

/// §8.2.2 Established: "Each time the local system sends a KEEPALIVE or UPDATE
/// message, it restarts its `KeepaliveTimer`".
#[tokio::test(start_paused = true)]
async fn sending_an_update_restarts_the_keepalive_timer() {
    let (handle, mut peer) = established(config(90)).await;
    peer.clear_sent();
    let start = Instant::now();

    tokio::time::advance(Duration::from_secs(20)).await;
    handle.update_sender().send(update(1)).await.unwrap();
    settle().await;
    tokio::time::advance(Duration::from_secs(29)).await;
    settle().await;
    assert!(
        peer.keepalive_times().is_empty(),
        "KEEPALIVE less than 30 s after an UPDATE"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert_eq!(peer.keepalive_times().len(), 1);
    assert!(start.elapsed() >= Duration::from_secs(50));
}
