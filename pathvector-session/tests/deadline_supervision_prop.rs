//! Random interleavings of input, deadlines and backpressure (issue #102).
//!
//! Whatever order UPDATEs arrive and leave in, and whenever the peer stops
//! reading or the consumer stops consuming, a session whose peer keeps talking
//! must:
//!
//! * stay up (no false Hold Timer expiry),
//! * keep writing often enough for the peer's `HoldTimer` while the peer reads
//!   (RFC 4271 §4.4),
//! * and converge once both resume: every event delivered and every outbound
//!   UPDATE written, once, in order.

mod supervision_support;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use proptest::prelude::*;
use tokio::sync::watch;
use tokio::time::Instant;

use pathvector_session::message::{BgpMessage, UpdateMessage};
use pathvector_session::transport::{SessionEvent, SessionHandle};
use supervision_support::*;

const HOLD: u16 = 9;

#[derive(Debug, Clone)]
enum Op {
    /// The peer sends this many UPDATEs back to back.
    Inbound(u16),
    /// The daemon queues this many outbound UPDATEs.
    Outbound(u16),
    /// Time passes.
    Advance(u8),
    ConsumerStalls(bool),
    PeerStopsReading(bool),
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (1u16..400).prop_map(Op::Inbound),
        3 => (1u16..100).prop_map(Op::Outbound),
        4 => (1u8..=8).prop_map(Op::Advance),
        1 => any::<bool>().prop_map(Op::ConsumerStalls),
        1 => any::<bool>().prop_map(Op::PeerStopsReading),
    ]
}

#[allow(clippy::too_many_lines)] // one scenario: drive, resume, check
async fn run(ops: Vec<Op>) -> Result<(), TestCaseError> {
    let (mut handle, mut peer) = established(config(HOLD)).await;
    peer.clear_sent();
    let updates = handle.update_sender();

    let (consume_tx, mut consume_rx) = watch::channel(true);
    let delivered: Arc<Mutex<Vec<SessionEvent>>> = Arc::default();
    let sink = Arc::clone(&delivered);
    tokio::spawn(async move {
        loop {
            if consume_rx.wait_for(|on| *on).await.is_err() {
                return;
            }
            tokio::select! {
                biased;
                changed = consume_rx.changed() => if changed.is_err() { return },
                event = handle.next_event() => match event {
                    Some(event) => sink.lock().unwrap().push(event),
                    None => return,
                },
            }
        }
    });

    let mut inbound = 0u32;
    let mut outbound = 0u32;
    let mut reading = true;
    // Moments from which the peer has been reading without interruption.
    let mut reading_since = Some(Instant::now());
    let mut quiet_spans = Vec::new();

    for op in ops {
        match op {
            Op::Inbound(n) => {
                for _ in 0..n {
                    peer.push(update_msg(inbound));
                    inbound += 1;
                }
            }
            Op::Outbound(n) => {
                for _ in 0..n {
                    if updates.try_send(update(outbound)).is_err() {
                        break;
                    }
                    outbound += 1;
                }
            }
            Op::Advance(secs) => {
                for _ in 0..secs {
                    // A live peer: a KEEPALIVE at least every second.
                    peer.push(BgpMessage::Keepalive);
                    tokio::time::advance(Duration::from_secs(1)).await;
                    settle().await;
                }
            }
            Op::ConsumerStalls(stalled) => {
                let _ = consume_tx.send(!stalled);
            }
            Op::PeerStopsReading(stopped) => {
                if stopped == reading {
                    reading = !stopped;
                    peer.set_reading(reading);
                    if reading {
                        settle().await;
                        reading_since = Some(Instant::now());
                    } else if let Some(since) = reading_since.take() {
                        quiet_spans.push((since, Instant::now()));
                    }
                }
            }
        }
        settle().await;
    }

    // Everything resumes.
    let _ = consume_tx.send(true);
    peer.set_reading(true);
    if !reading {
        settle().await;
        reading_since = Some(Instant::now());
    }
    for _ in 0..10 {
        peer.push(BgpMessage::Keepalive);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
    }
    quiet_spans.extend(reading_since.map(|since| (since, Instant::now())));

    let sent = peer.sent();
    prop_assert!(
        !sent
            .iter()
            .any(|s| matches!(s.msg, BgpMessage::Notification(_))),
        "the session was torn down"
    );
    prop_assert!(peer.connection_open());

    // While the peer reads, it never waits longer than one KeepaliveTime (plus
    // the one-second step of this test) for a message.
    let limit = Duration::from_secs(u64::from(HOLD) / 3 + 1);
    for (from, to) in quiet_spans {
        let mut last = from;
        for at in sent
            .iter()
            .map(|s| s.at)
            .filter(|at| *at >= from && *at <= to)
            .chain([to])
        {
            prop_assert!(at - last <= limit, "{:?} without a message", at - last);
            last = at;
        }
    }

    let written: Vec<UpdateMessage> = sent
        .into_iter()
        .filter_map(|s| match s.msg {
            BgpMessage::Update(u) => Some(u),
            _ => None,
        })
        .collect();
    prop_assert_eq!(written, (0..outbound).map(update).collect::<Vec<_>>());

    let events: Vec<UpdateMessage> = delivered
        .lock()
        .unwrap()
        .drain(..)
        .map(|e| match e {
            SessionEvent::RouteUpdate(u) => u,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    prop_assert_eq!(events, (0..inbound).map(update).collect::<Vec<_>>());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn any_interleaving_stays_up_and_converges(
        ops in proptest::collection::vec(arb_op(), 1..30)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(run(ops))?;
    }
}
