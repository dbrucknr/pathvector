//! Delivery of [`SessionEvent`]s without waiting for the consumer.
//!
//! Events go straight into the channel while it has room. Once it is full they
//! are held here, in order, and the session loop delivers them as one more
//! thing it waits for. The loop stops reading the peer while anything is held,
//! so the backlog stays small and the peer sees ordinary TCP flow control.

use std::collections::VecDeque;
use std::net::IpAddr;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use super::SessionEvent;

pub(super) struct Outbox {
    tx: mpsc::Sender<SessionEvent>,
    held: VecDeque<SessionEvent>,
    blocked_since: Option<std::time::Instant>,
    peer: IpAddr,
}

impl Outbox {
    pub(super) fn new(tx: mpsc::Sender<SessionEvent>, peer: IpAddr) -> Self {
        Self {
            tx,
            held: VecDeque::new(),
            blocked_since: None,
            peer,
        }
    }

    /// Whether any event is still waiting for room in the channel.
    pub(super) fn is_blocked(&self) -> bool {
        !self.held.is_empty()
    }

    /// How many events are waiting.
    pub(super) fn held(&self) -> usize {
        self.held.len()
    }

    /// Deliver `event` after everything already waiting. Never blocks. A closed
    /// channel discards it.
    pub(super) fn push(&mut self, event: SessionEvent) {
        if self.held.is_empty() {
            match self.tx.try_send(event) {
                Ok(()) | Err(TrySendError::Closed(_)) => {}
                Err(TrySendError::Full(event)) => {
                    self.blocked_since = Some(std::time::Instant::now());
                    self.held.push_back(event);
                }
            }
        } else {
            self.held.push_back(event);
        }
    }

    /// A sender to reserve room on, for use while [`Self::is_blocked`].
    pub(super) fn sender(&self) -> mpsc::Sender<SessionEvent> {
        self.tx.clone()
    }

    /// Room became available (`Err` if the consumer went away).
    pub(super) fn deliver(
        &mut self,
        permit: Result<mpsc::OwnedPermit<SessionEvent>, mpsc::error::SendError<()>>,
    ) {
        match permit {
            Ok(permit) => {
                if let Some(event) = self.held.pop_front() {
                    permit.send(event);
                }
                while let Some(event) = self.held.pop_front() {
                    match self.tx.try_send(event) {
                        Ok(()) => {}
                        Err(TrySendError::Full(event)) => {
                            self.held.push_front(event);
                            return;
                        }
                        Err(TrySendError::Closed(_)) => self.held.clear(),
                    }
                }
            }
            Err(_) => self.held.clear(),
        }
        self.record_unblocked();
    }

    /// Wait until nothing is held, because the consumer took it or went away.
    pub(super) async fn drain(&mut self) {
        while self.is_blocked() {
            let permit = self.sender().reserve_owned().await;
            self.deliver(permit);
        }
    }

    /// Records `pathvector_session_event_send_blocked_seconds{peer}`: how long
    /// events waited for the consumer. One sample per episode, from the first
    /// event that found the channel full until the backlog was empty again.
    fn record_unblocked(&mut self) {
        if let Some(since) = self.blocked_since.take() {
            metrics::histogram!(
                "pathvector_session_event_send_blocked_seconds",
                "peer" => self.peer.to_string()
            )
            .record(since.elapsed().as_secs_f64());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    use super::*;
    use crate::transport::TerminationReason;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const METRIC: &str = "pathvector_session_event_send_blocked_seconds";

    fn event(reason: TerminationReason) -> SessionEvent {
        SessionEvent::Terminated(reason)
    }

    fn reason(event: SessionEvent) -> TerminationReason {
        let SessionEvent::Terminated(reason) = event else {
            panic!("expected Terminated")
        };
        reason
    }

    /// Every histogram recorded so far, keyed by metric name, as raw samples.
    fn histograms(snapshotter: &Snapshotter) -> HashMap<String, Vec<f64>> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _unit, _desc, value)| match value {
                DebugValue::Histogram(samples) => Some((
                    key.key().name().to_string(),
                    samples.iter().map(|s| s.into_inner()).collect(),
                )),
                _ => None,
            })
            .collect()
    }

    /// With capacity available the event is delivered and *no* blocked sample
    /// is emitted — the metric's count must mean "number of times the session
    /// was actually blocked", not "number of sends".
    #[tokio::test(flavor = "current_thread")]
    async fn unblocked_push_delivers_without_recording() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let (tx, mut rx) = mpsc::channel(4);
        let mut outbox = Outbox::new(tx, PEER);
        outbox.push(event(TerminationReason::OperatorStop));

        assert!(!outbox.is_blocked());
        assert!(matches!(rx.recv().await, Some(SessionEvent::Terminated(_))));
        assert!(!histograms(&snapshotter).contains_key(METRIC));
    }

    /// A full channel holds events without blocking the caller, delivers them
    /// in order, and records the blocked time once.
    #[tokio::test(flavor = "current_thread")]
    async fn full_channel_holds_in_order_and_records_one_episode() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let (tx, mut rx) = mpsc::channel(1);
        let mut outbox = Outbox::new(tx, PEER);
        outbox.push(event(TerminationReason::Unclean));
        outbox.push(event(TerminationReason::OperatorStop));
        outbox.push(event(TerminationReason::Unclean));
        assert_eq!(outbox.held(), 2);

        std::thread::sleep(Duration::from_millis(40));
        let mut seen = Vec::new();
        while outbox.is_blocked() {
            seen.push(reason(rx.recv().await.unwrap()));
            outbox.deliver(outbox.sender().reserve_owned().await);
        }
        seen.push(reason(rx.recv().await.unwrap()));
        assert_eq!(
            seen,
            [
                TerminationReason::Unclean,
                TerminationReason::OperatorStop,
                TerminationReason::Unclean
            ]
        );

        let samples = histograms(&snapshotter)
            .remove(METRIC)
            .expect("blocked episode must be recorded");
        assert_eq!(samples.len(), 1);
        assert!(samples[0] >= 0.035, "held ~40ms, recorded {}", samples[0]);
    }

    /// A closed channel is ignored: nothing held, nothing recorded.
    #[tokio::test(flavor = "current_thread")]
    async fn closed_channel_is_ignored() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let mut outbox = Outbox::new(tx, PEER);
        outbox.push(event(TerminationReason::OperatorStop));

        assert!(!outbox.is_blocked());
        assert!(histograms(&snapshotter).is_empty());
    }

    /// A consumer that goes away while events are held releases them.
    #[tokio::test(flavor = "current_thread")]
    async fn consumer_dropped_while_blocked_discards_the_backlog() {
        let (tx, rx) = mpsc::channel(1);
        let mut outbox = Outbox::new(tx, PEER);
        outbox.push(event(TerminationReason::Unclean));
        outbox.push(event(TerminationReason::Unclean));
        drop(rx);
        let permit = outbox.sender().reserve_owned().await;
        outbox.deliver(permit);
        assert!(!outbox.is_blocked());
    }
}
