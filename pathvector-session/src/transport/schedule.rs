//! Deadline and budget policy for the session loop.
//!
//! Pure: no sockets, no channels, no clock reads. The caller passes `now` in
//! and acts on the answer, so every bound stated here can be tested without a
//! runtime.
//!
//! The session loop must keep supervising its timers (RFC 4271 §8.2.2 Events
//! 9 to 11) however much input is ready and however slow its peer and its
//! consumer are. Two rules give that:
//!
//! * [`Turns`] alternates between overdue timers and ready input, so neither
//!   starves the other.
//! * [`HoldGrace`] bounds how much already-received input an overdue
//!   `HoldTimer` reads before it expires.

use std::num::{NonZeroU32, NonZeroUsize};
use std::time::Duration;

use tokio::time::Instant;

/// A timer the session loop supervises.
///
/// Declaration order breaks ties between timers with the same deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Timer {
    /// RFC 9687 §4.2 Event 29.
    SendHold,
    /// RFC 4271 §8.1.3 Event 11.
    Keepalive,
    /// RFC 4271 §8.1.3 Event 10.
    Hold,
    /// RFC 4271 §8.1.3 Event 9.
    ConnectRetry,
    /// Waiting for a staged collision candidate's OPEN.
    CandidateOpen,
    /// Waiting for a closing connection to take its last bytes.
    CloseFlush,
}

impl Timer {
    pub(super) const ALL: [Self; 6] = [
        Self::SendHold,
        Self::Keepalive,
        Self::Hold,
        Self::ConnectRetry,
        Self::CandidateOpen,
        Self::CloseFlush,
    ];
}

/// The running timers. A timer with no deadline is stopped.
#[derive(Debug, Default)]
pub(super) struct Deadlines([Option<Instant>; Timer::ALL.len()]);

impl Deadlines {
    pub(super) fn arm(&mut self, timer: Timer, at: Instant) {
        self.0[timer as usize] = Some(at);
    }

    pub(super) fn cancel(&mut self, timer: Timer) {
        self.0[timer as usize] = None;
    }

    pub(super) fn get(&self, timer: Timer) -> Option<Instant> {
        self.0[timer as usize]
    }

    /// The next moment any timer needs attention.
    pub(super) fn earliest(&self) -> Option<Instant> {
        self.0.iter().flatten().min().copied()
    }

    /// The most overdue timer: earliest deadline first, so a timer that is
    /// re-armed with a very short interval cannot keep the others waiting.
    pub(super) fn due(&self, now: Instant) -> Option<Timer> {
        Timer::ALL
            .into_iter()
            .filter_map(|t| self.get(t).filter(|at| *at <= now).map(|at| (at, t)))
            .min_by_key(|(at, _)| *at)
            .map(|(_, t)| t)
    }
}

/// Alternates between overdue timers and ready input.
///
/// After handing out a timer, the next call returns `None` whatever is due, so
/// the loop looks at its inputs once. Hence at most one input is processed
/// ahead of each overdue timer, and at most one timer between inputs.
#[derive(Debug, Default)]
pub(super) struct Turns {
    input_owed: bool,
}

impl Turns {
    /// The timer to service now, or `None` to go and wait for input.
    pub(super) fn next(&mut self, deadlines: &Deadlines, now: Instant) -> Option<Timer> {
        if std::mem::take(&mut self.input_owed) {
            return None;
        }
        let due = deadlines.due(now);
        self.input_owed = due.is_some();
        due
    }
}

/// How many already-received messages an overdue `HoldTimer` may read before it
/// expires anyway.
///
/// A peer's KEEPALIVE can be waiting unread because this side was busy or had
/// stopped reading. Reading it is how the `HoldTimer` learns the peer is alive;
/// the bound is what keeps a peer that only sends messages which do not
/// restart the timer (ROUTE-REFRESH) from postponing expiry for ever.
#[derive(Debug)]
pub(super) struct HoldGrace {
    limit: NonZeroU32,
    used: u32,
}

impl HoldGrace {
    pub(super) const DEFAULT_LIMIT: NonZeroU32 = NonZeroU32::new(16).expect("non-zero");

    pub(super) fn new(limit: NonZeroU32) -> Self {
        Self { limit, used: 0 }
    }

    /// Take one read from the allowance. `false` once it is used up.
    pub(super) fn take(&mut self) -> bool {
        let left = self.used < self.limit.get();
        if left {
            self.used += 1;
        }
        left
    }

    /// The `HoldTimer` was restarted.
    pub(super) fn reset(&mut self) {
        self.used = 0;
    }
}

/// How many bytes of UPDATEs are encoded into the write buffer at a time.
///
/// The session takes no more UPDATEs from the daemon until the batch has been
/// written, so this (plus one message) bounds its write buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WriteBatch(NonZeroUsize);

impl WriteBatch {
    /// 8 KiB: many small UPDATEs per system call, and small enough that a slow
    /// but working peer finishes a batch well inside any BGP timer.
    pub(super) const DEFAULT: Self = Self(NonZeroUsize::new(8 * 1024).expect("non-zero"));

    #[cfg(test)]
    pub(super) fn new(bytes: usize) -> Option<Self> {
        NonZeroUsize::new(bytes).map(Self)
    }

    /// Whether a batch that already holds `queued` bytes may take another
    /// message.
    pub(super) fn has_room(self, queued: usize) -> bool {
        queued < self.0.get()
    }
}

/// How many events the session holds for a consumer that is not taking them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EventBacklogLimit(NonZeroUsize);

impl EventBacklogLimit {
    pub(super) const DEFAULT: Self = Self(NonZeroUsize::new(64).expect("non-zero"));

    pub(super) fn is_reached_by(self, held: usize) -> bool {
        held >= self.0.get()
    }
}

/// How long a closing connection may take to accept its last bytes (the
/// NOTIFICATION) before it is reset.
pub(super) const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn due_is_earliest_deadline_first_and_ignores_future_timers() {
        let base = Instant::now();
        let mut d = Deadlines::default();
        assert_eq!(d.due(base), None);
        assert_eq!(d.earliest(), None);
        d.arm(Timer::Keepalive, at(base, 20));
        d.arm(Timer::Hold, at(base, 10));
        d.arm(Timer::ConnectRetry, at(base, 50));
        assert_eq!(d.earliest(), Some(at(base, 10)));
        assert_eq!(d.due(at(base, 9)), None);
        assert_eq!(d.due(at(base, 10)), Some(Timer::Hold));
        assert_eq!(d.due(at(base, 100)), Some(Timer::Hold));
        d.cancel(Timer::Hold);
        assert_eq!(d.due(at(base, 100)), Some(Timer::Keepalive));
    }

    #[test]
    fn equal_deadlines_are_taken_in_declaration_order() {
        let base = Instant::now();
        let mut d = Deadlines::default();
        for t in Timer::ALL.into_iter().rev() {
            d.arm(t, base);
        }
        for expected in Timer::ALL {
            assert_eq!(d.due(base), Some(expected));
            d.cancel(expected);
        }
    }

    #[test]
    fn a_due_timer_is_followed_by_an_input_turn() {
        let base = Instant::now();
        let mut d = Deadlines::default();
        let mut turns = Turns::default();
        d.arm(Timer::Hold, base);
        assert_eq!(turns.next(&d, base), Some(Timer::Hold));
        assert_eq!(turns.next(&d, base), None);
        assert_eq!(turns.next(&d, base), Some(Timer::Hold));
    }

    #[test]
    fn hold_grace_is_bounded_and_refilled_by_a_restart() {
        let mut grace = HoldGrace::new(NonZeroU32::new(2).unwrap());
        assert!(grace.take());
        assert!(grace.take());
        assert!(!grace.take());
        assert!(!grace.take());
        grace.reset();
        assert!(grace.take());
    }

    #[test]
    fn write_batch_rejects_zero_and_bounds_a_batch() {
        assert_eq!(WriteBatch::new(0), None);
        let batch = WriteBatch::new(100).unwrap();
        assert!(batch.has_room(0));
        assert!(batch.has_room(99));
        assert!(!batch.has_room(100));
    }

    #[test]
    fn event_backlog_limit() {
        assert!(!EventBacklogLimit::DEFAULT.is_reached_by(63));
        assert!(EventBacklogLimit::DEFAULT.is_reached_by(64));
    }

    proptest! {
        /// Whatever is armed, and however fast serviced timers are re-armed,
        /// every timer that is overdue at the start is serviced within
        /// `2 * Timer::ALL.len()` calls, while inputs never lose two turns in
        /// a row.
        #[test]
        fn every_overdue_timer_is_serviced_within_a_bounded_number_of_turns(
            offsets in proptest::collection::vec(
                proptest::option::of(0u64..100),
                Timer::ALL.len(),
            ),
            rearm in proptest::collection::vec(0u64..3, Timer::ALL.len()),
            now_ms in 0u64..100,
        ) {
            let base = Instant::now();
            let mut d = Deadlines::default();
            for (t, off) in Timer::ALL.into_iter().zip(&offsets) {
                if let Some(off) = off {
                    d.arm(t, at(base, *off));
                }
            }
            let mut now = at(base, now_ms);
            let mut waiting: Vec<Timer> = Timer::ALL
                .into_iter()
                .filter(|t| d.get(*t).is_some_and(|a| a <= now))
                .collect();
            let mut turns = Turns::default();
            let mut last_was_timer = false;
            for _ in 0..2 * Timer::ALL.len() {
                match turns.next(&d, now) {
                    Some(timer) => {
                        prop_assert!(!last_was_timer, "two timers with no input turn between");
                        last_was_timer = true;
                        waiting.retain(|t| *t != timer);
                        // Re-armed immediately, possibly with a zero interval.
                        d.arm(timer, at(now, rearm[timer as usize]));
                    }
                    None => last_was_timer = false,
                }
                now = at(now, 1);
            }
            prop_assert!(waiting.is_empty(), "never serviced: {waiting:?}");
        }
    }
}
