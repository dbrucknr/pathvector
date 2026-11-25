// pathvectord/src/lock_timing.rs — write-lock wait/hold instrumentation for
// the shared `DaemonState` lock.
//
// PRODUCTION_READINESS.md PR-1 asks for a published capacity envelope and for
// proof that a slow operation on one peer does not stall every other peer.
// Both need a measurement of how long the single `Arc<RwLock<DaemonState>>`
// write lock is held, broken down by *what* held it. This module wraps
// `tokio::sync::RwLock::write()` so every instrumented acquisition records:
//
//   pathvectord_state_lock_wait_seconds{kind}  — time spent queued for the lock
//   pathvectord_state_lock_hold_seconds{kind}  — time the guard was alive
//
// `kind` is a small, fixed set of `&'static str` call-site names (never
// peer-derived), so cardinality is bounded by the number of instrumented
// sites.
//
// Hold time is measured from acquisition to `Drop`, so an explicit
// `drop(guard)` before an `.await` (the pattern throughout the event loop)
// ends the measurement at exactly that point. Holding a guard across an
// `.await` is therefore *included* in the hold time, which is the correct
// thing to report: that is time other tasks spend blocked.

use std::{
    ops::{Deref, DerefMut},
    time::{Duration, Instant},
};

use tokio::sync::{RwLock, RwLockWriteGuard};

/// A `RwLockWriteGuard` that records how long it was held when dropped.
///
/// Derefs transparently to the protected value, so call sites only change
/// from `lock.write().await` to `write_timed(&lock, "kind").await`.
pub(crate) struct TimedWriteGuard<'a, T> {
    guard: RwLockWriteGuard<'a, T>,
    kind: &'static str,
    acquired: Instant,
}

impl<'a, T> TimedWriteGuard<'a, T> {
    /// Wraps an already-acquired guard, recording the time spent waiting for
    /// it immediately and starting the hold-time clock.
    pub(crate) fn new(
        guard: RwLockWriteGuard<'a, T>,
        kind: &'static str,
        waited: Duration,
    ) -> Self {
        metrics::histogram!("pathvectord_state_lock_wait_seconds", "kind" => kind)
            .record(waited.as_secs_f64());
        Self {
            guard,
            kind,
            acquired: Instant::now(),
        }
    }
}

impl<T> Deref for TimedWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> DerefMut for TimedWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> Drop for TimedWriteGuard<'_, T> {
    fn drop(&mut self) {
        metrics::histogram!("pathvectord_state_lock_hold_seconds", "kind" => self.kind)
            .record(self.acquired.elapsed().as_secs_f64());
    }
}

/// Acquires `lock` for writing, recording wait and (on drop) hold time under
/// the given `kind` label.
pub(crate) async fn write_timed<'a, T>(
    lock: &'a RwLock<T>,
    kind: &'static str,
) -> TimedWriteGuard<'a, T> {
    let start = Instant::now();
    let guard = lock.write().await;
    TimedWriteGuard::new(guard, kind, start.elapsed())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;

    /// Same isolated-recorder pattern as `metrics::tests::capture`.
    fn capture(f: impl FnOnce()) -> HashMap<(String, Vec<(String, String)>), DebugValue> {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(composite_key, _unit, _desc, value)| {
                let key = composite_key.key();
                let mut labels: Vec<(String, String)> = key
                    .labels()
                    .map(|l| (l.key().to_string(), l.value().to_string()))
                    .collect();
                labels.sort();
                ((key.name().to_string(), labels), value)
            })
            .collect()
    }

    fn kind_label(kind: &str) -> Vec<(String, String)> {
        vec![("kind".to_string(), kind.to_string())]
    }

    fn histogram_samples(value: &DebugValue) -> Vec<f64> {
        match value {
            DebugValue::Histogram(v) => v.iter().map(|f| f.into_inner()).collect(),
            other => panic!("expected histogram, got {other:?}"),
        }
    }

    /// The wait duration handed to `new` is recorded verbatim, and the hold
    /// duration is recorded once, at drop, covering at least the time the
    /// guard was actually alive.
    #[test]
    fn records_wait_on_construction_and_hold_on_drop() {
        let lock = RwLock::new(0_u32);
        let snap = capture(|| {
            let guard = lock.try_write().expect("uncontended");
            let guard = TimedWriteGuard::new(guard, "unit", Duration::from_millis(7));
            std::thread::sleep(Duration::from_millis(20));
            drop(guard);
        });

        let waits = histogram_samples(
            &snap[&(
                "pathvectord_state_lock_wait_seconds".to_string(),
                kind_label("unit"),
            )],
        );
        assert_eq!(waits.len(), 1);
        assert!((waits[0] - 0.007).abs() < 1e-9, "wait was {}", waits[0]);

        let holds = histogram_samples(
            &snap[&(
                "pathvectord_state_lock_hold_seconds".to_string(),
                kind_label("unit"),
            )],
        );
        assert_eq!(holds.len(), 1);
        assert!(holds[0] >= 0.020, "hold was {}", holds[0]);
    }

    /// Hold time must not be recorded until the guard drops — a still-alive
    /// guard has produced no hold sample yet.
    #[test]
    fn hold_not_recorded_while_guard_alive() {
        let lock = RwLock::new(0_u32);
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let mut guard_slot = None;
        metrics::with_local_recorder(&recorder, || {
            let guard = lock.try_write().expect("uncontended");
            guard_slot = Some(TimedWriteGuard::new(guard, "alive", Duration::ZERO));
        });
        let has_hold = snapshotter
            .snapshot()
            .into_vec()
            .iter()
            .any(|(k, ..)| k.key().name() == "pathvectord_state_lock_hold_seconds");
        assert!(!has_hold, "hold sample emitted before drop");
        drop(guard_slot);
    }

    /// The wrapper is a transparent `Deref`/`DerefMut` to the protected value.
    #[test]
    fn derefs_to_inner_value() {
        let lock = RwLock::new(vec![1, 2, 3]);
        let mut guard = TimedWriteGuard::new(
            lock.try_write().expect("uncontended"),
            "deref",
            Duration::ZERO,
        );
        guard.push(4);
        assert_eq!(guard.len(), 4);
        assert_eq!(*guard, vec![1, 2, 3, 4]);
    }

    /// `write_timed` still provides mutual exclusion: a second writer queues
    /// behind a held guard for at least as long as the holder keeps it. (The
    /// metric values themselves are asserted by the synchronous tests above;
    /// this one guards against the wrapper changing locking behaviour.)
    #[tokio::test(flavor = "current_thread")]
    async fn write_timed_wait_reflects_contention() {
        let lock = std::sync::Arc::new(RwLock::new(()));
        let first = write_timed(&lock, "holder").await;

        let waiter_lock = std::sync::Arc::clone(&lock);
        let queued = tokio::spawn(async move {
            let start = Instant::now();
            let g = write_timed(&waiter_lock, "waiter").await;
            let waited = start.elapsed();
            drop(g);
            waited
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(first);
        let queue_time = queued.await.expect("queued task");
        assert!(
            queue_time >= Duration::from_millis(25),
            "waiter should have queued behind the holder, waited {queue_time:?}"
        );
    }
}
