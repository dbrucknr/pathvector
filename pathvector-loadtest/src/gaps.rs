//! Timing analysis for the two black-box signals the harness watches from
//! *outside* the daemon: how evenly a quiet control peer receives the
//! daemon's KEEPALIVEs, and how quickly the gRPC management plane answers.

use std::time::{Duration, Instant};

/// Message-arrival summary for one observation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapStats {
    /// Messages that arrived inside the window.
    pub messages: usize,
    /// Longest silence attributed to the window: gaps whose *ending* arrival
    /// is inside it, plus — if the session is still alive — the still-open
    /// gap from the last arrival to the end of the window. Counting the open
    /// gap is what catches a stall that has not yet ended when the window
    /// closes.
    pub max_gap: Duration,
}

/// Computes [`GapStats`] for arrivals recorded on one session.
///
/// `arrivals` must be ascending. `alive` says whether the session was still
/// up at `end`; a dead session has no "open" gap, its death is reported
/// separately.
#[must_use]
pub fn gap_stats(arrivals: &[Instant], start: Instant, end: Instant, alive: bool) -> GapStats {
    let mut max_gap = Duration::ZERO;
    let mut messages = 0usize;

    for pair in arrivals.windows(2) {
        let (prev, cur) = (pair[0], pair[1]);
        if cur >= start && cur <= end {
            max_gap = max_gap.max(cur.duration_since(prev));
        }
    }
    for &t in arrivals {
        if t >= start && t <= end {
            messages += 1;
        }
    }
    if alive && let Some(&last) = arrivals.iter().rev().find(|&&t| t <= end) {
        max_gap = max_gap.max(end.duration_since(last));
    }
    GapStats { messages, max_gap }
}

/// One timed gRPC management-plane request (`list_peers`).
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub at: Instant,
    pub latency: Duration,
    pub ok: bool,
}

/// Latency distribution of probes inside a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyStats {
    pub count: usize,
    pub failures: usize,
    pub p50: Duration,
    pub p99: Duration,
    pub max: Duration,
}

/// Summarises the probes whose start time lies in `[start, end]`. Failed
/// probes are counted separately and excluded from the percentiles (their
/// latency is a timeout, not a response time).
#[must_use]
pub fn latency_stats(probes: &[Probe], start: Instant, end: Instant) -> LatencyStats {
    let in_window: Vec<&Probe> = probes
        .iter()
        .filter(|p| p.at >= start && p.at <= end)
        .collect();
    let failures = in_window.iter().filter(|p| !p.ok).count();
    let mut lat: Vec<Duration> = in_window
        .iter()
        .filter(|p| p.ok)
        .map(|p| p.latency)
        .collect();
    lat.sort_unstable();
    LatencyStats {
        count: in_window.len(),
        failures,
        p50: percentile(&lat, 50.0),
        p99: percentile(&lat, 99.0),
        max: lat.last().copied().unwrap_or(Duration::ZERO),
    }
}

/// Nearest-rank percentile of an ascending slice; zero for an empty one.
#[must_use]
pub fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    // rank = ceil(p/100 * n), 1-based; n is small enough that f64 is exact.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn steady_keepalives_report_their_spacing() {
        let b = Instant::now();
        let arrivals: Vec<Instant> = (0..5).map(|i| at(b, i * 3000)).collect();
        let s = gap_stats(&arrivals, b, at(b, 12_000), true);
        assert_eq!(s.messages, 5);
        assert_eq!(s.max_gap, Duration::from_secs(3));
    }

    /// A gap that *ends* inside the window counts even though it began
    /// before the window started — a stall straddling a scenario boundary
    /// must be attributed, not lost.
    #[test]
    fn gap_straddling_window_start_is_attributed_by_its_end() {
        let b = Instant::now();
        let arrivals = vec![at(b, 0), at(b, 7000)];
        let s = gap_stats(&arrivals, at(b, 5000), at(b, 8000), true);
        assert_eq!(s.messages, 1);
        assert_eq!(s.max_gap, Duration::from_secs(7));
    }

    /// The open gap — silence still ongoing when the window closes — must be
    /// reported for a live session, else a stall in progress looks healthy.
    #[test]
    fn open_gap_counts_for_live_session_only() {
        let b = Instant::now();
        let arrivals = vec![at(b, 0), at(b, 3000)];
        let live = gap_stats(&arrivals, b, at(b, 20_000), true);
        assert_eq!(live.max_gap, Duration::from_secs(17));
        let dead = gap_stats(&arrivals, b, at(b, 20_000), false);
        assert_eq!(dead.max_gap, Duration::from_secs(3));
    }

    #[test]
    fn no_arrivals_yields_zero() {
        let b = Instant::now();
        let s = gap_stats(&[], b, at(b, 1000), true);
        assert_eq!(
            s,
            GapStats {
                messages: 0,
                max_gap: Duration::ZERO
            }
        );
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let v: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        assert_eq!(percentile(&v, 50.0), Duration::from_millis(50));
        assert_eq!(percentile(&v, 99.0), Duration::from_millis(99));
        assert_eq!(percentile(&v, 100.0), Duration::from_millis(100));
        assert_eq!(percentile(&[], 99.0), Duration::ZERO);
        assert_eq!(
            percentile(&[Duration::from_secs(1)], 1.0),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn latency_stats_windows_and_separates_failures() {
        let b = Instant::now();
        let probes = vec![
            Probe {
                at: at(b, 0),
                latency: Duration::from_millis(500),
                ok: true,
            }, // before window
            Probe {
                at: at(b, 1000),
                latency: Duration::from_millis(2),
                ok: true,
            },
            Probe {
                at: at(b, 1100),
                latency: Duration::from_millis(4),
                ok: true,
            },
            Probe {
                at: at(b, 1200),
                latency: Duration::from_secs(30),
                ok: false,
            }, // timeout
            Probe {
                at: at(b, 9000),
                latency: Duration::from_millis(900),
                ok: true,
            }, // after window
        ];
        let s = latency_stats(&probes, at(b, 1000), at(b, 2000));
        assert_eq!(s.count, 3);
        assert_eq!(s.failures, 1);
        assert_eq!(
            s.max,
            Duration::from_millis(4),
            "timeout must not inflate max"
        );
        assert_eq!(s.p50, Duration::from_millis(2));
    }
}
