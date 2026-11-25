//! Per-scenario results and their plain-text rendering.

use std::{fmt::Write as _, time::Duration};

use crate::{
    gaps::{GapStats, LatencyStats},
    promtext::HistDelta,
};

/// What the control peer saw — the harness's black-box answer to "did the
/// daemon keep other peers alive while it was busy?".
#[derive(Debug, Clone, Copy)]
pub struct ControlSummary {
    pub gaps: GapStats,
    /// Daemon keepalive cadence the control peer expects (`hold / 3`).
    pub expected_gap: Duration,
    /// The negotiated hold time; silence longer than this is a breach.
    pub hold: Duration,
    /// Session still established at the end of the window.
    pub alive: bool,
    /// `(code, subcode)` if the daemon sent a NOTIFICATION.
    pub notification: Option<(u8, u8)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// Keepalives arrived, but later than their cadence — within hold time.
    Late(String),
    /// Silence exceeded the hold time, or the session was lost.
    Failed(String),
}

impl ControlSummary {
    /// PR-1's pass/fail question for this window.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if !self.alive {
            let why = self.notification.map_or_else(
                || "connection closed".to_string(),
                |(c, s)| format!("NOTIFICATION {c}/{s}"),
            );
            return Verdict::Failed(format!("control session lost ({why})"));
        }
        if self.gaps.max_gap > self.hold {
            return Verdict::Failed(format!(
                "longest silence {} exceeded hold time {}",
                fmt_dur(self.gaps.max_gap),
                fmt_dur(self.hold)
            ));
        }
        // 1.5× tolerates ordinary scheduling jitter on a loaded machine.
        if self.gaps.max_gap > self.expected_gap.mul_f64(1.5) {
            return Verdict::Late(format!(
                "longest silence {} vs expected {}",
                fmt_dur(self.gaps.max_gap),
                fmt_dur(self.expected_gap)
            ));
        }
        Verdict::Ok
    }
}

/// Everything measured over one scenario window.
#[derive(Debug, Clone)]
pub struct WindowReport {
    pub title: String,
    pub duration: Duration,
    pub control: ControlSummary,
    pub mgmt: LatencyStats,
    pub lock_hold: Vec<HistDelta>,
    pub lock_wait: Vec<HistDelta>,
    pub batch_events: Option<HistDelta>,
    pub send_blocked: Vec<HistDelta>,
    pub keepalive_lateness: Vec<HistDelta>,
    pub peak_rss_kb: Option<u64>,
    /// Free-form facts the scenario wants recorded (durations, counts, …).
    pub notes: Vec<String>,
}

/// `12.3 ms`, `4.56 s`, `78 µs` — three significant-ish figures.
#[must_use]
pub fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 1.0 {
        format!("{s:.2} s")
    } else if s >= 0.001 {
        format!("{:.1} ms", s * 1e3)
    } else {
        format!("{:.0} µs", s * 1e6)
    }
}

/// Renders a bucket upper bound: `≤ 100 ms`, or `> 30 s` for the +Inf bucket.
#[must_use]
pub fn fmt_le(le: Option<f64>) -> String {
    match le {
        None => "—".to_string(),
        Some(v) if v.is_infinite() => "> 30 s".to_string(),
        Some(v) => format!("≤ {}", fmt_dur(Duration::from_secs_f64(v))),
    }
}

fn label(d: &HistDelta, key: &str) -> String {
    d.labels.get(key).cloned().unwrap_or_default()
}

fn hist_table(out: &mut String, title: &str, key: &str, rows: &[HistDelta], unit_seconds: bool) {
    if rows.is_empty() {
        return;
    }
    let mut rows = rows.to_vec();
    // Worst first: infinite bound sorts above any finite one.
    rows.sort_by(|a, b| {
        b.max_le
            .unwrap_or(0.0)
            .total_cmp(&a.max_le.unwrap_or(0.0))
            .then(b.sum.total_cmp(&a.sum))
    });
    let _ = writeln!(out, "  {title}");
    let _ = writeln!(
        out,
        "    {:<28} {:>9} {:>12} {:>12}",
        key, "count", "total", "max"
    );
    for r in &rows {
        let name = label(r, key);
        let total = if unit_seconds {
            fmt_dur(Duration::from_secs_f64(r.sum.max(0.0)))
        } else {
            format!("{:.0}", r.sum)
        };
        let max = if unit_seconds {
            fmt_le(r.max_le)
        } else {
            r.max_le.map_or_else(
                || "—".to_string(),
                |v| {
                    if v.is_infinite() {
                        "> 1024".into()
                    } else {
                        format!("≤ {v:.0}")
                    }
                },
            )
        };
        let _ = writeln!(out, "    {name:<28} {:>9} {total:>12} {max:>12}", r.count);
    }
}

/// Plain-text rendering of one window.
#[must_use]
pub fn render(r: &WindowReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "━━ {} ({})", r.title, fmt_dur(r.duration));

    let c = &r.control;
    let verdict = match c.verdict() {
        Verdict::Ok => "OK".to_string(),
        Verdict::Late(m) => format!("LATE — {m}"),
        Verdict::Failed(m) => format!("FAILED — {m}"),
    };
    let _ = writeln!(
        out,
        "  control peer   {} msgs, longest silence {} (expected {}, hold {}) → {verdict}",
        c.gaps.messages,
        fmt_dur(c.gaps.max_gap),
        fmt_dur(c.expected_gap),
        fmt_dur(c.hold),
    );

    let m = &r.mgmt;
    let _ = writeln!(
        out,
        "  gRPC list_peers {} probes ({} failed): p50 {}, p99 {}, max {}",
        m.count,
        m.failures,
        fmt_dur(m.p50),
        fmt_dur(m.p99),
        fmt_dur(m.max),
    );

    hist_table(
        &mut out,
        "write-lock hold by call site",
        "kind",
        &r.lock_hold,
        true,
    );
    hist_table(
        &mut out,
        "write-lock wait by call site",
        "kind",
        &r.lock_wait,
        true,
    );
    if let Some(b) = &r.batch_events {
        let _ = writeln!(
            out,
            "  event-loop batches: {} (events coalesced per lock hold: max {})",
            b.count,
            b.max_le.map_or_else(
                || "—".to_string(),
                |v| if v.is_infinite() {
                    "> 1024".into()
                } else {
                    format!("≤ {v:.0}")
                }
            ),
        );
    }
    hist_table(
        &mut out,
        "session blocked on full event channel",
        "peer",
        &r.send_blocked,
        true,
    );
    hist_table(
        &mut out,
        "daemon keepalive timer lateness",
        "peer",
        &r.keepalive_lateness,
        true,
    );

    if let Some(kb) = r.peak_rss_kb {
        #[allow(clippy::cast_precision_loss)]
        let _ = writeln!(out, "  peak RSS       {:.0} MiB", kb as f64 / 1024.0);
    }
    for n in &r.notes {
        let _ = writeln!(out, "  note: {n}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn control(max_gap_s: u64, alive: bool) -> ControlSummary {
        ControlSummary {
            gaps: GapStats {
                messages: 10,
                max_gap: Duration::from_secs(max_gap_s),
            },
            expected_gap: Duration::from_secs(3),
            hold: Duration::from_secs(9),
            alive,
            notification: None,
        }
    }

    #[test]
    fn verdict_thresholds() {
        assert_eq!(control(3, true).verdict(), Verdict::Ok);
        assert_eq!(
            control(4, true).verdict(),
            Verdict::Ok,
            "within 1.5x jitter allowance"
        );
        assert!(matches!(control(6, true).verdict(), Verdict::Late(_)));
        assert!(
            matches!(control(9, true).verdict(), Verdict::Late(_)),
            "exactly hold is not yet a breach"
        );
        assert!(
            matches!(control(10, true).verdict(), Verdict::Failed(m) if m.contains("exceeded hold"))
        );
    }

    /// A dead session fails regardless of how small the recorded gaps were,
    /// and a received NOTIFICATION is named in the reason.
    #[test]
    fn lost_session_always_fails() {
        let mut c = control(1, false);
        c.notification = Some((4, 0));
        assert!(matches!(c.verdict(), Verdict::Failed(m) if m.contains("NOTIFICATION 4/0")));
    }

    #[test]
    fn duration_and_bucket_formatting() {
        assert_eq!(fmt_dur(Duration::from_micros(78)), "78 µs");
        assert_eq!(fmt_dur(Duration::from_micros(12_300)), "12.3 ms");
        assert_eq!(fmt_dur(Duration::from_millis(4560)), "4.56 s");
        assert_eq!(fmt_le(Some(0.1)), "≤ 100.0 ms");
        assert_eq!(fmt_le(Some(f64::INFINITY)), "> 30 s");
        assert_eq!(fmt_le(None), "—");
    }

    #[test]
    fn render_lists_worst_lock_holder_first() {
        let mk = |kind: &str, max: f64| HistDelta {
            labels: BTreeMap::from([("kind".to_string(), kind.to_string())]),
            count: 3,
            sum: max,
            max_le: Some(max),
        };
        let report = WindowReport {
            title: "t".into(),
            duration: Duration::from_secs(2),
            control: control(3, true),
            mgmt: LatencyStats {
                count: 5,
                failures: 0,
                p50: Duration::from_millis(1),
                p99: Duration::from_millis(2),
                max: Duration::from_millis(3),
            },
            lock_hold: vec![
                mk("mrai", 0.001),
                mk("rpki_reeval", 2.5),
                mk("event_batch", 0.1),
            ],
            lock_wait: vec![],
            batch_events: None,
            send_blocked: vec![],
            keepalive_lateness: vec![],
            peak_rss_kb: Some(2048),
            notes: vec!["hello".into()],
        };
        let text = render(&report);
        let pos = |s: &str| {
            text.find(s)
                .unwrap_or_else(|| panic!("{s} missing in:\n{text}"))
        };
        assert!(pos("rpki_reeval") < pos("event_batch"));
        assert!(pos("event_batch") < pos("mrai"));
        assert!(text.contains("peak RSS       2 MiB"));
        assert!(text.contains("note: hello"));
    }
}
