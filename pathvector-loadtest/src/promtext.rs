//! Minimal Prometheus text-exposition parsing, just enough to read
//! pathvectord's own `/metrics` and diff histograms between two scrapes.
//!
//! Deliberately not a general parser: it handles the sample-line shape
//! `name{k="v",...} value [timestamp]` that `metrics-exporter-prometheus`
//! emits, and ignores `#` comment lines.

use std::collections::BTreeMap;

/// A label set, ordered for stable grouping/comparison.
pub type Labels = BTreeMap<String, String>;

#[derive(Debug, Clone)]
struct Sample {
    name: String,
    labels: Labels,
    value: f64,
}

/// All samples from one scrape.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    samples: Vec<Sample>,
}

/// One histogram series (a metric name + one label set) from one scrape.
#[derive(Debug, Clone, PartialEq)]
pub struct Histogram {
    pub labels: Labels,
    /// `(le, cumulative_count)`, ascending by `le`; the last is `+Inf`.
    pub buckets: Vec<(f64, f64)>,
    pub sum: f64,
    pub count: f64,
}

/// How a histogram series changed between two scrapes.
#[derive(Debug, Clone, PartialEq)]
pub struct HistDelta {
    pub labels: Labels,
    /// Samples recorded between the scrapes.
    pub count: u64,
    /// Sum of those samples.
    pub sum: f64,
    /// Upper bound on the largest sample: the smallest bucket `le` that
    /// contains every new sample. `f64::INFINITY` means it exceeded the
    /// largest finite bucket. `None` when no samples were recorded.
    pub max_le: Option<f64>,
}

impl Snapshot {
    /// Parses a text-exposition body. Malformed lines are skipped rather than
    /// failing the whole scrape — one bad line shouldn't hide the rest.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let samples = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(parse_line)
            .collect();
        Self { samples }
    }

    /// Value of the gauge/counter `name` whose labels include every pair in
    /// `labels` (extra labels on the series are allowed).
    #[must_use]
    pub fn value(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        self.samples
            .iter()
            .find(|s| {
                s.name == name
                    && labels
                        .iter()
                        .all(|(k, v)| s.labels.get(*k).is_some_and(|x| x == v))
            })
            .map(|s| s.value)
    }

    /// Every histogram series for the metric family `base` (e.g.
    /// `pathvectord_state_lock_hold_seconds`), grouped by label set.
    #[must_use]
    pub fn histograms(&self, base: &str) -> Vec<Histogram> {
        let bucket_name = format!("{base}_bucket");
        let sum_name = format!("{base}_sum");
        let count_name = format!("{base}_count");

        let mut by_labels: BTreeMap<Labels, Histogram> = BTreeMap::new();
        for s in &self.samples {
            let is_bucket = s.name == bucket_name;
            if !(is_bucket || s.name == sum_name || s.name == count_name) {
                continue;
            }
            let mut labels = s.labels.clone();
            let le = labels.remove("le");
            let h = by_labels
                .entry(labels.clone())
                .or_insert_with(|| Histogram {
                    labels,
                    buckets: Vec::new(),
                    sum: 0.0,
                    count: 0.0,
                });
            if is_bucket {
                if let Some(le) = le.and_then(|v| v.parse::<f64>().ok()) {
                    h.buckets.push((le, s.value));
                }
            } else if s.name == sum_name {
                h.sum = s.value;
            } else {
                h.count = s.value;
            }
        }

        let mut out: Vec<Histogram> = by_labels.into_values().collect();
        for h in &mut out {
            h.buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
        }
        out
    }
}

/// Per-label-set change in histogram family `base` between `before` and
/// `after`. A series absent from `before` is treated as all-zero (it was
/// created in the window). Series with no new samples are omitted.
#[must_use]
pub fn histogram_deltas(before: &Snapshot, after: &Snapshot, base: &str) -> Vec<HistDelta> {
    let before_h = before.histograms(base);
    let mut out = Vec::new();
    for a in after.histograms(base) {
        let b = before_h.iter().find(|h| h.labels == a.labels);
        let count = a.count - b.map_or(0.0, |h| h.count);
        if count <= 0.0 {
            continue;
        }
        let sum = a.sum - b.map_or(0.0, |h| h.sum);

        let max_le = a.buckets.iter().find_map(|&(le, cum_after)| {
            let cum_before = b
                .and_then(|h| {
                    h.buckets.iter().find(|(l, _)| {
                        (*l - le).abs() < f64::EPSILON || (l.is_infinite() && le.is_infinite())
                    })
                })
                .map_or(0.0, |&(_, c)| c);
            (cum_after - cum_before >= count).then_some(le)
        });

        out.push(HistDelta {
            labels: a.labels.clone(),
            // `count` is a non-negative whole-number difference of counters.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            count: count.round() as u64,
            sum,
            max_le,
        });
    }
    out
}

fn parse_line(line: &str) -> Option<Sample> {
    let (name_and_labels, rest) = if let Some(open) = line.find('{') {
        let close = find_closing_brace(line, open)?;
        (&line[..=close], line[close + 1..].trim())
    } else {
        let sp = line.find(char::is_whitespace)?;
        (&line[..sp], line[sp..].trim())
    };

    let (name, labels) = if let Some(open) = name_and_labels.find('{') {
        (
            &name_and_labels[..open],
            parse_labels(&name_and_labels[open + 1..name_and_labels.len() - 1])?,
        )
    } else {
        (name_and_labels, Labels::new())
    };

    // Value is the first token after the series; an optional timestamp may follow.
    let value = rest.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(Sample {
        name: name.to_string(),
        labels,
        value,
    })
}

/// Index of the `}` closing the label block opened at `open`, skipping any
/// `}` inside a quoted label value.
fn find_closing_brace(line: &str, open: usize) -> Option<usize> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in line.char_indices().skip(open + 1) {
        if escaped {
            escaped = false;
        } else if c == '\\' && in_quotes {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c == '}' && !in_quotes {
            return Some(i);
        }
    }
    None
}

fn parse_labels(body: &str) -> Option<Labels> {
    let mut labels = Labels::new();
    let mut chars = body.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            return Some(labels);
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                break;
            }
            key.push(c);
            chars.next();
        }
        chars.next()?; // '='
        if chars.next()? != '"' {
            return None;
        }
        let mut value = String::new();
        loop {
            match chars.next()? {
                '\\' => match chars.next()? {
                    'n' => value.push('\n'),
                    other => value.push(other),
                },
                '"' => break,
                c => value.push(c),
            }
        }
        labels.insert(key.trim().to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRAPE_A: &str = r#"
# TYPE pathvectord_state_lock_hold_seconds histogram
pathvectord_state_lock_hold_seconds_bucket{kind="event_batch",le="0.001"} 4
pathvectord_state_lock_hold_seconds_bucket{kind="event_batch",le="0.1"} 5
pathvectord_state_lock_hold_seconds_bucket{kind="event_batch",le="+Inf"} 5
pathvectord_state_lock_hold_seconds_sum{kind="event_batch"} 0.05
pathvectord_state_lock_hold_seconds_count{kind="event_batch"} 5
# TYPE pathvectord_bgp_adj_rib_in_prefixes gauge
pathvectord_bgp_adj_rib_in_prefixes{peer="127.0.0.2"} 1234
pathvectord_bgp_session_up{peer="127.0.0.2"} 1
"#;

    // Same series later: 3 new samples, one of which landed in (0.1, +Inf].
    const SCRAPE_B: &str = r#"
pathvectord_state_lock_hold_seconds_bucket{kind="event_batch",le="0.001"} 5
pathvectord_state_lock_hold_seconds_bucket{kind="event_batch",le="0.1"} 7
pathvectord_state_lock_hold_seconds_bucket{kind="event_batch",le="+Inf"} 8
pathvectord_state_lock_hold_seconds_sum{kind="event_batch"} 12.05
pathvectord_state_lock_hold_seconds_count{kind="event_batch"} 8
pathvectord_state_lock_hold_seconds_bucket{kind="mrai",le="0.001"} 2
pathvectord_state_lock_hold_seconds_bucket{kind="mrai",le="0.1"} 2
pathvectord_state_lock_hold_seconds_bucket{kind="mrai",le="+Inf"} 2
pathvectord_state_lock_hold_seconds_sum{kind="mrai"} 0.0004
pathvectord_state_lock_hold_seconds_count{kind="mrai"} 2
"#;

    #[test]
    fn parses_gauges_with_label_subset_match() {
        let s = Snapshot::parse(SCRAPE_A);
        assert_eq!(
            s.value(
                "pathvectord_bgp_adj_rib_in_prefixes",
                &[("peer", "127.0.0.2")]
            ),
            Some(1234.0)
        );
        assert_eq!(s.value("pathvectord_bgp_session_up", &[]), Some(1.0));
        assert_eq!(
            s.value("pathvectord_bgp_session_up", &[("peer", "9.9.9.9")]),
            None
        );
        assert_eq!(s.value("no_such_metric", &[]), None);
    }

    #[test]
    fn groups_histogram_buckets_by_label_set_and_sorts_le() {
        let hs = Snapshot::parse(SCRAPE_A).histograms("pathvectord_state_lock_hold_seconds");
        assert_eq!(hs.len(), 1);
        let h = &hs[0];
        assert_eq!(
            h.labels.get("kind").map(String::as_str),
            Some("event_batch")
        );
        assert_eq!(h.count, 5.0);
        assert!((h.sum - 0.05).abs() < 1e-12);
        let les: Vec<f64> = h.buckets.iter().map(|b| b.0).collect();
        assert_eq!(les, vec![0.001, 0.1, f64::INFINITY]);
    }

    /// The delta's count/sum are the difference of the two scrapes, and
    /// `max_le` is the smallest bucket holding *all* new samples — here one
    /// new sample overflowed the largest finite bucket, so the bound is +Inf
    /// even though most new samples were fast.
    #[test]
    fn delta_reports_count_sum_and_max_bucket_bound() {
        let d = histogram_deltas(
            &Snapshot::parse(SCRAPE_A),
            &Snapshot::parse(SCRAPE_B),
            "pathvectord_state_lock_hold_seconds",
        );
        let eb = d
            .iter()
            .find(|d| d.labels.get("kind").map(String::as_str) == Some("event_batch"))
            .expect("event_batch delta");
        assert_eq!(eb.count, 3);
        assert!((eb.sum - 12.0).abs() < 1e-9);
        assert_eq!(eb.max_le, Some(f64::INFINITY));
    }

    /// A series that first appears inside the window counts from zero.
    #[test]
    fn series_new_in_window_counts_from_zero() {
        let d = histogram_deltas(
            &Snapshot::parse(SCRAPE_A),
            &Snapshot::parse(SCRAPE_B),
            "pathvectord_state_lock_hold_seconds",
        );
        let m = d
            .iter()
            .find(|d| d.labels.get("kind").map(String::as_str) == Some("mrai"))
            .expect("mrai delta");
        assert_eq!(m.count, 2);
        assert_eq!(m.max_le, Some(0.001));
    }

    #[test]
    fn unchanged_series_are_omitted() {
        let s = Snapshot::parse(SCRAPE_A);
        assert_eq!(
            histogram_deltas(&s, &s, "pathvectord_state_lock_hold_seconds").len(),
            0
        );
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let s = Snapshot::parse("garbage line\nok_metric 3\nbad{label 4\n");
        assert_eq!(s.value("ok_metric", &[]), Some(3.0));
    }

    #[test]
    fn label_values_may_contain_braces_commas_and_escapes() {
        let s = Snapshot::parse(r#"m{a="x}y,z",b="q\"r"} 7"#);
        assert_eq!(s.value("m", &[("a", "x}y,z"), ("b", "q\"r")]), Some(7.0));
    }
}
