// pathvectord/src/metrics.rs — Prometheus instrumentation.
//
// Metrics exposed at `GET /metrics` on the configured port:
//
//   Gauges
//     pathvectord_bgp_session_up{peer}                              — 1 while established
//     pathvectord_bgp_session_established_timestamp_seconds{peer}   — Unix timestamp of last establishment
//     pathvectord_bgp_adj_rib_in_prefixes{peer}                     — routes received from peer
//     pathvectord_bgp_adj_rib_out_prefixes{peer}                    — routes advertised to peer
//     pathvectord_bgp_loc_rib_prefixes{afi}                         — best-path routes in Loc-RIB
//
//   Counters
//     pathvectord_bgp_sessions_established_total{peer}
//     pathvectord_bgp_sessions_terminated_total{peer, reason}       — reason: clean|notification|operator_stop|unclean
//     pathvectord_bgp_updates_received_total{peer}

use std::{collections::HashMap, net::Ipv4Addr};

use metrics_exporter_prometheus::PrometheusBuilder;
use pathvector_session::transport::TerminationReason;

/// Install the Prometheus recorder and start the HTTP scrape listener.
///
/// Must be called from within a Tokio runtime (the exporter spawns an internal
/// HTTP server task).  Panics if the recorder has already been installed or the
/// listener port is in use.
///
/// # Panics
///
/// Panics if the Prometheus exporter cannot bind to `port`.
pub fn install(port: u16) {
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], port))
        .install()
        .expect("failed to install Prometheus metrics exporter");
    tracing::info!(
        port,
        "Prometheus metrics listening on http://0.0.0.0:{port}/metrics"
    );
}

pub fn on_session_established(peer: Ipv4Addr) {
    let p = peer.to_string();
    metrics::counter!("pathvectord_bgp_sessions_established_total", "peer" => p.clone())
        .increment(1);
    metrics::gauge!("pathvectord_bgp_session_up", "peer" => p.clone()).set(1.0_f64);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    metrics::gauge!(
        "pathvectord_bgp_session_established_timestamp_seconds",
        "peer" => p
    )
    .set(ts);
}

pub fn on_session_terminated(peer: Ipv4Addr, reason: &TerminationReason) {
    let p = peer.to_string();
    let reason_label = match reason {
        TerminationReason::Unclean => "unclean",
        TerminationReason::Notification(_) => "notification",
        TerminationReason::OperatorStop => "operator_stop",
    };
    metrics::counter!(
        "pathvectord_bgp_sessions_terminated_total",
        "peer" => p.clone(),
        "reason" => reason_label
    )
    .increment(1);
    metrics::gauge!("pathvectord_bgp_session_up", "peer" => p.clone()).set(0.0_f64);
    // Zero out per-peer RIB gauges so they don't show stale values.
    metrics::gauge!("pathvectord_bgp_adj_rib_in_prefixes", "peer" => p.clone()).set(0.0_f64);
    metrics::gauge!("pathvectord_bgp_adj_rib_out_prefixes", "peer" => p).set(0.0_f64);
}

// Route/prefix counts are RIB sizes (well under 2^52), so the usize -> f64
// casts below never lose precision; Prometheus gauges are f64 by wire format.
#[allow(clippy::cast_precision_loss)]
pub fn on_route_update(peer: Ipv4Addr, adj_rib_in: usize) {
    let p = peer.to_string();
    metrics::counter!("pathvectord_bgp_updates_received_total", "peer" => p.clone()).increment(1);
    metrics::gauge!("pathvectord_bgp_adj_rib_in_prefixes", "peer" => p).set(adj_rib_in as f64);
}

/// Update RIB size gauges after a flush.  Call after `flush_pending()` so the
/// values reflect the post-propagation state.
#[allow(clippy::cast_precision_loss)]
pub fn update_rib_sizes(
    loc_rib_v4: usize,
    loc_rib_v6: usize,
    prefixes_advertised: &HashMap<Ipv4Addr, usize>,
) {
    metrics::gauge!("pathvectord_bgp_loc_rib_prefixes", "afi" => "ipv4").set(loc_rib_v4 as f64);
    metrics::gauge!("pathvectord_bgp_loc_rib_prefixes", "afi" => "ipv6").set(loc_rib_v6 as f64);
    for (peer, &count) in prefixes_advertised {
        metrics::gauge!(
            "pathvectord_bgp_adj_rib_out_prefixes",
            "peer" => peer.to_string()
        )
        .set(count as f64);
    }
}

#[cfg(test)]
mod tests {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;

    fn peer(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, n)
    }

    /// Runs `f` against a fresh, isolated recorder and returns every emitted
    /// metric as `(metric_name, sorted_labels) -> DebugValue`.
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

    #[test]
    fn established_sets_session_up_and_increments_counter() {
        let snap = capture(|| on_session_established(peer(1)));

        let labels = vec![("peer".to_string(), "10.0.0.1".to_string())];
        assert_eq!(
            snap.get(&("pathvectord_bgp_session_up".to_string(), labels.clone())),
            Some(&DebugValue::Gauge(1.0.into()))
        );
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_sessions_established_total".to_string(),
                labels.clone()
            )),
            Some(&DebugValue::Counter(1))
        );
        assert!(snap.contains_key(&(
            "pathvectord_bgp_session_established_timestamp_seconds".to_string(),
            labels
        )));
    }

    #[test]
    fn terminated_clears_session_up_and_rib_gauges() {
        let snap = capture(|| {
            on_session_established(peer(1));
            on_route_update(peer(1), 4);
            on_session_terminated(peer(1), &TerminationReason::Unclean);
        });

        let labels = vec![("peer".to_string(), "10.0.0.1".to_string())];
        assert_eq!(
            snap.get(&("pathvectord_bgp_session_up".to_string(), labels.clone())),
            Some(&DebugValue::Gauge(0.0.into())),
            "session_up must be reset to 0 on termination"
        );
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_adj_rib_in_prefixes".to_string(),
                labels.clone()
            )),
            Some(&DebugValue::Gauge(0.0.into())),
            "adj_rib_in must be zeroed so stale route counts don't linger"
        );
        assert_eq!(
            snap.get(&("pathvectord_bgp_adj_rib_out_prefixes".to_string(), labels)),
            Some(&DebugValue::Gauge(0.0.into())),
            "adj_rib_out must be zeroed so stale route counts don't linger"
        );
    }

    #[test]
    fn terminated_reason_is_labeled_correctly() {
        for (reason, expected_label) in [
            (TerminationReason::Unclean, "unclean"),
            (TerminationReason::OperatorStop, "operator_stop"),
        ] {
            let snap = capture(|| on_session_terminated(peer(1), &reason));
            let labels = vec![
                ("peer".to_string(), "10.0.0.1".to_string()),
                ("reason".to_string(), expected_label.to_string()),
            ];
            assert_eq!(
                snap.get(&(
                    "pathvectord_bgp_sessions_terminated_total".to_string(),
                    labels
                )),
                Some(&DebugValue::Counter(1)),
                "reason={expected_label}"
            );
        }
    }

    #[test]
    fn route_update_increments_counter_and_sets_adj_rib_in() {
        let snap = capture(|| {
            on_route_update(peer(2), 3);
            on_route_update(peer(2), 5);
        });

        let labels = vec![("peer".to_string(), "10.0.0.2".to_string())];
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_updates_received_total".to_string(),
                labels.clone()
            )),
            Some(&DebugValue::Counter(2)),
            "counter increments once per call"
        );
        assert_eq!(
            snap.get(&("pathvectord_bgp_adj_rib_in_prefixes".to_string(), labels)),
            Some(&DebugValue::Gauge(5.0.into())),
            "gauge reflects the most recent value, not a sum"
        );
    }

    #[test]
    fn update_rib_sizes_sets_loc_rib_and_per_peer_adj_rib_out() {
        let mut advertised = HashMap::new();
        advertised.insert(peer(1), 7usize);
        advertised.insert(peer(2), 0usize);

        let snap = capture(|| update_rib_sizes(10, 2, &advertised));

        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_loc_rib_prefixes".to_string(),
                vec![("afi".to_string(), "ipv4".to_string())]
            )),
            Some(&DebugValue::Gauge(10.0.into()))
        );
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_loc_rib_prefixes".to_string(),
                vec![("afi".to_string(), "ipv6".to_string())]
            )),
            Some(&DebugValue::Gauge(2.0.into()))
        );
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_adj_rib_out_prefixes".to_string(),
                vec![("peer".to_string(), "10.0.0.1".to_string())]
            )),
            Some(&DebugValue::Gauge(7.0.into()))
        );
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_adj_rib_out_prefixes".to_string(),
                vec![("peer".to_string(), "10.0.0.2".to_string())]
            )),
            Some(&DebugValue::Gauge(0.0.into())),
            "a peer with zero advertised routes still gets an explicit 0 gauge, \
             not a missing metric"
        );
    }
}
