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
    tracing::info!(port, "Prometheus metrics listening on http://0.0.0.0:{port}/metrics");
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

pub fn on_route_update(peer: Ipv4Addr, adj_rib_in: usize) {
    let p = peer.to_string();
    metrics::counter!("pathvectord_bgp_updates_received_total", "peer" => p.clone())
        .increment(1);
    metrics::gauge!("pathvectord_bgp_adj_rib_in_prefixes", "peer" => p)
        .set(adj_rib_in as f64);
}

/// Update RIB size gauges after a flush.  Call after `flush_pending()` so the
/// values reflect the post-propagation state.
pub fn update_rib_sizes(
    loc_rib_v4: usize,
    loc_rib_v6: usize,
    prefixes_advertised: &HashMap<Ipv4Addr, usize>,
) {
    metrics::gauge!("pathvectord_bgp_loc_rib_prefixes", "afi" => "ipv4")
        .set(loc_rib_v4 as f64);
    metrics::gauge!("pathvectord_bgp_loc_rib_prefixes", "afi" => "ipv6")
        .set(loc_rib_v6 as f64);
    for (peer, &count) in prefixes_advertised {
        metrics::gauge!(
            "pathvectord_bgp_adj_rib_out_prefixes",
            "peer" => peer.to_string()
        )
        .set(count as f64);
    }
}
