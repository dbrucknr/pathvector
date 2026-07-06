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
//     pathvectord_bgp_originated_routes{afi}                        — self-originated routes present in Loc-RIB
//     pathvectord_bgp_fib_routes_installed{afi}                     — routes currently installed in the kernel FIB
//
//   Counters
//     pathvectord_bgp_sessions_established_total{peer}
//     pathvectord_bgp_sessions_terminated_total{peer, reason}       — reason: clean|notification|operator_stop|unclean
//     pathvectord_bgp_updates_received_total{peer}
//     pathvectord_bgp_updates_sent_total{peer}
//     pathvectord_bgp_fib_write_failures_total{afi, op}             — op: install|blackhole|withdraw|withdraw_blackhole
//
// Cardinality note: series are keyed by peer IP and are never removed, only
// zeroed, when a peer is deconfigured (RemovePeer). For a static peer set
// (the common case — transit/blackhole upstreams rarely change) this is a
// non-issue. For deployments that add/remove peers frequently via the
// dynamic-peer gRPC API, this means the Prometheus registry accumulates one
// stale zeroed series per removed peer for the lifetime of the process. See
// TODO.md for the tracked follow-up (prune series on RemovePeer).
//
// Registration note: every gauge/counter above is created lazily — the first
// time a peer's label value is used. A peer that is *configured* but never
// reaches Established therefore has no series at all (not even
// `session_up=0`), which is indistinguishable from an unconfigured peer on a
// dashboard. `register_peer` (below) pre-creates the peer-state gauges at
// zero so a configured-but-never-established peer is still visible.

use std::{collections::HashMap, net::IpAddr};

use metrics_exporter_prometheus::PrometheusBuilder;
use pathvector_session::transport::TerminationReason;

/// Install the Prometheus recorder and start the HTTP scrape listener.
///
/// Must be called from within a Tokio runtime (the exporter spawns an internal
/// HTTP server task).  Like the kernel FIB integration, a failure here degrades
/// the daemon rather than crashing it: BGP session management and route
/// propagation do not depend on metrics being available. The caller is
/// expected to log the error and continue.
///
/// # Errors
///
/// Returns an error if the recorder has already been installed (only one
/// recorder may be installed per process) or if binding to `port` fails
/// (e.g. already in use, or insufficient privilege for a low port number).
pub fn install(port: u16) -> Result<(), metrics_exporter_prometheus::BuildError> {
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], port))
        .install()?;
    tracing::info!(
        port,
        "Prometheus metrics listening on http://0.0.0.0:{port}/metrics"
    );
    Ok(())
}

/// Pre-creates the peer-state gauges at zero so a configured peer that never
/// reaches Established is still visible on a dashboard (as "down"), rather
/// than having no series at all until its first Established/Terminated
/// event. Call once per peer, after `install` — at daemon startup for every
/// statically-configured peer, and from the dynamic-peer `AddPeer` handler,
/// before that peer's session task is spawned (so there is no session yet
/// that could have already set `session_up` to a nonzero value).
pub fn register_peer(peer: IpAddr) {
    let p = peer.to_string();
    metrics::gauge!("pathvectord_bgp_session_up", "peer" => p.clone()).set(0.0_f64);
    metrics::gauge!("pathvectord_bgp_adj_rib_in_prefixes", "peer" => p.clone()).set(0.0_f64);
    metrics::gauge!("pathvectord_bgp_adj_rib_out_prefixes", "peer" => p).set(0.0_f64);
}

pub fn on_update_sent(peer: IpAddr) {
    metrics::counter!("pathvectord_bgp_updates_sent_total", "peer" => peer.to_string())
        .increment(1);
}

pub fn on_session_established(peer: IpAddr) {
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

pub fn on_session_terminated(peer: IpAddr, reason: &TerminationReason) {
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
pub fn on_route_update(peer: IpAddr, adj_rib_in: usize) {
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
    prefixes_advertised: &HashMap<IpAddr, usize>,
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

/// Update the self-originated route count after an origination or withdrawal
/// batch. Call with the current `.len()` of `rib.originated_routes` /
/// `rib.originated_routes_v6` — always an absolute `set()`, not a delta, since
/// the exact count is already known at every call site in
/// `daemon/origination.rs`. Also pre-set to `(0, 0)` at daemon startup
/// (alongside `update_rib_sizes(0, 0, &HashMap::new())`) so a daemon that has
/// originated nothing shows a real `0`, not a missing series.
#[allow(clippy::cast_precision_loss)]
pub fn update_originated_routes(originated_v4: usize, originated_v6: usize) {
    metrics::gauge!("pathvectord_bgp_originated_routes", "afi" => "ipv4").set(originated_v4 as f64);
    metrics::gauge!("pathvectord_bgp_originated_routes", "afi" => "ipv6").set(originated_v6 as f64);
}

/// Kernel FIB write operation, used only to label
/// `pathvectord_bgp_fib_write_failures_total` and to select the sign of the
/// `pathvectord_bgp_fib_routes_installed` adjustment in `on_fib_write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FibOp {
    Install,
    Blackhole,
    Withdraw,
    WithdrawBlackhole,
}

impl FibOp {
    fn label(self) -> &'static str {
        match self {
            FibOp::Install => "install",
            FibOp::Blackhole => "blackhole",
            FibOp::Withdraw => "withdraw",
            FibOp::WithdrawBlackhole => "withdraw_blackhole",
        }
    }

    /// +1 for routes that add a kernel FIB entry, -1 for routes that remove one.
    fn gauge_delta(self) -> f64 {
        match self {
            FibOp::Install | FibOp::Blackhole => 1.0,
            FibOp::Withdraw | FibOp::WithdrawBlackhole => -1.0,
        }
    }
}

/// Records the outcome of one kernel FIB write from `fib::process_batch`.
///
/// On success, adjusts `pathvectord_bgp_fib_routes_installed{afi}` by +1
/// (install/blackhole) or -1 (withdraw/withdraw_blackhole) — this gauge
/// tracks actual kernel FIB state, as opposed to `loc_rib_prefixes`, which
/// tracks intended state; persistent divergence between the two is itself a
/// meaningful signal (the kernel is not converging with Loc-RIB). On failure,
/// increments `pathvectord_bgp_fib_write_failures_total{afi, op}` and leaves
/// the gauge untouched — nothing actually changed in the kernel.
#[allow(clippy::cast_precision_loss)]
pub fn on_fib_write(afi: &'static str, op: FibOp, success: bool) {
    if success {
        metrics::gauge!("pathvectord_bgp_fib_routes_installed", "afi" => afi)
            .increment(op.gauge_delta());
    } else {
        metrics::counter!(
            "pathvectord_bgp_fib_write_failures_total",
            "afi" => afi,
            "op" => op.label()
        )
        .increment(1);
    }
}

#[cfg(test)]
mod tests {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;

    fn peer(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n))
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

    #[test]
    fn register_peer_creates_zeroed_gauges_for_a_peer_with_no_prior_events() {
        let snap = capture(|| register_peer(peer(3)));

        let labels = vec![("peer".to_string(), "10.0.0.3".to_string())];
        assert_eq!(
            snap.get(&("pathvectord_bgp_session_up".to_string(), labels.clone())),
            Some(&DebugValue::Gauge(0.0.into())),
            "a configured-but-never-established peer must show as down, not be absent"
        );
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_adj_rib_in_prefixes".to_string(),
                labels.clone()
            )),
            Some(&DebugValue::Gauge(0.0.into()))
        );
        assert_eq!(
            snap.get(&("pathvectord_bgp_adj_rib_out_prefixes".to_string(), labels)),
            Some(&DebugValue::Gauge(0.0.into()))
        );
    }

    #[test]
    fn on_update_sent_increments_counter_once_per_call() {
        let snap = capture(|| {
            on_update_sent(peer(4));
            on_update_sent(peer(4));
            on_update_sent(peer(4));
        });

        let labels = vec![("peer".to_string(), "10.0.0.4".to_string())];
        assert_eq!(
            snap.get(&("pathvectord_bgp_updates_sent_total".to_string(), labels)),
            Some(&DebugValue::Counter(3))
        );
    }

    #[test]
    fn update_originated_routes_sets_both_afi_gauges() {
        let snap = capture(|| update_originated_routes(3, 1));

        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_originated_routes".to_string(),
                vec![("afi".to_string(), "ipv4".to_string())]
            )),
            Some(&DebugValue::Gauge(3.0.into()))
        );
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_originated_routes".to_string(),
                vec![("afi".to_string(), "ipv6".to_string())]
            )),
            Some(&DebugValue::Gauge(1.0.into()))
        );
    }

    #[test]
    fn update_originated_routes_reflects_latest_value_not_a_sum() {
        let snap = capture(|| {
            update_originated_routes(5, 5);
            update_originated_routes(2, 0);
        });
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_originated_routes".to_string(),
                vec![("afi".to_string(), "ipv4".to_string())]
            )),
            Some(&DebugValue::Gauge(2.0.into())),
            "gauge must reflect the most recent set(), not accumulate"
        );
    }

    #[test]
    fn on_fib_write_success_increments_routes_installed_gauge() {
        let snap = capture(|| on_fib_write("ipv4", FibOp::Install, true));
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_fib_routes_installed".to_string(),
                vec![("afi".to_string(), "ipv4".to_string())]
            )),
            Some(&DebugValue::Gauge(1.0.into()))
        );
        assert!(
            !snap.contains_key(&(
                "pathvectord_bgp_fib_write_failures_total".to_string(),
                vec![
                    ("afi".to_string(), "ipv4".to_string()),
                    ("op".to_string(), "install".to_string())
                ]
            )),
            "a success must not create a failure-counter series"
        );
    }

    #[test]
    fn on_fib_write_failure_increments_failure_counter_not_gauge() {
        let snap = capture(|| on_fib_write("ipv6", FibOp::Withdraw, false));
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_fib_write_failures_total".to_string(),
                vec![
                    ("afi".to_string(), "ipv6".to_string()),
                    ("op".to_string(), "withdraw".to_string())
                ]
            )),
            Some(&DebugValue::Counter(1))
        );
        assert!(
            !snap.contains_key(&(
                "pathvectord_bgp_fib_routes_installed".to_string(),
                vec![("afi".to_string(), "ipv6".to_string())]
            )),
            "a failure must not move the routes-installed gauge — nothing changed in the kernel"
        );
    }

    #[test]
    fn on_fib_write_withdraw_success_decrements_routes_installed_gauge() {
        let snap = capture(|| {
            on_fib_write("ipv4", FibOp::Install, true);
            on_fib_write("ipv4", FibOp::Install, true);
            on_fib_write("ipv4", FibOp::Withdraw, true);
        });
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_fib_routes_installed".to_string(),
                vec![("afi".to_string(), "ipv4".to_string())]
            )),
            Some(&DebugValue::Gauge(1.0.into())),
            "2 installs then 1 withdraw must net to 1"
        );
    }

    #[test]
    fn on_fib_write_blackhole_ops_use_the_blackhole_label() {
        let snap = capture(|| on_fib_write("ipv4", FibOp::Blackhole, false));
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_fib_write_failures_total".to_string(),
                vec![
                    ("afi".to_string(), "ipv4".to_string()),
                    ("op".to_string(), "blackhole".to_string())
                ]
            )),
            Some(&DebugValue::Counter(1))
        );
    }

    #[test]
    fn on_fib_write_withdraw_blackhole_ops_use_the_withdraw_blackhole_label() {
        let snap = capture(|| on_fib_write("ipv6", FibOp::WithdrawBlackhole, false));
        assert_eq!(
            snap.get(&(
                "pathvectord_bgp_fib_write_failures_total".to_string(),
                vec![
                    ("afi".to_string(), "ipv6".to_string()),
                    ("op".to_string(), "withdraw_blackhole".to_string())
                ]
            )),
            Some(&DebugValue::Counter(1))
        );
    }
}
