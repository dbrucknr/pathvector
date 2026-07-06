//! End-to-end tests for the Prometheus `/metrics` endpoint.
//!
//! Unit tests in `pathvectord/src/metrics.rs` prove that each instrumentation
//! function (`on_session_established`, `on_route_update`, etc.) emits the
//! correct metric values in isolation. They do **not** prove those functions
//! are actually called from the right places in `daemon/mod.rs`'s event loop.
//! These e2e tests close that gap: they stand up a real pathvectord + GoBGP
//! session, scrape the real HTTP endpoint, and assert the rendered Prometheus
//! text reflects real session and RIB state.

use std::time::Duration;

use pathvector_client::types::{Origin, OriginateRouteParams};
use pathvector_e2e::{MetricsHarness, scrape_metrics_text, wait_for_metric, wait_for_route};

fn basic_originate_params(prefix: &str) -> OriginateRouteParams {
    OriginateRouteParams {
        prefix: prefix.to_owned(),
        next_hop: "10.0.0.1".parse().unwrap(),
        origin: Origin::Igp,
        communities: vec![],
        large_communities: vec![],
        extended_communities: vec![],
        local_pref: None,
        med: None,
    }
}

/// After a session reaches Established, `/metrics` must report
/// `pathvectord_bgp_session_up{peer="..."} 1` — proving
/// `on_session_established` is wired into the real event loop, not just
/// covered by unit tests.
#[tokio::test]
async fn session_up_gauge_reflects_established_session() {
    let h = MetricsHarness::new().await;

    let expected = format!("pathvectord_bgp_session_up{{peer=\"{}\"}} 1", h.gobgp_ip);
    wait_for_metric(h.metrics_host_port, &expected, Duration::from_secs(10)).await;
}

/// The established-session counter and timestamp gauge must both appear
/// alongside `session_up`.
#[tokio::test]
async fn established_counter_and_timestamp_present() {
    let h = MetricsHarness::new().await;

    let body = scrape_metrics_text(h.metrics_host_port);
    let peer_label = format!("peer=\"{}\"", h.gobgp_ip);

    assert!(
        body.contains("pathvectord_bgp_sessions_established_total") && body.contains(&peer_label),
        "established counter missing for peer {}\nfull body:\n{body}",
        h.gobgp_ip
    );
    assert!(
        body.contains("pathvectord_bgp_session_established_timestamp_seconds"),
        "established timestamp gauge missing\nfull body:\n{body}"
    );
}

/// After GoBGP announces a route, `adj_rib_in_prefixes` must reflect the
/// updated count and `updates_received_total` must have incremented — proving
/// `on_route_update`'s metrics hook fires on the real UPDATE path.
#[tokio::test]
async fn adj_rib_in_gauge_updates_after_route_announce() {
    let h = MetricsHarness::new().await;

    // No baseline-absence check here: GoBGP's config (`write_gobgp_config`)
    // enables RFC 4724 graceful-restart, so it sends an End-of-RIB marker
    // (an empty UPDATE) immediately after Established, independent of
    // whether pathvectord negotiates GR itself. That EOR still flows through
    // `on_route_update` in the event loop, which unconditionally calls the
    // metrics hook and materializes `adj_rib_in_prefixes{peer}` at 0 — before
    // any real route exists. Asserting the series is *absent* pre-announce is
    // therefore a race against EOR delivery timing (this flaked on the CI
    // runner's scheduling while passing locally). The invariant that actually
    // matters — and is deterministic — is the transition to `1` below.

    h.gobgp_announce("10.200.0.0/24", &h.gobgp_ip.to_string());

    // Confirm the route landed in the Loc-RIB via gRPC first, so we know BGP
    // processing (not just the metrics call) has actually completed.
    let mut client = h.client.clone();
    wait_for_route(&mut client, "10.200.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.200.0.0/24 did not appear in Loc-RIB within 15 s");

    let expected_one = format!(
        "pathvectord_bgp_adj_rib_in_prefixes{{peer=\"{}\"}} 1",
        h.gobgp_ip
    );
    wait_for_metric(h.metrics_host_port, &expected_one, Duration::from_secs(10)).await;

    let body = scrape_metrics_text(h.metrics_host_port);
    let peer_label = format!("peer=\"{}\"", h.gobgp_ip);
    assert!(
        body.contains("pathvectord_bgp_updates_received_total") && body.contains(&peer_label),
        "updates_received_total counter missing for peer {}\nfull body:\n{body}",
        h.gobgp_ip
    );
}

/// `loc_rib_prefixes{afi="ipv4"}` must reflect the Loc-RIB size after a route
/// is accepted — proving `update_rib_sizes` fires from the real flush path
/// (called after `flush_pending()` in the event loop), not just in unit tests.
#[tokio::test]
async fn loc_rib_gauge_reflects_accepted_route() {
    let h = MetricsHarness::new().await;

    h.gobgp_announce("10.201.0.0/24", &h.gobgp_ip.to_string());

    let mut client = h.client.clone();
    wait_for_route(&mut client, "10.201.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.201.0.0/24 did not appear in Loc-RIB within 15 s");

    wait_for_metric(
        h.metrics_host_port,
        "pathvectord_bgp_loc_rib_prefixes{afi=\"ipv4\"} 1",
        Duration::from_secs(10),
    )
    .await;
}

// ── Originated-routes gauge ──────────────────────────────────────────────────

/// `pathvectord_bgp_originated_routes{afi="ipv4"}` must track the real
/// self-originated route count as `OriginateRoute`/`WithdrawOriginatedRoute`
/// gRPC calls land — proving `update_originated_routes` is wired into the
/// real `origination.rs` call sites, not just correct in isolation (covered
/// by unit tests in `metrics.rs` and `origination.rs`).
#[tokio::test]
async fn originated_routes_gauge_tracks_originate_and_withdraw() {
    let mut h = MetricsHarness::new().await;

    // Daemon has originated nothing yet: gauge must read a real 0, not be
    // absent, per the startup pre-set in `daemon/mod.rs`.
    wait_for_metric(
        h.metrics_host_port,
        "pathvectord_bgp_originated_routes{afi=\"ipv4\"} 0",
        Duration::from_secs(10),
    )
    .await;

    h.client
        .originate_route(basic_originate_params("198.51.100.0/24"))
        .await
        .expect("originate_route failed");

    wait_for_metric(
        h.metrics_host_port,
        "pathvectord_bgp_originated_routes{afi=\"ipv4\"} 1",
        Duration::from_secs(10),
    )
    .await;

    h.client
        .withdraw_originated_route("198.51.100.0/24")
        .await
        .expect("withdraw_originated_route failed");

    wait_for_metric(
        h.metrics_host_port,
        "pathvectord_bgp_originated_routes{afi=\"ipv4\"} 0",
        Duration::from_secs(10),
    )
    .await;
}
