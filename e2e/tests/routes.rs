//! End-to-end tests for route import, withdrawal, and import policy.
//!
//! RFC 4271 §9.2 — route advertisement and withdrawal.
//! RFC 8212        — eBGP import/export default reject.
//! Scenarios covered:
//!   - GoBGP announces a prefix → appears in pathvectord's Loc-RIB
//!   - GoBGP withdraws a prefix → removed from pathvectord's Loc-RIB
//!   - Multiple prefixes announced simultaneously
//!   - Import-reject policy: prefix is NOT installed despite being received

use std::time::Duration;

use pathvector_client::{
    DaemonClient,
    types::{Origin, PeerType},
};
use pathvector_e2e::{Harness, wait_for_route, wait_for_route_withdrawn};

/// RFC 4271 §9.2 — a route announced by GoBGP must appear in the Loc-RIB and
/// be returned by get_best_route.
#[tokio::test]
async fn announced_route_appears_in_rib() {
    let mut h = Harness::new().await;

    h.gobgp_announce("10.0.0.0/8", "10.0.0.1");
    let route = wait_for_route(&mut h.client, "10.0.0.0/8", Duration::from_secs(10))
        .await
        .expect("10.0.0.0/8 did not appear in RIB within 10 s");

    assert_eq!(route.prefix, "10.0.0.0/8");
    assert_eq!(route.peer_address, Some(std::net::IpAddr::V4(h.peer)));
    assert_eq!(route.peer_type, PeerType::External);
    assert_eq!(route.origin, Origin::Igp);
}

/// RFC 4271 §9.3 — withdrawing a route must remove it from the Loc-RIB.
#[tokio::test]
async fn withdrawn_route_removed_from_rib() {
    let mut h = Harness::new().await;

    h.gobgp_announce("192.168.0.0/16", "10.0.0.1");
    wait_for_route(&mut h.client, "192.168.0.0/16", Duration::from_secs(10))
        .await
        .expect("192.168.0.0/16 did not appear in RIB within 10 s");

    h.gobgp_withdraw("192.168.0.0/16");
    wait_for_route_withdrawn(&mut h.client, "192.168.0.0/16", Duration::from_secs(10))
        .await
        .expect("192.168.0.0/16 was not withdrawn from RIB within 10 s");
}

/// Multiple prefixes announced in sequence must all appear in the RIB.
#[tokio::test]
async fn multiple_routes_all_installed() {
    let mut h = Harness::new().await;

    let prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
    for prefix in prefixes {
        h.gobgp_announce(prefix, "10.0.0.1");
    }

    for prefix in prefixes {
        let route = wait_for_route(&mut h.client, prefix, Duration::from_secs(10))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(route.prefix, prefix);
    }

    let all_routes = h.client.list_routes(None).await.unwrap();
    assert_eq!(
        all_routes.len(),
        prefixes.len(),
        "list_routes should return all installed routes"
    );
}

/// Withdraw of one prefix must not disturb others.
#[tokio::test]
async fn partial_withdrawal_leaves_others_intact() {
    let mut h = Harness::new().await;

    h.gobgp_announce("10.0.0.0/8", "10.0.0.1");
    h.gobgp_announce("172.16.0.0/12", "10.0.0.1");
    wait_for_route(&mut h.client, "10.0.0.0/8", Duration::from_secs(10))
        .await
        .expect("10.0.0.0/8 did not appear in RIB within 10 s");
    wait_for_route(&mut h.client, "172.16.0.0/12", Duration::from_secs(10))
        .await
        .expect("172.16.0.0/12 did not appear in RIB within 10 s");

    h.gobgp_withdraw("10.0.0.0/8");
    wait_for_route_withdrawn(&mut h.client, "10.0.0.0/8", Duration::from_secs(10))
        .await
        .expect("10.0.0.0/8 was not withdrawn from RIB within 10 s");

    // 172.16.0.0/12 must still be present.
    let remaining = h.client.get_best_route("172.16.0.0/12").await.unwrap();
    assert!(
        remaining.is_some(),
        "172.16.0.0/12 must survive the 10.0.0.0/8 withdrawal"
    );
}

/// list_candidates returns all candidate routes for a prefix (just the one
/// peer in this topology, so length == 1).
#[tokio::test]
async fn list_candidates_returns_peer_route() {
    let mut h = Harness::new().await;

    h.gobgp_announce("203.0.113.0/24", "10.0.0.1");
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(10))
        .await
        .expect("203.0.113.0/24 did not appear in RIB within 10 s");

    let candidates = h.client.list_candidates("203.0.113.0/24").await.unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].prefix, "203.0.113.0/24");
}

/// get_best_route for an unknown prefix returns None.
#[tokio::test]
async fn unknown_prefix_returns_none() {
    let h = Harness::new().await;
    let result = h
        .client
        .clone()
        .get_best_route("198.51.100.0/24")
        .await
        .unwrap();
    assert!(
        result.is_none(),
        "no route should exist for a never-announced prefix"
    );
}
