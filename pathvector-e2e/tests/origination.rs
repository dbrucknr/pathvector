//! End-to-end tests for the route origination API (OriginationService).
//!
//! RFC 4271 §9.1 — locally originated routes are injected directly into the
//! Loc-RIB and propagated to established peers via normal export policy.
//! Scenarios covered:
//!   - Originated route appears in pathvectord's Loc-RIB
//!   - Originated route is propagated to a GoBGP peer
//!   - Withdrawn originated route is removed from Loc-RIB and from the peer's RIB
//!   - Batch origination: all prefixes propagate in a single pass
//!   - list_originated_routes reflects the current originated set
//!   - Re-originating the same prefix (idempotent update) replaces attributes

use std::{net::IpAddr, time::Duration};

use pathvector_client::{
    DaemonClient,
    types::{Origin, OriginateRouteParams},
};
use pathvector_e2e::{
    Harness, wait_for_gobgp_rib_entry, wait_for_gobgp_rib_withdrawn, wait_for_route,
    wait_for_route_withdrawn,
};

fn basic_params(prefix: &str) -> OriginateRouteParams {
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

/// An originated route must appear immediately in pathvectord's own Loc-RIB.
#[tokio::test]
async fn originated_route_appears_in_rib() {
    let mut h = Harness::new().await;

    h.client
        .originate_route(basic_params("198.51.100.0/24"))
        .await
        .expect("originate_route failed");

    let route = wait_for_route(&mut h.client, "198.51.100.0/24", Duration::from_secs(5))
        .await
        .expect("198.51.100.0/24 did not appear in Loc-RIB");

    assert_eq!(route.prefix, "198.51.100.0/24");
    assert_eq!(route.peer_address, None); // "local" sentinel → None
    assert_eq!(route.origin, Origin::Igp);
}

/// An originated route must be advertised to the established GoBGP peer.
#[tokio::test]
async fn originated_route_propagates_to_gobgp() {
    let mut h = Harness::new().await;

    h.client
        .originate_route(basic_params("203.0.113.0/24"))
        .await
        .expect("originate_route failed");

    wait_for_gobgp_rib_entry(&h.gobgpd_id, "203.0.113.0/24", Duration::from_secs(10))
        .await
        .expect("203.0.113.0/24 did not appear in GoBGP RIB within 10 s");
}

/// Withdrawing an originated route must remove it from the Loc-RIB.
#[tokio::test]
async fn withdrawn_originated_route_removed_from_rib() {
    let mut h = Harness::new().await;

    h.client
        .originate_route(basic_params("192.0.2.0/24"))
        .await
        .expect("originate_route failed");
    wait_for_route(&mut h.client, "192.0.2.0/24", Duration::from_secs(5))
        .await
        .expect("192.0.2.0/24 did not appear in Loc-RIB before withdrawal test");

    h.client
        .withdraw_originated_route("192.0.2.0/24")
        .await
        .expect("withdraw_originated_route failed");

    wait_for_route_withdrawn(&mut h.client, "192.0.2.0/24", Duration::from_secs(5))
        .await
        .expect("192.0.2.0/24 was not removed from Loc-RIB after withdrawal");
}

/// Withdrawing an originated route must remove it from the GoBGP peer's RIB.
#[tokio::test]
async fn withdrawn_originated_route_removed_from_gobgp() {
    let mut h = Harness::new().await;

    h.client
        .originate_route(basic_params("198.51.100.128/25"))
        .await
        .expect("originate_route failed");
    wait_for_gobgp_rib_entry(&h.gobgpd_id, "198.51.100.128/25", Duration::from_secs(10))
        .await
        .expect("198.51.100.128/25 did not appear in GoBGP RIB before withdrawal test");

    h.client
        .withdraw_originated_route("198.51.100.128/25")
        .await
        .expect("withdraw_originated_route failed");

    wait_for_gobgp_rib_withdrawn(&h.gobgpd_id, "198.51.100.128/25", Duration::from_secs(10))
        .await
        .expect("198.51.100.128/25 was not withdrawn from GoBGP RIB within 10 s");
}

/// Batch origination: all prefixes in a single OriginateRoutes call must
/// appear in both the Loc-RIB and the GoBGP peer's RIB.
#[tokio::test]
async fn batch_originate_all_propagate() {
    let mut h = Harness::new().await;

    let prefixes = [
        "10.10.0.0/24",
        "10.10.1.0/24",
        "10.10.2.0/24",
        "10.10.3.0/24",
        "10.10.4.0/24",
    ];

    h.client
        .originate_routes(prefixes.iter().map(|p| basic_params(p)).collect())
        .await
        .expect("originate_routes failed");

    for prefix in prefixes {
        wait_for_gobgp_rib_entry(&h.gobgpd_id, prefix, Duration::from_secs(10))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }

    let listed = h
        .client
        .list_originated_routes()
        .await
        .expect("list_originated_routes failed");
    assert_eq!(listed.len(), prefixes.len());
}

/// list_originated_routes must reflect the current originated set:
/// prefixes appear after origination and disappear after withdrawal.
#[tokio::test]
async fn list_originated_routes_tracks_state() {
    let mut h = Harness::new().await;

    let empty = h
        .client
        .list_originated_routes()
        .await
        .expect("list_originated_routes failed");
    assert!(
        empty.is_empty(),
        "expected empty list before any origination"
    );

    h.client
        .originate_route(basic_params("10.20.0.0/24"))
        .await
        .expect("originate_route failed");
    h.client
        .originate_route(basic_params("10.20.1.0/24"))
        .await
        .expect("originate_route failed");

    let after_originate = h
        .client
        .list_originated_routes()
        .await
        .expect("list_originated_routes failed");
    assert_eq!(after_originate.len(), 2);
    let prefixes: Vec<&str> = after_originate.iter().map(|r| r.prefix.as_str()).collect();
    assert!(prefixes.contains(&"10.20.0.0/24"));
    assert!(prefixes.contains(&"10.20.1.0/24"));

    h.client
        .withdraw_originated_route("10.20.0.0/24")
        .await
        .expect("withdraw_originated_route failed");

    let after_withdraw = h
        .client
        .list_originated_routes()
        .await
        .expect("list_originated_routes failed");
    assert_eq!(after_withdraw.len(), 1);
    assert_eq!(after_withdraw[0].prefix, "10.20.1.0/24");
}

/// Re-originating the same prefix replaces the previous route (idempotent
/// upsert). The updated route must reach GoBGP.
#[tokio::test]
async fn re_originate_same_prefix_replaces_route() {
    let mut h = Harness::new().await;

    h.client
        .originate_route(basic_params("10.30.0.0/24"))
        .await
        .expect("first originate failed");
    wait_for_gobgp_rib_entry(&h.gobgpd_id, "10.30.0.0/24", Duration::from_secs(10))
        .await
        .expect("initial route did not appear in GoBGP");

    // Re-originate with EGP origin.
    let mut updated = basic_params("10.30.0.0/24");
    updated.origin = Origin::Egp;
    h.client
        .originate_route(updated)
        .await
        .expect("second originate failed");

    // The route remains in the Loc-RIB (not a withdrawal + re-add gap).
    let route = wait_for_route(&mut h.client, "10.30.0.0/24", Duration::from_secs(5))
        .await
        .expect("route disappeared after re-origination");
    assert_eq!(route.origin, Origin::Egp);

    // Only one entry in list_originated_routes (upsert, not duplicate).
    let listed = h
        .client
        .list_originated_routes()
        .await
        .expect("list_originated_routes failed");
    assert_eq!(listed.len(), 1);

    // Verify peer_address is the "local" sentinel.
    assert_eq!(
        route.peer_address, None,
        "originated route should have no peer (local origin)"
    );
}

/// An originated route carries the communities it was created with.
#[tokio::test]
async fn originated_route_has_correct_attributes() {
    let mut h = Harness::new().await;

    let params = OriginateRouteParams {
        prefix: "10.40.0.0/24".to_owned(),
        next_hop: "10.0.0.1".parse().unwrap(),
        origin: Origin::Incomplete,
        communities: vec![0x0000_FFF1],
        large_communities: vec![],
        extended_communities: vec![],
        local_pref: Some(150),
        med: Some(100),
    };
    h.client
        .originate_route(params)
        .await
        .expect("originate_route failed");

    let route = wait_for_route(&mut h.client, "10.40.0.0/24", Duration::from_secs(5))
        .await
        .expect("10.40.0.0/24 did not appear in Loc-RIB");

    assert_eq!(route.origin, Origin::Incomplete);
    assert!(
        route.communities.contains(&0x0000_FFF1),
        "community 0x0000FFF1 should be present"
    );

    // local_pref and med are stored; eBGP strips local_pref on the wire but
    // it is visible in the Loc-RIB via gRPC.
    assert_eq!(route.local_pref, Some(150));
    assert_eq!(route.med, Some(100));
}

/// Withdraw-then-re-originate cycle: route must reappear in the peer's RIB.
#[tokio::test]
async fn withdraw_then_reoriginate_reappears_in_gobgp() {
    let mut h = Harness::new().await;

    h.client
        .originate_route(basic_params("10.50.0.0/24"))
        .await
        .expect("originate failed");
    wait_for_gobgp_rib_entry(&h.gobgpd_id, "10.50.0.0/24", Duration::from_secs(10))
        .await
        .expect("initial route did not reach GoBGP");

    h.client
        .withdraw_originated_route("10.50.0.0/24")
        .await
        .expect("withdraw failed");
    wait_for_gobgp_rib_withdrawn(&h.gobgpd_id, "10.50.0.0/24", Duration::from_secs(10))
        .await
        .expect("route was not withdrawn from GoBGP");

    h.client
        .originate_route(basic_params("10.50.0.0/24"))
        .await
        .expect("re-originate failed");
    wait_for_gobgp_rib_entry(&h.gobgpd_id, "10.50.0.0/24", Duration::from_secs(10))
        .await
        .expect("re-originated route did not reappear in GoBGP");
}

/// Withdrawing a prefix that was never originated is a no-op (does not panic
/// or return an error).
#[tokio::test]
async fn withdraw_nonexistent_is_noop() {
    let mut h = Harness::new().await;

    h.client
        .withdraw_originated_route("10.60.0.0/24")
        .await
        .expect("withdraw of non-existent prefix should be a no-op, not an error");

    // Confirm the RIB is still empty.
    let routes = h
        .client
        .list_routes(None)
        .await
        .expect("list_routes failed");
    let originated = h
        .client
        .list_originated_routes()
        .await
        .expect("list_originated_routes failed");
    assert!(routes.is_empty());
    assert!(originated.is_empty());
}

/// Batch withdrawal removes all specified prefixes and leaves others intact.
#[tokio::test]
async fn batch_withdraw_removes_specified_prefixes() {
    let mut h = Harness::new().await;

    let all = ["10.70.0.0/24", "10.70.1.0/24", "10.70.2.0/24"];
    h.client
        .originate_routes(all.iter().map(|p| basic_params(p)).collect())
        .await
        .expect("originate_routes failed");

    for prefix in all {
        wait_for_route(&mut h.client, prefix, Duration::from_secs(5))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }

    // Withdraw the first two; keep the third.
    h.client
        .withdraw_originated_routes(vec!["10.70.0.0/24".to_owned(), "10.70.1.0/24".to_owned()])
        .await
        .expect("withdraw_originated_routes failed");

    wait_for_route_withdrawn(&mut h.client, "10.70.0.0/24", Duration::from_secs(5))
        .await
        .expect("10.70.0.0/24 was not withdrawn");
    wait_for_route_withdrawn(&mut h.client, "10.70.1.0/24", Duration::from_secs(5))
        .await
        .expect("10.70.1.0/24 was not withdrawn");

    // Third prefix must remain.
    let route = h
        .client
        .get_best_route("10.70.2.0/24")
        .await
        .expect("get_best_route failed");
    assert!(route.is_some(), "10.70.2.0/24 should still be present");

    let listed = h
        .client
        .list_originated_routes()
        .await
        .expect("list_originated_routes failed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].prefix, "10.70.2.0/24");
}

/// An originated route with the BLACKHOLE community (65535:666, RFC 7999)
/// must propagate to the peer with the community intact.
#[tokio::test]
async fn originated_route_with_blackhole_community_propagates() {
    let mut h = Harness::new().await;

    // RFC 7999: BLACKHOLE = 0xFFFF029A (65535:666)
    let params = OriginateRouteParams {
        prefix: "192.0.2.128/32".to_owned(),
        next_hop: "10.0.0.1".parse().unwrap(),
        origin: Origin::Igp,
        communities: vec![0xFFFF_029A],
        large_communities: vec![],
        extended_communities: vec![],
        local_pref: None,
        med: None,
    };
    h.client
        .originate_route(params)
        .await
        .expect("originate_route failed");

    wait_for_gobgp_rib_entry(&h.gobgpd_id, "192.0.2.128/32", Duration::from_secs(10))
        .await
        .expect("blackhole route did not appear in GoBGP RIB");

    // Verify the community survives the round-trip through the Loc-RIB API.
    let route = h
        .client
        .get_best_route("192.0.2.128/32")
        .await
        .expect("get_best_route failed")
        .expect("route should be present");
    assert!(
        route.communities.contains(&0xFFFF_029A),
        "BLACKHOLE community must survive origination → Loc-RIB"
    );
}

/// Originated routes coexist with peer-learned routes: both appear in
/// list_routes and are independent — withdrawing one does not affect the other.
#[tokio::test]
async fn originated_and_peer_routes_coexist() {
    let mut h = Harness::new().await;

    // Inject a route from GoBGP (peer-learned side).
    h.gobgp_announce("172.16.0.0/12", "10.0.0.1");
    wait_for_route(&mut h.client, "172.16.0.0/12", Duration::from_secs(10))
        .await
        .expect("peer route did not appear");

    // Originate a local route.
    h.client
        .originate_route(basic_params("10.80.0.0/24"))
        .await
        .expect("originate_route failed");
    wait_for_route(&mut h.client, "10.80.0.0/24", Duration::from_secs(5))
        .await
        .expect("originated route did not appear");

    // Both present.
    let all = h
        .client
        .list_routes(None)
        .await
        .expect("list_routes failed");
    assert_eq!(all.len(), 2);

    // Withdrawing the originated route must not disturb the peer route.
    h.client
        .withdraw_originated_route("10.80.0.0/24")
        .await
        .expect("withdraw failed");
    wait_for_route_withdrawn(&mut h.client, "10.80.0.0/24", Duration::from_secs(5))
        .await
        .expect("originated route was not withdrawn");

    let after = h
        .client
        .list_routes(None)
        .await
        .expect("list_routes failed");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].prefix, "172.16.0.0/12");

    // Peer address for the remaining route must be the GoBGP container's IP.
    assert_eq!(
        after[0].peer_address,
        Some(IpAddr::V4(h.peer)),
        "remaining route must still be attributed to the GoBGP peer"
    );
}
