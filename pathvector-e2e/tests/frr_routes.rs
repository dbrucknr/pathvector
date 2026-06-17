//! End-to-end route exchange tests against FRRouting (FRR).
//!
//! Two directions tested:
//!  - FRR → pathvectord: routes pre-configured in FRR appear in the
//!    pathvectord Loc-RIB after the session establishes.
//!  - pathvectord → FRR: a route originated via the gRPC API reaches FRR's
//!    RIB, confirmed by polling `vtysh show bgp ipv4 unicast`.
//!
//! These tests mirror the canonical interop suite implemented for BIRD and
//! GoBGP.  FRR's stricter NEXT_HOP validation and attribute enforcement
//! catches bugs that GoBGP's lenient parser would hide.

use std::time::Duration;

use pathvector_client::types::{Origin, OriginateRouteParams};
use pathvector_e2e::{FrrHarness, get_frr_next_hop, wait_for_frr_rib_entry, wait_for_route};

/// A static route pre-announced by FRR must appear in pathvectord's Loc-RIB.
///
/// Validates the full inbound path: FRR UPDATE → pathvectord codec →
/// AdjRibIn → import policy → LocRib.
#[tokio::test]
async fn frr_static_route_appears_in_pathvectord_rib() {
    let mut h = FrrHarness::with_routes(&["10.200.0.0/24"]).await;

    wait_for_route(&mut h.client, "10.200.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.200.0.0/24 from FRR did not appear in pathvectord Loc-RIB");
}

/// Multiple static routes pre-announced by FRR all arrive in pathvectord.
#[tokio::test]
async fn frr_multiple_static_routes_appear_in_pathvectord_rib() {
    let mut h = FrrHarness::with_routes(&["10.201.0.0/24", "10.202.0.0/24", "10.203.0.0/24"]).await;

    for prefix in ["10.201.0.0/24", "10.202.0.0/24", "10.203.0.0/24"] {
        wait_for_route(&mut h.client, prefix, Duration::from_secs(15))
            .await
            .unwrap_or_else(|_| panic!("{prefix} from FRR did not appear in pathvectord Loc-RIB"));
    }
}

/// A route originated by pathvectord via gRPC must reach FRR's RIB.
///
/// Validates the full outbound path: OriginationService → LocRib →
/// AdjRibOut → export policy → UPDATE sent to FRR → FRR RIB.
#[tokio::test]
async fn pathvectord_originated_route_reaches_frr() {
    let mut h = FrrHarness::new().await;

    h.client
        .originate_route(OriginateRouteParams {
            prefix: "203.0.115.0/24".to_owned(),
            next_hop: "10.0.0.1".parse().unwrap(),
            origin: Origin::Igp,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        })
        .await
        .expect("originate_route failed");

    wait_for_frr_rib_entry(&h.frr_id, "203.0.115.0/24", Duration::from_secs(15))
        .await
        .expect("203.0.115.0/24 originated by pathvectord did not appear in FRR RIB");
}

/// RFC 4271 §5.1.3 regression: the eBGP NEXT_HOP pathvectord advertises to
/// FRR must be the TCP session's local interface address, not the BGP router
/// ID (`bgp_id = "10.0.0.2"`).
///
/// FRR validates §5.1.3 and would reject the route if the NEXT_HOP is not
/// reachable on the session interface.  This test asserts the exact NEXT_HOP
/// value that FRR stores, giving certainty the fix is in place end-to-end.
#[tokio::test]
async fn pathvectord_ebgp_next_hop_is_session_local_addr_not_router_id() {
    let mut h = FrrHarness::new().await;

    h.client
        .originate_route(OriginateRouteParams {
            prefix: "203.0.116.0/24".to_owned(),
            next_hop: "10.0.0.1".parse().unwrap(),
            origin: Origin::Igp,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        })
        .await
        .expect("originate_route failed");

    wait_for_frr_rib_entry(&h.frr_id, "203.0.116.0/24", Duration::from_secs(15))
        .await
        .expect("203.0.116.0/24 did not appear in FRR RIB");

    let next_hop = get_frr_next_hop(&h.frr_id, "203.0.116.0/24")
        .expect("NEXT_HOP not found in vtysh show bgp output");

    let expected = h.pathvectord_ip;
    assert_eq!(
        next_hop, expected,
        "eBGP NEXT_HOP must be the session local address ({expected}), not the router ID"
    );
}

/// The route received from FRR must carry the correct peer address.
#[tokio::test]
async fn frr_route_has_correct_peer_address() {
    let mut h = FrrHarness::with_routes(&["10.204.0.0/24"]).await;

    let route = wait_for_route(&mut h.client, "10.204.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.204.0.0/24 from FRR did not appear in pathvectord Loc-RIB");

    assert_eq!(
        route.peer_address,
        Some(h.frr_ip.into()),
        "route must be attributed to FRR's IP"
    );
}
