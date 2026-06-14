//! End-to-end route exchange tests against BIRD 2.
//!
//! Two directions tested:
//!  - BIRD → pathvectord: static routes pre-configured in BIRD appear in the
//!    pathvectord Loc-RIB after the session establishes.
//!  - pathvectord → BIRD: a route originated via the gRPC API reaches BIRD's
//!    RIB, confirmed by polling `birdc show route`.
//!
//! These tests mirror the GoBGP route tests in `routes.rs` and `origination.rs`
//! so that any regression that BIRD catches but GoBGP accepts is immediately
//! visible.

use std::time::Duration;

use pathvector_client::types::{Origin, OriginateRouteParams};
use pathvector_e2e::{BirdHarness, get_bird_next_hop, wait_for_bird_rib_entry, wait_for_route};

/// A static route pre-announced by BIRD must appear in pathvectord's Loc-RIB.
///
/// Validates the full inbound path: BIRD UPDATE → pathvectord codec →
/// AdjRibIn → import policy → LocRib.
#[tokio::test]
async fn bird_static_route_appears_in_pathvectord_rib() {
    let mut h = BirdHarness::with_routes(&["10.100.0.0/24"]).await;

    wait_for_route(&mut h.client, "10.100.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.100.0.0/24 from BIRD did not appear in pathvectord Loc-RIB");
}

/// Multiple static routes pre-announced by BIRD all arrive in pathvectord.
#[tokio::test]
async fn bird_multiple_static_routes_appear_in_pathvectord_rib() {
    let mut h =
        BirdHarness::with_routes(&["10.101.0.0/24", "10.102.0.0/24", "10.103.0.0/24"]).await;

    for prefix in ["10.101.0.0/24", "10.102.0.0/24", "10.103.0.0/24"] {
        wait_for_route(&mut h.client, prefix, Duration::from_secs(15))
            .await
            .unwrap_or_else(|_| panic!("{prefix} from BIRD did not appear in pathvectord Loc-RIB"));
    }
}

/// A route originated by pathvectord via gRPC must reach BIRD's RIB.
///
/// Validates the full outbound path: OriginationService → LocRib →
/// AdjRibOut → export policy → UPDATE sent to BIRD → BIRD RIB.
#[tokio::test]
async fn pathvectord_originated_route_reaches_bird() {
    let mut h = BirdHarness::new().await;

    h.client
        .originate_route(OriginateRouteParams {
            prefix: "203.0.113.0/24".to_owned(),
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

    wait_for_bird_rib_entry(&h.bird_id, "203.0.113.0/24", Duration::from_secs(15))
        .await
        .expect("203.0.113.0/24 originated by pathvectord did not appear in BIRD RIB");
}

/// RFC 4271 §5.1.3 regression: the eBGP NEXT_HOP that pathvectord advertises
/// to BIRD must be the TCP session's local interface address, not the BGP
/// router ID (`bgp_id = "10.0.0.2"`).
///
/// BIRD 2 validates §5.1.3 and would silently discard the route if the
/// NEXT_HOP is unreachable on the session interface.  This test goes one step
/// further than `pathvectord_originated_route_reaches_bird`: it parses the
/// `BGP.next_hop` attribute from `birdc show route all` and asserts the exact
/// IP value, giving certainty that the fix is in place end-to-end.
#[tokio::test]
async fn pathvectord_ebgp_next_hop_is_session_local_addr_not_router_id() {
    let mut h = BirdHarness::new().await;

    h.client
        .originate_route(OriginateRouteParams {
            prefix: "203.0.114.0/24".to_owned(),
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

    wait_for_bird_rib_entry(&h.bird_id, "203.0.114.0/24", Duration::from_secs(15))
        .await
        .expect("203.0.114.0/24 did not appear in BIRD RIB");

    let next_hop = get_bird_next_hop(&h.bird_id, "203.0.114.0/24")
        .expect("BGP.next_hop not found in birdc show route all output");

    let expected = h.pathvectord_ip;
    assert_eq!(
        next_hop, expected,
        "eBGP NEXT_HOP must be the session local address ({expected}), not the router ID"
    );
}

/// The route received from BIRD must carry the correct peer address.
#[tokio::test]
async fn bird_route_has_correct_peer_address() {
    let mut h = BirdHarness::with_routes(&["10.104.0.0/24"]).await;

    let route = wait_for_route(&mut h.client, "10.104.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.104.0.0/24 from BIRD did not appear in pathvectord Loc-RIB");

    assert_eq!(
        route.peer_address,
        Some(h.bird_ip.into()),
        "route must be attributed to BIRD's IP"
    );
}
