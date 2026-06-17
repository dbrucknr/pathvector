//! End-to-end tests for outbound BGP advertisement (pathvectord → peer).
//!
//! RFC 4271 §9.1.3 — route advertisement to peers.
//! Topology used in every test:
//!
//! ```text
//! GoBGP-source (AS 65003) ──BGP──► pathvectord (AS 65002) ──BGP──► GoBGP-sink (AS 65001)
//! ```
//!
//! All three run as Docker containers on an isolated bridge network.
//! `source_announce` injects a route at AS 65003; `wait_for_gobgp_rib_entry`
//! polls the sink's global RIB until the prefix arrives (or times out).
//!
//! Because the AS path is `[65002, 65003]` by the time the sink sees it,
//! GoBGP (AS 65001) detects no loop and installs the route — giving us a clean
//! end-to-end signal that pathvectord forwarded the UPDATE correctly.

use std::time::Duration;

use pathvector_client::types::Origin;
use pathvector_e2e::{TwoPeerHarness, wait_for_gobgp_rib_entry, wait_for_gobgp_rib_withdrawn};

/// A route announced at the source must propagate through pathvectord and
/// appear in the sink's global RIB.
#[tokio::test]
async fn announced_route_propagates_to_sink() {
    let h = TwoPeerHarness::new().await;

    h.source_announce("10.0.0.0/8", "10.0.0.1");

    wait_for_gobgp_rib_entry(&h.sink_id, "10.0.0.0/8", Duration::from_secs(15))
        .await
        .expect("10.0.0.0/8 did not appear in GoBGP-sink's RIB within 15 s");
}

/// Multiple prefixes announced at the source must all appear in the sink's RIB.
#[tokio::test]
async fn multiple_routes_all_propagate_to_sink() {
    let h = TwoPeerHarness::new().await;

    let prefixes = ["172.16.0.0/12", "192.168.0.0/16", "10.128.0.0/9"];
    for prefix in prefixes {
        h.source_announce(prefix, "10.0.0.1");
    }

    for prefix in prefixes {
        wait_for_gobgp_rib_entry(&h.sink_id, prefix, Duration::from_secs(15))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
}

/// When the source withdraws a prefix, pathvectord must propagate the
/// withdrawal and the route must disappear from the sink's RIB.
#[tokio::test]
async fn withdrawn_route_removed_from_sink() {
    let h = TwoPeerHarness::new().await;

    h.source_announce("203.0.113.0/24", "10.0.0.1");
    wait_for_gobgp_rib_entry(&h.sink_id, "203.0.113.0/24", Duration::from_secs(15))
        .await
        .expect("203.0.113.0/24 did not appear in sink before withdrawal test");

    h.source_withdraw("203.0.113.0/24");

    wait_for_gobgp_rib_withdrawn(&h.sink_id, "203.0.113.0/24", Duration::from_secs(15))
        .await
        .expect("203.0.113.0/24 was not withdrawn from sink within 15 s");
}

/// A route announced by the source is also visible in pathvectord's own
/// Loc-RIB via the management API.  This is an invariant — if pathvectord
/// can't see the route itself it certainly can't advertise it.
#[tokio::test]
async fn source_route_visible_in_pathvectord_rib() {
    let mut h = TwoPeerHarness::new().await;

    h.source_announce("198.51.100.0/24", "10.0.0.1");

    pathvector_e2e::wait_for_route(&mut h.client, "198.51.100.0/24", Duration::from_secs(10))
        .await
        .expect("198.51.100.0/24 did not appear in pathvectord's RIB within 10 s");
}

// ── IPv6 outbound ─────────────────────────────────────────────────────────────

use pathvector_client::types::OriginateRouteParams;
use pathvector_e2e::{Harness, wait_for_gobgp_rib_entry_v6};

/// RFC 4760 — pathvectord originates an IPv6 prefix and advertises it to a
/// GoBGP eBGP peer via MP_REACH_NLRI.  GoBGP must install it in its IPv6 RIB.
///
/// pathvectord rewrites the NEXT_HOP to `local_ipv6` (2001:db8::2) before
/// sending — confirmed by GoBGP showing the prefix in `gobgp global rib -a ipv6`.
#[tokio::test]
async fn originated_v6_route_propagates_to_gobgp() {
    let mut h = Harness::new_v6().await;

    h.client
        .originate_route(OriginateRouteParams {
            prefix: "2001:db8:1::/48".to_owned(),
            next_hop: "::".parse().unwrap(),
            origin: Origin::Igp,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        })
        .await
        .expect("originate_route RPC failed");

    wait_for_gobgp_rib_entry_v6(&h.gobgpd_id, "2001:db8:1::", Duration::from_secs(15))
        .await
        .expect("originated IPv6 route did not appear in GoBGP RIB within 15 s");
}
