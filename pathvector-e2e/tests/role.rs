//! End-to-end test proving pathvectord actually rejects a route-leak
//! delivered over a real BGP session — not just that the policy terms exist
//! in isolation (already covered by `pathvectord`'s own unit tests, e.g.
//! `test_route_leak_prevented_across_two_provider_peers`).
//!
//! RFC 9234 — BGP Role and `ONLY_TO_CUSTOMER` route-leak prevention.
//!
//! Uses a small, deterministic mock BGP peer (see
//! `src/bin/mock_bgp_peer.rs`) rather than a real router: this test needs to
//! be hermetic and deterministic in CI, and a well-behaved RFC-9234-conformant
//! router (like FRR — confirmed to support `neighbor <addr> local-role
//! <role>` as of FRR 8.4.4) would, by design, never let a leak reach us in
//! the first place. Reproducing a genuine leak over the wire requires a peer
//! willing to send one on purpose.

use std::time::Duration;

use pathvector_client::DaemonClient;
use pathvector_e2e::RoleHarness;

/// RFC 9234 §5: a route already carrying `ONLY_TO_CUSTOMER` must never be
/// accepted from a peer configured with `role = "provider"` (i.e. the peer is
/// our Customer — a well-behaved Customer never sends OTC at all), while a
/// clean announcement from the same peer must be accepted — over a real BGP
/// session, with the OPEN/UPDATE exchange going through the real wire codec.
#[tokio::test]
async fn leaked_route_is_rejected_clean_route_is_accepted() {
    let mut h = RoleHarness::new().await;

    // 198.51.100.0/24: clean announcement, no OTC — must be accepted.
    let clean =
        pathvector_e2e::wait_for_route(&mut h.client, "198.51.100.0/24", Duration::from_secs(10))
            .await
            .expect("clean route (198.51.100.0/24) should be accepted into the Loc-RIB");
    assert_eq!(clean.prefix, "198.51.100.0/24");

    // 203.0.113.0/24: already carries OTC when it arrives — a leak. Give it
    // the same generous window, then confirm it never appeared — mirrors the
    // RPKI e2e test's "assert absence after a wait" pattern.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let leaked = h
        .client
        .get_best_route("203.0.113.0/24")
        .await
        .expect("gRPC call succeeded");
    assert!(
        leaked.is_none(),
        "RFC 9234 violation: 203.0.113.0/24 (leaked — pre-attached OTC from a \
         peer configured as our Customer) appeared in Loc-RIB"
    );
}
