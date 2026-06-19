//! End-to-end tests for BGP route reflection (RFC 4456 §8).
//!
//! Topology:
//!
//! ```text
//! GoBGP-client (AS 65002, RR client) ──iBGP──► pathvectord (AS 65002, RR)
//!                                                       │
//!                                              iBGP (non-client)
//!                                                       │
//!                                            GoBGP-non-client (AS 65002)
//! ```
//!
//! pathvectord acts as the route reflector; GoBGP-client has
//! `is_rr_client = true`; GoBGP-non-client does not.
//!
//! Tests verify wire behavior that unit tests cannot: that reflected UPDATEs
//! actually arrive at the peer over the iBGP session.

use std::time::Duration;

use pathvector_e2e::{RrHarness, wait_for_gobgp_rib_entry};

/// RFC 4456 §8 — a route announced by an RR client must be reflected to a
/// non-client iBGP peer.
///
/// Without route reflection the normal iBGP split-horizon rule would prevent
/// pathvectord from forwarding a route learned from one iBGP peer to another.
#[tokio::test]
async fn rr_client_route_reflected_to_non_client() {
    let h = RrHarness::new().await;

    h.client_announce("10.100.0.0/16", "10.0.0.1");

    wait_for_gobgp_rib_entry(&h.non_client_id, "10.100.0.0/16", Duration::from_secs(15))
        .await
        .expect("route from RR client was not reflected to non-client within 15 s");
}

/// RFC 4456 §8 — a route announced by a non-client must be reflected to
/// an RR client.
///
/// The split-horizon rules permit a route from a non-client to be sent to
/// clients but not to other non-clients.
#[tokio::test]
async fn rr_non_client_route_reflected_to_client() {
    let h = RrHarness::new().await;

    h.non_client_announce("10.200.0.0/16", "10.0.0.1");

    wait_for_gobgp_rib_entry(&h.client_id, "10.200.0.0/16", Duration::from_secs(15))
        .await
        .expect("route from RR non-client was not reflected to client within 15 s");
}

/// RFC 4456 §8 — a route announced by an RR client must also appear in
/// pathvectord's own Loc-RIB.
///
/// This is an invariant: if pathvectord cannot see the route in its own RIB it
/// certainly cannot reflect it.
#[tokio::test]
async fn rr_client_route_visible_in_pathvectord_rib() {
    let mut h = RrHarness::new().await;

    h.client_announce("10.50.0.0/16", "10.0.0.1");

    pathvector_e2e::wait_for_route(&mut h.client, "10.50.0.0/16", Duration::from_secs(10))
        .await
        .expect("route from RR client did not appear in pathvectord Loc-RIB within 10 s");
}
