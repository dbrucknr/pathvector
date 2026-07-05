//! End-to-end test for pathvectord's BGP listener accepting a real inbound
//! IPv6-sourced connection.
//!
//! `ipv6_transport.rs`'s `session_establishes_over_ipv6_transport` proves
//! pathvectord can *dial* a peer over IPv6 — but that's the same direction
//! every other e2e test in this crate already exercises (GoBGP is always
//! configured passive-mode, so pathvectord's listener never sees real
//! traffic in any of them). This test closes the other half: pathvectord's
//! own outbound dial is made to fail on purpose (see
//! [`pathvector_e2e::Ipv6AcceptHarness`]), so the only way the session can
//! reach Established is through pathvectord's listener accepting
//! `mock_bgp_dialer`'s inbound connection and completing the handshake.

use std::net::IpAddr;

use pathvector_client::{DaemonClient, types::SessionState};
use pathvector_e2e::Ipv6AcceptHarness;

/// pathvectord's own outbound dial is configured to a port nothing listens
/// on, so `Ipv6AcceptHarness::new()` already proves half of this by not
/// panicking on its internal `wait_for_established` — the session could
/// only have reached Established via the accept path. The rest of this test
/// confirms gRPC reports that session back correctly.
#[tokio::test]
async fn session_establishes_over_ipv6_accept_path() {
    let mut h = Ipv6AcceptHarness::new().await;

    let peer_state = h
        .client
        .get_peer(IpAddr::V6(h.peer_v6))
        .await
        .expect("get_peer for the accept-path peer");
    assert_eq!(peer_state.session_state, SessionState::Established);
    assert_eq!(peer_state.address, IpAddr::V6(h.peer_v6));
    assert_eq!(peer_state.remote_as, 65099);

    let peers = h.client.list_peers().await.expect("list_peers");
    assert!(
        peers
            .iter()
            .any(|p| p.address == IpAddr::V6(h.peer_v6)
                && p.session_state == SessionState::Established),
        "list_peers did not report the accept-path peer as Established: {peers:?}"
    );
}
