//! End-to-end test for native IPv6 BGP transport.
//!
//! Every other IPv6-flavored e2e test (`graceful_restart_ipv6.rs`, the
//! `new_v6`/`new_v6_export_reject` harnesses, `role.rs`) exercises IPv6
//! *NLRI* — routes whose prefix or next-hop is an IPv6 address — carried
//! over what is still an IPv4 TCP session with GoBGP. None of them prove
//! that pathvectord can dial or accept a BGP session whose own transport
//! address is IPv6.
//!
//! This test closes that gap: `PeerConfig.address` is GoBGP's routable
//! (global-scope ULA) IPv6 address on an `--ipv6` Docker bridge network, so
//! the TCP SYN pathvectord sends to reach it travels over real IPv6, not
//! just carries IPv6 data over a v4 socket. Establishment, plus gRPC's
//! `get_peer`/`list_peers` correctly reporting that IPv6 address back,
//! together prove both halves of the ipv6-bgp-transport feature: the
//! dual-stack listener/dial path in pathvectord, and the gRPC exposure work
//! that stopped filtering IPv6 peers out of `PeerState`.

use std::net::IpAddr;

use pathvector_client::{DaemonClient, types::SessionState};
use pathvector_e2e::Ipv6TransportHarness;

/// pathvectord dials GoBGP over a real IPv6 TCP connection and the session
/// reaches Established — `Ipv6TransportHarness::new()` already asserts this
/// via `wait_for_established`, so reaching this line at all is half the
/// proof. The rest of the test confirms gRPC reports the session back
/// correctly, with the peer's address intact as IPv6 (not silently dropped
/// or mangled, as it would have been before the peer-identity migration).
#[tokio::test]
async fn session_establishes_over_ipv6_transport() {
    let mut h = Ipv6TransportHarness::new().await;

    let peer_state = h
        .client
        .get_peer(IpAddr::V6(h.peer_v6))
        .await
        .expect("get_peer for the IPv6-transport peer");
    assert_eq!(peer_state.session_state, SessionState::Established);
    assert_eq!(peer_state.address, IpAddr::V6(h.peer_v6));
    assert_eq!(peer_state.remote_as, 65001);

    // list_peers must include this peer too — this is exactly the path that
    // used to filter IPv6 addresses out of ListPeers/WatchPeers responses.
    let peers = h.client.list_peers().await.expect("list_peers");
    assert!(
        peers
            .iter()
            .any(|p| p.address == IpAddr::V6(h.peer_v6)
                && p.session_state == SessionState::Established),
        "list_peers did not report the IPv6-transport peer as Established: {peers:?}"
    );
}
