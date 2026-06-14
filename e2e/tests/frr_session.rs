//! End-to-end session tests against FRRouting (FRR).
//!
//! FRR is the most widely deployed open-source BGP implementation.  It
//! enforces RFC 4271 more strictly than GoBGP — in particular it validates
//! OPEN capability negotiation and rejects malformed attributes that GoBGP
//! silently accepts.  Passing these tests alongside the GoBGP and BIRD suites
//! gives confidence that pathvectord's handshake is broadly correct.
//!
//! RFC 4271 §8 — BGP finite state machine.

use pathvector_client::{
    DaemonClient,
    types::{PeerType, SessionState},
};
use pathvector_e2e::FrrHarness;

/// RFC 4271 §8 — FSM must reach Established with FRR.
///
/// FRR performs strict capability negotiation; reaching Established here
/// confirms pathvectord's OPEN exchange is RFC-correct with a second
/// independent implementation.
#[tokio::test]
async fn frr_session_reaches_established() {
    let h = FrrHarness::new().await;
    let peer = h.client.clone().get_peer(h.frr_ip.into()).await.unwrap();

    assert_eq!(
        peer.session_state,
        SessionState::Established,
        "session must be Established after harness setup"
    );
}

/// Peer state must expose the correct AS numbers and eBGP peer type.
#[tokio::test]
async fn frr_peer_state_fields_correct() {
    let h = FrrHarness::new().await;
    let peer = h.client.clone().get_peer(h.frr_ip.into()).await.unwrap();

    assert_eq!(peer.remote_as, 65001, "FRR is configured with AS 65001");
    assert_eq!(peer.local_as, 65002, "pathvectord runs AS 65002");
    assert_eq!(
        peer.peer_type,
        Some(PeerType::External),
        "65001 ≠ 65002 → eBGP"
    );
    assert!(
        peer.hold_time > 0,
        "hold_time must be negotiated and non-zero"
    );
}

/// `list_peers` must include the FRR peer with state Established.
#[tokio::test]
async fn frr_list_peers_includes_frr_peer() {
    let h = FrrHarness::new().await;
    let peers = h.client.clone().list_peers().await.unwrap();

    assert_eq!(peers.len(), 1, "exactly one peer configured");
    assert_eq!(
        peers[0].session_state,
        SessionState::Established,
        "FRR peer must be Established"
    );
}
