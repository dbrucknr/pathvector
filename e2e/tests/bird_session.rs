//! End-to-end session tests against BIRD 2.
//!
//! BIRD 2 is stricter about RFC 4271 compliance than GoBGP — it validates
//! OPEN capabilities more carefully and rejects attribute errors that GoBGP
//! silently tolerates.  Passing these tests alongside the GoBGP suite gives
//! confidence that pathvectord's handshake is broadly correct, not just
//! compatible with one lenient implementation.
//!
//! RFC 4271 §8 — BGP finite state machine.

use pathvector_client::{
    DaemonClient,
    types::{PeerType, SessionState},
};
use pathvector_e2e::BirdHarness;

/// RFC 4271 §8 — FSM must reach Established with BIRD 2.
///
/// BIRD 2 performs stricter capability negotiation than GoBGP; reaching
/// Established here confirms pathvectord's OPEN exchange is RFC-correct.
#[tokio::test]
async fn bird_session_reaches_established() {
    let h = BirdHarness::new().await;
    // BirdHarness::new() already waited for Established — final assertion.
    let peer = h.client.clone().get_peer(h.bird_ip.into()).await.unwrap();

    assert_eq!(
        peer.session_state,
        SessionState::Established,
        "session must be Established after harness setup"
    );
}

/// Peer state must expose the correct AS numbers and eBGP peer type.
#[tokio::test]
async fn bird_peer_state_fields_correct() {
    let h = BirdHarness::new().await;
    let peer = h.client.clone().get_peer(h.bird_ip.into()).await.unwrap();

    assert_eq!(peer.remote_as, 65001, "BIRD is configured with AS 65001");
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

/// `list_peers` must include the BIRD peer with state Established.
#[tokio::test]
async fn bird_list_peers_includes_bird_peer() {
    let h = BirdHarness::new().await;
    let peers = h.client.clone().list_peers().await.unwrap();

    assert_eq!(peers.len(), 1, "exactly one peer configured");
    assert_eq!(
        peers[0].session_state,
        SessionState::Established,
        "BIRD peer must be Established"
    );
}
