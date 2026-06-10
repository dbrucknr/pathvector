//! End-to-end tests for BGP session lifecycle.
//!
//! RFC 4271 §8 — BGP finite state machine.
//! Scenarios covered:
//!   - Session reaches Established (OPEN + KEEPALIVE exchange)
//!   - Peer state fields are populated correctly after establishment
//!   - list_peers returns the correct peer

use std::time::Duration;

use pathvector_client::{
    DaemonClient,
    types::{PeerType, SessionState},
};
use pathvector_e2e::{Harness, wait_for_established, wait_for_route, wait_for_route_withdrawn};

/// RFC 4271 §8 — verify the FSM reaches Established and the management API
/// reflects the correct session state.
#[tokio::test]
async fn session_reaches_established() {
    let h = Harness::new().await;
    // Harness::new() already waited for Established — this is a final assertion.
    let peer = h.client.clone().get_peer(h.peer.into()).await.unwrap();

    assert_eq!(
        peer.session_state,
        SessionState::Established,
        "session must be Established after harness setup"
    );
}

/// The peer state should expose the correct AS numbers and peer type.
#[tokio::test]
async fn peer_state_fields_correct_after_established() {
    let h = Harness::new().await;
    let peer = h.client.clone().get_peer(h.peer.into()).await.unwrap();

    assert_eq!(peer.remote_as, 65001, "GoBGP advertises AS 65001");
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
    assert!(
        peer.uptime_seconds < 60,
        "session was just established — uptime should be very small"
    );
}

/// list_peers must include the GoBGP peer.
#[tokio::test]
async fn list_peers_includes_gobgp_peer() {
    let h = Harness::new().await;
    let peers = h.client.clone().list_peers().await.unwrap();

    assert_eq!(peers.len(), 1, "exactly one peer configured");
    assert_eq!(peers[0].session_state, SessionState::Established,);
}

/// After the daemon is stopped, re-connecting a fresh client should time out
/// on session establishment.  This test verifies the polling deadline fires
/// correctly — returning `Err` — rather than hanging forever.
#[tokio::test]
async fn wait_for_established_respects_deadline() {
    // Connect to a port with nothing listening — the session will never establish.
    let mut client = pathvector_client::PathvectorClient::connect("http://127.0.0.1:1").unwrap();

    // The deadline fires after 1 s and returns Err; the whole call completes
    // well within our 3 s guard.
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_established(
            &mut client,
            "127.0.0.1".parse().unwrap(),
            Duration::from_secs(1),
        ),
    )
    .await;

    // Outer timeout must NOT have fired — the inner deadline returned first.
    assert!(result.is_ok(), "wait_for_established hung for > 3 s");
    // Must have returned Err (deadline expired), not Ok.
    assert!(
        result.unwrap().is_err(),
        "wait_for_established should return Err on deadline, not Ok"
    );
}

/// `wait_for_route` must fire its deadline and return `Err` rather than
/// hanging forever when no route ever appears.
#[tokio::test]
async fn wait_for_route_respects_deadline() {
    // Nothing is listening on port 1 — every gRPC call will fail, so the
    // route will never appear and the deadline must fire.
    let mut client = pathvector_client::PathvectorClient::connect("http://127.0.0.1:1").unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_route(&mut client, "10.0.0.0/8", Duration::from_secs(1)),
    )
    .await;

    assert!(result.is_ok(), "wait_for_route hung for > 3 s");
    assert!(
        result.unwrap().is_err(),
        "wait_for_route should return Err on deadline, not Ok"
    );
}

/// `wait_for_route_withdrawn` must fire its deadline and return `Err` rather
/// than hanging forever when the route is never withdrawn.
#[tokio::test]
async fn wait_for_route_withdrawn_respects_deadline() {
    // Nothing is listening on port 1 — every gRPC call fails, so
    // `Ok(None)` (route absent) is never observed and the deadline must fire.
    let mut client = pathvector_client::PathvectorClient::connect("http://127.0.0.1:1").unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_route_withdrawn(&mut client, "10.0.0.0/8", Duration::from_secs(1)),
    )
    .await;

    assert!(result.is_ok(), "wait_for_route_withdrawn hung for > 3 s");
    assert!(
        result.unwrap().is_err(),
        "wait_for_route_withdrawn should return Err on deadline, not Ok"
    );
}
