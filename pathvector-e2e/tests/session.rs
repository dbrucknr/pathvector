//! End-to-end tests for BGP session lifecycle.
//!
//! RFC 4271 §8 — BGP finite state machine.
//! RFC 4724 §2 — End-of-RIB marker acceptance.
//! Scenarios covered:
//!   - Session reaches Established (OPEN + KEEPALIVE exchange)
//!   - Peer state fields are populated correctly after establishment
//!   - list_peers returns the correct peer
//!   - Session stays Established after the EOR marker is sent (GoBGP did not reject it)

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

// ── RFC 4724 §2 — End-of-RIB send and receive ────────────────────────────────
//
// Send-side strategy: GoBGP sends a NOTIFICATION and drops the session if it
// receives a malformed UPDATE (including a malformed EOR). Tests verify the
// session stays Established after we send our EOR.
//
// Receive-side strategy: GoBGP also sends an EOR to us after its initial table
// dump. Tests verify pathvectord records the EOR and exposes it via PeerState.

/// RFC 4724 §2 — An empty-RIB EOR (minimum-length UPDATE, 23 bytes) must be
/// accepted by GoBGP without causing a NOTIFICATION or session reset.
///
/// This is the simplest EOR scenario: pathvectord has nothing to dump, so the
/// first and only message after KEEPALIVE is the IPv4 EOR.
#[tokio::test]
async fn eor_on_empty_rib_does_not_cause_session_reset() {
    let mut h = Harness::new().await;

    // Harness::new() already waited for Established.  Wait an additional 3 s
    // and re-check — if GoBGP rejected the EOR it would have sent a
    // NOTIFICATION and the session would have dropped by now.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let peer = h.client.clone().get_peer(h.peer.into()).await.unwrap();
    assert_eq!(
        peer.session_state,
        pathvector_client::types::SessionState::Established,
        "session must remain Established after the IPv4 EOR — GoBGP rejected it (NOTIFICATION)"
    );
}

/// RFC 4724 §2 — A non-empty-RIB full-table dump followed by an EOR must
/// be accepted by GoBGP without causing a session reset.
///
/// GoBGP pre-announces a route so that pathvectord's Adj-RIB-Out is non-empty.
/// After the dump and EOR, the route must be visible in pathvectord's Loc-RIB
/// AND the session must still be Established.
#[tokio::test]
async fn eor_after_full_table_dump_does_not_cause_session_reset() {
    let mut h = Harness::new().await;

    // Pre-announce a route so the dump sends at least one UPDATE before the EOR.
    h.gobgp_announce("10.0.0.0/8", "10.0.0.1");

    // Wait for pathvectord to receive the route — this confirms the session is
    // active and the dump UPDATE was accepted.
    wait_for_route(&mut h.client, "10.0.0.0/8", Duration::from_secs(10))
        .await
        .expect("10.0.0.0/8 did not appear in pathvectord's Loc-RIB within 10 s");

    // Wait another 3 s then verify Established — gives GoBGP time to process
    // and potentially reject a malformed EOR.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let peer = h.client.clone().get_peer(h.peer.into()).await.unwrap();
    assert_eq!(
        peer.session_state,
        pathvector_client::types::SessionState::Established,
        "session must remain Established after a full-table dump + EOR — GoBGP rejected the EOR"
    );
}

/// RFC 4724 §2 receive-side — GoBGP sends us an IPv4 EOR after establishing
/// the session.  pathvectord must detect it and expose `eor_ipv4_received = true`
/// in the management API.
///
/// GoBGP sends its EOR very quickly after Established (its RIB is empty at
/// session start), so we just need to allow a short settling window.
#[tokio::test]
async fn eor_ipv4_received_from_gobgp_is_recorded() {
    let mut h = Harness::new().await;

    // Give GoBGP a moment to send its EOR after the session reaches Established.
    // GoBGP sends EOR immediately after its initial dump (which is empty here),
    // so 2 s is more than enough; Established was already confirmed by Harness::new().
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let peer_state = loop {
        let p = h.client.clone().get_peer(h.peer.into()).await.unwrap();
        if p.eor_ipv4_received {
            break p;
        }
        if std::time::Instant::now() > deadline {
            break p;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    assert!(
        peer_state.eor_ipv4_received,
        "pathvectord must record GoBGP's IPv4 EOR in PeerState (RFC 4724 §2 receive-side)"
    );
}

/// RFC 4724 §2 receive-side — After a route is announced by GoBGP and then
/// withdrawn, GoBGP still sends an EOR (it sent it right after Established).
/// This verifies that receiving routes before or after the EOR does not
/// corrupt the recorded EOR state.
#[tokio::test]
async fn eor_ipv4_received_persists_after_route_churn() {
    let mut h = Harness::new().await;

    // Announce then immediately withdraw so the daemon processes real UPDATEs.
    h.gobgp_announce("10.0.0.0/8", "10.0.0.1");
    wait_for_route(&mut h.client, "10.0.0.0/8", Duration::from_secs(10))
        .await
        .expect("route must appear before withdrawal test");
    h.gobgp_withdraw("10.0.0.0/8");

    // Poll for the EOR flag — it should have been set at Established time and
    // must remain set through the route churn.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let peer_state = loop {
        let p = h.client.clone().get_peer(h.peer.into()).await.unwrap();
        if p.eor_ipv4_received {
            break p;
        }
        if std::time::Instant::now() > deadline {
            break p;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    assert!(
        peer_state.eor_ipv4_received,
        "eor_ipv4_received must remain set after route announce/withdraw churn"
    );
}
