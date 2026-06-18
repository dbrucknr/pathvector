//! End-to-end tests for dynamic peer management (AddPeer / RemovePeer gRPC RPCs).
//!
//! Tests here start `pathvectord` with **no** statically configured peers and
//! verify that peers, routes, and BGP sessions behave correctly when added and
//! removed at runtime via the gRPC API.
//!
//! Scenarios covered:
//!   - `add_peer` establishes a live BGP session
//!   - `add_peer` is idempotent (second call doesn't disrupt the session)
//!   - `remove_peer` withdraws routes from the Loc-RIB and removes the peer
//!   - Full add → establish → inject routes → remove → re-add cycle

use std::{net::IpAddr, time::Duration};

use pathvector_client::{
    DaemonClient,
    types::{AddPeerParams, PeerEventType, SessionState},
};
use pathvector_e2e::{
    DynamicPeerHarness, wait_for_established, wait_for_peer_absent, wait_for_route,
    wait_for_route_withdrawn,
};
use tokio_stream::StreamExt as _;

/// Helper: build `AddPeerParams` for the GoBGP container (AS 65001, port 179,
/// accept-all import and export policy).
fn gobgp_peer_params(gobgp_ip: std::net::Ipv4Addr) -> AddPeerParams {
    AddPeerParams {
        address: IpAddr::V4(gobgp_ip),
        remote_as: 65001,
        port: Some(179),
        import_default: Some(true),
        export_default: Some(true),
        md5_password: None,
    }
}

/// `add_peer` must start a BGP session that reaches `Established`.
#[tokio::test]
async fn dynamic_peer_add_establishes_session() {
    let mut h = DynamicPeerHarness::new().await;

    // No peers configured — list must be empty.
    let peers = h.client.list_peers().await.unwrap();
    assert!(
        peers.is_empty(),
        "list_peers must be empty before any dynamic add"
    );

    // Add the GoBGP peer at runtime.
    h.client
        .add_peer(gobgp_peer_params(h.gobgp_ip))
        .await
        .expect("add_peer must succeed");

    // Poll until the session reaches Established.
    wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(30))
        .await
        .expect("BGP session did not reach Established within 30 s after dynamic add_peer");

    let peer = h
        .client
        .get_peer(IpAddr::V4(h.gobgp_ip))
        .await
        .expect("get_peer must succeed after session is Established");

    assert_eq!(peer.session_state, SessionState::Established);
    assert_eq!(peer.remote_as, 65001, "GoBGP advertises AS 65001");
    assert_eq!(peer.local_as, 65002, "pathvectord runs AS 65002");
}

/// Calling `add_peer` twice for the same address must be a no-op — the second
/// call must not disrupt the existing session or appear as a second peer entry.
#[tokio::test]
async fn dynamic_peer_add_is_idempotent() {
    let mut h = DynamicPeerHarness::new().await;

    h.client
        .add_peer(gobgp_peer_params(h.gobgp_ip))
        .await
        .expect("first add_peer must succeed");

    wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(30))
        .await
        .expect("BGP session did not reach Established within 30 s");

    // Second add — must return OK and leave the session intact.
    h.client
        .add_peer(gobgp_peer_params(h.gobgp_ip))
        .await
        .expect("second add_peer (idempotent) must not return an error");

    // Still exactly one peer, still Established.
    let peers = h.client.list_peers().await.unwrap();
    assert_eq!(peers.len(), 1, "exactly one peer must be present");
    assert_eq!(
        peers[0].session_state,
        SessionState::Established,
        "session must still be Established after idempotent add"
    );
}

/// `remove_peer` must withdraw all routes learned from the peer and remove the
/// peer entry from the daemon's state.
#[tokio::test]
async fn dynamic_peer_remove_withdraws_routes_and_removes_peer() {
    let mut h = DynamicPeerHarness::new().await;

    h.client
        .add_peer(gobgp_peer_params(h.gobgp_ip))
        .await
        .expect("add_peer must succeed");

    wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(30))
        .await
        .expect("BGP session did not reach Established within 30 s");

    // Inject a route from GoBGP and wait for it to appear in the Loc-RIB.
    h.gobgp_announce("203.0.113.0/24", &h.gobgp_ip.to_string());
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(10))
        .await
        .expect("route 203.0.113.0/24 did not appear in Loc-RIB within 10 s");

    // Remove the peer — this must trigger route withdrawal.
    h.client
        .remove_peer(IpAddr::V4(h.gobgp_ip))
        .await
        .expect("remove_peer must succeed");

    // Route must disappear from the Loc-RIB.
    wait_for_route_withdrawn(&mut h.client, "203.0.113.0/24", Duration::from_secs(15))
        .await
        .expect(
            "route 203.0.113.0/24 was not withdrawn from Loc-RIB within 15 s after remove_peer",
        );

    // Peer must disappear from list_peers.
    wait_for_peer_absent(&mut h.client, h.gobgp_ip, Duration::from_secs(10))
        .await
        .expect("peer was not removed from list_peers within 10 s after remove_peer");
}

/// Full lifecycle: add → establish → inject routes → remove → re-add → re-establish.
///
/// This proves that re-adding a peer after a clean removal works end-to-end:
/// the daemon correctly tears down all state and re-initialises it for the
/// second session.
#[tokio::test]
async fn dynamic_peer_add_remove_cycle() {
    let mut h = DynamicPeerHarness::new().await;

    // ── First session ─────────────────────────────────────────────────────────

    h.client
        .add_peer(gobgp_peer_params(h.gobgp_ip))
        .await
        .expect("first add_peer must succeed");

    wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(30))
        .await
        .expect("first BGP session did not reach Established within 30 s");

    h.gobgp_announce("198.51.100.0/24", &h.gobgp_ip.to_string());
    wait_for_route(&mut h.client, "198.51.100.0/24", Duration::from_secs(10))
        .await
        .expect("route 198.51.100.0/24 did not appear in Loc-RIB within 10 s");

    // ── Remove ────────────────────────────────────────────────────────────────

    h.client
        .remove_peer(IpAddr::V4(h.gobgp_ip))
        .await
        .expect("remove_peer must succeed");

    wait_for_route_withdrawn(&mut h.client, "198.51.100.0/24", Duration::from_secs(15))
        .await
        .expect("route was not withdrawn within 15 s after first remove_peer");

    wait_for_peer_absent(&mut h.client, h.gobgp_ip, Duration::from_secs(10))
        .await
        .expect("peer was not removed within 10 s after first remove_peer");

    // ── Second session ────────────────────────────────────────────────────────

    h.client
        .add_peer(gobgp_peer_params(h.gobgp_ip))
        .await
        .expect("second add_peer (after full removal) must succeed");

    wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(30))
        .await
        .expect("second BGP session did not reach Established within 30 s");

    // GoBGP's RIB still has the route from before — it should re-advertise it
    // once the new session reaches Established.
    wait_for_route(&mut h.client, "198.51.100.0/24", Duration::from_secs(15))
        .await
        .expect(
            "route 198.51.100.0/24 did not re-appear in Loc-RIB within 15 s after second add_peer",
        );
}

/// `watch_peers` stream must deliver a `Removed` event with correct identity
/// fields (`remote_as`, `local_as`, `address`) when a peer is removed via
/// `remove_peer`.
///
/// This is the end-to-end correctness test for the `PEER_EVENT_TYPE_REMOVED`
/// flow: event loop → broadcast → gRPC stream → client type conversion.  The
/// `remote_as` and `local_as` fields must be non-zero — they are captured
/// immediately before the peer is erased from daemon state.
#[tokio::test]
async fn dynamic_peer_watch_peers_delivers_removed_event() {
    let mut h = DynamicPeerHarness::new().await;

    // Subscribe to the stream *before* adding the peer so we don't miss any
    // events.  The stream starts with a snapshot phase; we drain it below.
    let mut stream = h
        .client
        .watch_peers()
        .await
        .expect("watch_peers must open successfully");

    // Add the peer and wait for the session to be Established.
    h.client
        .add_peer(gobgp_peer_params(h.gobgp_ip))
        .await
        .expect("add_peer must succeed");

    wait_for_established(&mut h.client, h.gobgp_ip, Duration::from_secs(30))
        .await
        .expect("BGP session did not reach Established within 30 s");

    // Now remove the peer.  The daemon captures identity fields before erasure
    // and broadcasts an explicit Removed event.
    h.client
        .remove_peer(IpAddr::V4(h.gobgp_ip))
        .await
        .expect("remove_peer must succeed");

    // Poll the stream until we see a Removed event or time out.
    let removed = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match stream.next().await {
                Some(Ok(ev)) if ev.event_type == PeerEventType::Removed => break Some(ev),
                Some(Ok(_)) => {} // skip Current / EndInitial / Changed
                Some(Err(e)) => panic!("watch_peers stream error: {e}"),
                None => break None,
            }
        }
    })
    .await
    .expect("timed out waiting for Removed event on watch_peers stream")
    .expect("watch_peers stream closed before Removed event");

    let ps = removed
        .peer
        .expect("Removed event must carry a peer payload");

    assert_eq!(
        ps.address,
        IpAddr::V4(h.gobgp_ip),
        "Removed event address must match the removed peer"
    );
    assert_eq!(
        ps.remote_as, 65001,
        "Removed event remote_as must be non-zero (GoBGP AS 65001)"
    );
    assert_eq!(
        ps.local_as, 65002,
        "Removed event local_as must be non-zero (pathvectord AS 65002)"
    );
}
