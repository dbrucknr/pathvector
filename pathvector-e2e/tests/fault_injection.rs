//! End-to-end adversarial input / fault-injection tests (TODO.md Tier 3 #11).
//!
//! Unit tests in `pathvector-session` prove each piece of error handling in
//! isolation: RFC 7606 attribute-error policy (`update.rs`, `transport.rs`),
//! and — closed alongside this test file — RFC 4271 §6.1 Message Header
//! Error NOTIFICATION behavior (`transport.rs`). They do **not** prove any of
//! this holds against a real TCP session driving the real pathvectord
//! binary, or that a fault on one connection can't wedge the whole daemon.
//! These tests close that gap using `mock_bgp_fault_peer` (see
//! `src/bin/mock_bgp_fault_peer.rs` for the exact byte-level scenarios) and a
//! GoBGP **control** peer whose continued health is the throughline
//! assertion for every scenario.

use std::net::IpAddr;
use std::time::Duration;

use pathvector_client::DaemonClient;
use pathvector_client::types::SessionState;
use pathvector_e2e::{
    FaultInjectionHarness, Harness, wait_for_established, wait_for_route, wait_for_route_withdrawn,
};

/// Confirms the control peer is Established — the common precondition and
/// the throughline health check for every scenario in this file.
async fn assert_control_peer_established(h: &mut FaultInjectionHarness) {
    let control_peer = h.control_peer;
    wait_for_established(&mut h.client, control_peer, Duration::from_secs(30))
        .await
        .expect("control peer session did not reach/stay Established");
}

/// RFC 4271 §6.1: a corrupted marker must not wedge the daemon — the control
/// peer's session must establish and stay healthy regardless.
#[tokio::test]
async fn bad_marker_daemon_stays_healthy() {
    let mut h = FaultInjectionHarness::new("bad-marker").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_ne!(
        state.session_state,
        SessionState::Established,
        "a connection that only ever sent a corrupted marker must never reach Established"
    );

    // Throughline: the fault must not have wedged the daemon.
    assert_control_peer_established(&mut h).await;
}

/// RFC 4271 §6.1: a corrupted length field must not wedge the daemon.
#[tokio::test]
async fn bad_length_daemon_stays_healthy() {
    let mut h = FaultInjectionHarness::new("bad-length").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_ne!(
        state.session_state,
        SessionState::Established,
        "a connection that only ever sent a corrupted length field must never reach Established"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 4271 §6.1: an unrecognized message type must not wedge the daemon.
#[tokio::test]
async fn bad_type_daemon_stays_healthy() {
    let mut h = FaultInjectionHarness::new("bad-type").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_ne!(
        state.session_state,
        SessionState::Established,
        "a connection that only ever sent an unrecognized message type must never reach Established"
    );

    assert_control_peer_established(&mut h).await;
}

/// A connection that sends fewer than a full header's worth of bytes and
/// then never closes must leave pathvectord's codec genuinely waiting — not
/// crash, not busy-loop, and critically not block any other peer's session.
///
/// Doesn't wait out `OPEN_HOLD_TIMER` (a fixed 240s in `pathvector-session`,
/// independent of configured `hold_time`) — that would make this test
/// untenable in CI. The control peer staying Established for the whole
/// window is the actual property under test.
#[tokio::test]
async fn truncated_header_does_not_wedge_daemon() {
    let mut h = FaultInjectionHarness::new("truncated-header").await;
    assert_control_peer_established(&mut h).await;

    tokio::time::sleep(Duration::from_secs(10)).await;

    assert_control_peer_established(&mut h).await;
}

/// A connection that sends a handful of bytes (not even a complete header)
/// and then closes must be handled as a clean EOF during the OPEN exchange —
/// not crash, not wedge, and not affect the control peer.
#[tokio::test]
async fn truncated_during_open_exchange_does_not_wedge_daemon() {
    let mut h = FaultInjectionHarness::new("truncated-open").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_ne!(
        state.session_state,
        SessionState::Established,
        "a connection closed mid-OPEN-exchange must never reach Established"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 7606: an UPDATE with an invalid ORIGIN value must be treated as a
/// withdraw (session stays up) — over a real BGP session with the real wire
/// codec on both ends, not just hand-built `UpdateMessage` structs in unit
/// tests.
#[tokio::test]
async fn malformed_update_origin_treated_as_withdraw_session_stays_up() {
    let mut h = FaultInjectionHarness::new("malformed-update-origin").await;
    assert_control_peer_established(&mut h).await;

    // The first, clean UPDATE must land.
    wait_for_route(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 did not appear in Loc-RIB within 15 s");

    // The second, malformed UPDATE (invalid ORIGIN) must be treated as a
    // withdraw per RFC 7606 — the route disappears, but the session and the
    // rest of the daemon stay healthy.
    wait_for_route_withdrawn(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 was not withdrawn within 15 s after the malformed ORIGIN UPDATE");

    assert_control_peer_established(&mut h).await;
}

/// A mid-session TCP reset (simulated via a hard Docker-network disconnect,
/// already exercised by the GR test suite) must be followed by a clean
/// re-establishment once connectivity returns — reuses the existing
/// `Harness::disconnect_gobgp`/`reconnect_gobgp` helpers with no new
/// low-level socket code, as a dedicated non-GR-specific resilience check.
///
/// Uses `new_fast_retry` (2 s `connect_retry_time`) rather than plain `new`
/// (RFC-default 120 s) — otherwise pathvectord wouldn't redial until well
/// past any reasonable test timeout.
#[tokio::test]
async fn mid_session_tcp_reset_recovers_cleanly() {
    let mut h = Harness::new_fast_retry(2).await;
    let peer = h.peer;

    h.disconnect_gobgp();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let state = h
            .client
            .get_peer(IpAddr::from(peer))
            .await
            .expect("get_peer gRPC call succeeded");
        if state.session_state != SessionState::Established {
            break;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "session did not leave Established within 15 s of the network disconnect"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    h.reconnect_gobgp();

    wait_for_established(&mut h.client, peer, Duration::from_secs(30))
        .await
        .expect("session did not re-establish within 30 s of reconnecting");
}
