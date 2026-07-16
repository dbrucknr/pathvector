//! End-to-end proof of RFC 4271 §6.8 (connection collision resolution) and
//! RFC 4724 §4.2 (Established-state Graceful-Restart override).
//!
//! Unit and same-process-loopback-TCP tests in `pathvector-session` prove
//! each piece in isolation. They do **not** prove either holds against a
//! genuinely separate process racing two real TCP connections against
//! pathvectord's actual Docker-exposed listener. These tests close that gap
//! using `mock_bgp_collision_peer` (see `src/bin/mock_bgp_collision_peer.rs`
//! for the exact scenario mechanics), which both listens for pathvectord's
//! outbound dial and dials back into pathvectord's own listener to force a
//! real, deliberately-sequenced (not accidental) second TCP connection.

use std::time::Duration;

use pathvector_client::DaemonClient;
use pathvector_client::types::SessionState;
use pathvector_e2e::{CollisionHarness, wait_for_established};

/// RFC 4271 §6.8 rule 3: "Otherwise, the local system closes the newly
/// created BGP connection... and continues to use the existing one." The
/// mock advertises a BGP ID lower than pathvectord's configured
/// `10.0.0.2`, so pathvectord (the higher ID) must keep its own outbound
/// connection and reject the mock's later inbound dial outright.
#[tokio::test]
async fn collision_peer_id_lower_pathvectord_keeps_outbound() {
    let mut h = CollisionHarness::new("peer-id-lower").await;
    let peer_addr = std::net::IpAddr::from(h.mock_peer);
    assert_eq!(
        h.client
            .get_peer(peer_addr)
            .await
            .expect("get_peer gRPC call succeeded")
            .session_state,
        SessionState::Established,
        "session must reach Established over the kept outbound connection"
    );
}

/// RFC 4271 §6.8 rule 2: "If the value of the local BGP Identifier is less
/// than the remote one, the local system closes the BGP connection that
/// already exists... and accepts the BGP connection initiated by the remote
/// system." The mock advertises a BGP ID higher than pathvectord's
/// `10.0.0.2`, so pathvectord (the lower ID) must close its own outbound
/// connection — sending a Cease/ConnectionCollisionResolution NOTIFICATION
/// first — and adopt the mock's later inbound dial instead.
///
/// Together with the test above, these two scenarios are what actually
/// force the specific comparison branch under test: the mock only completes
/// a handshake on the connection it expects to "win," so if the fix were
/// still inverted, one of these two tests would hang waiting for
/// Established rather than merely asserting the wrong outcome.
#[tokio::test]
async fn collision_peer_id_higher_pathvectord_adopts_incoming() {
    let mut h = CollisionHarness::new("peer-id-higher").await;
    let peer_addr = std::net::IpAddr::from(h.mock_peer);
    assert_eq!(
        h.client
            .get_peer(peer_addr)
            .await
            .expect("get_peer gRPC call succeeded")
            .session_state,
        SessionState::Established,
        "session must reach Established over the adopted incoming connection"
    );
}

/// RFC 4724 §4.2: "the previous TCP session MUST be closed, and the new one
/// retained... no NOTIFICATION message should be sent." The mock
/// establishes with Graceful Restart negotiated, then abandons its
/// connection without ever closing it (no FIN/RST ever reaches
/// pathvectord — this harness's `hold_time = 0` config additionally rules
/// out pathvectord's own hold timer as an alternate explanation for
/// anything that happens here), and dials a fresh connection.
///
/// With hold_time disabled, pathvectord's FSM has no way to leave
/// Established on its own: no NOTIFICATION is ever sent by the mock, no
/// FIN/RST is ever produced, and the hold timer can't fire. So the *only*
/// path back to a fresh Established is the RFC 4724 §4.2
/// incoming-connection-collision code path under test — continuously
/// polling `session_state` and never seeing anything but `Established`,
/// combined with `uptime_seconds` resetting to a small value once the new
/// connection completes its handshake, is airtight proof this exact branch
/// fired, not just that "GR recovery happened somehow."
#[tokio::test]
async fn gr_established_collision_adopts_new_connection_silently() {
    let mut h = CollisionHarness::new("gr-established-override").await;
    let peer_addr = std::net::IpAddr::from(h.mock_peer);

    // Established was already reached once (over the mock's first
    // connection) by the time `CollisionHarness::new` returned. Poll for
    // well past the mock's abandon-then-redial delay (~2s) and confirm two
    // things: session_state never reports anything but Established, and
    // uptime_seconds is observed dropping back to a small value partway
    // through — proving the old connection was replaced by a genuinely new
    // one, not merely left in place untouched.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_uptime_reset = false;
    let mut ticks = 0;
    while tokio::time::Instant::now() < deadline {
        let state = h
            .client
            .get_peer(peer_addr)
            .await
            .expect("get_peer gRPC call succeeded");
        assert_eq!(
            state.session_state,
            SessionState::Established,
            "RFC 4724 §4.2: session must never leave Established while the \
             new connection replaces the old one (hold_time=0 rules out any \
             other explanation)"
        );
        // Only start checking for the reset after giving the *original*
        // connection's own fresh uptime (necessarily small right after
        // CollisionHarness::new returns) time to climb past the mock's
        // abandon-then-redial window — otherwise "uptime is small" would be
        // trivially true from the very first sample for the wrong reason.
        if ticks > 15 && state.uptime_seconds < 3 {
            saw_uptime_reset = true;
        }
        ticks += 1;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(
        saw_uptime_reset,
        "expected uptime_seconds to reset to a small value after the mock's \
         second connection replaced the first — proving a genuinely new \
         session, not the original one left untouched"
    );

    // Final sanity check via the standard helper.
    wait_for_established(&mut h.client, h.mock_peer, Duration::from_secs(5))
        .await
        .expect("session still Established at the end of the test");
}
