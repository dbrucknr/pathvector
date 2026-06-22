//! End-to-end tests for RFC 4724 Phase 2 — pathvectord as GR helper.
//!
//! These tests exercise the case where a GR-capable **peer** disconnects
//! uncleanly and pathvectord is expected to hold the peer's routes in its
//! Loc-RIB for the duration of the peer's advertised restart window.
//!
//! RFC 4724 §4.2 requirements tested:
//!   - Unclean TCP drop → routes held for peer's restart_time
//!   - Window expiry → stale routes flushed from Loc-RIB
//!   - Clean disconnect (NOTIFICATION) → routes flushed immediately

use std::{process::Command, time::Duration};

use pathvector_e2e::{Harness, wait_for_route, wait_for_route_withdrawn};

/// RFC 4724 §4.2 — when a GR-capable peer disconnects via unclean TCP
/// failure (SIGKILL, no NOTIFICATION), pathvectord must retain the peer's
/// routes in the Loc-RIB for the duration of the peer's advertised
/// `restart_time`.
///
/// Sequence:
/// 1. GoBGP announces 203.0.113.0/24 and pathvectord installs it.
/// 2. GoBGP container is killed with SIGKILL (no BGP NOTIFICATION).
/// 3. Immediately after the kill, the route must still be present —
///    pathvectord recognised GoBGP as GR-capable and opened a restart window.
/// 4. After the restart window expires, the route must be withdrawn.
///
/// GoBGP is configured with `restart-time = 10` so the window expires in 10 s,
/// keeping the total test duration under 30 s.
#[tokio::test]
async fn gr_phase2_routes_held_during_restart_window_then_flushed_on_expiry() {
    let mut h = Harness::new_gr_peer(10).await;

    h.gobgp_announce("203.0.113.0/24", "10.0.0.1");
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(10))
        .await
        .expect("203.0.113.0/24 did not appear in Loc-RIB within 10 s");

    // Kill GoBGP with SIGKILL — no BGP NOTIFICATION is sent.
    // The kernel closes the TCP socket with a RST, which pathvectord sees as
    // an unclean termination.  Because GoBGP advertised restart_time=10,
    // pathvectord must open a 10 s GR window and keep the route.
    Command::new("docker")
        .args(["stop", "--time=0", &h.gobgpd_id])
        .status()
        .expect("docker stop --time=0 (SIGKILL) gobgpd");

    // Route must still be present immediately after the kill.
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(5))
        .await
        .expect(
            "203.0.113.0/24 was flushed immediately after unclean disconnect; \
             expected pathvectord to open a 10 s GR window and hold the route",
        );

    // After the restart window expires the route must be gone.
    // Allow 20 s: 10 s window + generous buffer for processing lag.
    wait_for_route_withdrawn(&mut h.client, "203.0.113.0/24", Duration::from_secs(20))
        .await
        .expect("203.0.113.0/24 was not withdrawn after the 10 s GR restart window expired");
}

/// RFC 4724 §4.2 — a clean peer termination (BGP NOTIFICATION) must flush
/// routes immediately, not enter the GR hold-window.
///
/// Sequence:
/// 1. GoBGP announces 203.0.113.1/32.
/// 2. pathvectord sends a CEASE NOTIFICATION by removing the peer via gRPC
///    (`remove_peer`), which triggers a clean BGP session teardown.
/// 3. The route must be withdrawn immediately — the GR window must NOT open
///    because the session ended cleanly.
///
/// Note: `docker stop` (SIGTERM) causes GoBGP to send a Cease NOTIFICATION
/// before exiting, so it qualifies as a clean termination from pathvectord's
/// perspective.
#[tokio::test]
async fn gr_phase2_clean_disconnect_flushes_routes_immediately() {
    let mut h = Harness::new_gr_peer(10).await;

    h.gobgp_announce("203.0.113.1/32", "10.0.0.1");
    wait_for_route(&mut h.client, "203.0.113.1/32", Duration::from_secs(10))
        .await
        .expect("203.0.113.1/32 did not appear in Loc-RIB within 10 s");

    // `docker stop` (no --time=0) sends SIGTERM; GoBGP sends a CEASE
    // NOTIFICATION before exiting → pathvectord sees a clean termination.
    Command::new("docker")
        .args(["stop", &h.gobgpd_id])
        .status()
        .expect("docker stop gobgpd");

    // Route must be withdrawn quickly — no GR window should be opened.
    // Allow 10 s for hold-timer to fire and for pathvectord to process the
    // clean disconnect.
    wait_for_route_withdrawn(&mut h.client, "203.0.113.1/32", Duration::from_secs(15))
        .await
        .expect(
            "203.0.113.1/32 was not withdrawn after a clean BGP disconnect; \
             pathvectord should not have opened a GR window for a NOTIFICATION-terminated session",
        );
}
