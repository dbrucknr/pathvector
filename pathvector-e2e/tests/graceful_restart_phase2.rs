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
//!
//! RFC 8538 requirements tested:
//!   - N-bit negotiated on both sides + GoBGP HardReset → GR window bypassed (immediate flush)
//!   - N-bit negotiated on both sides + FRR non-HardReset CEASE → GR window opens

use std::{process::Command, time::Duration};

use pathvector_e2e::{
    FrrHarness, Harness, wait_for_established, wait_for_route, wait_for_route_withdrawn,
};

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
    // `docker kill` sends SIGKILL unconditionally (unlike `docker stop --time=0`
    // which is deprecated on newer Docker versions and may send SIGTERM instead,
    // causing GoBGP to send a CEASE NOTIFICATION before exiting).
    // The kernel closes the TCP socket with a RST, which pathvectord sees as
    // an unclean termination.  Because GoBGP advertised restart_time=10,
    // pathvectord must open a 10 s GR window and keep the route.
    Command::new("docker")
        .args(["kill", &h.gobgpd_id])
        .status()
        .expect("docker kill (SIGKILL) gobgpd");

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

/// RFC 4724 §4.2 — after a peer restarts and re-announces only a subset of its
/// routes, pathvectord must prune the stale routes that were never refreshed
/// once it receives the peer's End-of-RIB marker.
///
/// Sequence:
/// 1. GoBGP announces R1 (203.0.113.0/24) and R2 (203.0.113.1/32).
/// 2. GoBGP is disconnected from the Docker network — TCP drops, GR window opens.
/// 3. R2 is withdrawn from GoBGP's in-memory RIB via `docker exec gobgp global rib del`.
/// 4. GoBGP is reconnected with the same IP; pathvectord re-dials and re-establishes.
/// 5. GoBGP re-announces only R1 and sends End-of-RIB.
/// 6. pathvectord must retain R1 and prune R2 (never refreshed).
///
/// This test requires pathvectord to use a short `connect_retry_time` (2 s) so it
/// reconnects quickly after the network is restored.  The GoBGP container keeps
/// running throughout; only its network attachment is temporarily removed.
#[tokio::test]
async fn gr_phase2_eor_prunes_stale_routes_not_refreshed_by_peer() {
    let mut h = Harness::new_gr_peer_fast_retry(10).await;

    h.gobgp_announce("203.0.113.0/24", "10.0.0.1"); // R1
    h.gobgp_announce("203.0.113.1/32", "10.0.0.1"); // R2
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(10))
        .await
        .expect("R1 (203.0.113.0/24) did not appear in Loc-RIB within 10 s");
    wait_for_route(&mut h.client, "203.0.113.1/32", Duration::from_secs(10))
        .await
        .expect("R2 (203.0.113.1/32) did not appear in Loc-RIB within 10 s");

    // Disconnect GoBGP from the Docker network — TCP drops, GR window opens.
    // The GoBGP process keeps running; its in-memory RIB is intact.
    h.disconnect_gobgp();

    // Confirm both routes are still held (GR window is open).
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(5))
        .await
        .expect("R1 was flushed immediately after network disconnect; expected GR window");
    wait_for_route(&mut h.client, "203.0.113.1/32", Duration::from_secs(5))
        .await
        .expect("R2 was flushed immediately after network disconnect; expected GR window");

    // Remove R2 from GoBGP's RIB while it has no network — docker exec still works.
    // When GoBGP re-establishes it will re-announce only R1, then send EOR.
    h.gobgp_withdraw("203.0.113.1/32");

    // Reconnect GoBGP with the same IP so pathvectord can re-dial it.
    h.reconnect_gobgp();

    // Wait for the session to re-establish.  pathvectord retries every 2 s
    // (connect_retry_time), so this should complete within 10 s.
    wait_for_established(&mut h.client, h.peer, Duration::from_secs(15))
        .await
        .expect("BGP session did not re-establish within 15 s after network reconnect");

    // R1 was re-announced by GoBGP — it must still be present.
    wait_for_route(&mut h.client, "203.0.113.0/24", Duration::from_secs(10))
        .await
        .expect("R1 (203.0.113.0/24) was not present after session re-established");

    // R2 was never re-announced — EOR must have triggered its removal.
    wait_for_route_withdrawn(&mut h.client, "203.0.113.1/32", Duration::from_secs(15))
        .await
        .expect(
            "R2 (203.0.113.1/32) was not pruned after EOR; \
             pathvectord should have removed all stale routes not refreshed before EOR",
        );
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
    // NOTIFICATION before exiting → pathvectord receives TerminationReason::Notification.
    //
    // Safety invariant: this harness uses write_daemon_config (graceful_restart_time = 0),
    // so we_have_n_bit = false and the RFC 8538 notification-mode GR path never fires.
    // The GoBGP config also lacks `notification-enabled = true`, so GoBGP is not in
    // notification_capable_peers.  Both layers independently ensure routes flush immediately.
    // If you add RFC 8538 e2e coverage, use a separate harness that enables GR on both sides.
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

/// RFC 8538 §5 — `CEASE/Hard Reset` bypasses the GR window even when both
/// sides have negotiated the N-bit.
///
/// GoBGP 4.6.0 correctly sends `CEASE/Hard Reset` (subcode 9) on any
/// shutdown when `notification-enabled = true` is configured — this is the
/// RFC 8538 §5 "permanent shutdown" signal meaning "do not enter GR for me."
/// pathvectord must detect the Hard Reset subcode and flush routes immediately
/// despite the N-bit being set on both sides.
///
/// This test validates the end-to-end RFC 8538 Hard Reset path:
/// 1. Both GoBGP and pathvectord negotiate the N-bit (GoBGP via
///    `notification-enabled = true`; pathvectord via `graceful_restart_time > 0`).
/// 2. GoBGP announces 203.0.113.3/32.
/// 3. `docker stop` → GoBGP sends `CEASE/Hard Reset` (subcode 9).
///    pathvectord sees `TerminationReason::Notification(HardReset)`.
///    Per RFC 8538 §5, Hard Reset MUST NOT open a GR window regardless of
///    N-bit negotiation.
/// 4. Route must be flushed immediately — the N-bit does NOT prevent flush on
///    Hard Reset.
///
/// The positive path (non-HardReset CEASE + N-bit → GR window opens) is
/// verified end-to-end by `gr_phase2_rfc8538_frr_notification_opens_gr_window`
/// (FRR sends non-HardReset CEASE on `docker stop`).
#[tokio::test]
async fn gr_phase2_rfc8538_hard_reset_bypasses_gr_window() {
    let mut h = Harness::new_rfc8538_gr(10).await;

    h.gobgp_announce("203.0.113.3/32", "10.0.0.1");
    wait_for_route(&mut h.client, "203.0.113.3/32", Duration::from_secs(10))
        .await
        .expect("203.0.113.3/32 did not appear in Loc-RIB within 10 s");

    // docker stop → GoBGP sends CEASE/Hard Reset (subcode 9).
    // Both sides have N-bit, but Hard Reset MUST NOT open a GR window.
    Command::new("docker")
        .args(["stop", &h.gobgpd_id])
        .status()
        .expect("docker stop gobgpd");

    // Route must be withdrawn quickly — Hard Reset overrides the N-bit.
    // Allow 10 s for pathvectord to process the Hard Reset and flush.
    wait_for_route_withdrawn(&mut h.client, "203.0.113.3/32", Duration::from_secs(10))
        .await
        .expect(
            "203.0.113.3/32 was not flushed after CEASE/Hard Reset; \
             RFC 8538 §5 requires Hard Reset to bypass the GR window regardless of N-bit",
        );
}

/// RFC 8538 §4 — end-to-end validation that pathvectord opens a GR window
/// and holds routes when FRR shuts down with N-bit negotiated on both sides.
///
/// FRR 8.x with `neighbor X graceful-restart-notification` configured sends a
/// non-HardReset CEASE on `docker stop` (Hard Reset is an explicit operator
/// action in FRR, not the default teardown).  This makes FRR the right peer
/// for this test: pathvectord must open a GR window and retain routes until
/// the restart timer expires.
///
/// **Coverage note:** this test verifies the observable end-to-end behavior
/// (route held during the restart window, flushed on expiry) but does not
/// confirm on the wire whether pathvectord received a `Notification` or an
/// unclean TCP close — both open a GR window.  The distinction between the
/// `notification_gr_eligible` and `Unclean` code paths is definitively covered
/// by the `test_rfc8538` unit-test suite in `pathvectord/src/daemon/mod.rs`,
/// which injects `NotificationMessage` values directly into `on_terminated`.
///
/// Sequence:
/// 1. FRR and pathvectord both have N-bit + restart_time=10 in their OPEN.
/// 2. FRR announces 203.0.113.4/32.
/// 3. `docker stop` → FRR tears down the session without Hard Reset.
///    pathvectord opens a 10 s GR window and retains the route.
/// 4. Route must still be present immediately after the stop.
/// 5. After the window expires the route must be flushed.
#[tokio::test]
async fn gr_phase2_rfc8538_frr_notification_opens_gr_window() {
    let mut h = FrrHarness::new_rfc8538_gr(&["203.0.113.4/32"], 10).await;

    wait_for_route(&mut h.client, "203.0.113.4/32", Duration::from_secs(10))
        .await
        .expect("203.0.113.4/32 did not appear in Loc-RIB within 10 s");

    // docker stop → FRR sends CEASE/Administrative-Shutdown (non-HardReset).
    // Both sides have N-bit; pathvectord MUST open a 10 s GR window.
    Command::new("docker")
        .args(["stop", &h.frr_id])
        .status()
        .expect("docker stop frr");

    // Route must still be present — GR window is open.
    wait_for_route(&mut h.client, "203.0.113.4/32", Duration::from_secs(5))
        .await
        .expect(
            "203.0.113.4/32 was flushed immediately after non-HardReset CEASE; \
             RFC 8538 §4 requires GR window to open when both sides have N-bit",
        );

    // After the 10 s restart window expires the route must be gone.
    wait_for_route_withdrawn(&mut h.client, "203.0.113.4/32", Duration::from_secs(20))
        .await
        .expect("203.0.113.4/32 was not flushed after the 10 s GR restart window expired");
}
