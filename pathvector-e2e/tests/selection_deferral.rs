//! End-to-end tests for RFC 4724 §4.1 (Restarting-Speaker
//! Selection_Deferral_Timer) over a complete, real BGP session path.
//!
//! Closes the gap identified in review of PR #50: the existing unit-level
//! coverage (`pathvectord/src/daemon/mod.rs`'s `selection_deferral_tests`)
//! operates directly on `DaemonState`, bypassing TOML config parsing, real
//! OPEN capability negotiation, receiving an actual wire-encoded EOR, the
//! `tokio::select!` timer branch in `daemon/mod.rs`, and delivery of the
//! catch-up dump over a real BGP session. These tests exercise the complete
//! configuration → negotiation → route processing → timer/wait-set →
//! catch-up path via [`SelectionDeferralHarness`].

use std::time::Duration;

use pathvector_e2e::{
    SELECTION_DEFERRAL_TEST_PREFIX, SelectionDeferralHarness, wait_for_gobgp_rib_entry,
    wait_for_route,
};

/// RFC 4724 §4.1: a route learned from a GR-capable peer that never sends
/// its End-of-RIB marker must still reach pathvectord's own Loc-RIB
/// immediately (deferral is scoped to *outbound advertisement only* — see
/// `selection_deferral_time`'s doc comment), but must NOT be advertised to
/// another peer (the "observer") until the Selection_Deferral_Timer expires
/// — at which point it is force-released and flushed, and the observer
/// receives it.
#[tokio::test]
async fn route_withheld_from_observer_until_deferral_timer_expires() {
    const DEFERRAL_SECS: u16 = 8;
    let mut h = SelectionDeferralHarness::new("withhold-eor", DEFERRAL_SECS).await;

    // Loc-RIB is unaffected by deferral — the route must appear promptly
    // regardless of the withheld EOR.
    wait_for_route(
        &mut h.client,
        SELECTION_DEFERRAL_TEST_PREFIX,
        Duration::from_secs(15),
    )
    .await
    .expect("route did not appear in pathvectord's own Loc-RIB within 15 s");

    // The observer must NOT have received it yet — deferral is still active,
    // well before DEFERRAL_SECS has elapsed since the harness itself took a
    // few seconds to stand up both sessions.
    let rib_text = pathvector_e2e::gobgp_rib_text(&h.observer_id);
    assert!(
        !rib_text.contains(SELECTION_DEFERRAL_TEST_PREFIX),
        "RFC 4724 §4.1: the observer must not receive the deferred route before the \
         Selection_Deferral_Timer expires (source peer never sent EOR); got RIB:\n{rib_text}"
    );

    // Once the timer expires, the daemon force-releases both families and
    // flushes pending outbound state — the observer must then receive the
    // route.
    wait_for_gobgp_rib_entry(
        &h.observer_id,
        SELECTION_DEFERRAL_TEST_PREFIX,
        Duration::from_secs(u64::from(DEFERRAL_SECS) + 15),
    )
    .await
    .expect(
        "RFC 4724 §4.1: the observer must receive the deferred route once the \
         Selection_Deferral_Timer expires",
    );
}

/// RFC 4724 §4.1's wait-set-satisfied release path (distinct from the
/// timer-expiry path above): a GR-capable peer advertising
/// `restart_time == 0` (RFC 4724 §3's EOR-only mode) must still block
/// release until its own real EOR arrives — it is not exempt from the
/// wait-set merely because it claims no forwarding-state preservation.
///
/// Uses a `selection_deferral_time` deliberately much longer than the mock
/// peer's own EOR delay (`EOR_DELAY` in `mock_bgp_gr_peer.rs`, currently 3s):
/// if the route reaches the observer well before the configured deferral
/// deadline, that is direct evidence release was gated on this peer's real
/// EOR, not on the timer expiring on its own.
#[tokio::test]
async fn restart_time_zero_peer_blocks_release_until_its_own_eor_arrives() {
    const DEFERRAL_SECS: u16 = 30;
    let mut h = SelectionDeferralHarness::new("restart-time-zero-delayed-eor", DEFERRAL_SECS).await;

    wait_for_route(
        &mut h.client,
        SELECTION_DEFERRAL_TEST_PREFIX,
        Duration::from_secs(15),
    )
    .await
    .expect("route did not appear in pathvectord's own Loc-RIB within 15 s");

    // The observer must not have the route yet — if pathvectord wrongly
    // excluded a restart_time=0 peer from the wait-set entirely (the exact
    // regression this test guards; see PR #50's P1 fix), release would
    // happen immediately on Established, well before the mock's own
    // deliberately-delayed EOR (`EOR_DELAY`, 3s in mock_bgp_gr_peer.rs).
    let rib_text = pathvector_e2e::gobgp_rib_text(&h.observer_id);
    assert!(
        !rib_text.contains(SELECTION_DEFERRAL_TEST_PREFIX),
        "RFC 4724 §4.1: a restart_time=0 (EOR-only) peer must still block release \
         until its own EOR arrives — the route must not reach the observer this \
         early; got RIB:\n{rib_text}"
    );

    // The route must reach the observer well before DEFERRAL_SECS — proving
    // release was gated on the peer's real (delayed) EOR, not the timer.
    wait_for_gobgp_rib_entry(
        &h.observer_id,
        SELECTION_DEFERRAL_TEST_PREFIX,
        Duration::from_secs(15),
    )
    .await
    .expect(
        "RFC 4724 §4.1: a restart_time=0 (EOR-only) peer must still release the wait-set \
         once its own EOR arrives, well before the (deliberately much longer) \
         Selection_Deferral_Timer would have expired on its own",
    );
}
