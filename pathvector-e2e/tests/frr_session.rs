//! End-to-end session tests against FRRouting (FRR).
//!
//! FRR is the most widely deployed open-source BGP implementation.  It
//! enforces RFC 4271 more strictly than GoBGP — in particular it validates
//! OPEN capability negotiation and rejects malformed attributes that GoBGP
//! silently accepts.  Passing these tests alongside the GoBGP and BIRD suites
//! gives confidence that pathvectord's handshake is broadly correct.
//!
//! RFC 4271 §8 — BGP finite state machine.
//! RFC 4724 §3 — Restart State (R) bit verification.

use std::{process::Command, time::Duration};

use pathvector_client::{
    DaemonClient,
    types::{PeerType, SessionState},
};
use pathvector_e2e::{FrrHarness, wait_for_established, wait_for_frr_gr_rbit};

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

// ── RFC 4724 §3 — Restart State (R) bit ──────────────────────────────────────

/// RFC 4724 §3 — When `restarting = true` is set, pathvectord must set the
/// Restart State (R) bit in its GracefulRestart capability OPEN parameter.
///
/// FRR 8.4.x exposes the received R-bit in `show bgp neighbors <addr> json`
/// as `gracefulRestartInfo.rBit`, making it the most direct external proof
/// that the R-bit encoding is correct.  (GoBGP's `peer_restarting` field is
/// only set transiently and is cleared before polling is practical.)
///
/// This test passes `restarting = true` + `graceful_restart_time = 120` to
/// pathvectord, starts it against an FRR peer configured with
/// `neighbor X graceful-restart`, and asserts FRR sees `rBit: true`.
#[tokio::test]
async fn frr_gr_r_bit_set_in_open_when_restarting() {
    let h = FrrHarness::new_gr_restarting(120).await;
    let pv_ip = h.pathvectord_ip.to_string();

    // FRR 8.4.x: `show bgp neighbors <addr> json`
    // gracefulRestartInfo.rBit = true iff peer sent R=1 in its OPEN.
    //
    // pathvectord reporting the session Established doesn't guarantee FRR has
    // finished updating its own internal gracefulRestartInfo yet, so poll
    // rather than checking once.
    wait_for_frr_gr_rbit(&h.frr_id, &pv_ip, true, Duration::from_secs(10))
        .await
        .expect(
            "FRR must see rBit=true in gracefulRestartInfo when pathvectord sends R=1 in OPEN \
             (restarting=true, graceful_restart_time=120)",
        );
}

/// RFC 4724 §3 — After `graceful_restart_time` has elapsed, the R-bit must be
/// cleared in the next OPEN sent by pathvectord.
///
/// This is the operationally critical path: pathvectord restarts, sends R=1 to
/// hold upstream routes, then `graceful_restart_time` expires while the session
/// is live.  If the session drops and reconnects after that point, peers must
/// see R=0 — advertising R=1 past the window is incorrect and would cause peers
/// to defer stale-route cleanup indefinitely.
///
/// Mechanism under test: `SetCapabilities` is pushed on `SessionEvent::Terminated`
/// before `ConnectRetry` fires.  The fresh capabilities are built with
/// `restarting=false` (window expired), so the next OPEN carries R=0.
///
/// Sequence:
/// 1. Start with `restarting=true`, `graceful_restart_time=5` — FRR sees rBit=true.
/// 2. Wait 7 s — window expires.
/// 3. FRR resets the session via `clear bgp <addr>` (sends NOTIFICATION+CEASE).
/// 4. pathvectord: Terminated → SetCapabilities(R=0) → ConnectRetry → reconnect.
/// 5. Assert FRR sees rBit=false on the new session.
#[tokio::test]
async fn frr_gr_r_bit_cleared_after_restart_window_expires() {
    let h = FrrHarness::new_gr_restarting(5).await;
    let pv_ip = h.pathvectord_ip.to_string();

    // Phase 1: confirm rBit=true on the initial OPEN.
    let out = Command::new("docker")
        .args([
            "exec",
            &h.frr_id,
            "vtysh",
            "-c",
            &format!("show bgp neighbors {pv_ip} json"),
        ])
        .output()
        .expect("vtysh show bgp neighbors json (initial)");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(
        json.contains(r#""rBit": true"#) || json.contains(r#""rBit":true"#),
        "initial OPEN must have rBit=true;\nactual:\n{json}"
    );

    // Phase 2: wait past the 5 s restart window.
    tokio::time::sleep(Duration::from_secs(7)).await;

    // Phase 3: reset the session from FRR's side.  FRR sends NOTIFICATION+CEASE;
    // pathvectord receives it, fires Terminated, pushes SetCapabilities(R=0).
    Command::new("docker")
        .args([
            "exec",
            &h.frr_id,
            "vtysh",
            "-c",
            &format!("clear bgp {pv_ip}"),
        ])
        .status()
        .expect("clear bgp session");

    // Give pathvectord a moment to process the disconnect before polling.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Phase 4: wait for re-establishment.  pathvectord's ConnectRetry timer is
    // 120 s; after a NOTIFICATION the session won't retry until that fires.
    let mut client = h.client.clone();
    wait_for_established(&mut client, h.frr_ip, Duration::from_secs(135))
        .await
        .expect("session did not re-establish within 135 s after window expiry");

    // Phase 5: rBit must be false — the window had expired before reconnect.
    let out = Command::new("docker")
        .args([
            "exec",
            &h.frr_id,
            "vtysh",
            "-c",
            &format!("show bgp neighbors {pv_ip} json"),
        ])
        .output()
        .expect("vtysh show bgp neighbors json (after reconnect)");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(
        !json.contains(r#""rBit": true"#) && !json.contains(r#""rBit":true"#),
        "rBit must be false after restart window expired — SetCapabilities must have \
         cleared R before the reconnect OPEN was sent;\nactual:\n{json}"
    );
}
