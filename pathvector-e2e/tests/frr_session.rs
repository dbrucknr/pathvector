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

use std::process::Command;

use pathvector_client::{
    DaemonClient,
    types::{PeerType, SessionState},
};
use pathvector_e2e::FrrHarness;

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
    let out = Command::new("docker")
        .args(["exec", &h.frr_id, "vtysh", "-c", &format!("show bgp neighbors {pv_ip} json")])
        .output()
        .expect("vtysh show bgp neighbors json");
    let json = String::from_utf8_lossy(&out.stdout);

    assert!(
        json.contains(r#""rBit": true"#) || json.contains(r#""rBit":true"#),
        "FRR must see rBit=true in gracefulRestartInfo when pathvectord sends R=1 in OPEN \
         (restarting=true, graceful_restart_time=120);\n\
         actual gracefulRestartInfo from FRR:\n{json}"
    );
}
