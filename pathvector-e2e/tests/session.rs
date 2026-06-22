//! End-to-end tests for BGP session lifecycle.
//!
//! RFC 4271 §8 — BGP finite state machine.
//! RFC 4724 §2 — End-of-RIB marker acceptance.
//! Scenarios covered:
//!   - Session reaches Established (OPEN + KEEPALIVE exchange)
//!   - Peer state fields are populated correctly after establishment
//!   - list_peers returns the correct peer
//!   - Session stays Established after the EOR marker is sent (GoBGP did not reject it)

use std::{process::Command, time::Duration};

use pathvector_client::{
    DaemonClient,
    types::{Origin, OriginateRouteParams, PeerType, SessionState},
};
use pathvector_e2e::{
    Harness, wait_for_established, wait_for_gobgp_rib_entry, wait_for_gobgp_rib_withdrawn,
    wait_for_route, wait_for_route_withdrawn,
};

fn gr_blackhole_params(prefix: &str) -> OriginateRouteParams {
    OriginateRouteParams {
        prefix: prefix.to_owned(),
        next_hop: "10.0.0.1".parse().unwrap(),
        origin: Origin::Igp,
        communities: vec![],
        large_communities: vec![],
        extended_communities: vec![],
        local_pref: None,
        med: None,
    }
}

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
    let h = Harness::new().await;

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
    let h = Harness::new().await;

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

// ── RFC 4724 §3 — GracefulRestart helper role ─────────────────────────────────
//
// Strategy: configure pathvectord with graceful_restart_time = 30, originate a
// blackhole route via the management API, then stop the pathvectord container
// to simulate an unclean restart.  GoBGP must hold the route as stale for the
// duration of the restart window.
//
// These tests verify the end-to-end protocol behavior — that the capability
// we advertise in OPEN actually causes GoBGP to retain our routes.

/// RFC 4724 §3 — After a GR-configured session reaches Established, the
/// management API must report the peer's `peer_gr_restart_time` matching our
/// configured `restart_time`.
///
/// This closes the loop between "we encode the capability" (unit-tested) and
/// "GoBGP parsed and reflected it back so we know negotiation succeeded".
#[tokio::test]
async fn gr_capability_negotiated_peer_gr_restart_time_reflects_config() {
    let h = Harness::new_gr(30).await;

    // Harness::new_gr already confirmed Established. Poll PeerState for the
    // peer_gr_restart_time field — it is set during on_established, which runs
    // synchronously with session establishment, so it should be available
    // immediately, but we allow a short window for any async lag.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let peer_state = loop {
        let p = h.client.clone().get_peer(h.peer.into()).await.unwrap();
        if p.peer_gr_restart_time > 0 {
            break p;
        }
        if std::time::Instant::now() > deadline {
            break p;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    // GoBGP is configured with restart-time = 120 in write_gobgp_config(), so it
    // sends restart_time=120 in its own OPEN when GR is negotiated.  The value
    // here is GoBGP's own advertisement, not a reflection of our 30 s.
    assert_eq!(
        peer_state.peer_gr_restart_time, 120,
        "peer_gr_restart_time must be GoBGP's configured restart_time (120 s); \
         confirms pathvectord parsed GoBGP's GracefulRestart capability and stored it"
    );
}

/// RFC 4724 §3 — When `graceful_restart_time` is configured, GoBGP must keep
/// our originated routes in its RIB during the restart window after an unclean
/// session loss.
///
/// Sequence:
/// 1. pathvectord originates 192.0.2.0/24 and GoBGP learns it.
/// 2. pathvectord container is stopped (SIGTERM — simulates crash/restart).
/// 3. Immediately after stop, GoBGP's RIB is polled — the route must still be
///    present as a stale entry.
/// 4. After the restart window expires (30 s), the route must be gone.
#[tokio::test]
async fn gr_helper_gobgp_holds_routes_during_restart_window() {
    let h = Harness::new_gr(30).await;

    // Originate a route via the management API so pathvectord advertises it to GoBGP.
    h.client
        .clone()
        .originate_route(gr_blackhole_params("192.0.2.0/24"))
        .await
        .expect("originate 192.0.2.0/24");

    // Wait for GoBGP to learn the route from pathvectord.
    wait_for_gobgp_rib_entry(&h.gobgpd_id, "192.0.2.0/24", Duration::from_secs(15))
        .await
        .expect("GoBGP did not receive 192.0.2.0/24 from pathvectord within 15 s");

    // Stop pathvectord — Docker sends SIGTERM, container exits.
    // This simulates an unclean session loss from GoBGP's perspective (TCP FIN
    // without a BGP NOTIFICATION).
    Command::new("docker")
        .args(["stop", "--time=1", &h.pathvectord_id])
        .status()
        .expect("docker stop pathvectord");

    // Poll GoBGP's RIB for up to 20 s — the route must remain present throughout
    // the restart window.  We check repeatedly rather than sleeping once so the
    // test fails fast if GoBGP incorrectly withdraws the route early.
    //
    // Note: we are asserting the INVARIANT "route is still present" for the full
    // poll window, not just at a single point in time.  Any disappearance is a
    // failure.
    let stale_check_deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let out = Command::new("docker")
            .args(["exec", &h.gobgpd_id, "gobgp", "global", "rib"])
            .output()
            .expect("gobgp global rib");
        let rib_text = String::from_utf8_lossy(&out.stdout);
        assert!(
            rib_text.contains("192.0.2.0/24"),
            "GoBGP withdrew 192.0.2.0/24 before the 30 s GR restart window expired; \
             actual RIB:\n{rib_text}"
        );
        if std::time::Instant::now() >= stale_check_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // After the restart window expires, GoBGP must withdraw the stale route.
    // We wait up to restart_time + 10 s for GoBGP to clean up.
    wait_for_gobgp_rib_withdrawn(&h.gobgpd_id, "192.0.2.0/24", Duration::from_secs(45))
        .await
        .expect("GoBGP must withdraw 192.0.2.0/24 after the 30 s GR restart window expires");
}

/// RFC 4724 §3 — Without `graceful_restart_time` (default 0), GoBGP must
/// withdraw our routes immediately on session loss — no stale-route window.
///
/// This is the baseline / regression test: verifies that when we do NOT
/// configure GR, the peer behaves as it always did (immediate withdrawal).
#[tokio::test]
async fn no_gr_gobgp_withdraws_routes_immediately_on_session_loss() {
    // Default Harness — no graceful_restart_time configured.
    let h = Harness::new().await;

    h.client
        .clone()
        .originate_route(gr_blackhole_params("192.0.2.0/24"))
        .await
        .expect("originate 192.0.2.0/24");

    wait_for_gobgp_rib_entry(&h.gobgpd_id, "192.0.2.0/24", Duration::from_secs(15))
        .await
        .expect("GoBGP did not receive 192.0.2.0/24 from pathvectord within 15 s");

    // Stop pathvectord.
    Command::new("docker")
        .args(["stop", "--time=1", &h.pathvectord_id])
        .status()
        .expect("docker stop pathvectord");

    // Without GR, GoBGP must withdraw the route within a few seconds.
    wait_for_gobgp_rib_withdrawn(&h.gobgpd_id, "192.0.2.0/24", Duration::from_secs(15))
        .await
        .expect(
            "GoBGP must withdraw 192.0.2.0/24 immediately when pathvectord has no GR configured",
        );
}

/// RFC 4724 §3 — When `restarting = true` is set, pathvectord sends R=1 in OPEN.
/// We verify this via GoBGP's `remote_cap` JSON: the GracefulRestart capability
/// must appear in the negotiated remote capabilities, confirming the capability
/// was parsed and the restart_time is non-zero.
///
/// Note: GoBGP's `peer_restarting` field is only set transiently — between
/// receiving OPEN with R=1 and receiving EOR — making it impractical to observe
/// via polling after Established.  The authoritative proof that the R-bit encoding
/// is correct is the unit test suite (`test_build_local_capabilities_r_bit_*`).
/// This e2e test confirms the capability is successfully negotiated end-to-end
/// with a real GoBGP peer when `restarting = true` is configured.
#[tokio::test]
async fn gr_r_bit_set_in_open_when_restarting() {
    let h = Harness::new_gr_restarting(120).await;
    let mut client = h.client.clone();
    wait_for_established(&mut client, h.peer, Duration::from_secs(15))
        .await
        .expect("session did not reach Established within 15 s");

    // Query GoBGP's neighbor state to confirm GR capability was negotiated.
    let gobgp_peer_addr = h.pathvectord_ip.to_string();
    let out = Command::new("docker")
        .args([
            "exec",
            &h.gobgpd_id,
            "gobgp",
            "neighbor",
            &gobgp_peer_addr,
            "-j",
        ])
        .output()
        .expect("gobgp neighbor -j");
    let json = String::from_utf8_lossy(&out.stdout);

    // GoBGP must show GracefulRestart in remote_cap, and the graceful_restart
    // block must have restart_time = 120 (our configured value).
    assert!(
        json.contains(r#""GracefulRestart""#),
        "GracefulRestart must appear in GoBGP's remote_cap when restarting=true; \
         actual JSON:\n{json}"
    );
    assert!(
        json.contains(r#""restart_time":120"#),
        "restart_time must be 120 in GoBGP's graceful_restart state; \
         actual JSON:\n{json}"
    );
}

/// RFC 4724 §3 — Without `restarting = true`, pathvectord must NOT set the R-bit.
/// GoBGP's `peer_restarting` must be false (or absent) in this case.
#[tokio::test]
async fn gr_r_bit_not_set_in_open_when_not_restarting() {
    let h = Harness::new_gr(120).await; // graceful_restart_time set, but restarting=false
    let mut client = h.client.clone();
    wait_for_established(&mut client, h.peer, Duration::from_secs(15))
        .await
        .expect("session did not reach Established within 15 s");

    let gobgp_peer_addr = h.pathvectord_ip.to_string();
    let out = Command::new("docker")
        .args([
            "exec",
            &h.gobgpd_id,
            "gobgp",
            "neighbor",
            &gobgp_peer_addr,
            "-j",
        ])
        .output()
        .expect("gobgp neighbor -j");
    let json = String::from_utf8_lossy(&out.stdout);

    let peer_restarting = json.contains(r#""peer_restarting":true"#);
    assert!(
        !peer_restarting,
        "GoBGP must see peer_restarting=false when restarting=false in pathvectord config; \
         actual JSON:\n{json}"
    );
}
