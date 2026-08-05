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
    FaultInjectionHarness, Harness, wait_for_docker_log, wait_for_established, wait_for_route,
    wait_for_route_withdrawn,
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

/// RFC 4724 §3: "the receiver of the advertisement MUST ignore all but the
/// last instance of the Graceful Restart Capability." Over a real BGP
/// session with the real wire codec on both ends: the fault peer's OPEN
/// carries two GracefulRestart capabilities (restart_time=90, then 300);
/// pathvectord must end up recording the *last* one (300), not the first.
#[tokio::test]
async fn gr_duplicate_capabilities_last_instance_wins() {
    let mut h = FaultInjectionHarness::new("gr-duplicate-capabilities").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    wait_for_established(&mut h.client, fault_peer, Duration::from_secs(15))
        .await
        .expect("fault peer session did not reach Established within 15 s");

    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.peer_gr_restart_time, 300,
        "RFC 4724 §3: the last GracefulRestart instance (restart_time=300) \
         must be authoritative, not the first (restart_time=90)"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 9234 §4.2: "If multiple BGP Role Capabilities are received and not
/// all of them have the same value, then the BGP speaker MUST reject the
/// connection using the Role Mismatch Notification." Over a real BGP
/// session: the fault peer's OPEN carries two *differing* Role capabilities
/// (Customer, then Peer) — pathvectord must reject the connection outright,
/// never reaching Established, regardless of whatever Role (if any) it has
/// configured locally for this peer.
#[tokio::test]
async fn role_differing_duplicates_are_rejected() {
    let mut h = FaultInjectionHarness::new("role-differing-duplicates").await;
    assert_control_peer_established(&mut h).await;

    // Assert on what the mock actually observed over the wire, not just on
    // pathvectord's session state: a session that never reaches Established
    // is also consistent with the mock's own connection handling breaking
    // for a reason unrelated to Role Mismatch (the false-pass shape this
    // scenario was written to catch — see mock_bgp_fault_peer.rs's
    // `role_differing_duplicates_open` doc comment). Requiring this exact
    // line in the mock's logs proves pathvectord actually sent a Role
    // Mismatch NOTIFICATION (code 2, subcode 11), not merely that some
    // connection failure occurred.
    wait_for_docker_log(
        &h.fault_peer_container_id,
        "SCENARIO_OUTCOME: role_mismatch_notification_received",
        Duration::from_secs(10),
    )
    .await
    .expect(
        "RFC 9234 §4.2: pathvectord must send a Role Mismatch NOTIFICATION to a peer \
         advertising two differing Role capabilities",
    );

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_ne!(
        state.session_state,
        SessionState::Established,
        "RFC 9234 §4.2: an OPEN carrying two differing Role capabilities \
         must be rejected (Role Mismatch), never reaching Established"
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

/// RFC 7606 §3(d): "If any of the well-known mandatory attributes are not
/// present in an UPDATE message, then 'treat-as-withdraw' MUST be used." —
/// distinct from the invalid-value case above: here ORIGIN is missing
/// entirely, not present-but-malformed. Over a real BGP session with the
/// real wire codec on both ends, proving both the withdrawal (RFC 7606 §2:
/// "removed from the Adj-RIB-In") and — the one thing the invalid-value test
/// above only proves indirectly via the control peer — that the fault
/// peer's *own* session stays Established rather than being torn down with
/// a NOTIFICATION (the pre-fix, RFC-4271-§6.3-only behavior).
#[tokio::test]
async fn missing_mandatory_origin_treated_as_withdraw_session_stays_up() {
    let mut h = FaultInjectionHarness::new("missing-origin").await;
    assert_control_peer_established(&mut h).await;

    // The first, clean UPDATE must land.
    wait_for_route(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 did not appear in Loc-RIB within 15 s");

    // The second UPDATE (missing ORIGIN) must be treated as a withdraw per
    // RFC 7606 §3(d)/§2 — the route disappears, but the session and the
    // rest of the daemon stay healthy.
    wait_for_route_withdrawn(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 was not withdrawn within 15 s after the UPDATE missing ORIGIN");

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.session_state,
        SessionState::Established,
        "RFC 7606 §3(d): the fault peer's own session must stay Established, \
         not be reset with a NOTIFICATION"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 7606 §3(c) (revising RFC 4271 §4.3): "If the value of either the
/// Optional or Transitive bits in the Attribute Flags is in conflict with
/// their specified values, then the attribute MUST be treated as malformed
/// and the 'treat-as-withdraw' approach used." Distinct from the
/// invalid-*value* case above: here ORIGIN's value is valid (IGP) but its
/// flags byte wrongly marks it Optional — a check that didn't exist at all
/// before this fix, so this proves the mechanism itself, not just a
/// particular value it happens to reject. Also proves the fault peer's own
/// session stays Established (treat-as-withdraw, not a NOTIFICATION/reset),
/// same rigor as the missing-ORIGIN test above.
#[tokio::test]
async fn attribute_flags_conflict_treated_as_withdraw_session_stays_up() {
    let mut h = FaultInjectionHarness::new("attribute-flags-conflict").await;
    assert_control_peer_established(&mut h).await;

    // The first, clean UPDATE must land.
    wait_for_route(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 did not appear in Loc-RIB within 15 s");

    // The second UPDATE (ORIGIN with conflicting flags) must be treated as a
    // withdraw per RFC 7606 §3(c) — the route disappears, but the session
    // and the rest of the daemon stay healthy.
    wait_for_route_withdrawn(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect(
            "10.99.0.0/24 was not withdrawn within 15 s after the UPDATE with conflicting flags",
        );

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.session_state,
        SessionState::Established,
        "RFC 7606 §3(c): the fault peer's own session must stay Established, \
         not be reset with a NOTIFICATION"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 9234 §5: "The OTC Attribute is considered malformed if the length
/// value is not 4. An UPDATE message with a malformed OTC Attribute SHALL be
/// handled using the approach of 'treat-as-withdraw' \[RFC7606\]." Security-
/// relevant: proves a malformed OTC causes the *route* to be withdrawn
/// rather than the attribute being silently discarded and the route
/// accepted as if OTC had never been present — which would let a route
/// bypass OTC-based leak detection entirely.
#[tokio::test]
async fn malformed_otc_treated_as_withdraw_session_stays_up() {
    let mut h = FaultInjectionHarness::new("malformed-otc").await;
    assert_control_peer_established(&mut h).await;

    // The first, clean UPDATE must land.
    wait_for_route(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 did not appear in Loc-RIB within 15 s");

    // The second UPDATE (3-byte OTC instead of 4) must be treated as a
    // withdraw per RFC 9234 §5 — the route disappears, but the session and
    // the rest of the daemon stay healthy.
    wait_for_route_withdrawn(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 was not withdrawn within 15 s after the malformed-length OTC UPDATE");

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.session_state,
        SessionState::Established,
        "RFC 9234 §5: the fault peer's own session must stay Established, \
         not be reset with a NOTIFICATION"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 4271 §5.1.5: "If it is contained in an UPDATE message that is
/// received from an external peer, then this attribute MUST be ignored by
/// the receiving speaker." Unlike every other scenario in this file, the
/// UPDATE here is entirely well-formed — proves policy-violating-but-valid
/// input is handled correctly, not just malformed bytes. Over a real BGP
/// session with the real wire codec, not just hand-built `Route` structs in
/// unit tests: an eBGP peer's bogus `u32::MAX` LOCAL_PREF must never surface
/// in the installed route, and the session must stay Established throughout
/// since nothing here is actually malformed.
#[tokio::test]
async fn ebgp_local_pref_is_ignored_session_stays_up() {
    let mut h = FaultInjectionHarness::new("ebgp-local-pref").await;
    assert_control_peer_established(&mut h).await;

    let route = wait_for_route(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 did not appear in Loc-RIB within 15 s");
    assert_eq!(
        route.local_pref, None,
        "RFC 4271 §5.1.5: LOCAL_PREF received from an external peer MUST be \
         ignored — the fault peer's u32::MAX LOCAL_PREF must not surface in \
         the installed route"
    );

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.session_state,
        SessionState::Established,
        "nothing in this UPDATE is malformed — the fault peer's own session \
         must stay Established"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 7606 §3(g)/(h): unlike every other malformed-UPDATE scenario in this
/// file, a duplicated MP_REACH_NLRI must NOT be treated as a withdraw — it
/// is the one per-attribute error RFC 7606 escalates back to a full session
/// reset (a Malformed Attribute List NOTIFICATION). Over a real BGP session
/// with the real wire codec on both ends, proving the fault peer's own
/// session actually leaves Established, while the control peer's session
/// stays completely unaffected.
#[tokio::test]
async fn duplicate_mp_reach_nlri_resets_session() {
    let mut h = FaultInjectionHarness::new("duplicate-mp-reach").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;

    // Anchor on the fault peer actually reaching Established first.
    // `SessionState` only has two variants (`Idle` covers every
    // pre-Established FSM state, `Established` the rest) and
    // `FaultInjectionHarness::new` only waits for the *control* peer — so
    // without this, the poll loop below could observe `Idle` because the
    // fault peer simply hasn't finished its handshake yet, and treat that
    // as "correctly reset" without the RFC 7606 §3(g) behavior ever having
    // been exercised at all.
    wait_for_established(&mut h.client, fault_peer, Duration::from_secs(15))
        .await
        .expect("fault peer session did not reach Established before the fault UPDATE");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let state = h
            .client
            .get_peer(IpAddr::from(fault_peer))
            .await
            .expect("get_peer(fault_peer) gRPC call succeeded");
        if state.session_state != SessionState::Established {
            break;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "RFC 7606 §3(g): session with a duplicated MP_REACH_NLRI must leave \
             Established within 15 s, not stay up like every other RFC 7606 case"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Throughline: the fault must not have wedged the daemon or affected
    // unrelated sessions.
    assert_control_peer_established(&mut h).await;
}

/// RFC 5065 §5 condition 1: "It is an error for a BGP speaker to receive an
/// UPDATE message with an AS_PATH attribute that contains AS_CONFED_SEQUENCE
/// or AS_CONFED_SET segments from a neighbor that is not located in the same
/// confederation." The fault peer is configured as a plain `External` peer
/// (no `confederation_member`), so its AS_CONFED_SEQUENCE segment is
/// malformed. Since the UPDATE carries reachable NLRI, RFC 7606 §3(e)
/// reclassifies this as treat-as-withdraw — over a real BGP session with the
/// real wire codec on both ends, not just the hand-built `UpdateMessage`
/// structs `pathvectord`'s own unit tests use.
#[tokio::test]
async fn rfc5065_confed_segment_with_nlri_treated_as_withdraw_session_stays_up() {
    let mut h = FaultInjectionHarness::new("rfc5065-confed-segment-with-nlri").await;
    assert_control_peer_established(&mut h).await;

    // The first, clean UPDATE must land.
    wait_for_route(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 did not appear in Loc-RIB within 15 s");

    // The second UPDATE (AS_CONFED_SEQUENCE from an External peer) must be
    // treated as a withdraw per RFC 5065 §5 / RFC 7606 §3(e) — the route
    // disappears, but the session and the rest of the daemon stay healthy.
    wait_for_route_withdrawn(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 was not withdrawn within 15 s after the AS_CONFED_SEQUENCE UPDATE");

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.session_state,
        SessionState::Established,
        "RFC 5065 §5 / RFC 7606 §3(e): the fault peer's own session must stay \
         Established, not be reset with a NOTIFICATION"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 5065 §5 condition 1 again, but sent as the *only* UPDATE with no
/// reachable NLRI at all. RFC 7606 §5.2: treat-as-withdraw would be a no-op
/// with nothing to withdraw, so this must instead reset the session with a
/// `MalformedAsPath` NOTIFICATION — the one RFC 5065 §5 case (alongside the
/// with-NLRI case above) that isn't treat-as-withdraw. Mirrors
/// `duplicate_mp_reach_nlri_resets_session`'s polling shape.
///
/// Asserts on the mock's own decoded view of the NOTIFICATION, not just
/// "left Established" — a session that drops for an unrelated reason (e.g.
/// a hold-timer expiry racing the test) would also leave Established,
/// which is exactly the false-pass shape `role_differing_duplicates_are_rejected`
/// guards against with the same `wait_for_docker_log` pattern.
#[tokio::test]
async fn rfc5065_confed_segment_no_nlri_resets_session() {
    let mut h = FaultInjectionHarness::new("rfc5065-confed-segment-no-nlri").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    // Anchor on the fault peer actually reaching Established first — see
    // `duplicate_mp_reach_nlri_resets_session`'s comment on why this matters.
    wait_for_established(&mut h.client, fault_peer, Duration::from_secs(15))
        .await
        .expect("fault peer session did not reach Established before the fault UPDATE");

    wait_for_docker_log(
        &h.fault_peer_container_id,
        "SCENARIO_OUTCOME: malformed_as_path_notification_received",
        Duration::from_secs(15),
    )
    .await
    .expect(
        "RFC 7606 §5.2: pathvectord must send a MalformedAsPath NOTIFICATION for a \
         malformed AS_PATH with no reachable NLRI",
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let state = h
            .client
            .get_peer(IpAddr::from(fault_peer))
            .await
            .expect("get_peer(fault_peer) gRPC call succeeded");
        if state.session_state != SessionState::Established {
            break;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "RFC 7606 §5.2: session with a malformed AS_PATH and no reachable NLRI \
             must leave Established within 15 s, not stay up like the with-NLRI case"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Throughline: the fault must not have wedged the daemon or affected
    // unrelated sessions.
    assert_control_peer_established(&mut h).await;
}

/// RFC 5065 §5 condition 2: "a UPDATE... received... with an AS_PATH
/// attribute that does not start with an AS_CONFED_SEQUENCE... from a
/// neighbor that is located in the same confederation." Unlike condition 1
/// (above), this fault peer IS configured as `confederation_member = true`
/// (see [`FaultInjectionHarness::new_confed_member`]) — the fault is an
/// ordinary AS_SEQUENCE-first AS_PATH from a peer pathvectord believes is a
/// fellow Member-AS. Since the UPDATE carries reachable NLRI, RFC 7606
/// §3(e) reclassifies this as treat-as-withdraw.
#[tokio::test]
async fn rfc5065_confed_member_wrong_first_segment_with_nlri_treated_as_withdraw_session_stays_up()
{
    let mut h = FaultInjectionHarness::new_confed_member(
        "rfc5065-confed-member-wrong-first-segment-with-nlri",
    )
    .await;
    assert_control_peer_established(&mut h).await;

    // The first, clean UPDATE (leading AS_CONFED_SEQUENCE) must land.
    wait_for_route(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 did not appear in Loc-RIB within 15 s");

    // The second UPDATE (AS_SEQUENCE-first AS_PATH from a confed-member
    // peer) must be treated as a withdraw per RFC 5065 §5 condition 2 / RFC
    // 7606 §3(e) — the route disappears, but the session and the rest of
    // the daemon stay healthy.
    wait_for_route_withdrawn(&mut h.client, "10.99.0.0/24", Duration::from_secs(15))
        .await
        .expect("10.99.0.0/24 was not withdrawn within 15 s after the AS_SEQUENCE-first UPDATE");

    let fault_peer = h.fault_peer;
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.session_state,
        SessionState::Established,
        "RFC 5065 §5 condition 2 / RFC 7606 §3(e): the fault peer's own session must \
         stay Established, not be reset with a NOTIFICATION"
    );

    assert_control_peer_established(&mut h).await;
}

/// RFC 5065 §5 condition 2 again, but sent as the *only* UPDATE with no
/// reachable NLRI at all. RFC 7606 §5.2: treat-as-withdraw would be a no-op
/// with nothing to withdraw, so this must instead reset the session with a
/// `MalformedAsPath` NOTIFICATION.
#[tokio::test]
async fn rfc5065_confed_member_wrong_first_segment_no_nlri_resets_session() {
    let mut h = FaultInjectionHarness::new_confed_member(
        "rfc5065-confed-member-wrong-first-segment-no-nlri",
    )
    .await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    wait_for_established(&mut h.client, fault_peer, Duration::from_secs(15))
        .await
        .expect("fault peer session did not reach Established before the fault UPDATE");

    wait_for_docker_log(
        &h.fault_peer_container_id,
        "SCENARIO_OUTCOME: malformed_as_path_notification_received",
        Duration::from_secs(15),
    )
    .await
    .expect(
        "RFC 7606 §5.2: pathvectord must send a MalformedAsPath NOTIFICATION for a \
         malformed (AS_SEQUENCE-first, confed-member peer) AS_PATH with no reachable NLRI",
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let state = h
            .client
            .get_peer(IpAddr::from(fault_peer))
            .await
            .expect("get_peer(fault_peer) gRPC call succeeded");
        if state.session_state != SessionState::Established {
            break;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "RFC 7606 §5.2: session with a malformed (AS_SEQUENCE-first, confed-member \
             peer) AS_PATH and no reachable NLRI must leave Established within 15 s, \
             not stay up like the with-NLRI case"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Throughline: the fault must not have wedged the daemon or affected
    // unrelated sessions.
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

/// RFC 5065 §4: a route can loop back into a confederation via the
/// confederation identifier itself (not just via a Member-AS Number) — e.g.
/// relayed out to a genuine external peer and back in through a different
/// Member-AS. A well-formed UPDATE whose AS_PATH contains the confederation
/// identifier must be silently dropped: the announced NLRI never reaches
/// pathvectord's own Loc-RIB, and the session stays Established throughout.
/// Currently unit-only in `route.rs`'s `has_loop` check — this proves it
/// over a real BGP session with the real wire codec on both ends.
#[tokio::test]
async fn confederation_id_in_as_path_is_treated_as_loop_and_dropped() {
    let mut h = FaultInjectionHarness::new_with_confederation_id("confederation-id-loop").await;
    assert_control_peer_established(&mut h).await;

    let fault_peer = h.fault_peer;
    wait_for_established(&mut h.client, fault_peer, Duration::from_secs(15))
        .await
        .expect("fault peer session did not reach Established within 15 s");

    // Give pathvectord a real window to have processed the UPDATE (and,
    // if the loop-detection check were broken, to have installed the
    // route) before asserting its absence.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let route = h
        .client
        .get_best_route("10.99.0.0/24")
        .await
        .expect("get_best_route gRPC call succeeded");
    assert!(
        route.is_none(),
        "RFC 5065 §4: a route whose AS_PATH contains the confederation identifier must be \
         silently dropped as a loop, never reaching Loc-RIB; got: {route:?}"
    );

    // The session itself must stay healthy — this is a policy-violating
    // but well-formed UPDATE, not a wire-format fault.
    let state = h
        .client
        .get_peer(IpAddr::from(fault_peer))
        .await
        .expect("get_peer(fault_peer) gRPC call succeeded");
    assert_eq!(
        state.session_state,
        SessionState::Established,
        "RFC 5065 §4: a confederation-identifier loop must not affect the session itself"
    );

    assert_control_peer_established(&mut h).await;
}
