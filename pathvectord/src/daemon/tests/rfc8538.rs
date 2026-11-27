//! ── RFC 8538: Notification Support for Graceful Restart ──────────────────────

use std::net::{IpAddr, Ipv4Addr};

use pathvector_session::message::{
    Capability, CeaseError, GracefulRestartFamily, NotificationError, NotificationMessage,
    UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AfiSafi, AsPath, Asn, Nlri, Origin, PeerType};

use crate::config;
use crate::daemon::*;

const LOCAL_AS: u32 = 65001;
const PEER_AS: u32 = 65002;
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

/// Build a GR capability advertising the N-bit (RFC 8538 §2, bit 0x04).
fn gr_cap_with_n_bit(restart_time: u16) -> Capability {
    Capability::GracefulRestart {
        restart_flags: 0x04, // N-bit
        restart_time,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: false,
        }],
    }
}

/// Build a GR capability WITHOUT the N-bit (RFC 4724 only).
fn gr_cap_without_n_bit(restart_time: u16) -> Capability {
    Capability::GracefulRestart {
        restart_flags: 0x00,
        restart_time,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: false,
        }],
    }
}

fn make_state() -> DaemonState {
    let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
    let peer = config::PeerConfig {
        address: IpAddr::V4(PEER_IP),
        port: 179,
        remote_as: PEER_AS,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    // Build local capabilities with GR time 120 and N-bit set, matching a
    // realistic pathvectord deployment that participates in RFC 8538.
    let local_caps = build_local_capabilities(LOCAL_AS, 120, false, None);
    DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[peer],
        [(IpAddr::V4(PEER_IP), tx)].into(),
        local_caps,
    )
}

fn announce(prefixes: &[&str]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            pathvector_session::message::PathAttribute::Origin(Origin::Igp),
            pathvector_session::message::PathAttribute::AsPath(AsPath::from_sequence(vec![
                Asn::new(PEER_AS),
            ])),
            pathvector_session::message::PathAttribute::NextHop(PEER_IP),
        ],
        announced: prefixes.iter().map(|s| nlri(s)).collect(),
    }
}

fn establish(state: &mut DaemonState, caps: &[Capability]) {
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        caps,
        None,
    );
}

fn notification(error: NotificationError) -> TerminationReason {
    TerminationReason::Notification(NotificationMessage {
        error,
        data: vec![],
    })
}

/// RFC 8538 §4 — if both sides have the N-bit and the peer's NOTIFICATION is
/// not HardReset, the helper MUST open a GR window (not flush immediately).
#[test]
fn notification_non_hard_reset_with_n_bit_enters_gr_window() {
    let mut state = make_state();
    // Our daemon config uses graceful_restart_time > 0, so we advertise N-bit.
    // Simulate that by pre-populating gr_capable_peers (normally done by on_established
    // of our own session; here we inject it because our local GR config is what
    // drives this — any non-zero gr_restart_time means we have the N-bit).
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert_eq!(
        state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"])),
        None,
        "unexpected CEASE on route announce"
    );

    // Peer sends a non-HardReset NOTIFICATION (e.g. Hold Timer Expired).
    let reason = notification(NotificationError::HoldTimerExpired);
    state.on_terminated(IpAddr::V4(PEER_IP), reason, false);

    // GR window must be open: stale route still present in AdjRibIn.
    let adj_len = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_IP))
        .expect("AdjRibIn must still exist")
        .len();
    assert_eq!(
        adj_len, 1,
        "stale route must be retained in GR window after NOTIFICATION"
    );

    // A GR deadline must be scheduled.
    assert!(
        state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "GR deadline must be set after non-HardReset NOTIFICATION from N-capable peer"
    );
}

/// RFC 8538 §4 — CEASE/HardReset (subcode 9) MUST trigger immediate flush
/// even when both sides have the N-bit.
#[test]
fn notification_hard_reset_always_flushes() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert_eq!(
        state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"])),
        None,
        "unexpected CEASE on route announce"
    );

    let reason = notification(NotificationError::Cease(CeaseError::HardReset));
    state.on_terminated(IpAddr::V4(PEER_IP), reason, false);

    let adj_len = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_IP))
        .map_or(0, pathvector_rib::AdjRibIn::len);
    assert_eq!(
        adj_len, 0,
        "CEASE/HardReset must flush routes immediately, even with N-bit"
    );
    assert!(
        !state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "no GR deadline must be set after HardReset"
    );
}

/// RFC 8538 §4 — if the peer did NOT advertise the N-bit, any NOTIFICATION
/// must flush immediately (RFC 4724 §4.2 behaviour preserved).
#[test]
fn notification_without_peer_n_bit_flushes() {
    let mut state = make_state();
    // Peer has GR but NOT the N-bit.
    establish(&mut state, &[gr_cap_without_n_bit(120)]);
    assert_eq!(
        state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"])),
        None,
        "unexpected CEASE on route announce"
    );

    // Non-HardReset notification, but peer didn't negotiate N-bit.
    let reason = notification(NotificationError::HoldTimerExpired);
    state.on_terminated(IpAddr::V4(PEER_IP), reason, false);

    let adj_len = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_IP))
        .map_or(0, pathvector_rib::AdjRibIn::len);
    assert_eq!(
        adj_len, 0,
        "NOTIFICATION from non-N-capable peer must flush routes (RFC 4724 §4.2)"
    );
    assert!(
        !state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "no GR deadline when peer has no N-bit"
    );
}

/// RFC 9687 Send Hold Timer expiry is a NOTIFICATION this side generates.
/// RFC 8538 §4: "The BGP speaker generating the BGP NOTIFICATION message
/// MUST also follow the rules for the Receiving Speaker" — with the N bit
/// exchanged, the peer's routes are retained as stale.
#[test]
fn send_hold_expiry_with_n_bit_enters_gr_window() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert_eq!(
        state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"])),
        None
    );

    state.on_terminated(
        IpAddr::V4(PEER_IP),
        TerminationReason::SendHoldTimerExpired,
        false,
    );

    assert_eq!(state.adj_ribs_in[&IpAddr::V4(PEER_IP)].len(), 1);
    assert!(state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)));
}

/// Without the N bit it is an ordinary NOTIFICATION teardown (RFC 4271
/// §8.2.2, "releases all BGP resources"), not the silent TCP failure
/// RFC 4724 §4.2 retains routes for: a peer stuck badly enough to be
/// closed must not keep its routes installed.
#[test]
fn send_hold_expiry_without_n_bit_flushes() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_without_n_bit(120)]);
    assert_eq!(
        state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"])),
        None
    );

    state.on_terminated(
        IpAddr::V4(PEER_IP),
        TerminationReason::SendHoldTimerExpired,
        false,
    );

    let adj_len = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_IP))
        .map_or(0, pathvector_rib::AdjRibIn::len);
    assert_eq!(adj_len, 0);
    assert!(!state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)));
}

/// OperatorStop must always flush, regardless of GR capability or N-bit.
#[test]
fn operator_stop_always_flushes() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert_eq!(
        state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"])),
        None,
        "unexpected CEASE on route announce"
    );

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::OperatorStop, false);

    let adj_len = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_IP))
        .map_or(0, pathvector_rib::AdjRibIn::len);
    assert_eq!(
        adj_len, 0,
        "OperatorStop must always flush routes immediately"
    );
    assert!(
        !state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "no GR deadline on OperatorStop"
    );
}

/// RFC 8538 §2 — `build_local_capabilities` must set the N-bit (0x04) in
/// `restart_flags` whenever `graceful_restart_time > 0`.
#[test]
fn build_local_capabilities_sets_n_bit_when_gr_enabled() {
    let caps = build_local_capabilities(LOCAL_AS, 120, false, None);
    let gr_cap = caps.iter().find_map(|c| {
        if let Capability::GracefulRestart {
            restart_flags,
            restart_time,
            ..
        } = c
        {
            Some((*restart_flags, *restart_time))
        } else {
            None
        }
    });
    let (flags, time) = gr_cap.expect("GracefulRestart capability must be present");
    assert_eq!(time, 120, "restart_time must be threaded through");
    assert_ne!(
        flags & 0x04,
        0,
        "N-bit must be set when graceful_restart_time > 0"
    );
    assert_eq!(
        flags & 0x08,
        0,
        "R-bit must be clear on non-restarting startup"
    );
}

/// When graceful_restart_time = 0, N-bit must NOT be set.
#[test]
fn build_local_capabilities_no_n_bit_when_gr_disabled() {
    let caps = build_local_capabilities(LOCAL_AS, 0, false, None);
    let gr_cap = caps.iter().find_map(|c| {
        if let Capability::GracefulRestart {
            restart_flags,
            restart_time,
            ..
        } = c
        {
            Some((*restart_flags, *restart_time))
        } else {
            None
        }
    });
    let (flags, time) = gr_cap.expect("GracefulRestart capability must be present");
    assert_eq!(time, 0);
    assert_eq!(flags & 0x04, 0, "N-bit must not be set when GR is disabled");
}

/// N-bit from peer's OPEN must be tracked in gr.notification_capable_peers.
#[test]
fn n_bit_peer_tracked_on_established() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert!(
        state
            .gr
            .notification_capable_peers
            .contains(&IpAddr::V4(PEER_IP)),
        "peer advertising N-bit must be in notification_capable_peers"
    );
}

/// Peer without N-bit must NOT be tracked in notification_capable_peers.
#[test]
fn non_n_bit_peer_not_tracked_on_established() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_without_n_bit(120)]);
    assert!(
        !state
            .gr
            .notification_capable_peers
            .contains(&IpAddr::V4(PEER_IP)),
        "peer without N-bit must not be in notification_capable_peers"
    );
}

/// N-bit tracking must be cleared when the peer re-establishes without the N-bit.
#[test]
fn n_bit_cleared_when_peer_re_establishes_without_it() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert!(
        state
            .gr
            .notification_capable_peers
            .contains(&IpAddr::V4(PEER_IP))
    );

    // Re-establish without N-bit.
    establish(&mut state, &[gr_cap_without_n_bit(120)]);
    assert!(
        !state
            .gr
            .notification_capable_peers
            .contains(&IpAddr::V4(PEER_IP)),
        "N-bit tracking must be cleared when peer re-establishes without it"
    );
}

/// RFC 8538 §4 — if WE don't have the N-bit (our graceful_restart_time = 0),
/// a NOTIFICATION from an N-capable peer must still flush immediately.
/// This verifies the we_have_n_bit check reads from our own config_capabilities,
/// not the peer's gr_restart_time.
#[test]
fn notification_flushes_when_local_daemon_has_no_gr() {
    let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
    let peer = config::PeerConfig {
        address: IpAddr::V4(PEER_IP),
        port: 179,
        remote_as: PEER_AS,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    // Local daemon has graceful_restart_time = 0 → no N-bit advertised.
    let mut state = DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &[peer],
        [(IpAddr::V4(PEER_IP), tx)].into(),
        build_local_capabilities(LOCAL_AS, 0, false, None),
    );
    // Peer advertises N-bit, but we don't → notification mode must NOT engage.
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert_eq!(
        state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"])),
        None,
        "unexpected CEASE on announce"
    );

    let reason = notification(NotificationError::HoldTimerExpired);
    state.on_terminated(IpAddr::V4(PEER_IP), reason, false);

    let adj_len = state
        .adj_ribs_in
        .get(&IpAddr::V4(PEER_IP))
        .map_or(0, pathvector_rib::AdjRibIn::len);
    assert_eq!(
        adj_len, 0,
        "NOTIFICATION must flush when local daemon has no N-bit (graceful_restart_time = 0)"
    );
    assert!(
        !state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "no GR deadline when local daemon has no N-bit"
    );
}

/// N-bit tracking must be cleared on peer removal.
#[test]
fn n_bit_cleared_on_remove_peer() {
    let mut state = make_state();
    establish(&mut state, &[gr_cap_with_n_bit(120)]);
    assert!(
        state
            .gr
            .notification_capable_peers
            .contains(&IpAddr::V4(PEER_IP))
    );
    state.remove_peer(IpAddr::V4(PEER_IP));
    assert!(
        !state
            .gr
            .notification_capable_peers
            .contains(&IpAddr::V4(PEER_IP)),
        "N-bit tracking must be cleared on remove_peer"
    );
}
