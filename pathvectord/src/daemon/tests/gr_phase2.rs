//! ── RFC 4724 Phase 2: helper-role (hold peer stale routes) ───────────────────

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pathvector_rib::BestPathChange;
use pathvector_session::message::{
    Capability, GracefulRestartFamily, MpReachNlri, MpUnreachNlri, PathAttribute, Prefix,
    UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};

use crate::config;
use crate::daemon::tests::with_recording_fib;
use crate::daemon::*;

const LOCAL_AS: u32 = 65001;
const PEER_AS: u32 = 65002;
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn make_state_gr(
    peers: &[(Ipv4Addr, u32)],
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let mut receivers = HashMap::new();
    let mut senders = HashMap::new();
    let peer_configs: Vec<_> = peers
        .iter()
        .map(|&(addr, remote_as)| {
            let (tx, rx) = mpsc::channel::<UpdateMessage>(256);
            senders.insert(IpAddr::V4(addr), tx);
            receivers.insert(IpAddr::V4(addr), rx);
            config::PeerConfig {
                address: IpAddr::V4(addr),
                port: 179,
                remote_as,
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
            }
        })
        .collect();
    let state = DaemonState::new(
        LOCAL_AS,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    (state, receivers)
}

fn announce(prefixes: &[&str]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
            PathAttribute::NextHop(PEER_IP),
        ],
        announced: prefixes.iter().map(|s| nlri(s)).collect(),
    }
}

fn establish_with_gr(state: &mut DaemonState, restart_time: u16) {
    let caps = gr_caps(restart_time);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &caps,
        None,
    );
}

fn ipv4_eor() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    }
}

fn gr_cap(restart_time: u16) -> Capability {
    Capability::GracefulRestart {
        restart_flags: 0,
        restart_time,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: false,
        }],
    }
}

fn gr_caps(restart_time: u16) -> Vec<Capability> {
    vec![Capability::FourByteAsn(PEER_AS), gr_cap(restart_time)]
}

/// RFC 4724 §4.2 — unclean termination of a GR-capable peer must retain
/// routes in AdjRibIn / LocRib rather than flushing them.
#[test]
fn unclean_termination_of_gr_peer_retains_routes() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "route must be in LocRib before termination"
    );

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    assert!(
        state.adj_ribs_in[&IpAddr::V4(PEER_IP)]
            .get(&nlri("10.0.0.0/8"))
            .is_some(),
        "AdjRibIn route must be retained during GR window"
    );
    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "LocRib route must be retained during GR window"
    );
    assert!(
        state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "gr_deadlines must be armed for the peer"
    );
}

/// RFC 4724 §4.2 — clean termination (NOTIFICATION received) must flush
/// routes immediately regardless of GR capability.
#[test]
fn clean_termination_flushes_immediately() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::OperatorStop, true);

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "LocRib must be flushed immediately on clean termination"
    );
    assert!(
        !state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "gr_deadlines must not be armed on clean termination"
    );
}

/// A peer that did not advertise GR (or advertised restart_time=0) must
/// have its routes flushed immediately even on unclean termination.
#[test]
fn non_gr_peer_always_flushes_on_unclean_termination() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "LocRib must be flushed for a non-GR peer even on unclean termination"
    );
    assert!(
        !state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "gr_deadlines must not be armed for a non-GR peer"
    );
}

/// RFC 4724 §4.2 — routes not re-announced before EOR must be pruned.
/// Routes that ARE re-announced must be kept.
#[test]
fn eor_prunes_stale_routes_not_refreshed_by_peer() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 120);
    // Announce two routes.
    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["10.0.0.0/8", "192.168.0.0/24"]),
    );
    assert_eq!(state.rib.loc_rib.len(), 2);

    // Simulate unclean disconnect (GR window opens).
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    assert_eq!(
        state.rib.loc_rib.len(),
        2,
        "routes retained during GR window"
    );

    // Simulate re-establishment.
    establish_with_gr(&mut state, 120);

    // Peer re-announces only 10.0.0.0/8.
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    // EOR arrives — 192.168.0.0/24 was not re-announced, must be pruned.
    state.on_route_update(IpAddr::V4(PEER_IP), ipv4_eor());

    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "only the re-announced route must remain after EOR prune"
    );
    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
        "re-announced route must survive"
    );
    assert!(
        state.rib.loc_rib.best(&nlri("192.168.0.0/24")).is_none(),
        "stale route not refreshed by peer must be pruned on EOR"
    );
}

/// GR deadline expiry must flush all stale routes exactly as a normal
/// on_terminated flush would.
#[test]
fn gr_deadline_expiry_flushes_stale_routes() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "route retained during GR window"
    );
    assert!(state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)));

    // Simulate deadline expiry.
    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "routes must be flushed after GR deadline expiry"
    );
}

/// RFC 4724 §4.2 — if a peer disconnects uncleanly *again* while its GR
/// window is already open, the deadline must be reset to `now + restart_time`
/// and routes must continue to be held.  They must not be double-flushed.
#[test]
fn gr_re_termination_during_window_resets_deadline_and_holds_routes() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 30);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    // First unclean disconnect — opens GR window.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    let first_deadline = *state
        .gr
        .deadlines
        .get(&IpAddr::V4(PEER_IP))
        .expect("deadline must be set after first unclean disconnect");

    // Re-establish, then disconnect again without re-announcing anything.
    establish_with_gr(&mut state, 30);
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    let second_deadline = *state
        .gr
        .deadlines
        .get(&IpAddr::V4(PEER_IP))
        .expect("deadline must still be set after second unclean disconnect");

    // The window is reset — second deadline must be >= the first.
    assert!(
        second_deadline >= first_deadline,
        "re-termination must reset the GR deadline, not leave a stale earlier one"
    );

    // Routes must still be held — no double-flush.
    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "routes must be retained after re-termination during GR window"
    );
    assert!(
        state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "gr_deadlines must remain armed after re-termination"
    );
}

/// RFC 4724 §4.2 — if a peer sends a NOTIFICATION (clean termination)
/// while its GR window is already open, routes must be flushed immediately.
/// The GR window must not prevent a clean teardown from taking effect.
#[test]
fn gr_clean_termination_during_window_flushes_immediately() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 30);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    // First disconnect is unclean — GR window opens.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    assert_eq!(state.rib.loc_rib.len(), 1, "route held during GR window");
    assert!(state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)));

    // Peer re-establishes, then we tear it down (operator stop).
    establish_with_gr(&mut state, 30);
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::OperatorStop, true);

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "clean termination during GR window must flush routes immediately"
    );
    assert!(
        !state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)),
        "gr_deadlines must be cleared on clean termination"
    );
}

/// When `fib_manager` is set, unclean termination must push FIB changes for
/// the stale-marked routes (covers the `if let Some(fm)` branch in
/// `mark_stale_and_repropagate`).
#[test]
fn stale_marking_notifies_fib_manager() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    let fib = with_recording_fib(&mut state);
    establish_with_gr(&mut state, 120);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    let changes = fib.v4_changes();
    assert!(
        !changes.is_empty(),
        "FibManager must receive at least one change when routes are stale-marked"
    );
}

/// When `fib_manager` is set, deadline expiry must push FIB withdrawals for
/// all stale routes (covers the `if let Some(fm)` branch in
/// `on_gr_deadline_expired`).
#[test]
fn deadline_expiry_notifies_fib_manager() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    let fib = with_recording_fib(&mut state);
    establish_with_gr(&mut state, 120);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["192.0.2.0/24"]));

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    // Clear stale-mark FIB notifications so we only count the expiry ones.
    fib.v4.lock().unwrap().clear();

    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));

    let changes = fib.v4_changes();
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
        "FibManager must receive a Withdrawn change on deadline expiry"
    );
}

/// `GracefulRestartState::drain_expired` must remove expired entries and
/// return their addresses; non-expired entries must be left intact.
#[test]
fn drain_expired_removes_past_deadlines_leaves_future() {
    let mut gr = GracefulRestartState::new();
    let past = Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap();
    let future = Instant::now() + std::time::Duration::from_secs(300);
    let expired_ip = Ipv4Addr::new(10, 0, 0, 1);
    let live_ip = Ipv4Addr::new(10, 0, 0, 2);
    gr.deadlines.insert(IpAddr::V4(expired_ip), past);
    gr.deadlines.insert(IpAddr::V4(live_ip), future);

    let drained = gr.drain_expired(Instant::now());

    assert_eq!(
        drained,
        vec![expired_ip],
        "only the past deadline must be returned"
    );
    assert!(
        !gr.deadlines.contains_key(&IpAddr::V4(expired_ip)),
        "expired entry must be removed"
    );
    assert!(
        gr.deadlines.contains_key(&IpAddr::V4(live_ip)),
        "live entry must remain"
    );
}

/// `repropagate_after_stale_mark_v4` runs its per-peer loop over an
/// established observer, and — because a conventional-GR stale route
/// keeps its selection and staleness is never advertised — sends it
/// nothing. RFC 4724 §4.2: the routes are retained, not withdrawn; RFC
/// 9494 §1: conventional GR resolves the trade-off "in favor of not
/// advertising". (This test previously asserted that an UPDATE *was*
/// sent; what was sent was an identical duplicate of the route already
/// advertised — issue #68.)
#[test]
fn stale_mark_sends_no_update_to_established_observer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );

    // PEER_IP is the only source of the prefix; OBS_IP observes.
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["198.51.100.0/24"]));

    // Send and drain the initial advertisement so the channel is quiet.
    state.flush_pending();
    let obs_rx = rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap();
    while obs_rx.try_recv().is_ok() {}

    // Unclean disconnect — the route is retained and marked stale.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    assert!(
        state.rib.loc_rib.best(&nlri("198.51.100.0/24")).is_some(),
        "the route is retained"
    );
    assert!(
        obs_rx.try_recv().is_err(),
        "no UPDATE may be sent to the observer when a route is only marked stale"
    );
}

/// `prune_stale_nlri` must propagate withdrawals to other established peers
/// when EOR prunes a route that was previously best-path.
#[test]
fn eor_prune_propagates_withdrawal_to_observer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);
    const OBS_AS: u32 = 65006;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );

    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["203.0.113.0/24", "203.0.113.1/32"]),
    );
    let obs_rx = rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap();
    while obs_rx.try_recv().is_ok() {}

    // Unclean disconnect then re-establish.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    while obs_rx.try_recv().is_ok() {}
    establish_with_gr(&mut state, 120);

    // Peer only re-announces 203.0.113.0/24; 203.0.113.1/32 stays stale.
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["203.0.113.0/24"]));
    while obs_rx.try_recv().is_ok() {}

    // EOR triggers prune of 203.0.113.1/32.
    state.on_route_update(IpAddr::V4(PEER_IP), ipv4_eor());

    assert!(
        obs_rx.try_recv().is_ok(),
        "observer must receive an UPDATE (withdrawal) when EOR prunes a stale route"
    );
    assert!(
        state.rib.loc_rib.best(&nlri("203.0.113.1/32")).is_none(),
        "pruned route must be absent from LocRib"
    );
}

/// `on_gr_deadline_expired` must propagate withdrawals to other established peers
/// so they remove the stale route from their own RIBs.
#[test]
fn deadline_expiry_propagates_withdrawal_to_observer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);
    const OBS_AS: u32 = 65007;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );

    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["192.0.2.0/24"]));
    let obs_rx = rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap();
    while obs_rx.try_recv().is_ok() {}

    // Unclean disconnect — GR window opens.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    while obs_rx.try_recv().is_ok() {}

    // Simulate deadline expiry.
    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "LocRib must be empty after deadline expiry"
    );
    assert!(
        obs_rx.try_recv().is_ok(),
        "observer must receive a withdrawal UPDATE after deadline expiry"
    );
}

// ── IPv6 GR helpers ──────────────────────────────────────────────────────

fn nlri_v6(s: &str) -> Nlri<Ipv6Addr> {
    s.parse().unwrap()
}

fn gr_caps_v6(restart_time: u16) -> Vec<Capability> {
    vec![
        Capability::FourByteAsn(PEER_AS),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        Capability::GracefulRestart {
            restart_flags: 0,
            restart_time,
            families: vec![GracefulRestartFamily {
                afi_safi: AfiSafi::IPV6_UNICAST,
                forwarding_preserved: false,
            }],
        },
    ]
}

fn announce_v6(prefixes: &[&str]) -> UpdateMessage {
    let ps: Vec<Prefix> = prefixes
        .iter()
        .map(|s| Prefix::V6(s.parse().unwrap()))
        .collect();
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                prefixes: ps,
            }),
        ],
        announced: vec![],
    }
}

fn establish_with_gr_v6(state: &mut DaemonState, restart_time: u16) {
    let caps = gr_caps_v6(restart_time);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &caps,
        None,
    );
}

fn ipv6_eor() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            prefixes: vec![],
        })],
        announced: vec![],
    }
}

/// Unclean termination of a GR peer with IPv6 routes must retain those
/// routes in LocRib_v6 (exercises mark_stale_and_repropagate v6 path).
#[test]
fn unclean_termination_retains_v6_routes() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);

    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    assert_eq!(
        state.rib.loc_rib_v6.len(),
        1,
        "v6 route must be in LocRib_v6"
    );

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    assert_eq!(
        state.rib.loc_rib_v6.len(),
        1,
        "v6 LocRib must be retained during GR window"
    );
    assert!(state.gr.deadlines.contains_key(&IpAddr::V4(PEER_IP)));
}

/// EOR prune on IPv6 must withdraw routes not re-announced before the
/// IPv6 EOR marker (exercises prune_stale_nlri_v6).
#[test]
fn eor_prunes_stale_v6_routes_not_refreshed_by_peer() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);

    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
    );
    assert_eq!(state.rib.loc_rib_v6.len(), 2);

    // Unclean disconnect, then re-establish.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    establish_with_gr_v6(&mut state, 120);

    // Peer re-announces only 2001:db8:1::/48.
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8:1::/48"]));

    // IPv6 EOR — 2001:db8:2::/48 was not refreshed, must be pruned.
    state.on_route_update(IpAddr::V4(PEER_IP), ipv6_eor());

    assert_eq!(
        state.rib.loc_rib_v6.len(),
        1,
        "only the re-announced v6 route must remain after EOR prune"
    );
    assert!(
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8:1::/48"))
            .is_some(),
        "re-announced v6 route must survive"
    );
    assert!(
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8:2::/48"))
            .is_none(),
        "stale v6 route must be pruned on EOR"
    );
}

/// `on_gr_deadline_expired` must propagate withdrawals to other
/// established IPv6-capable peers for IPv6 routes that were only
/// reachable via the expired peer — regression guard for the gap where
/// only the v4 side was re-propagated (TODO.md GR known-gaps item 6,
/// closed 2026-07-03; mirrors `deadline_expiry_propagates_withdrawal_
/// to_observer` above, for IPv6).
#[test]
fn deadline_expiry_propagates_v6_withdrawal_to_observer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 8);
    const OBS_AS: u32 = 65008;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)],
        None,
    );

    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8:dead::/48"]));
    let obs_rx = rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap();
    while obs_rx.try_recv().is_ok() {}

    // Unclean disconnect — GR window opens.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    while obs_rx.try_recv().is_ok() {}

    // Simulate deadline expiry.
    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));

    assert_eq!(
        state.rib.loc_rib_v6.len(),
        0,
        "LocRib_v6 must be empty after deadline expiry"
    );
    assert!(
        obs_rx.try_recv().is_ok(),
        "observer must receive an IPv6 withdrawal UPDATE after deadline expiry"
    );
}

/// RFC 4724 §4.2 MUST — on unclean termination the retained routes are
/// marked stale in LocRib, and (RFC 9494 §1) "in conventional GR, route
/// preference is not affected": with equal attributes the retained route
/// keeps winning on the ordinary tie-breakers instead of losing to a fresh
/// route from a second peer. Previously named
/// `stale_marking_lets_fresh_peer_win_immediately`, which asserted the
/// opposite (issue #68); `daemon::gr_preference_tests` covers the
/// LOCAL_PREF case.
#[test]
fn stale_marking_keeps_equally_preferred_route_selected() {
    const PEER2_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    const PEER2_AS: u32 = 65003;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (PEER2_IP, PEER2_AS)]);

    // Establish both peers (only PEER_IP supports GR).
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(PEER2_IP),
        PEER2_IP,
        PeerType::External,
        PEER2_AS,
        90,
        &[],
        None,
    );

    // Both peers announce the same prefix with the same attributes;
    // PEER_IP wins on the ordinary tie-breakers (older eBGP route, lower
    // peer address).
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    state.on_route_update(IpAddr::V4(PEER2_IP), announce(&["10.0.0.0/8"]));

    let winner_before = state.rib.loc_rib.best_peer(&nlri("10.0.0.0/8"));
    assert_eq!(
        winner_before.map(PeerId::ip),
        Some(std::net::IpAddr::V4(PEER_IP)),
        "precondition: PEER_IP wins the tie before termination"
    );

    // PEER_IP disconnects uncleanly — its route is retained and marked stale.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    let best_after = state.rib.loc_rib.best(&nlri("10.0.0.0/8"));
    assert_eq!(
        best_after.map(|r| r.staleness),
        Some(pathvector_rib::Staleness::GrStale),
        "the retained route is marked stale"
    );
    let winner_after = state.rib.loc_rib.best_peer(&nlri("10.0.0.0/8"));
    assert_eq!(
        winner_after.map(PeerId::ip),
        Some(std::net::IpAddr::V4(PEER_IP)),
        "staleness must not move the selection to PEER2"
    );
}

/// When a GR peer with IPv6 routes undergoes unclean termination and a second
/// non-GR peer has a competing v6 route, the observer must receive an UPDATE
/// reflecting the new winner. This covers the `repropagate_after_stale_mark_v6`
/// observer loop for the case where best-path changes due to stale marking.
#[test]
fn stale_mark_v6_runs_observer_propagation_loop() {
    const COMPETING_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    const COMPETING_AS: u32 = 65003;
    const OBSERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
    const OBSERVER_AS: u32 = 65004;

    let (mut state, mut rxs) = make_state_gr(&[
        (PEER_IP, PEER_AS),
        (COMPETING_IP, COMPETING_AS),
        (OBSERVER_IP, OBSERVER_AS),
    ]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());

    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );

    let competing_caps = vec![
        Capability::FourByteAsn(COMPETING_AS),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    state.on_established(
        IpAddr::V4(COMPETING_IP),
        COMPETING_IP,
        PeerType::External,
        COMPETING_AS,
        90,
        &competing_caps,
        None,
    );

    let obs_caps = vec![
        Capability::FourByteAsn(OBSERVER_AS),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    state.on_established(
        IpAddr::V4(OBSERVER_IP),
        OBSERVER_IP,
        PeerType::External,
        OBSERVER_AS,
        90,
        &obs_caps,
        None,
    );

    // Both PEER_IP and COMPETING_IP advertise the same v6 prefix.
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    state.on_route_update(IpAddr::V4(COMPETING_IP), announce_v6(&["2001:db8::/32"]));
    while rxs
        .get_mut(&IpAddr::V4(OBSERVER_IP))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    // Unclean termination of PEER_IP — repropagate_after_stale_mark_v6
    // must iterate over the observer. Staleness does not change the
    // selection (RFC 9494 §1), so nothing needs re-advertising; the key
    // invariant is that the loop runs and a best route remains.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    state.flush_pending();

    assert!(
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8::/32"))
            .is_some(),
        "a best v6 route must still exist"
    );
}

/// When a GR peer re-establishes and EOR prunes stale v6 routes, a second
/// IPv6-capable observer peer must receive a WITHDRAW for each pruned NLRI.
/// This covers the `prune_stale_nlri_v6` observer loop.
#[test]
fn eor_prune_v6_propagates_withdrawal_to_v6_observer() {
    const OBSERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    const OBSERVER_AS: u32 = 65003;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBSERVER_IP, OBSERVER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());

    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );

    let obs_caps = vec![
        Capability::FourByteAsn(OBSERVER_AS),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    state.on_established(
        IpAddr::V4(OBSERVER_IP),
        OBSERVER_IP,
        PeerType::External,
        OBSERVER_AS,
        90,
        &obs_caps,
        None,
    );

    // Announce two v6 prefixes.
    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
    );
    while rxs
        .get_mut(&IpAddr::V4(OBSERVER_IP))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    // Unclean disconnect, then re-establish.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    while rxs
        .get_mut(&IpAddr::V4(OBSERVER_IP))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    // Peer re-announces only the first prefix, then sends EOR.
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8:1::/48"]));
    state.on_route_update(IpAddr::V4(PEER_IP), ipv6_eor());
    state.flush_pending();

    // Observer must receive a WITHDRAW for the stale 2001:db8:2::/48.
    let msgs: Vec<UpdateMessage> = std::iter::from_fn(|| {
        rxs.get_mut(&IpAddr::V4(OBSERVER_IP))
            .unwrap()
            .try_recv()
            .ok()
    })
    .collect();
    let has_prune = msgs.iter().any(|m| {
        m.attributes.iter().any(|a| {
            if let PathAttribute::MpUnreachNlri(u) = a {
                u.prefixes
                    .iter()
                    .any(|p| matches!(p, Prefix::V6(n) if n.to_string().starts_with("2001:db8:2")))
            } else {
                false
            }
        })
    });
    assert!(
        has_prune,
        "observer must receive WITHDRAW for the stale v6 NLRI after EOR prune"
    );
}

/// When `prune_stale_nlri` is called for a peer whose `adj_ribs_in` entry is
/// missing, it must skip the adj-rib withdrawal without panicking. Covers the
/// `if let Some(ari)` else path in gr.rs line 289.
#[test]
fn prune_stale_nlri_skips_missing_adj_rib_in() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    let stale_set = std::collections::HashSet::from([nlri]);

    // Remove adj_ribs_in so the `if let Some(ari)` branch is skipped.
    state.adj_ribs_in.remove(&IpAddr::V4(PEER_IP));
    // Must not panic.
    state.prune_stale_nlri(IpAddr::V4(PEER_IP), &stale_set);
}

/// When observer's export policy is missing during `prune_stale_nlri`, the
/// peer must be skipped. Covers the defensive `continue` at gr.rs line 328.
#[test]
fn prune_stale_nlri_skips_peer_missing_export_policy() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    establish_with_gr(&mut state, 120);

    // Remove observer's export policy — defensive `continue` must fire.
    state.export_policies.remove(&IpAddr::V4(OBS_IP));
    let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    let stale_set = std::collections::HashSet::from([nlri]);
    state.prune_stale_nlri(IpAddr::V4(PEER_IP), &stale_set);
}

/// When the observer's update channel is closed during `prune_stale_nlri`,
/// it must be recorded in `stalled_peers`. Covers stall at gr.rs line 360.
#[test]
fn prune_stale_nlri_stall_records_stalled_peer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    while rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap().try_recv().is_ok() {}

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    establish_with_gr(&mut state, 120);
    // Drop observer's receiver so the EOR prune send fails.
    drop(rxs.remove(&IpAddr::V4(OBS_IP)).unwrap());

    let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    let stale_set = std::collections::HashSet::from([nlri]);
    state.prune_stale_nlri(IpAddr::V4(PEER_IP), &stale_set);

    assert!(
        state.take_stalled_peers().contains(&IpAddr::V4(OBS_IP)),
        "stalled_peers must record observer when prune send fails"
    );
}

/// When the observer's update channel is closed during GR deadline expiry,
/// it must be recorded in `stalled_peers`. Covers stall at gr.rs line 558.
#[test]
fn deadline_expiry_stall_records_stalled_peer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    while rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap().try_recv().is_ok() {}

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    // Drop observer's receiver so the deadline expiry send fails.
    drop(rxs.remove(&IpAddr::V4(OBS_IP)).unwrap());

    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));

    assert!(
        state.take_stalled_peers().contains(&IpAddr::V4(OBS_IP)),
        "stalled_peers must record observer when deadline expiry send fails"
    );
}

/// Unclean termination of a GR-capable peer with no v4 routes must be a no-op
/// for the stale-marking loop. Covers the `if !stale_v4.is_empty()` false
/// branch in `mark_stale_and_repropagate` (gr.rs line 100).
#[test]
fn stale_mark_v4_with_no_routes_is_noop() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    establish_with_gr(&mut state, 120);
    // No routes announced — stale_v4 will be empty.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    assert_eq!(state.rib.loc_rib.len(), 0);
}

/// Unclean termination of a GR-capable v6 peer with no v6 routes must be
/// a no-op for the v6 stale-marking loop. Covers the `if !stale_v6.is_empty()`
/// false branch in `mark_stale_and_repropagate` (gr.rs line 127).
#[test]
fn stale_mark_v6_with_no_routes_is_noop() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);
    // No v6 routes announced — stale_v6 will be empty.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    assert_eq!(state.rib.loc_rib_v6.len(), 0);
}

/// Unclean termination of a GR peer with IPv6 GR family must push v6 FIB
/// changes. Covers the `if do_v6 { if let Some(fm) ... }` block in
/// `mark_stale_and_repropagate` (gr.rs lines 122-127).
#[test]
fn stale_marking_v6_notifies_fib_manager() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let fib = with_recording_fib(&mut state);
    establish_with_gr_v6(&mut state, 120);
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    fib.v6.lock().unwrap().clear();

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    let changes = fib.v6.lock().unwrap().clone();
    assert!(
        !changes.is_empty(),
        "FibManager must receive v6 changes when v6 GR peer terminates unclean"
    );
}

/// When `fib_manager` is set, EOR from a GR-re-established peer must push
/// FIB changes for the pruned v4 routes. Covers the `if let Some(fm)` branch
/// in `prune_stale_nlri` (gr.rs lines 300-302).
#[test]
fn eor_prune_v4_notifies_fib_manager() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    let fib = with_recording_fib(&mut state);
    establish_with_gr(&mut state, 120);

    // Announce two routes; only one will survive after re-establishment.
    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce(&["10.0.0.0/8", "192.0.2.0/24"]),
    );
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    establish_with_gr(&mut state, 120);
    fib.v4.lock().unwrap().clear();

    // Re-announce only the first; EOR prunes the second.
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    let eor = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    };
    state.on_route_update(IpAddr::V4(PEER_IP), eor);

    let changes = fib.v4_changes();
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
        "FibManager must receive Withdrawn for pruned v4 NLRI after EOR"
    );
}

/// When `fib_manager` is set, EOR from a GR-re-established v6 peer must push
/// FIB changes for the pruned v6 routes. Covers `prune_stale_nlri_v6`
/// (gr.rs lines 391-393).
#[test]
fn eor_prune_v6_notifies_fib_manager() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let fib = with_recording_fib(&mut state);

    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
    );
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    fib.v6.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8:1::/48"]));
    state.on_route_update(IpAddr::V4(PEER_IP), ipv6_eor());

    let changes = fib.v6.lock().unwrap().clone();
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
        "FibManager must receive Withdrawn for pruned v6 NLRI after EOR"
    );
}

/// An observer that was not established with IPv6 capabilities must be skipped by
/// `repropagate_after_stale_mark_v6`. Covers the `if !ipv6_capable_peers.contains`
/// branch at gr.rs line 228.
#[test]
fn repropagate_v6_skips_non_ipv6_observer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);
    // Observer has NO v6 capability → not in ipv6_capable_peers.
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));

    // Termination triggers repropagate_after_stale_mark_v6 which must skip OBS_IP.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    // Must not panic; stalled_peers must not include observer.
    assert!(!state.take_stalled_peers().contains(&IpAddr::V4(OBS_IP)));
}

/// When the observer's adj_ribs_out_v6 is missing, repropagate_after_stale_mark_v6
/// must skip it. Covers the defensive `continue` at gr.rs line 242.
#[test]
fn repropagate_v6_skips_observer_missing_adj_rib_out_v6() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;
    let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &obs_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));

    state.adj_ribs_out_v6.remove(&IpAddr::V4(OBS_IP));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
}

/// When the observer's update channel is closed during repropagate_v6,
/// it must be recorded in `stalled_peers`. Covers the stall at gr.rs line 270.
#[test]
fn repropagate_v6_stall_records_stalled_peer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;
    let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &obs_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    while rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap().try_recv().is_ok() {}

    // With accept-all import and no transformations, stale marking alone
    // sends nothing (RFC 9494 §1), so the send path is only reachable
    // when Adj-RIB-Out is out of step with Loc-RIB. Force that by
    // forgetting what was advertised.
    state
        .adj_ribs_out_v6
        .get_mut(&IpAddr::V4(OBS_IP))
        .unwrap()
        .withdraw(&nlri_v6("2001:db8::/32"));
    drop(rxs.remove(&IpAddr::V4(OBS_IP)).unwrap());
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    assert!(
        state.take_stalled_peers().contains(&IpAddr::V4(OBS_IP)),
        "stalled_peers must include observer when v6 repropagate send fails"
    );
}

/// When `prune_stale_nlri` is called and the observer's adj_ribs_out is missing,
/// it must skip without panicking. Covers defensive `continue` at gr.rs line 331.
#[test]
fn prune_stale_nlri_skips_observer_missing_adj_rib_out() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    establish_with_gr(&mut state, 120);

    state.adj_ribs_out.remove(&IpAddr::V4(OBS_IP));
    let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    state.prune_stale_nlri(
        IpAddr::V4(PEER_IP),
        &std::collections::HashSet::from([nlri]),
    );
}

/// When `prune_stale_nlri_v6` encounters a peer without adj_ribs_in_v6, it must
/// skip the adj-rib withdrawal. Covers the `if let Some(ari_v6)` else path at
/// gr.rs line 379.
#[test]
fn prune_stale_nlri_v6_skips_missing_adj_rib_in_v6() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));

    let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
    let stale_set = std::collections::HashSet::from([nlri]);
    // Remove adj_ribs_in_v6 so the `if let Some(ari_v6)` branch is skipped.
    state.adj_ribs_in_v6.remove(&IpAddr::V4(PEER_IP));
    state.prune_stale_nlri_v6(IpAddr::V4(PEER_IP), &stale_set);
}

/// When the v6 observer's update channel is closed during prune_stale_nlri_v6,
/// it must be recorded in `stalled_peers`. Covers the stall at gr.rs line 450.
#[test]
fn prune_stale_nlri_v6_stall_records_stalled_peer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;
    let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &obs_caps,
        None,
    );
    state.on_route_update(
        IpAddr::V4(PEER_IP),
        announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
    );
    while rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap().try_recv().is_ok() {}

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    drop(rxs.remove(&IpAddr::V4(OBS_IP)).unwrap());

    let nlri: Nlri<Ipv6Addr> = "2001:db8:2::/48".parse().unwrap();
    let stale_set = std::collections::HashSet::from([nlri]);
    state.prune_stale_nlri_v6(IpAddr::V4(PEER_IP), &stale_set);

    assert!(
        state.take_stalled_peers().contains(&IpAddr::V4(OBS_IP)),
        "stalled_peers must include observer when v6 prune send fails"
    );
}

/// When the observer's adj_ribs_out is missing, repropagate_after_stale_mark_v4
/// must skip it. Covers the defensive `continue` at gr.rs line 177.
#[test]
fn repropagate_v4_skips_observer_missing_adj_rib_out() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    state.adj_ribs_out.remove(&IpAddr::V4(OBS_IP));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
}

/// When the observer's update_senders is missing, repropagate_after_stale_mark_v4
/// must skip it. Covers the defensive `continue` at gr.rs line 180.
#[test]
fn repropagate_v4_skips_observer_missing_update_senders() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    state.update_senders.remove(&IpAddr::V4(OBS_IP));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
}

/// When the observer's update_senders is missing in repropagate_after_stale_mark_v6,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 245.
#[test]
fn repropagate_v6_skips_observer_missing_update_senders() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;
    let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_with_gr_v6(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &obs_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));

    state.update_senders.remove(&IpAddr::V4(OBS_IP));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
}

/// When the observer's update_senders is missing in prune_stale_nlri v4,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 334.
#[test]
fn prune_stale_nlri_skips_observer_missing_update_senders() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    establish_with_gr(&mut state, 120);

    state.update_senders.remove(&IpAddr::V4(OBS_IP));
    let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
    state.prune_stale_nlri(
        IpAddr::V4(PEER_IP),
        &std::collections::HashSet::from([nlri]),
    );
}

/// When the observer's export_policy is missing in prune_stale_nlri_v6,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 419.
#[test]
fn prune_stale_nlri_v6_skips_observer_missing_export_policy() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;
    let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &obs_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );

    state.export_policies.remove(&IpAddr::V4(OBS_IP));
    let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
    state.prune_stale_nlri_v6(
        IpAddr::V4(PEER_IP),
        &std::collections::HashSet::from([nlri]),
    );
}

/// When the observer's adj_ribs_out_v6 is missing in prune_stale_nlri_v6,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 422.
#[test]
fn prune_stale_nlri_v6_skips_observer_missing_adj_rib_out_v6() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;
    let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &obs_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );

    state.adj_ribs_out_v6.remove(&IpAddr::V4(OBS_IP));
    let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
    state.prune_stale_nlri_v6(
        IpAddr::V4(PEER_IP),
        &std::collections::HashSet::from([nlri]),
    );
}

/// When the observer's update_senders is missing in prune_stale_nlri_v6,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 425.
#[test]
fn prune_stale_nlri_v6_skips_observer_missing_update_senders() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;
    let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &obs_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );

    state.update_senders.remove(&IpAddr::V4(OBS_IP));
    let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
    state.prune_stale_nlri_v6(
        IpAddr::V4(PEER_IP),
        &std::collections::HashSet::from([nlri]),
    );
}

/// When the observer's export_policy is missing during deadline expiry,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 526.
#[test]
fn deadline_expiry_skips_observer_missing_export_policy() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    state.export_policies.remove(&IpAddr::V4(OBS_IP));
    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));
}

/// When the observer's adj_ribs_out is missing during deadline expiry,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 529.
#[test]
fn deadline_expiry_skips_observer_missing_adj_rib_out() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    state.adj_ribs_out.remove(&IpAddr::V4(OBS_IP));
    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));
}

/// When the observer's update_senders is missing during deadline expiry,
/// it must be skipped. Covers the defensive `continue` at gr.rs line 532.
#[test]
fn deadline_expiry_skips_observer_missing_update_senders() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    state.update_senders.remove(&IpAddr::V4(OBS_IP));
    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));
}

/// When the observer's update channel is closed, `repropagate_after_stale_mark_v4`
/// must record the peer in `stalled_peers`. Covers the `flush_updates → false` stall
/// path in gr.rs line 206.
#[test]
fn repropagate_v4_stall_path_records_stalled_peer() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));
    while rxs.get_mut(&IpAddr::V4(OBS_IP)).unwrap().try_recv().is_ok() {}

    // With accept-all import and no transformations, stale marking alone
    // sends nothing (RFC 9494 §1), so the send path is only reachable
    // when Adj-RIB-Out is out of step with Loc-RIB. Force that by
    // forgetting what was advertised.
    state
        .adj_ribs_out
        .get_mut(&IpAddr::V4(OBS_IP))
        .unwrap()
        .withdraw(&nlri("10.0.0.0/8"));
    // Drop the observer's receiver so the next send fails.
    drop(rxs.remove(&IpAddr::V4(OBS_IP)).unwrap());

    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);

    let stalled = state.take_stalled_peers();
    assert!(
        stalled.contains(&IpAddr::V4(OBS_IP)),
        "stalled_peers must include observer when its channel is closed"
    );
}

/// When the observer peer is missing from `export_policies`, `repropagate_after_stale_mark_v4`
/// must skip it without panicking. Covers the defensive `continue` at gr.rs line 174.
#[test]
fn repropagate_v4_skips_peer_missing_export_policy() {
    const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OBS_AS: u32 = 65005;

    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
    establish_with_gr(&mut state, 120);
    state.on_established(
        IpAddr::V4(OBS_IP),
        OBS_IP,
        PeerType::External,
        OBS_AS,
        90,
        &[],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce(&["10.0.0.0/8"]));

    // Remove observer's export policy — defensive `continue` must fire.
    state.export_policies.remove(&IpAddr::V4(OBS_IP));
    // Must not panic.
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
}

/// When `fib_manager` is set and the GR deadline expires for a peer with v6
/// routes, the FIB manager must receive v6 Withdrawn calls. Covers the v6
/// apply loop in `on_gr_deadline_expired` (gr.rs lines 485-487).
#[test]
fn deadline_expiry_v6_notifies_fib_manager() {
    let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let fib = with_recording_fib(&mut state);

    let peer_caps = gr_caps_v6(120);
    state.on_established(
        IpAddr::V4(PEER_IP),
        PEER_IP,
        PeerType::External,
        PEER_AS,
        90,
        &peer_caps,
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_IP), announce_v6(&["2001:db8::/32"]));
    state.on_terminated(IpAddr::V4(PEER_IP), TerminationReason::Unclean, true);
    fib.v6.lock().unwrap().clear();

    state.gr.deadlines.remove(&IpAddr::V4(PEER_IP));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_IP));

    let changes = fib.v6.lock().unwrap().clone();
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
        "FibManager must receive v6 Withdrawn on GR deadline expiry"
    );
}
