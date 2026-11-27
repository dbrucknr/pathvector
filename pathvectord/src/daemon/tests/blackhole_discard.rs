use super::*;

// ── RFC 7999 — BLACKHOLE community discard ───────────────────────────────

#[test]
fn test_handle_update_blackhole_route_not_installed() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::Communities(vec![Community::BLACKHOLE]),
            ],
            announced: vec![nlri("192.0.2.0/24")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    // BLACKHOLE-tagged route must not enter LocRib even with accept-all policy.
    assert_eq!(rib.len(), 0, "BLACKHOLE route must not be installed");
}

#[test]
fn test_handle_update_blackhole_route_stored_in_adj_rib_in() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let prefix = nlri("192.0.2.0/24");
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::Communities(vec![Community::BLACKHOLE]),
            ],
            announced: vec![prefix],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    // Pre-policy route stored in AdjRibIn for soft-reconfig visibility.
    assert!(
        ari.get(&prefix).is_some(),
        "BLACKHOLE route must be in AdjRibIn"
    );
}

#[test]
fn test_handle_update_non_blackhole_route_installed_normally() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                // Regular community, not BLACKHOLE.
                PathAttribute::Communities(vec![Community::NO_EXPORT]),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(rib.len(), 1);
}

// ── RFC 7999 blackhole FIB integration ───────────────────────────────────

/// RFC 7999 §3.3: the operator agrees to honor BLACKHOLE on `peer`'s
/// session for the prefixes the tests below announce. Without this a
/// BLACKHOLE-tagged announcement is denied (the default).
fn agree_blackholes(state: &mut DaemonState, peer: IpAddr) {
    state.set_blackhole_scope(
        peer,
        Some(&crate::blackhole::BlackholeScope::new(["10.0.0.0/8", "192.0.0.0/8"]).unwrap()),
    );
}

fn blackhole_announce(prefix: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
            PathAttribute::Communities(vec![Community::BLACKHOLE]),
        ],
        announced: vec![prefix.parse().unwrap()],
    }
}

fn blackhole_withdraw(prefix: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![prefix.parse().unwrap()],
        attributes: vec![],
        announced: vec![],
    }
}

fn unicast_announce(prefix: &str, next_hop: &str) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop(next_hop.parse::<Ipv4Addr>().unwrap()),
        ],
        announced: vec![prefix.parse().unwrap()],
    }
}

/// A BLACKHOLE-tagged route must trigger `apply_blackhole_v4` on the FIB
/// manager so the kernel programs a null route.
#[test]
fn blackhole_route_programs_kernel_null_route() {
    let (mut state, _rxs) = make_state(65001, &[(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002)]);
    let fib = with_recording_fib(&mut state);
    let peer = Ipv4Addr::new(10, 0, 0, 2);
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.set_import_default(IpAddr::V4(peer), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer));

    state.on_route_update(IpAddr::V4(peer), blackhole_announce("192.0.2.0/24"));

    let bh = fib.blackhole_v4.lock().unwrap().clone();
    let announced_nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
    assert!(
        bh.iter()
            .any(|(n, announced)| *n == announced_nlri && *announced),
        "apply_blackhole_v4 must be called for BLACKHOLE-tagged prefix"
    );
}

/// A BLACKHOLE-tagged route must NOT enter the LocRib or be advertised
/// outbound — only the kernel null route is programmed.
#[test]
fn blackhole_route_not_in_loc_rib() {
    let (mut state, _rxs) = make_state(65001, &[(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002)]);
    with_recording_fib(&mut state);
    let peer = Ipv4Addr::new(10, 0, 0, 2);
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.set_import_default(IpAddr::V4(peer), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer));

    state.on_route_update(IpAddr::V4(peer), blackhole_announce("192.0.2.0/24"));

    // LocRib must remain empty for the blackhole prefix.
    assert_eq!(
        Arc::clone(&state.rib).loc_rib.len(),
        0,
        "BLACKHOLE route must not enter LocRib"
    );
}

/// When a previously-announced BLACKHOLE route is withdrawn by the peer,
/// `withdraw_blackhole_v4` must be called to remove the kernel null route.
#[test]
fn blackhole_route_withdrawal_removes_kernel_null_route() {
    let (mut state, _rxs) = make_state(65001, &[(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002)]);
    let fib = with_recording_fib(&mut state);
    let peer = Ipv4Addr::new(10, 0, 0, 2);
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.set_import_default(IpAddr::V4(peer), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer));

    state.on_route_update(IpAddr::V4(peer), blackhole_announce("192.0.2.0/24"));
    fib.blackhole_v4.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(peer), blackhole_withdraw("192.0.2.0/24"));

    let bh = fib.blackhole_v4.lock().unwrap().clone();
    let withdrawn_nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
    assert!(
        bh.iter()
            .any(|(n, announced)| *n == withdrawn_nlri && !announced),
        "withdraw_blackhole_v4 must be called when BLACKHOLE route is withdrawn"
    );
}

/// Regression: when a session tears down, kernel null routes installed for
/// BLACKHOLE-tagged prefixes from that peer must be withdrawn.
/// Previously `on_terminated` cleared AdjRibIn without scanning for
/// BLACKHOLE routes, leaking the kernel null route indefinitely.
#[test]
fn blackhole_route_removed_on_session_teardown() {
    let (mut state, _rxs) = make_state(65001, &[(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002)]);
    let fib = with_recording_fib(&mut state);
    let peer = Ipv4Addr::new(10, 0, 0, 2);
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.set_import_default(IpAddr::V4(peer), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer));

    state.on_route_update(IpAddr::V4(peer), blackhole_announce("192.0.2.0/24"));
    fib.blackhole_v4.lock().unwrap().clear();

    state.on_terminated(IpAddr::V4(peer), TerminationReason::OperatorStop, false);

    let bh = fib.blackhole_v4.lock().unwrap().clone();
    let nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
    assert!(
        bh.iter().any(|(n, announced)| *n == nlri && !*announced),
        "on_terminated must call withdraw_blackhole_v4 for BLACKHOLE-tagged prefixes"
    );
}

/// Regression: when a unicast route for prefix X is in LocRib and a peer
/// re-announces X with the BLACKHOLE community, the unicast LocRib entry
/// must be removed so a unicast kernel route and a null route don't coexist.
#[test]
fn blackhole_upgrade_evicts_unicast_from_loc_rib() {
    let (mut state, _rxs) = make_state(65001, &[(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002)]);
    with_recording_fib(&mut state);
    let peer = Ipv4Addr::new(10, 0, 0, 2);
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.set_import_default(IpAddr::V4(peer), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer));

    // First announce as unicast — enters LocRib.
    state.on_route_update(
        IpAddr::V4(peer),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
            ],
            announced: vec!["10.0.0.0/8".parse().unwrap()],
        },
    );
    assert_eq!(
        Arc::clone(&state.rib).loc_rib.len(),
        1,
        "unicast must be in LocRib"
    );

    // Now re-announce the same prefix with BLACKHOLE community.
    state.on_route_update(IpAddr::V4(peer), blackhole_announce("10.0.0.0/8"));

    assert_eq!(
        Arc::clone(&state.rib).loc_rib.len(),
        0,
        "re-announcement as BLACKHOLE must evict the unicast LocRib entry"
    );
}

/// Regression: a BLACKHOLE route held through GR (peer's stale routes
/// retained) must have its kernel null route removed when the GR deadline
/// expires and the stale routes are flushed.
#[test]
fn blackhole_route_removed_when_gr_deadline_expires() {
    use pathvector_session::message::{Capability, GracefulRestartFamily};
    use pathvector_types::AfiSafi;

    let peer = Ipv4Addr::new(10, 0, 0, 2);
    let (mut state, _rxs) = make_state(65001, &[(IpAddr::V4(peer), 65002)]);
    let fib = with_recording_fib(&mut state);

    let gr_family = GracefulRestartFamily {
        afi_safi: AfiSafi::IPV4_UNICAST,
        forwarding_preserved: true,
    };
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: vec![gr_family],
        }],
        None,
    );
    state.set_import_default(IpAddr::V4(peer), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer));

    // Install a BLACKHOLE kernel null route.
    state.on_route_update(IpAddr::V4(peer), blackhole_announce("192.0.2.0/24"));
    fib.blackhole_v4.lock().unwrap().clear();

    // Session drops uncleanly — GR helper mode entered, stale routes kept.
    state.on_terminated(IpAddr::V4(peer), TerminationReason::Unclean, false);

    // GR deadline expires — stale routes must be flushed.
    state.on_gr_deadline_expired(IpAddr::V4(peer));

    let bh = fib.blackhole_v4.lock().unwrap().clone();
    let nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
    assert!(
        bh.iter().any(|(n, announced)| *n == nlri && !*announced),
        "GR deadline expiry must withdraw the kernel null route for stale BLACKHOLE prefix"
    );
}

/// When a peer has GR capability for IPv6 only (not IPv4), and the session
/// drops uncleanly, IPv4 AdjRibIn is cleared immediately. Any IPv4 BLACKHOLE
/// kernel null routes must be withdrawn BEFORE the clear — they bypass LocRib
/// and are otherwise invisible to the normal withdrawal path.
#[test]
fn blackhole_route_removed_for_non_gr_family_on_unclean_termination() {
    use pathvector_session::message::{Capability, GracefulRestartFamily};
    use pathvector_types::AfiSafi;

    let peer = Ipv4Addr::new(10, 0, 0, 2);
    let (mut state, _rxs) = make_state(65001, &[(IpAddr::V4(peer), 65002)]);
    let fib = with_recording_fib(&mut state);

    // Peer advertises GR for IPv6 only — IPv4 is NOT covered.
    let gr_family_v6 = GracefulRestartFamily {
        afi_safi: AfiSafi::IPV6_UNICAST,
        forwarding_preserved: true,
    };
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        65002,
        90,
        &[Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: vec![gr_family_v6],
        }],
        None,
    );
    state.set_import_default(IpAddr::V4(peer), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer));

    // Peer announces an IPv4 BLACKHOLE prefix.
    state.on_route_update(IpAddr::V4(peer), blackhole_announce("192.0.5.0/24"));
    fib.blackhole_v4.lock().unwrap().clear();

    // Unclean termination — enters GR helper mode for IPv6, but IPv4 is
    // NOT covered by GR, so IPv4 AdjRibIn is cleared immediately.
    // The kernel null route for 192.0.5.0/24 must be withdrawn first.
    state.on_terminated(IpAddr::V4(peer), TerminationReason::Unclean, false);

    let bh = fib.blackhole_v4.lock().unwrap().clone();
    let nlri: Nlri<Ipv4Addr> = "192.0.5.0/24".parse().unwrap();
    assert!(
        bh.iter().any(|(n, announced)| *n == nlri && !*announced),
        "IPv4 BLACKHOLE kernel null route must be withdrawn when IPv4 is not a GR family"
    );
}

/// When peer A sends a BLACKHOLE route for prefix X (suppressing any prior
/// unicast entry), and peer B has a unicast route for X in LocRib, withdrawing
/// the BLACKHOLE must re-install peer B's unicast route in the kernel FIB.
///
/// Without the fix, `loc_rib.withdraw(&peer_a, X)` returns `Unchanged` (A was
/// never in LocRib for the BLACKHOLE) and no FIB event fires for B's route —
/// leaving the kernel with no route for X despite LocRib having B's path.
#[test]
fn blackhole_withdrawal_restores_surviving_peer_unicast_route() {
    let peer_a = Ipv4Addr::new(10, 0, 0, 2);
    let peer_b = Ipv4Addr::new(10, 0, 0, 3);
    let (mut state, _rxs) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );
    let fib = with_recording_fib(&mut state);

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_b),
        peer_b,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    state.set_import_default(IpAddr::V4(peer_a), DefaultAction::Accept);
    agree_blackholes(&mut state, IpAddr::V4(peer_a));
    state.set_import_default(IpAddr::V4(peer_b), DefaultAction::Accept);

    // Peer B announces a unicast route for the prefix.
    state.on_route_update(
        IpAddr::V4(peer_b),
        unicast_announce("10.2.0.0/24", "10.0.0.3"),
    );

    // Peer A announces the same prefix with BLACKHOLE community.
    // This should program a kernel null route.
    state.on_route_update(IpAddr::V4(peer_a), blackhole_announce("10.2.0.0/24"));

    // Clear the recorded FIB events so we only observe what happens on withdrawal.
    fib.v4.lock().unwrap().clear();
    fib.blackhole_v4.lock().unwrap().clear();

    // Peer A withdraws the BLACKHOLE route.
    state.on_route_update(IpAddr::V4(peer_a), blackhole_withdraw("10.2.0.0/24"));

    let nlri: Nlri<Ipv4Addr> = "10.2.0.0/24".parse().unwrap();

    // The kernel null route must be withdrawn.
    let bh = fib.blackhole_v4.lock().unwrap().clone();
    assert!(
        bh.iter().any(|(n, announced)| *n == nlri && !*announced),
        "BLACKHOLE withdrawal must remove the kernel null route"
    );

    // Peer B's unicast route must be re-installed in the kernel FIB.
    let v4 = fib.v4.lock().unwrap().clone();
    assert!(
        v4.iter()
            .any(|c| matches!(c, BestPathChange::Announced(n, _) if *n == nlri)),
        "BLACKHOLE withdrawal must trigger re-install of surviving peer-B unicast route; \
         got: {v4:?}"
    );
}
