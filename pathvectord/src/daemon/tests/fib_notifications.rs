use super::*;

// ── DaemonState::on_fib_change ────────────────────────────────────────────

/// Oracle that can be toggled reachable/unreachable at test time.
#[derive(Clone)]
struct ToggleOracle(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl ToggleOracle {
    fn reachable() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            true,
        )))
    }

    fn set(&self, v: bool) {
        self.0.store(v, std::sync::atomic::Ordering::Relaxed);
    }
}

impl NextHopOracle for ToggleOracle {
    fn is_reachable(&self, _: &pathvector_types::NextHop) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn igp_metric(&self, _: &pathvector_types::NextHop) -> Option<u32> {
        None
    }
}

#[test]
fn test_on_fib_change_withdraws_when_next_hop_goes_down() {
    use pathvector_types::{AsPath, Asn, Origin};

    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );

    // Install a toggle oracle (both peers initially reachable).
    let oracle = ToggleOracle::reachable();
    state.set_oracles(oracle.clone(), oracle.clone());

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
    drain_all(&mut receivers);

    // Announce a route from peer_a with an explicit next-hop.
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    // Drain initial propagation to peer_b.
    state.flush_pending();
    receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .ok();

    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
        "route must be in Loc-RIB"
    );

    // Next-hop goes down — FIB change fires.
    oracle.set(false);
    state.on_fib_change();
    state.flush_pending();

    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
        "route must be removed from Loc-RIB when next-hop is unreachable"
    );

    let msg = receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b must receive WITHDRAW when next-hop goes down");
    assert!(!msg.withdrawn.is_empty(), "UPDATE must carry a WITHDRAW");
    assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
}

#[test]
fn test_on_fib_change_reannounces_when_next_hop_recovers() {
    use pathvector_types::{AsPath, Asn, Origin};

    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );

    // Start with next-hop unreachable so the initial INSERT produces no best path.
    let oracle = ToggleOracle::reachable();
    oracle.set(false);
    state.set_oracles(oracle.clone(), oracle.clone());

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

    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    // No best path yet — nothing should have been sent to peer_b.
    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none());
    state.flush_pending();
    receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .ok(); // discard any spurious message

    // Next-hop recovers.
    oracle.set(true);
    state.on_fib_change();
    state.flush_pending();

    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
        "route must appear in Loc-RIB after next-hop recovery"
    );

    let msg = receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b must receive UPDATE when next-hop recovers");
    assert!(!msg.announced.is_empty(), "UPDATE must carry an ANNOUNCE");
    assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
}

#[test]
fn test_on_fib_change_noop_when_nothing_changes() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );

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
    drain_all(&mut receivers);

    // FIB change fires with empty RIB — should be a no-op.
    state.on_fib_change();
    assert!(
        receivers
            .get_mut(&IpAddr::V4(peer_b))
            .unwrap()
            .try_recv()
            .is_err()
    );
}

/// When a FIB change evicts a best route, the FIB manager must receive a
/// `Withdrawn` call for the now-unreachable NLRI.
#[test]
fn test_on_fib_change_notifies_fib_manager_on_withdraw() {
    use pathvector_types::{AsPath, Asn, Origin};

    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_state(65001, &[(IpAddr::V4(peer_a), 65002)]);
    let fib = with_recording_fib(&mut state);

    let oracle = ToggleOracle::reachable();
    state.set_oracles(oracle.clone(), oracle.clone());

    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    fib.v4.lock().unwrap().clear();

    oracle.set(false);
    state.on_fib_change();

    let changes = fib.v4_changes();
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
        "FIB manager must receive a Withdrawn call when next-hop goes down"
    );
}

/// When a v6 FIB change evicts a v6 best route, the FIB manager must receive
/// a Withdrawn call. Covers the v6 path in `on_fib_change` (daemon/fib.rs).
#[test]
fn test_on_fib_change_v6_notifies_fib_manager_on_withdraw() {
    use pathvector_rib::BestPathChange;
    use pathvector_session::message::{MpReachNlri, PathAttribute, Prefix, UpdateMessage};
    use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Origin};

    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_state(65001, &[(IpAddr::V4(peer_a), 65002)]);
    let fib = with_recording_fib(&mut state);

    let oracle = ToggleOracle::reachable();
    state.set_oracles(oracle.clone(), oracle.clone());
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());

    let v6_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &v6_caps,
        None,
    );
    drain_all(&mut receivers);

    let nlri_v6: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
    let announce_v6 = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                prefixes: vec![Prefix::V6(nlri_v6)],
            }),
        ],
        announced: vec![],
    };
    state.on_route_update(IpAddr::V4(peer_a), announce_v6);
    fib.v6.lock().unwrap().clear();

    oracle.set(false);
    state.on_fib_change();

    let v6_changes = fib.v6.lock().unwrap().clone();
    assert!(
        v6_changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
        "FIB manager must receive a Withdrawn call for v6 route when oracle goes down"
    );
}

/// `on_route_update` must notify the FIB manager for routes that change the
/// best path. Covers the `if let Some(fm)` branch in daemon/route.rs.
#[test]
fn test_on_route_update_notifies_fib_manager() {
    use pathvector_rib::BestPathChange;
    use pathvector_types::{AsPath, Asn, Origin};

    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rxs) = make_state(65001, &[(peer_ip, 65002)]);
    let fib = with_recording_fib(&mut state);

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(
        peer_ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    let changes = fib.v4_changes();
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Announced(..))),
        "FIB manager must receive Announced when route is installed"
    );
}

// ── DaemonState::on_route_update ──────────────────────────────────────────

#[test]
fn test_on_route_update_inserts_route_into_rib() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(
        peer_ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    assert_eq!(state.rib.loc_rib.len(), 1);
    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
}
