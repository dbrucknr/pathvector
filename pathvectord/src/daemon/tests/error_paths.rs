use super::*;

// ── on_established error paths ────────────────────────────────────────────

#[test]
fn test_on_established_missing_adj_rib_out_logs_and_returns() {
    // export_policies is present but adj_ribs_out was removed — the second
    // let-else guard fires; must not panic and peer_type is still recorded.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    state.adj_ribs_out.remove(&peer_ip);

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    // peer_type is inserted before the guard, so it should be present.
    assert!(state.rib.peer_types.contains_key(&peer_ip));
}

#[test]
fn test_on_established_missing_update_sender_logs_and_returns() {
    // export_policies and adj_ribs_out are present but update_senders was
    // removed — the third let-else guard fires; must not panic.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    state.update_senders.remove(&peer_ip);

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    assert!(state.rib.peer_types.contains_key(&peer_ip));
}

// ── on_terminated propagation error paths ────────────────────────────────

#[test]
fn test_on_terminated_propagation_missing_adj_rib_out_continues() {
    // Peer B's adj_rib_out is removed. When peer A terminates, propagation
    // to peer B hits the adj_rib_out guard and continues — no panic.
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, _) = make_state(
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
    state.adj_ribs_out.remove(&IpAddr::V4(peer_b));

    state.on_terminated(IpAddr::V4(peer_a), TerminationReason::Unclean, true);

    assert!(!state.rib.peer_types.contains_key(&IpAddr::V4(peer_a)));
    assert!(state.rib.peer_types.contains_key(&IpAddr::V4(peer_b)));
}

#[test]
fn test_on_terminated_propagation_missing_update_sender_continues() {
    // Peer B's update_sender is removed. Propagation hits the update_sender
    // guard and continues — no panic.
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, _) = make_state(
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
    state.update_senders.remove(&IpAddr::V4(peer_b));

    state.on_terminated(IpAddr::V4(peer_a), TerminationReason::Unclean, true);

    assert!(!state.rib.peer_types.contains_key(&IpAddr::V4(peer_a)));
}

// ── on_route_update error paths ───────────────────────────────────────────

#[test]
fn test_on_route_update_missing_adj_rib_in_logs_and_returns() {
    // import_policy is present but adj_ribs_in was removed — the second
    // let-else guard fires; must not panic and RIB stays empty.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    // Registered, so the UPDATE gets past the unregistered-session guard.
    state.on_established(
        peer_ip,
        Ipv4Addr::new(10, 0, 0, 2),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.adj_ribs_in.remove(&peer_ip);

    state.on_route_update(
        peer_ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    assert_eq!(state.rib.loc_rib.len(), 0);
}

#[test]
fn test_on_route_update_propagation_missing_adj_rib_out_continues() {
    // Peer B's adj_rib_out is removed. When peer A sends an UPDATE,
    // propagation to peer B hits the adj_rib_out guard and continues.
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, _) = make_state(
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
    state.adj_ribs_out.remove(&IpAddr::V4(peer_b));

    state.on_route_update(
        IpAddr::V4(peer_a),
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

    // Route lands in the RIB; missing peer B did not cause a panic.
    assert_eq!(state.rib.loc_rib.len(), 1);
}

#[test]
fn test_on_route_update_propagation_missing_update_sender_continues() {
    // Peer B's update_sender is removed. Propagation hits the update_sender
    // guard and continues — no panic and route still lands.
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, _) = make_state(
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
    state.update_senders.remove(&IpAddr::V4(peer_b));

    state.on_route_update(
        IpAddr::V4(peer_a),
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
}

// ── propagate_prefix channel-full stall paths ────────────────────────────

/// Returns a `Sender` whose single-slot channel is already full so that
/// the very next `try_send` returns `Err(Full)`.
fn full_channel() -> (mpsc::Sender<UpdateMessage>, mpsc::Receiver<UpdateMessage>) {
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    })
    .expect("pre-fill");
    (tx, rx)
}

#[test]
fn test_propagate_prefix_channel_full_update_returns_false() {
    // Best route → export accepted → INSERT into empty AdjRibOut → try_send
    // UPDATE fails because the channel is full. Must return false.
    let n = nlri("10.0.0.0/8");
    let mut loc_rib = LocRib::new();
    loc_rib.insert(
        peer(),
        RouteBuilder::new(n, Origin::Igp, AsPath::new()).build(),
        &AlwaysReachable,
    );

    let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
    let mut aro = AdjRibOut::new(out_peer, PeerType::External);

    let (tx, _rx) = full_channel();
    let ok = propagate_and_flush(
        n,
        &loc_rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        &tx,
    );
    assert!(!ok, "full UPDATE channel must return false");
    // AdjRibOut records the route even though the wire message was not sent;
    // the caller is responsible for closing the session to restore consistency.
    assert_eq!(aro.len(), 1);
}

#[test]
fn test_propagate_prefix_channel_full_split_horizon_eviction_returns_false() {
    // iBGP peer's AdjRibOut has a pre-stored eBGP route. The new best is an
    // iBGP route → InsertOutcome::Filtered(Some(_)) → WITHDRAW → channel full
    // → returns false.
    let n = nlri("10.0.0.0/8");

    let mut loc_rib = LocRib::new();
    loc_rib.insert(
        peer(),
        RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .peer_type(PeerType::Internal)
            .build(),
        &AlwaysReachable,
    );

    let out_peer = PeerId::new(IpAddr::V4("10.0.0.3".parse().unwrap()));
    let mut aro = AdjRibOut::new(out_peer, PeerType::Internal);
    aro.insert(
        RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build(),
    );

    let (tx, _rx) = full_channel();
    let ok = propagate_and_flush(
        n,
        &loc_rib,
        &mut aro,
        &accept_all(),
        PeerType::Internal,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        &tx,
    );
    assert!(
        !ok,
        "full WITHDRAW channel (split-horizon eviction) must return false"
    );
    assert!(aro.is_empty());
}

#[test]
fn test_propagate_prefix_channel_full_export_reject_returns_false() {
    // Best route exists but export policy rejects it. AdjRibOut had a prior
    // route → WITHDRAW generated → channel full → returns false.
    let n = nlri("10.0.0.0/8");

    let mut loc_rib = LocRib::new();
    loc_rib.insert(
        peer(),
        RouteBuilder::new(n, Origin::Igp, AsPath::new()).build(),
        &AlwaysReachable,
    );

    let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
    let mut aro = AdjRibOut::new(out_peer, PeerType::External);
    aro.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());

    let (tx, _rx) = full_channel();
    let ok = propagate_and_flush(
        n,
        &loc_rib,
        &mut aro,
        &reject_all(),
        PeerType::External,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        &tx,
    );
    assert!(
        !ok,
        "full WITHDRAW channel (export reject) must return false"
    );
    assert!(aro.is_empty());
}

#[test]
fn test_propagate_prefix_channel_full_no_best_returns_false() {
    // No best route in LocRib. AdjRibOut has a stale route → WITHDRAW →
    // channel full → returns false.
    let n = nlri("10.0.0.0/8");
    let loc_rib: LocRib<Ipv4Addr> = LocRib::new();

    let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
    let mut aro = AdjRibOut::new(out_peer, PeerType::External);
    aro.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());

    let (tx, _rx) = full_channel();
    let ok = propagate_and_flush(
        n,
        &loc_rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        &tx,
    );
    assert!(!ok, "full WITHDRAW channel (no best) must return false");
    assert!(aro.is_empty());
}

/// When `on_terminated` propagates to other established peers, a ghost peer
/// (one that reached `Established` via `on_established` but was never in the
/// config maps) triggers the missing-export-policy error path.  Must not
/// panic.
#[test]
fn test_on_terminated_ghost_established_peer_does_not_panic() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(IpAddr::V4(peer_a), 65002)]);
    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    // Inject a ghost peer into peer_types (never registered in config maps).
    let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
    state.on_established(
        IpAddr::V4(ghost),
        ghost,
        PeerType::External,
        65099,
        90,
        &[],
        None,
    );

    // Terminating peer_a iterates established peers; ghost has no policy /
    // rib entries — the error branch logs and continues without panicking.
    state.on_terminated(IpAddr::V4(peer_a), TerminationReason::Unclean, true);
    assert!(!state.rib.peer_types.contains_key(&IpAddr::V4(peer_a)));
}

/// Calling `on_route_update` with an unknown peer IP does nothing: not even
/// an End-of-RIB marker is recorded.
#[test]
fn test_on_route_update_unknown_peer_is_noop() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

    let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
    state.on_route_update(
        IpAddr::V4(unknown),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        },
    );
    assert_eq!(state.rib.loc_rib.len(), 0);
    assert!(!state.rib.eor_received.contains(&IpAddr::V4(unknown)));
}

/// When `on_route_update` propagates to established peers, a ghost peer
/// (in `peer_types` but absent from policy maps) triggers the error path.
/// Must not panic.
#[test]
fn test_on_route_update_ghost_established_peer_does_not_panic() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(IpAddr::V4(peer_a), 65002)]);
    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
    state.on_established(
        IpAddr::V4(ghost),
        ghost,
        PeerType::External,
        65099,
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
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    assert_eq!(state.rib.loc_rib.len(), 1);
}
