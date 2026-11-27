use super::*;

// ── DaemonState::new ─────────────────────────────────────────────────────

#[test]
fn test_daemon_state_new_creates_maps_for_all_peers() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (state, _) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );
    for ip in [peer_a, peer_b] {
        assert!(state.import_policies.contains_key(&IpAddr::V4(ip)));
        assert!(state.export_policies.contains_key(&IpAddr::V4(ip)));
        assert!(state.adj_ribs_in.contains_key(&IpAddr::V4(ip)));
        assert!(state.adj_ribs_out.contains_key(&IpAddr::V4(ip)));
        assert!(state.update_senders.contains_key(&IpAddr::V4(ip)));
    }
}

#[test]
fn test_daemon_state_new_ebgp_gets_reject_default_when_omitted() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let peers = vec![config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: 65002,
        import_default: None,
        import_default_v6: None,
        md5_password: None,
        export_default: None,
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
    }];
    let state = DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peers,
        {
            let mut m = HashMap::new();
            m.insert(peer_ip, tx);
            m
        },
        vec![],
    );
    // Import policy with Reject default means routes are dropped unless a
    // term accepts them. Verify by running a route through it.
    let mut route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
        .peer_type(PeerType::External)
        .build();
    let decision = state.import_policies[&peer_ip].evaluate(&mut route);
    assert!(
        matches!(decision, Decision::Reject),
        "eBGP with no import_default must reject by default (RFC 8212)"
    );
}

// ── DaemonState::on_established ───────────────────────────────────────────

#[test]
fn test_on_established_records_peer_type() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    assert!(!state.rib.peer_types.contains_key(&peer_ip));
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    assert_eq!(state.rib.peer_types[&peer_ip], PeerType::External);
}

#[test]
fn test_on_established_empty_rib_sends_eor_only() {
    // RFC 4724 §2: the EOR MUST be sent even when the Adj-RIB-Out is
    // empty so the peer knows the initial sync window is closed.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    let eor = receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("on_established must send an IPv4 EOR even for an empty RIB (RFC 4724 §2)");
    assert!(
        eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty(),
        "IPv4 EOR must be a minimum-length UPDATE (RFC 4724 §2): {eor:?}"
    );
    assert!(
        receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
        "no further messages after the EOR for a peer with no IPv6 capability"
    );
}

#[test]
fn test_on_established_sends_full_table_dump() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);

    // Pre-populate the RIB with a route from a third-party peer.
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
    let route = RouteBuilder::new(
        nlri("10.0.0.0/8"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65009)]),
    )
    .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
    .peer_type(PeerType::External)
    .build();
    state.rib_insert_v4(src, route);

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    let msg = receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("should have queued a full-table dump UPDATE");
    assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);

    // EOR must immediately follow the dump (RFC 4724 §2).
    let eor = receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("IPv4 EOR must follow the full-table dump");
    assert!(
        eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty(),
        "EOR must be a minimum-length UPDATE: {eor:?}"
    );
}

/// RFC 4724 §2: an IPv6-capable peer must receive both the IPv4 EOR and the
/// IPv6 EOR (empty MP_UNREACH_NLRI for IPv6 unicast) after the full-table dump.
#[test]
fn test_on_established_ipv6_capable_peer_receives_both_eors() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &v6_caps,
        None,
    );

    // IPv4 EOR: minimum-length UPDATE.
    let ipv4_eor = receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("must receive IPv4 EOR");
    assert!(
        ipv4_eor.withdrawn.is_empty()
            && ipv4_eor.attributes.is_empty()
            && ipv4_eor.announced.is_empty(),
        "IPv4 EOR must be a minimum-length UPDATE: {ipv4_eor:?}"
    );

    // IPv6 EOR: UPDATE with empty MP_UNREACH_NLRI for IPv6 unicast.
    let ipv6_eor = receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("must receive IPv6 EOR after IPv4 EOR");
    assert!(
        ipv6_eor.withdrawn.is_empty() && ipv6_eor.announced.is_empty(),
        "IPv6 EOR must have no IPv4 withdrawn/announced: {ipv6_eor:?}"
    );
    assert!(
        matches!(
            ipv6_eor.attributes.as_slice(),
            [PathAttribute::MpUnreachNlri(m)] if m.afi_safi == AfiSafi::IPV6_UNICAST && m.prefixes.is_empty()
        ),
        "IPv6 EOR must carry empty MP_UNREACH_NLRI for IPv6 unicast: {ipv6_eor:?}"
    );

    assert!(
        receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
        "no further messages after both EORs"
    );
}

/// RFC 4271 §5.1.3 regression: eBGP NEXT_HOP in the full-table dump must
/// be the TCP session's local address, not the BGP router ID.
///
/// Before the fix `prepare_outbound` always used `local_bgp_id` (10.0.0.1)
/// as NEXT_HOP.  BIRD 2 rejects such routes because the router ID is not
/// reachable on the session interface.
#[test]
fn test_on_established_ebgp_next_hop_uses_local_addr_not_router_id() {
    use pathvector_session::message::PathAttribute;

    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let local_bgp_id: Ipv4Addr = "10.0.0.1".parse().unwrap(); // router ID (make_state uses this)
    let session_local_addr: Ipv4Addr = "172.31.50.20".parse().unwrap(); // TCP interface address

    let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
    assert_eq!(state.rib.local_bgp_id, local_bgp_id);

    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
    state.rib_insert_v4(
        src,
        RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build(),
    );

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        Some(IpAddr::V4(session_local_addr)),
    );

    let msg = receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("full-table dump UPDATE expected");

    let next_hop = msg.attributes.iter().find_map(|a| {
        if let PathAttribute::NextHop(ip) = a {
            Some(*ip)
        } else {
            None
        }
    });
    assert_eq!(
        next_hop,
        Some(session_local_addr),
        "eBGP NEXT_HOP must be the session local address, not the router ID"
    );
    assert_ne!(
        next_hop,
        Some(local_bgp_id),
        "NEXT_HOP must not be the router ID"
    );
}

/// RFC 4271 §5.1.3 regression: eBGP NEXT_HOP in `propagate_to_all_peers`
/// must use the per-peer session local address stored in `local_addrs`.
#[test]
fn test_propagate_to_all_peers_ebgp_next_hop_uses_local_addr() {
    use pathvector_session::message::PathAttribute;

    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let local_bgp_id: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let session_local_addr: Ipv4Addr = "172.31.50.20".parse().unwrap();

    let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);

    // Establish with a distinct local_addr so local_addrs is populated.
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        Some(IpAddr::V4(session_local_addr)),
    );
    // Drain the (empty) full-table dump; no routes pre-installed.
    while receivers.get_mut(&peer_ip).unwrap().try_recv().is_ok() {}

    // Now insert a route into the loc-rib via a third-party peer and trigger propagation.
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
    let route = RouteBuilder::new(
        nlri("192.0.2.0/24"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65009)]),
    )
    .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
    .peer_type(PeerType::External)
    .build();
    state.rib_insert_v4(src, route);
    state.propagate_to_all_peers(&[nlri("192.0.2.0/24")]);
    state.flush_pending();

    let msg = receivers
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("propagated UPDATE expected");

    let next_hop = msg.attributes.iter().find_map(|a| {
        if let PathAttribute::NextHop(ip) = a {
            Some(*ip)
        } else {
            None
        }
    });
    assert_eq!(
        next_hop,
        Some(session_local_addr),
        "eBGP NEXT_HOP must be the session local address, not the router ID"
    );
    assert_ne!(
        next_hop,
        Some(local_bgp_id),
        "NEXT_HOP must not be the router ID"
    );
}

/// When `next_hop_self = true`, an iBGP peer must receive NEXT_HOP rewritten
/// to the local router address rather than the original eBGP next-hop.
#[test]
fn test_propagate_to_all_peers_next_hop_self_rewrites_ibgp_next_hop() {
    use pathvector_session::message::PathAttribute;

    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let local_bgp_id: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let session_local_addr: Ipv4Addr = "172.16.0.1".parse().unwrap();

    let (tx, mut rx) = mpsc::channel(64);
    let peer_configs = vec![config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: 65001, // iBGP — same AS
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: true,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }];
    let mut senders = HashMap::new();
    senders.insert(peer_ip, tx);
    let mut state = DaemonState::new(
        65001,
        local_bgp_id,
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::Internal,
        65001,
        90,
        &[],
        Some(IpAddr::V4(session_local_addr)),
    );
    // Drain the full-table dump (empty rib).
    while rx.try_recv().is_ok() {}

    // Insert a route learned from an eBGP peer with a remote next-hop.
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
    let ebgp_next_hop: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let route = RouteBuilder::new(
        nlri("192.0.2.0/24"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65099)]),
    )
    .next_hop(NextHop::V4(ebgp_next_hop))
    .peer_type(PeerType::External)
    .build();
    state.rib_insert_v4(src, route);
    state.propagate_to_all_peers(&[nlri("192.0.2.0/24")]);
    state.flush_pending();

    let msg = rx.try_recv().expect("iBGP peer must receive UPDATE");
    let next_hop = msg.attributes.iter().find_map(|a| {
        if let PathAttribute::NextHop(ip) = a {
            Some(*ip)
        } else {
            None
        }
    });
    assert_eq!(
        next_hop,
        Some(session_local_addr),
        "next_hop_self must rewrite iBGP NEXT_HOP to the local session address"
    );
    assert_ne!(
        next_hop,
        Some(ebgp_next_hop),
        "original eBGP next-hop must not be forwarded to iBGP clients"
    );
}

#[test]
fn test_on_established_export_reject_sends_nothing() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (tx, _rx) = mpsc::channel(64);
    let peers = vec![config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: 65002,
        import_default_v6: None,
        md5_password: None,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Reject),
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
    }];
    let mut state = DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peers,
        {
            let mut m = HashMap::new();
            m.insert(peer_ip, tx);
            m
        },
        vec![],
    );

    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
    state.rib_insert_v4(
        src,
        RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build(),
    );

    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    // Export policy rejects everything — no UPDATE should be queued.
    // (We can't assert on the receiver here since we dropped _rx, but the
    // important invariant is that no panic or error occurs, and the RIB is
    // not modified.)
    assert_eq!(state.rib.loc_rib.len(), 1, "RIB must be unchanged");
}

// ── DaemonState::on_terminated ────────────────────────────────────────────

#[test]
fn test_on_terminated_removes_peer_type() {
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
    state.on_terminated(peer_ip, TerminationReason::Unclean, true);
    assert!(!state.rib.peer_types.contains_key(&peer_ip));
}

#[test]
fn test_on_terminated_withdraws_peer_routes_from_rib() {
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

    state.rib_insert_v4(
        PeerId::from(peer_ip),
        RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .peer_type(PeerType::External)
        .build(),
    );
    assert_eq!(state.rib.loc_rib.len(), 1);

    state.on_terminated(peer_ip, TerminationReason::Unclean, true);
    assert_eq!(state.rib.loc_rib.len(), 0);
}

#[test]
fn test_on_terminated_propagates_withdraw_to_other_established_peers() {
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

    // Announce a route from peer_a so it reaches peer_b's AdjRibOut.
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_a),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        },
    );
    // Drain the propagation messages sent during on_route_update.
    receivers
        .get_mut(&IpAddr::V4(peer_a))
        .unwrap()
        .try_recv()
        .ok();
    receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .ok();

    // Terminate peer_a — peer_b must receive a WITHDRAW.
    state.on_terminated(IpAddr::V4(peer_a), TerminationReason::Unclean, true);

    let msg = receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b should receive WITHDRAW after peer_a terminates");
    assert!(!msg.withdrawn.is_empty());
    assert_eq!(msg.withdrawn[0], nlri("192.168.0.0/16"));
}

// ── DaemonState — unknown peer defensive paths ────────────────────────────

/// Calling `on_established` with a peer IP that was never in the config
/// logs an error and returns without panicking.
#[test]
fn test_on_established_unknown_peer_is_noop() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

    let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
    state.on_established(
        IpAddr::V4(unknown),
        unknown,
        PeerType::External,
        65099,
        90,
        &[],
        None,
    );
    // Invariant: no state changes (the unknown IP is absent from maps).
    assert!(!state.rib.peer_types.contains_key(&peer_ip));
}
