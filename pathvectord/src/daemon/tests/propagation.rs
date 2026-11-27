use super::*;

// Finding I — RFC 4456 §8: RR split-horizon must apply during full-table dump.

#[test]
fn test_on_established_rr_split_horizon_blocks_non_client_to_non_client() {
    // Topology: local speaker is RR with one client (10.0.0.3) and one
    // non-client (10.0.0.4). A route from another non-client iBGP peer
    // (10.0.0.5) must NOT be sent to 10.0.0.4 on establish (finding I).
    let non_client_a: Ipv4Addr = "10.0.0.4".parse().unwrap();
    let non_client_b: Ipv4Addr = "10.0.0.5".parse().unwrap();
    let client: Ipv4Addr = "10.0.0.3".parse().unwrap();

    let (mut state, mut rxs) = make_state(
        65001,
        &[
            (IpAddr::V4(non_client_a), 65001), // iBGP
            (IpAddr::V4(non_client_b), 65001), // iBGP
            (IpAddr::V4(client), 65001),       // iBGP
        ],
    );
    // Designate client as an RR client.
    Arc::make_mut(&mut state.rib)
        .rr_clients
        .insert(IpAddr::V4(client));

    // non_client_b establishes and deposits a route.
    state.on_established(
        IpAddr::V4(non_client_b),
        non_client_b,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    let src = PeerId::new(IpAddr::V4(non_client_b));
    let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4(non_client_b))
        .peer_type(PeerType::Internal)
        .build();
    state.rib_insert_v4(src, route);

    // Drain non_client_b's channel (its own establish dump).
    while rxs
        .get_mut(&IpAddr::V4(non_client_b))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    // non_client_a establishes — must NOT receive the route from non_client_b.
    state.on_established(
        IpAddr::V4(non_client_a),
        non_client_a,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    // Drain all EOR markers (RFC 4724 §2) from on_established, then verify no
    // actual route UPDATE was sent. EORs are either empty UpdateMessages (IPv4)
    // or UpdateMessages with empty MP_UNREACH_NLRI (IPv6, RFC 4724 §2).
    let rx = rxs.get_mut(&IpAddr::V4(non_client_a)).unwrap();
    let mut route_received = false;
    while let Ok(m) = rx.try_recv() {
        let has_announced_nlri = !m.announced.is_empty();
        let has_mp_reach = m
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if !mp.prefixes.is_empty()));
        if has_announced_nlri || has_mp_reach {
            route_received = true;
        }
    }
    assert!(
        !route_received,
        "non-client must not receive routes from other non-clients during full-table dump (RFC 4456 §8)"
    );
}

#[test]
fn test_on_established_rr_client_receives_all_routes_in_dump() {
    // An RR client MUST receive the full table on establish, including routes
    // from non-client iBGP peers.
    let non_client: Ipv4Addr = "10.0.0.4".parse().unwrap();
    let client: Ipv4Addr = "10.0.0.3".parse().unwrap();

    let (mut state, mut rxs) = make_state(
        65001,
        &[(IpAddr::V4(non_client), 65001), (IpAddr::V4(client), 65001)],
    );
    Arc::make_mut(&mut state.rib)
        .rr_clients
        .insert(IpAddr::V4(client));

    // non_client deposits a route.
    state.on_established(
        IpAddr::V4(non_client),
        non_client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    let src = PeerId::new(IpAddr::V4(non_client));
    let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4(non_client))
        .peer_type(PeerType::Internal)
        .build();
    state.rib_insert_v4(src, route);
    while rxs
        .get_mut(&IpAddr::V4(non_client))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    // RR client establishes — MUST receive the route from the non-client.
    state.on_established(
        IpAddr::V4(client),
        client,
        PeerType::Internal,
        65001,
        90,
        &[],
        None,
    );
    assert!(
        rxs.get_mut(&IpAddr::V4(client)).unwrap().try_recv().is_ok(),
        "RR client must receive routes from non-client iBGP peers in full-table dump"
    );
}

// Finding K — RFC 4760: IPv6 routes must only be sent to peers that negotiated
// MultiProtocol(IPV6_UNICAST) capability.

#[test]
fn test_ipv6_route_not_propagated_to_non_ipv6_capable_peer() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut rxs) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );

    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    // peer_a negotiated IPv6; peer_b did NOT.
    let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        IpAddr::V4(peer_a),
        peer_a,
        PeerType::External,
        65002,
        90,
        &v6_caps,
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

    // peer_a announces an IPv6 prefix.
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
    );

    // peer_b (no IPv6 capability) gets an IPv4 EOR from on_established
    // but must not receive any MP_REACH_NLRI — drain the EOR first.
    rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv().ok(); // IPv4 EOR
    assert!(
        rxs.get_mut(&IpAddr::V4(peer_b))
            .unwrap()
            .try_recv()
            .is_err(),
        "peer without IPv6 capability must not receive MP_REACH_NLRI (RFC 4760)"
    );
}

#[test]
fn test_ipv6_full_table_dump_not_sent_to_non_ipv6_capable_peer() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, mut rxs) = make_state(65001, &[(peer_ip, 65002)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    // Pre-populate v6 RIB.
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
    let v6_route = RouteBuilder::new(
        nlri_v6("2001:db8::/32"),
        Origin::Igp,
        AsPath::from_sequence(vec![Asn::new(65009)]),
    )
    .next_hop(NextHop::V6("2001:db8::9".parse().unwrap()))
    .peer_type(PeerType::External)
    .build();
    state.rib_insert_v6(src, v6_route);

    // Establish without IPv6 capability.
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    // Must receive exactly one message: the IPv4 EOR. No IPv6 dump, no IPv6 EOR.
    let eor = rxs
        .get_mut(&peer_ip)
        .unwrap()
        .try_recv()
        .expect("must receive IPv4 EOR even for non-IPv6-capable peer");
    assert!(
        eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty(),
        "only the IPv4 EOR should arrive — got: {eor:?}"
    );
    assert!(
        rxs.get_mut(&peer_ip).unwrap().try_recv().is_err(),
        "full-table IPv6 dump must not be sent to peers without IPv6 capability (RFC 4760)"
    );
}

fn ebgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
    let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    (p, AdjRibOut::new(p, PeerType::External))
}

fn ibgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
    let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    (p, AdjRibOut::new(p, PeerType::Internal))
}

#[test]
fn test_propagate_prefix_sends_update_for_new_route() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );

    let msg = rx.try_recv().expect("should have queued an UPDATE");
    assert!(!msg.announced.is_empty());
    assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
}

#[test]
fn test_propagate_prefix_no_send_when_route_unchanged() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let _ = rx.try_recv();

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(
        rx.try_recv().is_err(),
        "identical route must not produce a second UPDATE"
    );
}

#[test]
fn test_propagate_prefix_sends_withdraw_when_route_removed() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let _ = rx.try_recv();

    rib.withdraw(&peer(), &nlri("10.0.0.0/8"), &AlwaysReachable);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let msg = rx.try_recv().expect("should have queued a WITHDRAW");
    assert!(!msg.withdrawn.is_empty());
    assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    assert!(msg.announced.is_empty());
}

#[test]
fn test_propagate_prefix_sends_withdraw_when_export_policy_rejects() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let _ = rx.try_recv();

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &reject_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let msg = rx.try_recv().expect("should have queued a WITHDRAW");
    assert!(!msg.withdrawn.is_empty());
    assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
}

#[test]
fn test_propagate_prefix_no_withdraw_for_never_advertised_route() {
    let (_, mut aro) = ebgp_out_peer();
    let rib = LocRib::<Ipv4Addr>::new();
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &reject_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(
        rx.try_recv().is_err(),
        "no message expected for a route that was never advertised"
    );
}

#[test]
fn test_propagate_prefix_ebgp_source_peer_not_readvertised() {
    // A route learned from an eBGP peer must never be re-advertised back
    // to that same peer.  This mirrors the GoBGP "No matching path for
    // withdraw found" warning: routes were ending up in AdjRibOut for the
    // source peer and producing spurious WITHDRAWs.
    let (src_peer, mut aro) = ebgp_out_peer(); // same peer as source AND target
    let mut rib = LocRib::new();
    rib.insert(src_peer, ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(
        rx.try_recv().is_err(),
        "source-peer split horizon must suppress eBGP re-advertisement"
    );
    assert!(
        aro.is_empty(),
        "AdjRibOut must not store route for source peer"
    );
}

/// Full exchange lifecycle regression test.
///
/// Simulates the scripts/exchange.sh scenario entirely in-process:
/// 1. Peer (GoBGP) establishes and announces three prefixes.
/// 2. Daemon originates two local prefixes → peer receives ANNOUNCEs.
/// 3. Import policy flipped to reject → peer routes drop from LocRib.
/// 4. Import policy restored to accept → peer routes return to LocRib.
/// 5. Peer withdraws two of its three routes.
/// 6. Daemon withdraws its local routes → peer receives WITHDRAWs.
///
/// Final invariant: only the one surviving peer route remains in LocRib.
#[test]
fn test_exchange_lifecycle_final_rib_has_only_surviving_peer_route() {
    let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let (mut state, mut rx_map) = make_state(65002, &[(IpAddr::V4(gobgp), 65001)]);

    // ── 1. Session establishes; GoBGP announces {10, 172, 192} ───────────
    state.on_established(
        IpAddr::V4(gobgp),
        gobgp,
        PeerType::External,
        65001,
        90,
        &[],
        None,
    );

    let gobgp_announces = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Egp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
            PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
        ],
        announced: vec![
            nlri("10.0.0.0/8"),
            nlri("172.16.0.0/12"),
            nlri("192.168.0.0/16"),
        ],
    };
    state.on_route_update(IpAddr::V4(gobgp), gobgp_announces);
    state.flush_pending();
    // Drain the table-dump messages generated during on_established + propagation
    // (source-peer check suppresses re-advertisement back to GoBGP).
    while rx_map
        .get_mut(&IpAddr::V4(gobgp))
        .unwrap()
        .try_recv()
        .is_ok()
    {}
    assert_eq!(
        state.rib.loc_rib.len(),
        3,
        "phase 1: all three GoBGP routes in LocRib"
    );

    // ── 2. Originate {203, 198}; GoBGP should receive ANNOUNCEs ──────────
    let route_203 = RouteBuilder::new(nlri("203.0.113.0/24"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4("10.0.0.2".parse().unwrap()))
        .build();
    let route_198 = RouteBuilder::new(nlri("198.51.100.0/24"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V4("10.0.0.2".parse().unwrap()))
        .build();
    state.originate_routes(vec![route_203, route_198]);
    state.flush_pending();

    let mut announced_to_gobgp: Vec<Nlri<Ipv4Addr>> = Vec::new();
    while let Ok(msg) = rx_map.get_mut(&IpAddr::V4(gobgp)).unwrap().try_recv() {
        announced_to_gobgp.extend(msg.announced);
    }
    assert!(
        announced_to_gobgp.contains(&nlri("203.0.113.0/24")),
        "phase 2: GoBGP must receive ANNOUNCE for 203.0.113.0/24"
    );
    assert!(
        announced_to_gobgp.contains(&nlri("198.51.100.0/24")),
        "phase 2: GoBGP must receive ANNOUNCE for 198.51.100.0/24"
    );
    assert_eq!(
        state.rib.loc_rib.len(),
        5,
        "phase 2: 3 GoBGP + 2 local routes in LocRib"
    );

    // ── 3. Import policy → reject; GoBGP routes leave LocRib ─────────────
    state.set_import_default(IpAddr::V4(gobgp), DefaultAction::Reject);
    state.flush_pending();
    while rx_map
        .get_mut(&IpAddr::V4(gobgp))
        .unwrap()
        .try_recv()
        .is_ok()
    {}
    assert_eq!(
        state.rib.loc_rib.len(),
        2,
        "phase 3 reject: only local originated routes remain"
    );

    // ── 4. Import policy → accept; GoBGP routes return ───────────────────
    state.set_import_default(IpAddr::V4(gobgp), DefaultAction::Accept);
    state.flush_pending();
    while rx_map
        .get_mut(&IpAddr::V4(gobgp))
        .unwrap()
        .try_recv()
        .is_ok()
    {}
    assert_eq!(
        state.rib.loc_rib.len(),
        5,
        "phase 4 restore: all 5 routes back in LocRib"
    );

    // ── 5. GoBGP withdraws {10, 172} ──────────────────────────────────────
    let gobgp_withdraws = UpdateMessage {
        withdrawn: vec![nlri("10.0.0.0/8"), nlri("172.16.0.0/12")],
        attributes: vec![],
        announced: vec![],
    };
    state.on_route_update(IpAddr::V4(gobgp), gobgp_withdraws);
    state.flush_pending();
    while rx_map
        .get_mut(&IpAddr::V4(gobgp))
        .unwrap()
        .try_recv()
        .is_ok()
    {}
    assert_eq!(
        state.rib.loc_rib.len(),
        3,
        "phase 5: 192 from GoBGP + 2 local routes remain"
    );

    // ── 6. Daemon withdraws {203, 198}; GoBGP must receive WITHDRAWs ─────
    state.withdraw_originated_routes(&[nlri("203.0.113.0/24"), nlri("198.51.100.0/24")]);
    state.flush_pending();
    let mut withdrawn_to_gobgp: Vec<Nlri<Ipv4Addr>> = Vec::new();
    while let Ok(msg) = rx_map.get_mut(&IpAddr::V4(gobgp)).unwrap().try_recv() {
        withdrawn_to_gobgp.extend(msg.withdrawn);
    }
    assert!(
        withdrawn_to_gobgp.contains(&nlri("203.0.113.0/24")),
        "phase 6: GoBGP must receive WITHDRAW for 203.0.113.0/24"
    );
    assert!(
        withdrawn_to_gobgp.contains(&nlri("198.51.100.0/24")),
        "phase 6: GoBGP must receive WITHDRAW for 198.51.100.0/24"
    );

    // ── Final: only 192.168.0.0/16 (from GoBGP) survives in LocRib ───────
    assert_eq!(
        state.rib.loc_rib.len(),
        1,
        "final: only 192.168.0.0/16 must remain in LocRib"
    );
    assert!(
        state.rib.loc_rib.best(&nlri("192.168.0.0/16")).is_some(),
        "final: 192.168.0.0/16 must be the surviving route"
    );
}

#[test]
fn test_originate_routes_v6_peer_receives_announces() {
    use pathvector_types::{AsPath, Origin};
    let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let (mut state, mut rx_map) = make_state(65001, &[(IpAddr::V4(gobgp), 65002)]);
    state.on_established(
        IpAddr::V4(gobgp),
        gobgp,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    while rx_map
        .get_mut(&IpAddr::V4(gobgp))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
        .build();
    state.originate_route_v6(route);

    assert!(
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8::/32"))
            .is_some(),
        "originated v6 route must be in loc_rib_v6"
    );
    assert!(
        state
            .rib
            .originated_routes_v6
            .contains(&nlri_v6("2001:db8::/32")),
        "originated v6 route must be tracked in originated_routes_v6"
    );
}

#[test]
fn test_withdraw_originated_routes_v6_removes_from_rib_and_notifies_peer() {
    use pathvector_types::{AsPath, Origin};
    let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let (mut state, mut rx_map) = make_state(65001, &[(IpAddr::V4(gobgp), 65002)]);
    state.on_established(
        IpAddr::V4(gobgp),
        gobgp,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    while rx_map
        .get_mut(&IpAddr::V4(gobgp))
        .unwrap()
        .try_recv()
        .is_ok()
    {}

    let route = RouteBuilder::new(nlri_v6("2001:db8:1::/48"), Origin::Igp, AsPath::new())
        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
        .build();
    state.originate_route_v6(route);

    // Drain the ANNOUNCE
    while rx_map
        .get_mut(&IpAddr::V4(gobgp))
        .unwrap()
        .try_recv()
        .is_ok()
    {}
    assert!(
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8:1::/48"))
            .is_some()
    );

    state.withdraw_originated_route_v6(nlri_v6("2001:db8:1::/48"));

    assert!(
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8:1::/48"))
            .is_none(),
        "withdrawn v6 route must be removed from loc_rib_v6"
    );
    assert!(
        !state
            .rib
            .originated_routes_v6
            .contains(&nlri_v6("2001:db8:1::/48")),
        "withdrawn v6 route must be removed from originated_routes_v6"
    );
}

#[test]
fn test_withdraw_originated_routes_v6_noop_for_unknown_prefix() {
    let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(IpAddr::V4(gobgp), 65002)]);
    // Should not panic on an unknown prefix.
    state.withdraw_originated_route_v6(nlri_v6("2001:db8:ff::/48"));
    assert!(
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8:ff::/48"))
            .is_none()
    );
}

#[test]
fn test_propagate_prefix_ibgp_split_horizon_no_send() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ibgp_route("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ibgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::Internal,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(
        rx.try_recv().is_err(),
        "iBGP split-horizon must suppress re-advertisement"
    );
    assert!(aro.is_empty());
}

#[test]
fn test_propagate_prefix_ebgp_prepends_local_as_in_wire_message() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);

    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );

    let msg = rx.try_recv().unwrap();
    let aspath_attr = msg
        .attributes
        .iter()
        .find_map(|a| {
            if let PathAttribute::AsPath(p) = a {
                Some(p.clone())
            } else {
                None
            }
        })
        .expect("UPDATE must carry AS_PATH");
    assert!(
        aspath_attr.contains(Asn::new(65001)),
        "local AS must be prepended"
    );
}

// ── propagate_prefix — iBGP split-horizon eviction ────────────────────────

/// When the best path for a prefix switches from eBGP to iBGP, the
/// previously stored eBGP entry in the iBGP peer's `AdjRibOut` is evicted
/// (`InsertOutcome::Filtered(Some(_))`), triggering a WITHDRAW.
#[test]
fn test_propagate_prefix_ibgp_split_horizon_eviction_sends_withdraw() {
    let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
    let (_, mut aro) = ibgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);

    // Phase 1: best path is eBGP — stored in the iBGP peer's AdjRibOut.
    let mut rib = LocRib::new();
    rib.insert(src, ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::Internal,
        65001,
        bgp_id(),
        &tx,
    );
    let _ = rx.try_recv(); // consume the UPDATE

    // Phase 2: best path switches to iBGP — split-horizon evicts the stored
    // eBGP entry and the peer must receive a WITHDRAW.
    let mut rib2 = LocRib::new();
    rib2.insert(src, ibgp_route("10.0.0.0/8"), &AlwaysReachable);
    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib2,
        &mut aro,
        &accept_all(),
        PeerType::Internal,
        65001,
        bgp_id(),
        &tx,
    );
    let msg = rx
        .try_recv()
        .expect("split-horizon eviction must send WITHDRAW");
    assert!(!msg.withdrawn.is_empty());
    assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
}

// ── propagate_prefix — StubRibView (dependency-inversion tests) ─────────────

/// Minimal `RibView` implementation for unit tests that want to inject a
/// specific best route without constructing a full `LocRib`.
struct StubRibView(Option<Route<Ipv4Addr>>);

impl RibView<Ipv4Addr> for StubRibView {
    fn best(&self, _nlri: &Nlri<Ipv4Addr>) -> Option<&Route<Ipv4Addr>> {
        self.0.as_ref()
    }
}

#[test]
fn test_propagate_prefix_stub_rib_announces_when_route_present() {
    let rib = StubRibView(Some(ebgp_route_with_lp("10.0.0.0/8")));
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);
    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let msg = rx
        .try_recv()
        .expect("should announce when best route present");
    assert!(!msg.announced.is_empty());
    assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
}

#[test]
fn test_propagate_prefix_stub_rib_no_message_when_no_route() {
    let rib = StubRibView(None);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);
    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &reject_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(
        rx.try_recv().is_err(),
        "no message when RIB has no best route and prefix was never advertised"
    );
}

#[test]
fn test_propagate_prefix_stub_rib_withdraw_when_route_gone() {
    // First advertise via a real LocRib, then call again with empty StubRibView
    // to verify a WITHDRAW is produced even without constructing a second LocRib.
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(16);
    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let _ = rx.try_recv(); // consume announcement

    // Now inject an empty view — simulates route having been withdrawn
    let empty_rib = StubRibView(None);
    propagate_and_flush(
        nlri("10.0.0.0/8"),
        &empty_rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    let msg = rx
        .try_recv()
        .expect("should WITHDRAW when best route disappears");
    assert!(!msg.withdrawn.is_empty());
    assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
}

// ── propagate_prefix — channel-full stall detection ──────────────────────

/// When the outbound UPDATE channel is full, propagate_prefix returns false
/// so the caller can close the session and restore a consistent peer view.
#[test]
fn test_propagate_prefix_full_update_channel_returns_false() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, _rx) = mpsc::channel(1);

    // Fill the single-slot channel so the next try_send fails.
    tx.try_send(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    })
    .unwrap();

    let ok = propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(!ok, "full channel must return false");
}

/// When the outbound WITHDRAW channel is full (Reject/Next decision path),
/// propagate_prefix returns false.
#[test]
fn test_propagate_prefix_full_withdraw_on_reject_returns_false() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(1);

    // Advertise the route so it is stored in AdjRibOut.
    let ok = propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(ok);
    let _ = rx.try_recv();

    // Fill the channel before the second call so try_send fails.
    tx.try_send(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    })
    .unwrap();

    // Export policy now rejects — triggers WITHDRAW try_send on a full channel.
    let ok = propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &reject_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(!ok, "full channel on WITHDRAW (reject) must return false");
}

/// When the outbound WITHDRAW channel is full (no best route / None path),
/// propagate_prefix returns false.
#[test]
fn test_propagate_prefix_full_withdraw_on_empty_rib_returns_false() {
    let mut rib = LocRib::new();
    rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
    let (_, mut aro) = ebgp_out_peer();
    let (tx, mut rx) = mpsc::channel(1);

    // Store the route in AdjRibOut.
    let ok = propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(ok);
    let _ = rx.try_recv();

    // Remove the route so loc_rib.best returns None.
    rib.withdraw(&peer(), &nlri("10.0.0.0/8"), &AlwaysReachable);

    // Fill the channel so the WITHDRAW try_send fails.
    tx.try_send(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    })
    .unwrap();

    let ok = propagate_and_flush(
        nlri("10.0.0.0/8"),
        &rib,
        &mut aro,
        &accept_all(),
        PeerType::External,
        65001,
        bgp_id(),
        &tx,
    );
    assert!(!ok, "full channel on WITHDRAW (no best) must return false");
}
