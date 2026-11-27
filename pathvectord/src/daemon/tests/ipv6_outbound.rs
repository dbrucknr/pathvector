use super::*;

// ── IPv6 outbound (propagate_prefix_v6 / flush_updates_v6) ───────────────

fn peer_b() -> PeerId {
    peer_id("10.0.0.2")
}

fn make_adj_rib_out_v6(pt: PeerType) -> AdjRibOut<Ipv6Addr> {
    // Use a distinct peer ID from `peer()` (the typical route source) so
    // that the source-peer split-horizon check in propagate_prefix_v6 does
    // not suppress the announcement in these unit tests.
    AdjRibOut::new(peer_b(), pt)
}

#[test]
fn test_propagate_prefix_v6_ibgp_announces_route() {
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let mut aro = make_adj_rib_out_v6(PeerType::Internal);
    let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
        .peer_type(PeerType::External)
        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
        .build();
    rib_v6.insert(peer(), route, &AlwaysReachable);

    let decision = propagate_prefix_v6(
        nlri_v6("2001:db8::/32"),
        &rib_v6,
        &mut aro,
        &std::collections::HashSet::new(),
        &accept_all_v6(),
        PeerType::Internal,
        65001,
        65001,
        None, // no local_ipv6 — OK for iBGP
        false,
        false,
    );

    assert!(
        matches!(decision, PrefixDecisionV6::Announce(_)),
        "iBGP peer should receive v6 announcement regardless of local_ipv6"
    );
}

#[test]
fn test_propagate_prefix_v6_ebgp_with_local_ipv6_rewrites_nexthop() {
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let mut aro = make_adj_rib_out_v6(PeerType::External);
    let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
        .peer_type(PeerType::External)
        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
        .build();
    rib_v6.insert(peer(), route, &AlwaysReachable);

    let local_v6: Ipv6Addr = "2001:db8::ff".parse().unwrap();
    let decision = propagate_prefix_v6(
        nlri_v6("2001:db8::/32"),
        &rib_v6,
        &mut aro,
        &std::collections::HashSet::new(),
        &accept_all_v6(),
        PeerType::External,
        65001,
        65001,
        Some(local_v6),
        false,
        false,
    );

    match decision {
        PrefixDecisionV6::Announce(r) => {
            assert_eq!(
                r.next_hop,
                Some(NextHop::V6(local_v6)),
                "eBGP next-hop must be rewritten to local_ipv6"
            );
        }
        other => panic!("expected Announce, got {other:?}"),
    }
}

#[test]
fn test_propagate_prefix_v6_ebgp_without_local_ipv6_is_no_announce() {
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let mut aro = make_adj_rib_out_v6(PeerType::External);
    let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
        .peer_type(PeerType::External)
        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
        .build();
    rib_v6.insert(peer(), route, &AlwaysReachable);

    let decision = propagate_prefix_v6(
        nlri_v6("2001:db8::/32"),
        &rib_v6,
        &mut aro,
        &std::collections::HashSet::new(),
        &accept_all_v6(),
        PeerType::External,
        65001,
        65001,
        None, // no local_ipv6 — eBGP must NOT announce
        false,
        false,
    );

    assert!(
        matches!(decision, PrefixDecisionV6::NoChange),
        "eBGP peer without local_ipv6 must not receive v6 announcement"
    );
}

#[test]
fn test_propagate_prefix_v6_withdraw_when_best_disappears() {
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let mut aro = make_adj_rib_out_v6(PeerType::Internal);
    // Pre-populate AdjRibOut with an existing announcement.
    let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
        .peer_type(PeerType::External)
        .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
        .build();
    rib_v6.insert(peer(), route.clone(), &AlwaysReachable);
    // Announce it first so AdjRibOut records it.
    propagate_prefix_v6(
        nlri_v6("2001:db8::/32"),
        &rib_v6,
        &mut aro,
        &std::collections::HashSet::new(),
        &accept_all_v6(),
        PeerType::Internal,
        65001,
        65001,
        None,
        false,
        false,
    );

    // Now withdraw from loc_rib_v6 and propagate again.
    rib_v6.withdraw(&peer(), &nlri_v6("2001:db8::/32"), &AlwaysReachable);
    let decision = propagate_prefix_v6(
        nlri_v6("2001:db8::/32"),
        &rib_v6,
        &mut aro,
        &std::collections::HashSet::new(),
        &accept_all_v6(),
        PeerType::Internal,
        65001,
        65001,
        None,
        false,
        false,
    );

    assert!(
        matches!(decision, PrefixDecisionV6::Withdraw(_)),
        "must produce Withdraw when best path is gone"
    );
}

#[test]
fn test_on_established_sends_v6_full_table_dump() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, mut rxs) = make_state(65001, &[(peer_ip, 65002)]);

    // Pre-populate the v6 RIB with a route from a third-party peer.
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

    // Set local_ipv6 so eBGP dump works.
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

    let caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &caps,
        None,
    );

    // RFC 4724 §4.1: v4 and v6 dumps are independently gated (each family
    // sends its own EOR right after its own flush), so the v6
    // MP_REACH_NLRI is no longer guaranteed to be the very first message
    // — the (empty here) v4 dump's EOR precedes it. Drain messages until
    // the MP_REACH_NLRI UPDATE is found.
    let rx = rxs.get_mut(&peer_ip).unwrap();
    let has_mp_reach = std::iter::from_fn(|| rx.try_recv().ok()).any(|msg| {
        msg.attributes.iter().any(
            |a| matches!(a, PathAttribute::MpReachNlri(mp) if mp.afi_safi == AfiSafi::IPV6_UNICAST),
        )
    });
    assert!(
        has_mp_reach,
        "Established full-table dump must include v6 MP_REACH_NLRI"
    );
}

#[test]
fn test_on_route_update_v6_propagates_to_peer() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut rxs) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );

    // Set local_ipv6 so eBGP next-hop rewrite works for peer_b.
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

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
        &v6_caps,
        None,
    );
    drain_all(&mut rxs);

    // Peer A announces an IPv6 route via MP_REACH_NLRI.
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

    state.flush_pending();

    // peer_b should receive an UPDATE with MP_REACH_NLRI for the v6 prefix.
    let msg = rxs
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b should receive a v6 UPDATE");
    let has_v6 = msg.attributes.iter().any(
        |a| matches!(a, PathAttribute::MpReachNlri(mp) if mp.afi_safi == AfiSafi::IPV6_UNICAST),
    );
    assert!(
        has_v6,
        "propagated UPDATE must contain MP_REACH_NLRI for v6 prefix"
    );
}
