use super::*;

// ── MP_UNREACH_NLRI / MP_REACH_NLRI (RFC 4760) ───────────────────────────

#[test]
fn test_handle_update_mp_unreach_withdraws_ipv4_route() {
    // Peer first announces a route via the traditional field, then
    // withdraws it via MP_UNREACH_NLRI (AFI=1, SAFI=1) — valid per RFC 4760
    // and done by some modern implementations when multiprotocol is negotiated.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(rib.len(), 1);

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV4_UNICAST,
                prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
            })],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    assert!(
        rib.is_empty(),
        "MP_UNREACH_NLRI should have removed the route"
    );
    assert!(ari.is_empty(), "AdjRibIn should also be cleared");
}

#[test]
fn test_handle_update_mp_reach_announces_ipv4_route() {
    // Peer announces via MP_REACH_NLRI instead of the traditional NLRI field.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::LocalPref(150),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    next_hop: NextHop::V4("10.0.0.2".parse().unwrap()),
                    prefixes: vec![
                        Prefix::V4(nlri("192.168.1.0/24")),
                        Prefix::V4(nlri("192.168.2.0/24")),
                    ],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        // PeerType::Internal — this test proves MP_REACH_NLRI route
        // installation, not eBGP-specific LOCAL_PREF semantics (RFC
        // 4271 §5.1.5, covered separately below).
        PeerType::Internal,
    );

    assert_eq!(rib.len(), 2, "both MP_REACH prefixes should be in LocRib");
    assert_eq!(ari.len(), 2, "both MP_REACH prefixes should be in AdjRibIn");

    let route = rib.best(&nlri("192.168.1.0/24")).unwrap();
    assert_eq!(route.local_pref, Some(LP::new(150)));
    assert_eq!(
        route.next_hop,
        Some(NextHop::V4("10.0.0.2".parse().unwrap()))
    );
}

#[test]
fn test_handle_update_mp_reach_mixed_with_traditional() {
    // Traditional NLRI + MP_REACH_NLRI V4 in the same UPDATE — both should land.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop("10.0.0.2".parse().unwrap()),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    next_hop: NextHop::V4("10.0.0.3".parse().unwrap()),
                    prefixes: vec![Prefix::V4(nlri("172.16.0.0/12"))],
                }),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    assert_eq!(rib.len(), 2);
    // Traditional NLRI uses NEXT_HOP attribute
    assert_eq!(
        rib.best(&nlri("10.0.0.0/8")).unwrap().next_hop,
        Some(NextHop::V4("10.0.0.2".parse().unwrap()))
    );
    // MP_REACH_NLRI uses its own embedded next-hop
    assert_eq!(
        rib.best(&nlri("172.16.0.0/12")).unwrap().next_hop,
        Some(NextHop::V4("10.0.0.3".parse().unwrap()))
    );
}

#[test]
fn test_handle_update_mp_unreach_non_ipv4_is_skipped() {
    // MP_UNREACH_NLRI for a non-IPv4 AFI/SAFI is silently skipped —
    // no panic, no crash, IPv4 RIB unchanged.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![], // IPv6 prefixes; we have none to construct here
            })],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    assert!(rib.is_empty());
}

#[test]
fn test_handle_update_mp_reach_import_policy_applied() {
    // Import policy must be evaluated for MP_REACH_NLRI routes just as
    // it is for traditional NLRIs.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    next_hop: NextHop::V4("10.0.0.2".parse().unwrap()),
                    prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &reject_all(),
        PeerType::External,
    );

    // Policy rejected it: AdjRibIn stores the raw route, LocRib stays empty.
    assert_eq!(ari.len(), 1, "pre-policy route stored in AdjRibIn");
    assert!(rib.is_empty(), "rejected route must not enter LocRib");
}

#[test]
fn test_on_route_update_mp_unreach_propagates_withdraw_to_peers() {
    // End-to-end: a peer withdraws via MP_UNREACH_NLRI, and the best-path
    // change must reach all other established peers as a WITHDRAW UPDATE.
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut rxs) = make_state(
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
    drain_all(&mut rxs);

    // Peer A announces 10.0.0.0/8 via traditional field.
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
    // Drain the announcement that went to peer B.
    state.flush_pending();
    let _ = rxs.get_mut(&IpAddr::V4(peer_b)).unwrap().try_recv();

    // Peer A now withdraws via MP_UNREACH_NLRI.
    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV4_UNICAST,
                prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
            })],
            announced: vec![],
        },
    );
    state.flush_pending();

    assert_eq!(
        state.rib.loc_rib.len(),
        0,
        "LocRib must be empty after MP_UNREACH_NLRI"
    );

    let withdraw_msg = rxs
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer B should receive a WITHDRAW");
    assert!(
        withdraw_msg.withdrawn.contains(&nlri("10.0.0.0/8")),
        "WITHDRAW must contain the MP-withdrawn prefix"
    );
}

#[test]
fn test_handle_update_mp_reach_ipv6_inserts_into_loc_rib_v6() {
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );

    assert_eq!(rib_v6.len(), 1, "IPv6 route must enter loc_rib_v6");
    assert!(rib.is_empty(), "IPv4 LocRib must remain empty");
    let route = rib_v6.best(&nlri_v6("2001:db8::/32")).unwrap();
    assert_eq!(route.origin, Origin::Igp);
}

#[test]
fn test_handle_update_mp_reach_ipv6_stored_in_adj_rib_in_v6() {
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("fe80::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("fd00::/16"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );

    assert_eq!(ari_v6.len(), 1, "pre-policy route must be in adj_rib_in_v6");
}

#[test]
fn test_rfc8212_ebgp_ipv6_reject_without_policy() {
    // RFC 8212: eBGP peers with no import policy configured must have routes
    // rejected by default. This verifies the IPv6 path applies the same gate
    // as IPv4 — previously IPv6 was accept-all regardless of peer type.
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let reject_policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Reject);

    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &reject_policy_v6,
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );

    assert!(
        rib_v6.is_empty(),
        "eBGP IPv6 route must be rejected when import policy is Reject (RFC 8212)"
    );
    assert_eq!(
        ari_v6.len(),
        1,
        "rejected route must still be stored in AdjRibIn for soft-reconfig"
    );
}

// ── import_default_v6 TOML wiring ────────────────────────────────────────

/// When `import_default_v6` is not set in config, the IPv6 import policy
/// falls back to `import_default`. This test verifies the fallback: an eBGP
/// peer with `import_default = "accept"` and no `import_default_v6` must
/// accept IPv6 routes.
#[test]
fn test_import_default_v6_falls_back_to_import_default() {
    use std::collections::HashMap;

    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let peers = vec![config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: 65002, // eBGP
        import_default: Some(config::ImportDefault::Accept),
        import_default_v6: None, // omitted → falls back to import_default
        export_default: None,
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

    let policy_v6 = state.import_policies_v6.get(&peer_ip).unwrap();
    let mut dummy = route_v6("2001:db8::/32");
    assert_eq!(
        policy_v6.evaluate(&mut dummy),
        Decision::Accept,
        "IPv6 policy must fall back to import_default (Accept) when import_default_v6 is None"
    );
}

/// When `import_default_v6` is set it overrides `import_default` for the
/// IPv6 policy only. The IPv4 policy must remain unaffected.
#[test]
fn test_import_default_v6_overrides_import_default() {
    use std::collections::HashMap;

    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let peers = vec![config::PeerConfig {
        address: peer_ip,
        port: 179,
        remote_as: 65002, // eBGP
        import_default: Some(config::ImportDefault::Accept),
        import_default_v6: Some(config::ImportDefault::Reject),
        export_default: None,
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

    let policy_v4 = state.import_policies.get(&peer_ip).unwrap();
    let policy_v6 = state.import_policies_v6.get(&peer_ip).unwrap();

    let mut dummy_v4 = route_v4("192.0.2.0/24");
    let mut dummy_v6 = route_v6("2001:db8::/32");

    assert_eq!(
        policy_v4.evaluate(&mut dummy_v4),
        Decision::Accept,
        "IPv4 policy must remain Accept (import_default)"
    );
    assert_eq!(
        policy_v6.evaluate(&mut dummy_v6),
        Decision::Reject,
        "IPv6 policy must be Reject (import_default_v6 overrides)"
    );
}

#[test]
fn test_handle_update_mp_unreach_ipv6_withdraws_route() {
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

    // Announce first.
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
    assert_eq!(rib_v6.len(), 1);

    // Then withdraw.
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
            })],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );

    assert!(
        rib_v6.is_empty(),
        "loc_rib_v6 must be empty after withdrawal"
    );
    assert!(rib.is_empty(), "IPv4 LocRib must be unaffected");
}

#[test]
fn test_handle_update_ipv4_and_ipv6_in_same_update() {
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &accept_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );

    assert_eq!(rib.len(), 1, "IPv4 route must be in loc_rib");
    assert_eq!(rib_v6.len(), 1, "IPv6 route must be in loc_rib_v6");
}
