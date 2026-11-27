use super::*;

// ── import policy ─────────────────────────────────────────────────────────

#[test]
fn test_reject_all_policy_blocks_all_routes() {
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
            announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
        },
        &mut ari,
        &mut rib,
        &reject_all(),
        PeerType::External,
    );
    assert!(rib.is_empty());
}

#[test]
fn test_accept_all_policy_passes_all_routes() {
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
            announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(rib.len(), 2);
}

#[test]
fn test_policy_modifies_route_before_insert() {
    let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
    policy.add_term(Term::new(
        AnyCondition,
        ActionSequence::new()
            .then(SetLocalPref::new(LP::new(200)))
            .then(Accept),
    ));

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
        &policy,
        PeerType::External,
    );

    let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
    assert_eq!(route.local_pref, Some(LP::new(200)));
}

#[test]
fn test_policy_partial_reject_only_accepted_routes_inserted() {
    let blocked = Community::from_parts(65001, 1);
    let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
    policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::Communities(vec![blocked]),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &policy,
        PeerType::External,
    );

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        },
        &mut ari,
        &mut rib,
        &policy,
        PeerType::External,
    );

    assert!(
        rib.best(&nlri("10.0.0.0/8")).is_none(),
        "blocked route must not be in RIB"
    );
    assert!(
        rib.best(&nlri("192.168.0.0/16")).is_some(),
        "clean route must be in RIB"
    );
}

#[test]
fn test_peer_type_tagged_on_route() {
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
        PeerType::Internal,
    );
    let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
    assert_eq!(route.peer_type, PeerType::Internal);
}

// ── Adj-RIB-In pre-policy store ───────────────────────────────────────────

#[test]
fn test_adj_rib_in_stores_raw_route_even_when_rejected() {
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
        &reject_all(),
        PeerType::External,
    );
    assert!(rib.is_empty());
    assert_eq!(ari.len(), 1);
    assert!(ari.get(&nlri("10.0.0.0/8")).is_some());
}

#[test]
fn test_adj_rib_in_stores_raw_attributes_before_policy_modification() {
    let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
    policy.add_term(Term::new(
        AnyCondition,
        ActionSequence::new()
            .then(SetLocalPref::new(LP::new(200)))
            .then(Accept),
    ));

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
        &policy,
        PeerType::External,
    );

    assert_eq!(
        rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
        Some(LP::new(200))
    );
    assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
}

#[test]
fn test_adj_rib_in_withdraw_clears_both_tables() {
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
    assert_eq!(ari.len(), 1);
    assert_eq!(rib.len(), 1);

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![nlri("10.0.0.0/8")],
            attributes: vec![],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(ari.is_empty());
    assert!(rib.is_empty());
}

// ── soft reconfiguration ──────────────────────────────────────────────────

#[test]
fn test_reapply_accepts_previously_rejected_route() {
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
        &reject_all(),
        PeerType::External,
    );
    assert!(rib.is_empty());

    reapply_without_blackholes(
        peer(),
        &ari,
        &mut rib,
        &accept_all(),
        &test_gate(),
        &AlwaysReachable,
    );
    assert!(rib.best(&nlri("10.0.0.0/8")).is_some());
}

#[test]
fn test_reapply_rejects_previously_accepted_route() {
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
    assert!(rib.best(&nlri("10.0.0.0/8")).is_some());

    reapply_without_blackholes(
        peer(),
        &ari,
        &mut rib,
        &reject_all(),
        &test_gate(),
        &AlwaysReachable,
    );
    assert!(rib.best(&nlri("10.0.0.0/8")).is_none());
}

#[test]
fn test_reapply_applies_new_policy_modifications() {
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
    assert_eq!(rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref, None);

    let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
    new_policy.add_term(Term::new(
        AnyCondition,
        ActionSequence::new()
            .then(SetLocalPref::new(LP::new(300)))
            .then(Accept),
    ));

    reapply_without_blackholes(
        peer(),
        &ari,
        &mut rib,
        &new_policy,
        &test_gate(),
        &AlwaysReachable,
    );
    assert_eq!(
        rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
        Some(LP::new(300))
    );
    assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
}

#[test]
fn test_reapply_partial_accept_reject() {
    let blocked = Community::from_parts(65001, 1);
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::Communities(vec![blocked]),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(rib.len(), 2);

    let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
    new_policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

    reapply_without_blackholes(
        peer(),
        &ari,
        &mut rib,
        &new_policy,
        &test_gate(),
        &AlwaysReachable,
    );
    assert!(
        rib.best(&nlri("10.0.0.0/8")).is_none(),
        "blocked route must be withdrawn"
    );
    assert!(
        rib.best(&nlri("192.168.0.0/16")).is_some(),
        "clean route must remain"
    );
}

// ── reapply_import_policy_v6 ──────────────────────────────────────────────

#[test]
fn test_reapply_v6_accepts_previously_rejected_route() {
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();

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
        &mut fresh_ari(),
        &mut LocRib::new(),
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &reject_all_v6(),
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    );
    assert!(rib_v6.is_empty(), "route rejected by initial policy");

    reapply_without_blackholes(
        peer(),
        &ari_v6,
        &mut rib_v6,
        &accept_all_v6(),
        &test_gate(),
        &AlwaysReachable,
    );
    assert!(
        rib_v6.best(&nlri_v6("2001:db8::/32")).is_some(),
        "route must be accepted after policy change"
    );
}

#[test]
fn test_reapply_v6_rejects_previously_accepted_route() {
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();

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
        &mut fresh_ari(),
        &mut LocRib::new(),
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
    assert!(rib_v6.best(&nlri_v6("2001:db8::/32")).is_some());

    reapply_without_blackholes(
        peer(),
        &ari_v6,
        &mut rib_v6,
        &reject_all_v6(),
        &test_gate(),
        &AlwaysReachable,
    );
    assert!(
        rib_v6.best(&nlri_v6("2001:db8::/32")).is_none(),
        "route must be withdrawn after policy change"
    );
}
