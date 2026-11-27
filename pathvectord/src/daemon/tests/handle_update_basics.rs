use super::*;

// ── basic handle_update behaviour ─────────────────────────────────────────

#[test]
fn test_handle_update_inserts_route_with_all_attributes() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let msg = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Egp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(200),
            PathAttribute::Med(50),
            PathAttribute::Communities(vec![Community::new(0x0001_0001)]),
            PathAttribute::LargeCommunities(vec![LargeCommunity::new(65000, 1, 100)]),
            PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::route_target_as2(65000, 1)]),
            PathAttribute::AtomicAggregate,
            PathAttribute::Aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(1, 1, 1, 1))),
        ],
        announced: vec![nlri("192.168.0.0/16")],
    };
    // PeerType::Internal — this test proves generic attribute capture,
    // not eBGP-specific LOCAL_PREF semantics (RFC 4271 §5.1.5, covered
    // separately below). LOCAL_PREF is only ever honored from an
    // internal (iBGP) peer.
    handle_update_v4(
        peer(),
        msg,
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::Internal,
    );

    let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
    assert_eq!(route.origin, Origin::Egp);
    assert_eq!(route.local_pref, Some(LocalPref::new(200)));
    assert_eq!(route.med, Some(Med::new(50)));
    let rare = route.rare_or_default();
    assert_eq!(rare.communities.len(), 1);
    assert_eq!(rare.large_communities.len(), 1);
    assert_eq!(rare.extended_communities.len(), 1);
    assert!(rare.atomic_aggregate);
    assert!(rare.aggregator.is_some());
}

// ── RFC 4271 §5: unrecognized transitive optional attributes ──────────────
// "Paths with unrecognized transitive optional attributes SHOULD be
// accepted [and] passed... to other BGP peers with the Partial bit...
// set to 1. Unrecognized non-transitive optional attributes MUST be
// quietly ignored and not passed along."

#[test]
fn test_handle_update_stores_unrecognized_transitive_attribute() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let msg = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Unknown {
                flags: 0xC0, // Optional (0x80) | Transitive (0x40)
                type_code: 200,
                value: vec![0xDE, 0xAD],
            },
        ],
        announced: vec![nlri("192.168.0.0/16")],
    };
    handle_update_v4(
        peer(),
        msg,
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
    let unknown = &route.rare_or_default().unknown;
    assert_eq!(
        unknown.len(),
        1,
        "unrecognized transitive attribute must be stored"
    );
    assert_eq!(unknown[0].type_code, 200);
    assert_eq!(unknown[0].value, vec![0xDE, 0xAD]);
}

#[test]
fn test_handle_update_quietly_ignores_unrecognized_non_transitive_attribute() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let msg = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::Unknown {
                flags: 0x80, // Optional only — non-transitive
                type_code: 201,
                value: vec![0xBE, 0xEF],
            },
        ],
        announced: vec![nlri("192.168.0.0/16")],
    };
    handle_update_v4(
        peer(),
        msg,
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
    assert!(
        route.rare_or_default().unknown.is_empty(),
        "unrecognized non-transitive attribute must be quietly ignored, not stored"
    );
}

// ── RFC 4271 §5.1.5: LOCAL_PREF from an external peer MUST be ignored ─────

#[test]
fn test_local_pref_ignored_from_ebgp_peer() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let msg = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(u32::MAX),
        ],
        announced: vec![nlri("192.168.0.0/16")],
    };
    handle_update_v4(
        peer(),
        msg,
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
    assert_eq!(
        route.local_pref, None,
        "RFC 4271 §5.1.5: LOCAL_PREF received from an external peer MUST be ignored"
    );
}

#[test]
fn test_local_pref_honored_from_ibgp_peer() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let msg = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(200),
        ],
        announced: vec![nlri("192.168.0.0/16")],
    };
    handle_update_v4(
        peer(),
        msg,
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::Internal,
    );

    let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
    assert_eq!(
        route.local_pref,
        Some(LocalPref::new(200)),
        "LOCAL_PREF from an internal (iBGP) peer must still be honored"
    );
}

/// RFC 4271 §5.1.5's actual security consequence, not just field-level
/// presence/absence: a malicious eBGP peer attaching an arbitrary
/// LOCAL_PREF must not be able to force its route to win best-path
/// selection against a route we'd otherwise prefer. Two eBGP peers
/// announce the same prefix; the attacker's LOCAL_PREF (`u32::MAX`) would
/// win outright at the very first Decision Process tie-break step if
/// honored — with it correctly ignored, both routes fall back to
/// `LocalPref::DEFAULT` and the comparison proceeds to the next
/// criterion (AS_PATH length), where the legitimate peer's shorter path
/// wins.
#[test]
fn test_ebgp_local_pref_cannot_win_best_path_over_shorter_as_path() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    // Attacker: bogus LOCAL_PREF, longer AS_PATH.
    handle_update_v4(
        peer_id("10.0.0.98"),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65098),
                    Asn::new(65099),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 98)),
                PathAttribute::LocalPref(u32::MAX),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    // Legitimate peer: no LOCAL_PREF, shorter AS_PATH. AS 65003 — not
    // 65002, which is this test harness's fixed `local_as` (see
    // `handle_update_v4`) and would trigger AS-PATH loop detection
    // (RFC 4271 §6.3), silently dropping the announcement for an
    // unrelated reason.
    handle_update_v4(
        peer_id("10.0.0.2"),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65003)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );

    let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
    assert_eq!(
        route.next_hop,
        Some(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2))),
        "an eBGP peer's bogus LOCAL_PREF must not let its route win \
         over a route we'd otherwise prefer on a lower-priority \
         criterion (AS_PATH length)"
    );
    assert_eq!(route.local_pref, None);
}

#[test]
fn test_handle_update_withdraw_removes_route() {
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
            withdrawn: vec![nlri("10.0.0.0/8")],
            attributes: vec![],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(rib.is_empty());
    assert!(ari.is_empty());
}

#[test]
fn test_handle_update_empty_announced_is_noop() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(rib.is_empty());
    assert!(ari.is_empty());
}

#[test]
fn test_handle_update_unknown_attribute_is_skipped() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::Unknown {
                    flags: 0x80,
                    type_code: 255,
                    value: vec![1, 2, 3],
                },
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
