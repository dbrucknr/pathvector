use super::*;

// ── RFC correctness regressions ───────────────────────────────────────────

// Finding A — RFC 4271 §9.1.2: AS_PATH loop detection.
// A route whose AS_PATH contains the local AS MUST be silently dropped.

#[test]
fn test_as_path_loop_detection_drops_traditional_nlri() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    // local_as == 65002; route contains 65002 in AS_PATH → loop detected.
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65100),
                    Asn::new(65002), // local AS
                    Asn::new(65200),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "route with local AS in AS_PATH must be dropped (RFC 4271 §9.1.2)"
    );
    // RFC 4271 §9: an announcement replaces the peer's older route in the
    // Adj-RIB-In, and §9.1.2 only "excludes" a looped route from the
    // Phase 2 decision function, so it is stored there as ineligible
    // (issue #138). Before that fix this asserted "silently ignored
    // means do not store", which let a looped replacement leave the
    // peer's *older* route selected; no RFC clause says an ineligible
    // route is not stored.
    assert!(
        ari.get(&nlri("10.0.0.0/8")).is_some(),
        "the ineligible announcement is kept in the Adj-RIB-In (RFC 4271 §9)"
    );
}

#[test]
fn test_as_path_loop_detection_drops_mp_reach_nlri() {
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
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65100),
                    Asn::new(65002), // local AS
                ])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::9".parse().unwrap()),
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
    assert!(
        rib_v6.is_empty(),
        "IPv6 route with local AS in AS_PATH must be dropped (RFC 4271 §9.1.2)"
    );
}

#[test]
fn test_as_path_loop_detection_permits_empty_as_path() {
    // iBGP routes may have an empty AS_PATH — must not be dropped.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::Internal,
    );
    assert_eq!(rib.len(), 1, "route with empty AS_PATH must be accepted");
}

#[test]
fn test_as_path_loop_detection_does_not_block_withdrawals() {
    // Withdrawals MUST be processed even if the AS_PATH contains our own AS.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    // First install a route via a clean update from a different AS.
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(rib.len(), 1, "prerequisite: route must be installed");

    // Now send a withdrawal that also carries a looping AS_PATH.
    // RFC 4271 §9.1.2 says loop detection applies to announcements, not withdrawals.
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![nlri("10.0.0.0/8")],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65002), // local AS in path
                ])),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "withdrawal must be processed despite looping AS_PATH"
    );
}

// ── RFC 5065: confederation Member-AS import semantics ───────────────────

#[test]
fn test_local_pref_honored_from_confed_member_peer() {
    // RFC 4271 §5.1.5's "except in the case of BGP Confederations"
    // exception, reinforced by RFC 5065 §5.2's explicit removal of the
    // eBGP-only restriction: a ConfedMember peer's LOCAL_PREF must be
    // honored, not dropped like a genuine External peer's.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_segments(vec![
                    pathvector_types::AsPathSegment::ConfedSequence(vec![Asn::new(65100)]),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::LocalPref(200),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::ConfedMember,
    );
    let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
    assert_eq!(
        route.local_pref,
        Some(LocalPref::new(200)),
        "LOCAL_PREF from a ConfedMember peer must be honored (RFC 5065 §5.2)"
    );
}

#[test]
fn test_as_path_loop_detection_drops_confederation_id_in_path() {
    // RFC 5065 §4: loop detection extends to the Confederation
    // Identifier, not just the local Member-AS Number — a route whose
    // AS_PATH contains our confederation's public AS has looped back
    // through the confederation, even though it never contains our
    // private Member-AS Number.
    let mut ari = fresh_ari();
    let mut rib = LocRib::new();
    let mut ari_v6 = fresh_ari_v6();
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(pathvector_policy::DefaultAction::Accept);
    handle_update(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65100),
                    Asn::new(64500), // confederation ID, not local_as
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &accept_all(),
        &policy_v6,
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,        // local_as (does NOT appear in the path above)
        Some(64_500), // confederation_id
        None,
        None,
    );
    assert!(
        rib.is_empty(),
        "route whose AS_PATH contains the confederation ID must be dropped (RFC 5065 §4)"
    );
}

#[test]
fn test_as_path_loop_detection_confederation_id_absent_does_not_block() {
    // Sanity check for the test above: without a configured
    // confederation_id, the same AS_PATH must NOT be treated as a loop.
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65100),
                    Asn::new(64500),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(
        rib.len(),
        1,
        "without confederation_id configured, 64500 in AS_PATH is an ordinary transit AS"
    );
}

fn handle_update_get_notification_for(
    peer_type: PeerType,
    confederation_id: Option<u32>,
    msg: UpdateMessage,
) -> Option<NotificationMessage> {
    let p = peer();
    let mut ari = AdjRibIn::new(p);
    let mut rib = LocRib::new();
    let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(p);
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let policy = accept_all();
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(pathvector_policy::DefaultAction::Accept);
    handle_update(
        p,
        msg,
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &policy,
        &policy_v6,
        peer_type,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        confederation_id,
        None,
        None,
    )
    .notification
}

#[test]
fn test_malformed_as_path_confed_segment_from_external_peer_is_treat_as_withdraw() {
    // RFC 5065 §5 condition 1: a confederation segment received from a
    // peer outside the confederation is malformed. RFC 7606 §3(e)
    // reclassifies this as treat-as-withdraw (not session reset) — see
    // the doc comment at the check site for the RFC-7606-scope
    // reasoning.
    let n = handle_update_get_notification_for(
        PeerType::External,
        Some(64_500),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_segments(vec![
                    pathvector_types::AsPathSegment::ConfedSequence(vec![Asn::new(65100)]),
                    pathvector_types::AsPathSegment::Sequence(vec![Asn::new(65200)]),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    assert!(
        n.is_none(),
        "RFC 5065 §5 condition 1 must be treat-as-withdraw (RFC 7606 §3(e)), \
         not a session-reset NOTIFICATION; got {n:?}"
    );
}

#[test]
fn test_malformed_as_path_confed_member_peer_missing_confed_sequence_is_treat_as_withdraw() {
    // RFC 5065 §5 condition 2: a non-empty AS_PATH from a ConfedMember
    // peer whose first segment is not AS_CONFED_SEQUENCE is malformed —
    // treat-as-withdraw per RFC 7606 §3(e), not session reset.
    let n = handle_update_get_notification_for(
        PeerType::ConfedMember,
        Some(64_500),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65100)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    assert!(
        n.is_none(),
        "RFC 5065 §5 condition 2 must be treat-as-withdraw (RFC 7606 §3(e)), \
         not a session-reset NOTIFICATION; got {n:?}"
    );
}

#[test]
fn test_malformed_as_path_empty_from_confed_member_peer_is_treat_as_withdraw() {
    // RFC 5065 §5 condition 2 also covers an *empty* AS_PATH from a
    // ConfedMember peer: an empty path has no first segment, so it
    // cannot be AS_CONFED_SEQUENCE — RFC 5065 §4.1(b)(3) requires even
    // an originated route sent to a neighboring Member-AS to carry a
    // ConfedSequence. There is no legitimate-empty-AS_PATH exemption
    // for ConfedMember peers (unlike, e.g., an Internal peer within the
    // same Member-AS, where an empty AS_PATH is normal).
    let n = handle_update_get_notification_for(
        PeerType::ConfedMember,
        Some(64_500),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    assert!(
        n.is_none(),
        "empty AS_PATH from a ConfedMember peer is treat-as-withdraw, not session reset; got {n:?}"
    );
}

#[test]
fn test_malformed_as_path_confed_member_peer_with_confed_sequence_first_is_accepted() {
    // Negative case for condition 2: a ConfedMember peer whose AS_PATH
    // *does* start with AS_CONFED_SEQUENCE is well-formed.
    let n = handle_update_get_notification_for(
        PeerType::ConfedMember,
        Some(64_500),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_segments(vec![
                    pathvector_types::AsPathSegment::ConfedSequence(vec![Asn::new(65100)]),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    assert!(
        n.is_none(),
        "well-formed ConfedMember AS_PATH must not trigger a NOTIFICATION, got {n:?}"
    );
}

// ── RFC 7606 §5.2: RFC 5065 §5 conditions on an UPDATE with no reachable NLRI ──
//
// Treat-as-withdraw is meaningless when there is nothing to withdraw —
// RFC 7606 §5.2 requires session reset instead whenever an UPDATE
// carries path attributes but no reachable NLRI at all, and the
// attribute error found calls for something stronger than "attribute
// discard" (treat-as-withdraw qualifies).

#[test]
fn test_malformed_as_path_confed_segment_from_external_peer_no_nlri_resets_session() {
    let n = handle_update_get_notification_for(
        PeerType::External,
        Some(64_500),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_segments(vec![
                    pathvector_types::AsPathSegment::ConfedSequence(vec![Asn::new(65100)]),
                    pathvector_types::AsPathSegment::Sequence(vec![Asn::new(65200)]),
                ])),
            ],
            announced: vec![],
        },
    );
    assert!(
        matches!(
            n,
            Some(NotificationMessage {
                error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAsPath),
                ..
            })
        ),
        "no reachable NLRI (RFC 7606 §5.2) must force session reset, got {n:?}"
    );
}

#[test]
fn test_malformed_as_path_confed_member_peer_missing_confed_sequence_no_nlri_resets_session() {
    let n = handle_update_get_notification_for(
        PeerType::ConfedMember,
        Some(64_500),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65100)])),
            ],
            announced: vec![],
        },
    );
    assert!(
        matches!(
            n,
            Some(NotificationMessage {
                error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAsPath),
                ..
            })
        ),
        "no reachable NLRI (RFC 7606 §5.2) must force session reset, got {n:?}"
    );
}

#[test]
fn test_malformed_as_path_empty_from_confed_member_peer_no_nlri_resets_session() {
    let n = handle_update_get_notification_for(
        PeerType::ConfedMember,
        Some(64_500),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
            ],
            announced: vec![],
        },
    );
    assert!(
        matches!(
            n,
            Some(NotificationMessage {
                error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAsPath),
                ..
            })
        ),
        "no reachable NLRI (RFC 7606 §5.2) must force session reset, got {n:?}"
    );
}

#[test]
fn test_malformed_as_path_confed_conditions_are_treat_as_withdraw_not_session_reset() {
    // RFC 7606 §3(e) reclassifies RFC 5065 §5's two conditions as
    // treat-as-withdraw (see the doc comment at the check site):
    // no NOTIFICATION, and the announced route is actively withdrawn
    // (not merely left un-inserted) rather than installed.
    let p = peer();
    let mut ari = AdjRibIn::new(p);
    let mut rib = LocRib::new();
    let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(p);
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let policy = accept_all();
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(pathvector_policy::DefaultAction::Accept);
    let target = nlri("10.0.0.0/8");
    let result = handle_update(
        p,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_segments(vec![
                    pathvector_types::AsPathSegment::ConfedSequence(vec![Asn::new(65100)]),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![target],
        },
        &mut ari,
        &mut rib,
        &mut ari_v6,
        &mut rib_v6,
        &policy,
        &policy_v6,
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        Some(64_500),
        None,
        None,
    );
    assert!(
        result.notification.is_none(),
        "RFC 5065 §5 malformed AS_PATH must be treat-as-withdraw (RFC 7606 §3(e)), \
         not a session-reset NOTIFICATION"
    );
    assert!(
        ari.get(&target).is_none(),
        "the malformed-AS_PATH route must not be installed into AdjRibIn"
    );
}

#[test]
fn test_as_path_loop_detection_fires_for_as_set() {
    // RFC 4271 §9.1.2 applies regardless of segment type. If the local AS
    // appears in an AS_SET produced by aggregation, the route must still be dropped.
    use pathvector_types::AsPathSegment;
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    let path = AsPath::from_segments(vec![
        AsPathSegment::Sequence(vec![Asn::new(65100)]),
        AsPathSegment::Set(vec![Asn::new(65002), Asn::new(65200)]), // local AS in set
    ]);
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "route with local AS in AS_SET must be dropped (RFC 4271 §9.1.2)"
    );
}

// Finding L — RFC 7607: AS 0 in AS_PATH MUST be rejected.

#[test]
fn test_as_zero_in_path_drops_route() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(65100),
                    Asn::new(0), // reserved — RFC 7607
                    Asn::new(65200),
                ])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "route with AS 0 in AS_PATH must be dropped (RFC 7607)"
    );
}

#[test]
fn test_as_zero_does_not_block_withdrawals() {
    let mut rib = LocRib::new();
    let mut ari = fresh_ari();

    // Install a route first.
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert_eq!(rib.len(), 1, "prerequisite: route must be installed");

    // Withdraw it in an UPDATE that also carries AS 0 in the path.
    handle_update_v4(
        peer(),
        UpdateMessage {
            withdrawn: vec![nlri("10.0.0.0/8")],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(0)])),
            ],
            announced: vec![],
        },
        &mut ari,
        &mut rib,
        &accept_all(),
        PeerType::External,
    );
    assert!(
        rib.is_empty(),
        "withdrawal must be processed even when AS_PATH contains AS 0"
    );
}
