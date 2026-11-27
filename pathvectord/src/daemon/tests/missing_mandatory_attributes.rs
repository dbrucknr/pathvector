use super::*;

// ── RFC 7606 §3(d): missing well-known mandatory attribute ───────────────
//
// RFC 7606 §3(d): "If any of the well-known mandatory attributes are not
// present in an UPDATE message, then 'treat-as-withdraw' MUST be used."
// This revises RFC 4271 §6.3's session-reset behavior — handle_update
// must NOT return a NOTIFICATION for this case, and any route the
// malformed UPDATE would have announced must be removed from Adj-RIB-In/
// LocRib exactly as if it had been explicitly withdrawn (RFC 7606 §2).

fn handle_update_get_notification(msg: UpdateMessage) -> Option<NotificationMessage> {
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
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        65002,
        None, // confederation_id
        None,
        None,
    )
    .notification
}

#[test]
fn missing_origin_treated_as_withdraw_no_notification() {
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        announced: vec![nlri("10.0.0.0/8")],
    });
    assert!(
        n.is_none(),
        "RFC 7606 §3(d): missing ORIGIN must be treat-as-withdraw, not a NOTIFICATION"
    );
}

#[test]
fn missing_as_path_treated_as_withdraw_no_notification() {
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        announced: vec![nlri("10.0.0.0/8")],
    });
    assert!(
        n.is_none(),
        "RFC 7606 §3(d): missing AS_PATH must be treat-as-withdraw, not a NOTIFICATION"
    );
}

#[test]
fn missing_next_hop_for_traditional_ipv4_treated_as_withdraw_no_notification() {
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            // No NEXT_HOP
        ],
        announced: vec![nlri("10.0.0.0/8")],
    });
    assert!(
        n.is_none(),
        "RFC 7606 §3(d): missing NEXT_HOP must be treat-as-withdraw, not a NOTIFICATION"
    );
}

/// RFC 7606 §2: "treat-as-withdraw"... "MUST be treated as though all
/// contained routes had been withdrawn... thus causing them to be
/// removed from the Adj-RIB-In" — this is the test that actually
/// distinguishes treat-as-withdraw from mere "attribute discard"/ignore:
/// a pre-existing route for the same prefix must be removed, not left
/// in place, when a later UPDATE for it arrives missing ORIGIN.
#[test]
fn missing_origin_withdraws_preexisting_route_for_same_prefix() {
    let p = peer();
    let mut ari = AdjRibIn::new(p);
    let mut rib = LocRib::new();
    let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(p);
    let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
    let policy = accept_all();
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(pathvector_policy::DefaultAction::Accept);
    let n = nlri("10.0.0.0/8");

    // First, a well-formed UPDATE installs a route for the prefix.
    handle_update(
        p,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![n],
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
        65001,
        None, // confederation_id
        None,
        None,
    );
    assert!(
        rib.best(&n).is_some(),
        "sanity check: route must be installed by the well-formed UPDATE"
    );

    // Now a malformed UPDATE (missing ORIGIN) for the same prefix arrives.
    let result = handle_update(
        p,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![n],
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
        65001,
        None, // confederation_id
        None,
        None,
    );

    assert!(result.notification.is_none());
    assert!(
        rib.best(&n).is_none(),
        "RFC 7606 §2: the previously-installed route must be removed from \
         LocRib when a later UPDATE for it is missing a mandatory attribute"
    );
    assert!(
        ari.get(&n).is_none(),
        "RFC 7606 §2: the route must also be removed from Adj-RIB-In"
    );
}

/// The fix's treat-as-withdraw block drains `mp_v6_announced` alongside
/// the traditional-NLRI/`mp_v4_announced` paths (`route.rs`'s
/// `treat_as_withdraw_v6`), but every other test for this fix — unit and
/// e2e — exercises only the IPv4 traditional-NLRI path. This is the same
/// scenario as `missing_origin_withdraws_preexisting_route_for_same_prefix`
/// above, but via `MpReachNlri`/IPv6, using the full `DaemonState` (not
/// `handle_update` directly) so `on_established`'s MultiProtocol
/// capability wiring is exercised too.
#[test]
fn missing_origin_withdraws_preexisting_v6_route_for_same_prefix() {
    use pathvector_session::message::{MpReachNlri, Prefix};
    use pathvector_types::{AfiSafi, NextHop};

    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) = make_state(65001, &[(peer_ip, 65002)]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)],
        None,
    );

    let n: Nlri<Ipv6Addr> = "2001:db8:beef::/48".parse().unwrap();
    let mp_reach = |include_origin: bool| {
        let mut attributes = vec![PathAttribute::AsPath(AsPath::from_sequence(vec![
            Asn::new(65002),
        ]))];
        if include_origin {
            attributes.insert(0, PathAttribute::Origin(Origin::Igp));
        }
        attributes.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
            prefixes: vec![Prefix::V6(n)],
        }));
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![],
        }
    };

    // First, a well-formed UPDATE installs a v6 route for the prefix.
    state.on_route_update(peer_ip, mp_reach(true));
    assert!(
        state.rib.loc_rib_v6.best(&n).is_some(),
        "sanity check: v6 route must be installed by the well-formed UPDATE"
    );

    // Now a malformed UPDATE (missing ORIGIN) for the same v6 prefix.
    let result = state.on_route_update(peer_ip, mp_reach(false));

    assert!(
        result.is_none(),
        "RFC 7606 §3(d): missing ORIGIN on the MP_REACH_NLRI/IPv6 path \
         must be treat-as-withdraw, not a NOTIFICATION"
    );
    assert!(
        state.rib.loc_rib_v6.best(&n).is_none(),
        "RFC 7606 §2: the previously-installed v6 route must be removed \
         from LocRib_v6 when a later UPDATE for it is missing a \
         mandatory attribute"
    );
    assert!(
        state
            .adj_ribs_in_v6
            .get(&peer_ip)
            .expect("adj_ribs_in_v6 entry for peer")
            .get(&n)
            .is_none(),
        "RFC 7606 §2: the v6 route must also be removed from Adj-RIB-In"
    );
}

#[test]
fn withdraw_only_update_no_notification_for_missing_attrs() {
    // Withdraw-only UPDATEs are exempt from mandatory attribute checks.
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![nlri("10.0.0.0/8")],
        attributes: vec![], // no attributes at all — allowed for withdraw-only
        announced: vec![],
    });
    assert!(
        n.is_none(),
        "withdraw-only UPDATE must not trigger mandatory attribute NOTIFICATION"
    );
}

#[test]
fn all_mandatory_attributes_present_no_notification() {
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        announced: vec![nlri("10.0.0.0/8")],
    });
    assert!(
        n.is_none(),
        "well-formed UPDATE must not trigger NOTIFICATION"
    );
}

/// RFC 7606 §5.2 "Missing NLRI": an UPDATE with path attributes other
/// than MP_UNREACH_NLRI but no reachable NLRI at all (no traditional
/// NLRI, no MP_REACH_NLRI) cannot be confidently treated-as-withdraw —
/// there is no reliable NLRI to withdraw. If such a message also
/// carries a missing-mandatory-attribute error (which §3(d) would
/// otherwise resolve via treat-as-withdraw), §5.2 requires the
/// "session reset" approach instead. Pre-fix, `has_any_announces` being
/// false skipped the mandatory-attribute check entirely, silently
/// accepting this malformed UPDATE as a no-op.
#[test]
fn missing_nlri_update_with_attributes_resets_session() {
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        // AS_PATH present, ORIGIN missing, no NLRI/MP_REACH_NLRI/
        // MP_UNREACH_NLRI at all.
        attributes: vec![PathAttribute::AsPath(AsPath::from_sequence(vec![
            Asn::new(65002),
        ]))],
        announced: vec![],
    });
    assert!(
        matches!(
            n,
            Some(NotificationMessage {
                error: NotificationError::UpdateMessage(UpdateMsgError::MissingWellKnownAttribute),
                ..
            })
        ),
        "an UPDATE with attributes but no reachable NLRI and a missing \
         mandatory attribute must reset the session (RFC 7606 §5.2), \
         got {n:?}"
    );
}

/// Companion to the test above: a fully empty UPDATE (the "legacy"
/// End-of-RIB encoding, RFC 4724 §2) has no attributes other than
/// MP_UNREACH_NLRI (it has none at all) and must remain valid.
#[test]
fn legacy_empty_update_no_notification() {
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    });
    assert!(
        n.is_none(),
        "a fully empty legacy End-of-RIB UPDATE must not trigger a \
         NOTIFICATION, got {n:?}"
    );
}

/// Companion to the two tests above: an End-of-RIB encoded as an
/// MP_UNREACH_NLRI attribute carrying no NLRI (RFC 4724 §2) has no
/// attribute other than MP_UNREACH_NLRI and must remain valid.
#[test]
fn mp_unreach_only_eor_no_notification() {
    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi_safi: pathvector_types::AfiSafi::IPV4_UNICAST,
            prefixes: vec![],
        })],
        announced: vec![],
    });
    assert!(
        n.is_none(),
        "an MP_UNREACH_NLRI-only End-of-RIB UPDATE must not trigger a \
         NOTIFICATION, got {n:?}"
    );
}

/// [Codex] `has_any_announces` is filtered to only the AFI/SAFIs this
/// daemon recognizes (IPv4/IPv6 unicast) — an `MP_REACH_NLRI` for an
/// unsupported AFI/SAFI (e.g. IPv4 multicast) is silently skipped in
/// the attribute-processing loop and never counted there. A missing
/// mandatory attribute on such an UPDATE must NOT be escalated to a
/// session reset: the wire message plainly does encode reachable NLRI
/// (RFC 7606 §5.2's session-reset exception only applies when there's
/// no reachable NLRI at all), even though this daemon doesn't
/// support/install that particular AFI/SAFI locally.
#[test]
fn missing_origin_with_unsupported_afi_safi_mp_reach_no_notification() {
    use pathvector_session::message::{MpReachNlri, Prefix};
    use pathvector_types::{AfiSafi, NextHop};

    let n = handle_update_get_notification(UpdateMessage {
        withdrawn: vec![],
        // ORIGIN is missing; AS_PATH is present. MP_REACH_NLRI carries
        // a real prefix, but for IPv4 Multicast — an AFI/SAFI this
        // daemon doesn't install routes for.
        attributes: vec![
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV4_MULTICAST,
                next_hop: NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)),
                prefixes: vec![Prefix::V4(nlri("192.0.2.0/24"))],
            }),
        ],
        announced: vec![],
    });
    assert!(
        n.is_none(),
        "a missing mandatory attribute on an UPDATE whose only \
         reachable NLRI is for an unsupported AFI/SAFI must not reset \
         the session, got {n:?}"
    );
}
