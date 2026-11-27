use super::*;

// ── RPKI ROV (Phase 2) ───────────────────────────────────────────────────

#[test]
fn test_install_rpki_import_terms_adds_one_term_per_peer_v4_and_v6() {
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, _) = make_state(
        65001,
        &[(IpAddr::V4(peer_a), 65002), (IpAddr::V4(peer_b), 65003)],
    );
    let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());

    state.install_rpki_import_terms(&rtr);

    for ip in [peer_a, peer_b] {
        assert_eq!(state.import_policies[&IpAddr::V4(ip)].len(), 1);
        assert_eq!(state.import_policies_v6[&IpAddr::V4(ip)].len(), 1);
    }
}

#[test]
fn test_rov_accepts_route_with_valid_roa() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    let rtr = pathvector_rpki::for_testing(
        [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 65002)],
        std::iter::empty(),
    );
    state.install_rpki_import_terms(&rtr);
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
                PathAttribute::NextHop(must_v4(peer_ip)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
}

#[test]
fn test_rov_rejects_route_with_invalid_roa_wrong_origin_asn() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    // ROA authorizes AS 99999 for this prefix, not AS 65002 — the peer's
    // announcement will be Invalid.
    let rtr = pathvector_rpki::for_testing(
        [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999)],
        std::iter::empty(),
    );
    state.install_rpki_import_terms(&rtr);
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
                PathAttribute::NextHop(must_v4(peer_ip)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none());
}

#[test]
fn test_rov_accepts_route_with_no_covering_roa() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    // Empty ROA table — every prefix is NotFound, which must be accepted
    // by default, not treated the same as Invalid.
    let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
    state.install_rpki_import_terms(&rtr);
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
                PathAttribute::NextHop(must_v4(peer_ip)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
}

#[test]
fn test_rov_not_installed_invalid_route_still_accepted() {
    // Regression guard: without calling install_rpki_import_terms (the
    // `reject_invalid = false` config path), ROV must have zero effect —
    // an Invalid route is accepted exactly as it would be in Phase 1.
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
                PathAttribute::NextHop(must_v4(peer_ip)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );

    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
}

#[test]
fn test_reevaluate_all_import_policies_closes_fail_open_window() {
    // Gap 3: a route accepted while the RTR cache was still empty (the
    // window before the first sync completes) must get correctly
    // rejected once the cache actually reflects it as Invalid, without
    // needing a session reset. reevaluate_all_import_policies is what
    // makes that happen.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
    state.install_rpki_import_terms(&rtr);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    // Accepted now: the cache is empty, so this reads as NotFound.
    state.on_route_update(
        peer_ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(must_v4(peer_ip)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());

    // The cache now learns of a ROA that makes this exact route Invalid
    // (covers 10.0.0.0/8, but authorizes a different ASN).
    rtr.insert_roa_v4(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999);
    state.reevaluate_all_import_policies();

    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
        "route must be rejected once the cache reflects it as Invalid"
    );
}

#[test]
fn test_reevaluate_all_import_policies_does_not_duplicate_terms() {
    // Regression guard: reevaluate_all_import_policies must never touch
    // the installed Policy itself (unlike set_import_default, which
    // replaces it) — calling it repeatedly must not grow the term list.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
    let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
    state.install_rpki_import_terms(&rtr);

    let before = state.import_policies[&peer_ip].len();
    state.reevaluate_all_import_policies();
    state.reevaluate_all_import_policies();
    assert_eq!(state.import_policies[&peer_ip].len(), before);
    assert_eq!(state.import_policies_v6[&peer_ip].len(), before);
}

#[test]
fn test_on_route_update_propagates_to_other_established_peer() {
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

    state.on_route_update(
        IpAddr::V4(peer_a),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_a),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    state.flush_pending();

    let msg = receivers
        .get_mut(&IpAddr::V4(peer_b))
        .unwrap()
        .try_recv()
        .expect("peer_b should receive UPDATE for the new route");
    assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
}

#[test]
fn test_on_route_update_withdraw_removes_route_from_rib() {
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

    state.on_route_update(
        peer_ip,
        UpdateMessage {
            withdrawn: vec![nlri("10.0.0.0/8")],
            attributes: vec![],
            announced: vec![],
        },
    );
    assert_eq!(state.rib.loc_rib.len(), 0);
}
