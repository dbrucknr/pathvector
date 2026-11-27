use super::*;

// ── RFC 9234 — BGP Role + OTC route-leak prevention ───────────────────────

fn make_state_with_roles(
    local_as: u32,
    peers: &[(IpAddr, u32, config::PeerRole)],
) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();
    for &(ip, _, _) in peers {
        let (tx, rx) = mpsc::channel(64);
        senders.insert(ip, tx);
        receivers.insert(ip, rx);
    }
    let peer_configs: Vec<config::PeerConfig> = peers
        .iter()
        .map(|&(address, remote_as, role)| config::PeerConfig {
            address,
            port: 179,
            remote_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: Some(role),
            confederation_member: false,
            blackhole_authorized_prefixes: None,
        })
        .collect();
    let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
    let state = DaemonState::new(
        local_as,
        local_bgp_id,
        None,
        None,
        None, // confederation_id (RFC 5065 — TODO: thread real value)
        &peer_configs,
        senders,
        vec![],
    );
    (state, receivers)
}

fn announce_with_otc(peer_as: u32, prefix: &str, otc: Option<u32>) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(peer_as)])),
        PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
    ];
    if let Some(asn) = otc {
        attributes.push(PathAttribute::OnlyToCustomer(Asn::new(asn)));
    }
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![nlri(prefix)],
    }
}

#[test]
fn test_install_otc_terms_counts_per_role() {
    use config::PeerRole;
    // (role, expected import term count [v4 and v6 identical], expected export term count)
    let cases = [
        (PeerRole::Provider, 1, 1),
        (PeerRole::RouteServer, 1, 1),
        (PeerRole::Customer, 2, 1),
        (PeerRole::RsClient, 2, 1),
        (PeerRole::Peer, 2, 2),
    ];
    for (role, expected_import, expected_export) in cases {
        let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let (state, _rx) = make_state_with_roles(65001, &[(peer_ip, 65002, role)]);
        assert_eq!(
            state.import_policies[&peer_ip].len(),
            expected_import,
            "{role:?}: import policy term count"
        );
        assert_eq!(
            state.import_policies_v6[&peer_ip].len(),
            expected_import,
            "{role:?}: import_v6 policy term count"
        );
        assert_eq!(
            state.export_policies[&peer_ip].len(),
            expected_export,
            "{role:?}: export policy term count"
        );
    }
}

#[test]
fn test_no_role_configured_installs_no_otc_terms() {
    // Regression guard: omitting `role` must have zero effect — matches
    // RFC 9234's own non-strict default of not requiring Role at all.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rx) = make_state(65001, &[(peer_ip, 65002)]);
    assert_eq!(state.import_policies[&peer_ip].len(), 0);
    assert_eq!(state.import_policies_v6[&peer_ip].len(), 0);
    assert_eq!(state.export_policies[&peer_ip].len(), 0);
}

/// RFC 9234 is eBGP-only by definition. If an operator mistakenly sets
/// `role` on an iBGP peer (`remote_as == local_as`), it must be ignored
/// — no `Capability::Role` in OPEN, no OTC terms installed — rather than
/// silently applying leak-detection logic to internal sessions, which
/// could reject a route that legitimately carries OTC from its original
/// eBGP ingestion elsewhere in the network.
#[test]
fn test_role_ignored_for_ibgp_peer() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65001, config::PeerRole::Provider)]);

    assert_eq!(
        state.import_policies[&peer_ip].len(),
        0,
        "no OTC import term for an iBGP peer, even with role configured"
    );
    assert_eq!(state.import_policies_v6[&peer_ip].len(), 0);
    assert_eq!(
        state.export_policies[&peer_ip].len(),
        0,
        "no OTC export term for an iBGP peer, even with role configured"
    );
    assert!(
        !state.rib.peer_roles.contains_key(&peer_ip),
        "peer_roles must not record a role for an iBGP peer"
    );
}

/// Regression guard: `set_import_default`/`set_export_default` (the
/// gRPC-triggered PolicyService handlers) must never silently disable
/// RFC 9234 leak protection. Both used to fully replace the peer's
/// `Policy` (`Policy::new(action)`), discarding any installed terms —
/// confirmed as a real bug via a throwaway reproduction before this fix
/// landed. `Policy::set_default` changes only the default action now.
#[test]
fn test_set_import_and_export_default_preserve_otc_terms() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Peer)]);
    // Peer role installs 2 import terms and 2 export terms (see
    // test_install_otc_terms_counts_per_role).
    assert_eq!(state.import_policies[&peer_ip].len(), 2);
    assert_eq!(state.export_policies[&peer_ip].len(), 2);

    state.set_import_default(peer_ip, DefaultAction::Accept);
    state.set_export_default(peer_ip, DefaultAction::Reject);

    assert_eq!(
        state.import_policies[&peer_ip].len(),
        2,
        "set_import_default must not remove OTC terms"
    );
    assert_eq!(
        state.import_policies_v6[&peer_ip].len(),
        2,
        "set_import_default must not remove OTC terms from the v6 policy either"
    );
    assert_eq!(
        state.export_policies[&peer_ip].len(),
        2,
        "set_export_default must not remove OTC terms"
    );
    assert_eq!(
        state.import_policies[&peer_ip].default_action(),
        DefaultAction::Accept,
        "the default action itself must still change"
    );
    assert_eq!(
        state.export_policies[&peer_ip].default_action(),
        DefaultAction::Reject,
        "the default action itself must still change"
    );

    // And the actual leak-rejection behavior must still function after
    // the default-action change, not just the term count.
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(99999)));
    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
        "leak rejection must still fire after set_import_default"
    );
}

/// The same `set_import_default` bug fixed above also silently disabled
/// RFC 6811 ROV via the identical code path — `install_rpki_import_terms`
/// adds its reject term to `import_policies`/`import_policies_v6`, which
/// `set_import_default` used to fully replace. This is a direct
/// regression guard for that specific claim (made in `CHANGELOG.md` and
/// `pathvector-rpki/RFC.md`), not just an OTC-flavored duplicate of the
/// test above — a peer with no `role` configured at all (ROV is
/// role-independent) must still have its ROV term survive.
#[test]
fn test_set_import_default_preserves_rpki_rov_term() {
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) = make_state(65001, &[(peer_ip, 65002)]);
    let rtr = pathvector_rpki::for_testing(
        [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999)],
        std::iter::empty(),
    );
    state.install_rpki_import_terms(&rtr);
    assert_eq!(state.import_policies[&peer_ip].len(), 1);

    state.set_import_default(peer_ip, DefaultAction::Accept);

    assert_eq!(
        state.import_policies[&peer_ip].len(),
        1,
        "set_import_default must not remove the RPKI ROV term"
    );

    // And ROV rejection must still actually fire afterward.
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
    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
        "ROV rejection (wrong origin AS) must still fire after set_import_default"
    );
}

#[test]
fn test_provider_role_rejects_route_leaked_with_otc_from_customer() {
    // session_role = Provider: the peer is our Customer. A well-behaved
    // Customer never sends OTC — receiving one at all is a leak.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Provider)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(1)));

    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
        "route leaked with OTC from a Customer must be rejected"
    );
}

#[test]
fn test_provider_role_accepts_clean_route_without_attaching_otc() {
    // session_role = Provider: a route without OTC from our Customer is
    // legitimate and accepted; no ingress attach happens on this side
    // (attach only applies when session_role is Customer/Peer/RsClient).
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Provider)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", None));

    let route = state
        .rib
        .loc_rib
        .best(&nlri("10.0.0.0/8"))
        .expect("clean route from Customer must be accepted");
    assert_eq!(route.otc(), None);
}

#[test]
fn test_customer_role_attaches_peer_asn_on_ingress() {
    // session_role = Customer: the peer is our Provider. No leak
    // detection applies here; the route gets OTC = peer's ASN attached
    // so downstream OTC enforcement (at the next hop) can work.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Customer)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", None));

    let route = state
        .rib
        .loc_rib
        .best(&nlri("10.0.0.0/8"))
        .expect("route from Provider must be accepted");
    assert_eq!(route.otc(), Some(Asn::new(65002)));
}

#[test]
fn test_peer_role_rejects_route_with_mismatched_otc_asn() {
    // session_role = Peer: OTC present with a value other than the
    // peer's own ASN indicates a leak further upstream.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Peer)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(99999)));

    assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none());
}

#[test]
fn test_route_leak_prevented_across_two_provider_peers() {
    // The canonical RFC 9234 scenario: a route learned from one Provider
    // must never be re-advertised to another Provider (the leak that
    // caused the 2019 Verizon/Allegheny/Cloudflare incident). peer_a and
    // peer_b are both configured as our Customer (session_role =
    // Customer — they are our upstream Providers); peer_c is configured
    // as our Provider (session_role = Provider — they are our Customer).
    let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let peer_c: Ipv4Addr = "10.0.0.4".parse().unwrap();
    let (mut state, mut receivers) = make_state_with_roles(
        65001,
        &[
            (IpAddr::V4(peer_a), 65002, config::PeerRole::Customer),
            (IpAddr::V4(peer_b), 65003, config::PeerRole::Customer),
            (IpAddr::V4(peer_c), 65004, config::PeerRole::Provider),
        ],
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
    state.on_established(
        IpAddr::V4(peer_c),
        peer_c,
        PeerType::External,
        65004,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // Learned from peer_a (our Provider) with no OTC yet — gets attached.
    state.on_route_update(
        IpAddr::V4(peer_a),
        announce_with_otc(65002, "10.0.0.0/8", None),
    );
    state.flush_pending();

    let stored = state
        .rib
        .loc_rib
        .best(&nlri("10.0.0.0/8"))
        .expect("route from peer_a must be accepted");
    assert_eq!(
        stored.otc(),
        Some(Asn::new(65002)),
        "ingress attach must fire for a Customer-role session"
    );

    // Must NOT reach peer_b — another Provider. This is the leak.
    assert!(
        receivers
            .get_mut(&IpAddr::V4(peer_b))
            .unwrap()
            .try_recv()
            .is_err(),
        "route already carrying OTC must never be advertised to another Provider"
    );

    // Must reach peer_c — our Customer — with OTC preserved on the wire.
    let msg = receivers
        .get_mut(&IpAddr::V4(peer_c))
        .unwrap()
        .try_recv()
        .expect("route must be advertised to our Customer");
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::OnlyToCustomer(asn) if *asn == Asn::new(65002))),
        "OTC must be preserved unchanged on the wire toward our Customer"
    );
}

#[test]
fn test_route_server_role_rejects_leak_accepts_clean_without_attach() {
    // session_role = RouteServer: the peer is our RS-Client. Mirrors the
    // Provider case — RouteServer wasn't previously exercised at the
    // daemon/route level, only via the term-count table.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::RouteServer)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(1)));
    assert!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
        "OTC from an RS-Client must always be rejected as a leak"
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "198.51.100.0/24", None));
    let route = state
        .rib
        .loc_rib
        .best(&nlri("198.51.100.0/24"))
        .expect("clean route from RS-Client must be accepted");
    assert_eq!(
        route.otc(),
        None,
        "no ingress attach for RouteServer role (only Customer/Peer/RsClient attach)"
    );
}

#[test]
fn test_rs_client_role_attaches_peer_asn_on_ingress() {
    // session_role = RsClient: the peer is our RouteServer. Mirrors the
    // Customer case — RsClient wasn't previously exercised at the
    // daemon/route level, only via the term-count table.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::RsClient)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", None));

    let route = state
        .rib
        .loc_rib
        .best(&nlri("10.0.0.0/8"))
        .expect("route from RouteServer must be accepted");
    assert_eq!(route.otc(), Some(Asn::new(65002)));
}

#[test]
fn test_peer_role_accepts_and_preserves_matching_otc() {
    // session_role = Peer, OTC present and matching the peer's own ASN —
    // not a leak per RFC 9234 §5 rule 2. Must be accepted, and SetOtc
    // must not overwrite the already-correct value.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Peer)]);
    state.on_established(
        peer_ip,
        must_v4(peer_ip),
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );

    state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(65002)));

    let route = state
        .rib
        .loc_rib
        .best(&nlri("10.0.0.0/8"))
        .expect("OTC matching the peer's own ASN must not be treated as a leak");
    assert_eq!(route.otc(), Some(Asn::new(65002)));
}

#[test]
fn test_peer_role_egress_blocks_leaked_route_and_attaches_clean_one() {
    // session_role = Peer on egress: a route that already carries OTC
    // (learned from peer_provider, a Customer-role session on our side)
    // must never reach a Peer-role destination — RFC 9234 §6 rule 2
    // treats Peer the same as Provider/RS on the block side. A separate,
    // clean route (no OTC yet) must be advertised to the Peer-role
    // destination *with* OTC attached — §6 rule 1 also treats Peer the
    // same as Provider/RS on the attach side. Both rules apply to the
    // same Peer-role session simultaneously.
    let peer_provider: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_lateral: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_state_with_roles(
        65001,
        &[
            (IpAddr::V4(peer_provider), 65002, config::PeerRole::Customer),
            (IpAddr::V4(peer_lateral), 65003, config::PeerRole::Peer),
        ],
    );
    state.on_established(
        IpAddr::V4(peer_provider),
        peer_provider,
        PeerType::External,
        65002,
        90,
        &[],
        None,
    );
    state.on_established(
        IpAddr::V4(peer_lateral),
        peer_lateral,
        PeerType::External,
        65003,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    // Learned from peer_provider (our Provider) with no OTC — gets
    // attached (session_role = Customer is in the ingress-attach set).
    state.on_route_update(
        IpAddr::V4(peer_provider),
        announce_with_otc(65002, "10.0.0.0/8", None),
    );
    state.flush_pending();
    assert_eq!(
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).unwrap().otc(),
        Some(Asn::new(65002))
    );
    assert!(
        receivers
            .get_mut(&IpAddr::V4(peer_lateral))
            .unwrap()
            .try_recv()
            .is_err(),
        "a route already carrying OTC must never reach a Peer-role destination"
    );

    // A second, clean route learned from the same Provider stays clean
    // only until it crosses to peer_lateral, where it must get OTC
    // attached (session_role = Peer is also in the egress-attach set).
    // Use a peer with no attach-on-ingress applicable here by importing
    // directly via a peer with no configured role instead, to isolate
    // the egress-attach behavior from ingress-attach.
    let peer_plain: Ipv4Addr = "10.0.0.4".parse().unwrap();
    state.add_peer(
        &config::PeerConfig {
            address: IpAddr::V4(peer_plain),
            port: 179,
            remote_as: 65004,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
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
        },
        mpsc::channel(64).0,
    );
    state.on_established(
        IpAddr::V4(peer_plain),
        peer_plain,
        PeerType::External,
        65004,
        90,
        &[],
        None,
    );
    drain_all(&mut receivers);

    state.on_route_update(
        IpAddr::V4(peer_plain),
        announce_with_otc(65004, "198.51.100.0/24", None),
    );
    state.flush_pending();
    assert_eq!(
        state
            .rib
            .loc_rib
            .best(&nlri("198.51.100.0/24"))
            .unwrap()
            .otc(),
        None,
        "no configured role on peer_plain means no ingress attach"
    );
    let msg = receivers
        .get_mut(&IpAddr::V4(peer_lateral))
        .unwrap()
        .try_recv()
        .expect("clean route must reach the Peer-role destination");
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::OnlyToCustomer(asn) if *asn == Asn::new(65001))),
        "OTC = local ASN must be attached on egress toward a Peer-role destination"
    );
}

#[test]
fn test_ipv6_ingress_otc_extraction_and_leak_rejection() {
    // The daemon-level OTC tests above all exercise the IPv4 ingress
    // path only; this confirms the IPv6 MP_REACH_NLRI path (route.rs's
    // second RouteBuilder + `.otc(asn)` call) is actually wired, not
    // just compiling.
    let peer_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let (mut state, _rx) =
        make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Provider)]);
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

    let leaked_v6: Nlri<Ipv6Addr> = "2001:db8:dead::/48".parse().unwrap();
    state.on_route_update(
        peer_ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                    prefixes: vec![Prefix::V6(leaked_v6)],
                }),
                PathAttribute::OnlyToCustomer(Asn::new(65100)),
            ],
            announced: vec![],
        },
    );
    assert!(
        state.rib.loc_rib_v6.best(&leaked_v6).is_none(),
        "IPv6 route leaked with OTC from a Customer must be rejected"
    );

    let clean_v6: Nlri<Ipv6Addr> = "2001:db8:beef::/48".parse().unwrap();
    state.on_route_update(
        peer_ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                    prefixes: vec![Prefix::V6(clean_v6)],
                }),
            ],
            announced: vec![],
        },
    );
    let route = state
        .rib
        .loc_rib_v6
        .best(&clean_v6)
        .expect("clean IPv6 route from Customer must be accepted");
    assert_eq!(
        route.otc(),
        None,
        "Provider role does not ingress-attach OTC"
    );
}

#[test]
fn test_ipv6_egress_otc_block_and_attach() {
    // IPv6 counterpart of `test_peer_role_egress_blocks_leaked_route_and_
    // attaches_clean_one` — regression guard for the IPv6 export-policy
    // gap: `propagate_prefix_v6` used to never consult any export policy
    // at all, so RFC 9234's OTC egress block/attach terms (installed
    // correctly into `export_policies_v6`) had zero effect on IPv6
    // UPDATEs. Same scenario as the v4 test, over IPv6 NLRIs.
    let peer_provider: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let peer_lateral: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let (mut state, mut receivers) = make_state_with_roles(
        65001,
        &[
            (IpAddr::V4(peer_provider), 65002, config::PeerRole::Customer),
            (IpAddr::V4(peer_lateral), 65003, config::PeerRole::Peer),
        ],
    );
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());
    let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
    state.on_established(
        IpAddr::V4(peer_provider),
        peer_provider,
        PeerType::External,
        65002,
        90,
        &v6_caps,
        None,
    );
    state.on_established(
        IpAddr::V4(peer_lateral),
        peer_lateral,
        PeerType::External,
        65003,
        90,
        &v6_caps,
        None,
    );
    drain_all(&mut receivers);

    // Learned from peer_provider (our Provider) with no OTC — gets
    // attached on ingress (session_role = Customer is in the
    // ingress-attach set), so it already carries OTC by the time it's
    // considered for export.
    let leaked_v6: Nlri<Ipv6Addr> = "2001:db8:dead::/48".parse().unwrap();
    state.on_route_update(
        IpAddr::V4(peer_provider),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                    prefixes: vec![Prefix::V6(leaked_v6)],
                }),
            ],
            announced: vec![],
        },
    );
    state.flush_pending();
    assert_eq!(
        state.rib.loc_rib_v6.best(&leaked_v6).unwrap().otc(),
        Some(Asn::new(65002))
    );
    assert!(
        receivers
            .get_mut(&IpAddr::V4(peer_lateral))
            .unwrap()
            .try_recv()
            .is_err(),
        "an IPv6 route already carrying OTC must never reach a Peer-role destination"
    );

    // A second, clean IPv6 route from a peer with no configured role
    // (so no ingress attach) crosses to peer_lateral, where it must get
    // OTC attached on egress (session_role = Peer is in the
    // egress-attach set too).
    let peer_plain: Ipv4Addr = "10.0.0.4".parse().unwrap();
    state.add_peer(
        &config::PeerConfig {
            address: IpAddr::V4(peer_plain),
            port: 179,
            remote_as: 65004,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
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
        },
        mpsc::channel(64).0,
    );
    state.on_established(
        IpAddr::V4(peer_plain),
        peer_plain,
        PeerType::External,
        65004,
        90,
        &v6_caps,
        None,
    );
    drain_all(&mut receivers);

    let clean_v6: Nlri<Ipv6Addr> = "2001:db8:beef::/48".parse().unwrap();
    state.on_route_update(
        IpAddr::V4(peer_plain),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65004)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::4".parse().unwrap()),
                    prefixes: vec![Prefix::V6(clean_v6)],
                }),
            ],
            announced: vec![],
        },
    );
    state.flush_pending();
    assert_eq!(
        state.rib.loc_rib_v6.best(&clean_v6).unwrap().otc(),
        None,
        "no configured role on peer_plain means no ingress attach"
    );
    let msg = receivers
        .get_mut(&IpAddr::V4(peer_lateral))
        .unwrap()
        .try_recv()
        .expect("clean IPv6 route must reach the Peer-role destination");
    assert!(
        msg.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::OnlyToCustomer(asn) if *asn == Asn::new(65001))),
        "OTC = local ASN must be attached on IPv6 egress toward a Peer-role destination"
    );
}
