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

// ── RPKI ROV for peers added at runtime (issue #194) ─────────────────────
//
// RFC 6811 §3 leaves the use of the validation state to route policy, so
// `reject_invalid` is the operator's policy and must cover every session,
// however it was configured. RFC 6811 §4: when a mapping is added or deleted
// "the implementation MUST re-validate any affected prefixes and run the BGP
// decision process if needed."

const STARTUP_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const RUNTIME_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

/// How a peer reaches the daemon after startup.
#[derive(Debug, Clone, Copy)]
enum Arrival {
    /// `AddPeer` for an address that was never configured.
    Added,
    /// `RemovePeer` then `AddPeer` for a peer present at startup.
    ReAdded,
}

fn peer_config(address: IpAddr, remote_as: u32) -> config::PeerConfig {
    config::PeerConfig {
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
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    }
}

/// A daemon with one startup peer, with `rtr` wired in by the same
/// `install_rpki` that production startup calls.
async fn daemon_with_rpki(
    rtr: &pathvector_rpki::RtrHandle,
    reject_invalid: bool,
) -> Arc<RwLock<DaemonState>> {
    let (state, _) = make_state(65001, &[(STARTUP_PEER, 65002)]);
    let state = Arc::new(RwLock::new(state));
    install_rpki(rtr.clone(), reject_invalid, &state).await;
    state
}

/// Brings a peer in at runtime and returns its address, AS number and the
/// receiver that keeps its outbound channel open.
fn arrive(
    state: &mut DaemonState,
    arrival: Arrival,
) -> (IpAddr, u32, mpsc::Receiver<UpdateMessage>) {
    let (ip, asn) = match arrival {
        Arrival::Added => (RUNTIME_PEER, 65003),
        Arrival::ReAdded => {
            assert!(state.remove_peer(STARTUP_PEER));
            (STARTUP_PEER, 65002)
        }
    };
    let (tx, rx) = mpsc::channel(64);
    assert!(state.add_peer(&peer_config(ip, asn), tx));
    (ip, asn, rx)
}

/// Establishes `ip` and announces 10.0.0.0/8 and 2001:db8::/32 from `asn`.
fn establish_and_announce(state: &mut DaemonState, ip: IpAddr, asn: u32) {
    state.on_established(ip, must_v4(ip), PeerType::External, asn, 90, &[], None);
    let path = AsPath::from_sequence(vec![Asn::new(asn)]);
    state.on_route_update(
        ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path.clone()),
                PathAttribute::NextHop(must_v4(ip)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        },
    );
    state.on_route_update(
        ip,
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(path),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8:ffff::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                }),
            ],
            announced: vec![],
        },
    );
}

/// Whether the announced prefixes are in the (IPv4, IPv6) Loc-RIB.
fn installed(state: &DaemonState) -> (bool, bool) {
    (
        state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
        state
            .rib
            .loc_rib_v6
            .best(&nlri_v6("2001:db8::/32"))
            .is_some(),
    )
}

/// ROAs naming AS 99999 for both announced prefixes, so any other origin AS
/// is Invalid (RFC 6811 §2: Covered, but not Matched).
fn invalidating_roas() -> pathvector_rpki::RtrHandle {
    pathvector_rpki::for_testing(
        [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999)],
        [("2001:db8::".parse().unwrap(), 32, 32, 99999)],
    )
}

#[tokio::test]
async fn runtime_peer_rejects_invalid_routes() {
    for arrival in [Arrival::Added, Arrival::ReAdded] {
        let state = daemon_with_rpki(&invalidating_roas(), true).await;
        let mut state = state.write().await;
        let (ip, asn, _rx) = arrive(&mut state, arrival);

        establish_and_announce(&mut state, ip, asn);

        assert_eq!(
            installed(&state),
            (false, false),
            "{arrival:?}: Invalid routes must be rejected in both families"
        );
    }
}

#[tokio::test]
async fn runtime_peer_routes_are_revalidated_on_a_later_roa_change() {
    for arrival in [Arrival::Added, Arrival::ReAdded] {
        let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
        let state = daemon_with_rpki(&rtr, true).await;
        let _rx = {
            let mut guard = state.write().await;
            let (ip, asn, rx) = arrive(&mut guard, arrival);
            establish_and_announce(&mut guard, ip, asn);
            assert_eq!(
                installed(&guard),
                (true, true),
                "{arrival:?}: NotFound routes are accepted"
            );
            rx
        };

        rtr.insert_roa_v4(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999);
        rtr.insert_roa_v6("2001:db8::".parse().unwrap(), 32, 32, 99999);

        // Only the task `install_rpki` spawned reacts to the change.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while installed(&*state.read().await) != (false, false) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{arrival:?}: routes still installed after the ROA change"));
    }
}

#[tokio::test]
async fn runtime_peer_has_no_rov_term_when_reject_invalid_is_false() {
    for arrival in [Arrival::Added, Arrival::ReAdded] {
        let state = daemon_with_rpki(&invalidating_roas(), false).await;
        let mut state = state.write().await;
        let (ip, asn, _rx) = arrive(&mut state, arrival);
        assert_eq!(state.import_policies[&ip].len(), 0, "{arrival:?}");
        assert_eq!(state.import_policies_v6[&ip].len(), 0, "{arrival:?}");

        establish_and_announce(&mut state, ip, asn);

        // RFC 6811 §2: a route MUST NOT be excluded for its validation state
        // "unless explicitly configured to do so".
        assert_eq!(installed(&state), (true, true), "{arrival:?}");
    }
}

/// Every term a startup peer gets, a runtime peer with the same configuration
/// gets too: RFC 9234 ingress terms and the RFC 6811 reject term, on eBGP and
/// iBGP sessions.
#[tokio::test]
async fn runtime_and_startup_peers_get_the_same_import_terms() {
    let ebgp_with_role = config::PeerConfig {
        role: Some(config::PeerRole::Customer),
        ..peer_config(STARTUP_PEER, 65002)
    };
    let ibgp = peer_config(STARTUP_PEER, 65001);
    let rtr = invalidating_roas();

    for startup_config in [ebgp_with_role, ibgp] {
        let runtime_config = config::PeerConfig {
            address: RUNTIME_PEER,
            ..startup_config.clone()
        };
        let (tx, _startup_rx) = mpsc::channel(64);
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            None,
            std::slice::from_ref(&startup_config),
            HashMap::from([(STARTUP_PEER, tx)]),
            vec![],
        );
        let state = Arc::new(RwLock::new(state));
        install_rpki(rtr.clone(), true, &state).await;
        let mut state = state.write().await;
        let (tx, _runtime_rx) = mpsc::channel(64);
        assert!(state.add_peer(&runtime_config, tx));

        let remote_as = startup_config.remote_as;
        assert_eq!(
            state.import_policies[&RUNTIME_PEER].len(),
            state.import_policies[&STARTUP_PEER].len(),
            "IPv4 terms for a peer in AS {remote_as}"
        );
        assert_eq!(
            state.import_policies_v6[&RUNTIME_PEER].len(),
            state.import_policies_v6[&STARTUP_PEER].len(),
            "IPv6 terms for a peer in AS {remote_as}"
        );
    }
}
