// daemon/blackhole_tests.rs — RFC 7999 BLACKHOLE handling end to end through
// the daemon: authorization, the ROV exception, revocation, re-evaluation,
// multi-peer ownership, Graceful Restart, and a model property test of the
// classification pipeline.
//
// RFC 7999 §3.3 (quoted where each test proves it):
//
//   "BGP speakers in a bilateral peering relationship using the BLACKHOLE
//    community MUST only accept and honor BGP announcements carrying the
//    BLACKHOLE community under the two following conditions:
//    o  The announced prefix is covered by an equal or shorter prefix that
//       the neighboring network is authorized to advertise.
//    o  The receiving party agreed to honor the BLACKHOLE community on the
//       particular BGP session."
//
//   "An operator MUST ensure that origin validation techniques (such as the
//    one described in [RFC6811]) do not inadvertently block legitimate
//    announcements carrying the BLACKHOLE community."
//
// RFC 7999 §3.2 keeps a blackhole local ("prevent propagation of the prefix
// outside the local AS"), which the implementation meets by never putting an
// authorized blackhole in the Loc-RIB, so it is never a unicast export.

use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_policy::DefaultAction;
use pathvector_rib::BestPathChange;
use pathvector_session::message::PathAttribute;
use pathvector_types::{Asn, Community, Role};

use super::PeerId;
use super::issue_81_82_tests::support::{
    a, announces4, announces6, b, bh4, bh6, c, drop_a, eor_v4, eor_v6, established_gr, p4, p6,
    reestablish_a, v4_update, v4_withdraw, v6_update, v6_withdraw,
};
use super::last_feasible_tests::{AS_A, PEER_A, PEER_B, PEER_C, drain, sent_to};
use crate::blackhole::BlackholeScope;

const BH: Community = Community::BLACKHOLE;
const HOST_V4: &str = "192.0.2.77/32";
const HOST_V4_2: &str = "192.0.2.78/32";
const HOST_V6: &str = "2001:db8:ffff::77/128";
const HOST_V6_2: &str = "2001:db8:ffff::78/128";
/// The authorized covering prefixes (RFC 7999 §3.3 condition 1).
const SCOPE: [&str; 2] = ["192.0.2.0/24", "2001:db8:ffff::/48"];

fn scope(prefixes: &[&str]) -> BlackholeScope {
    BlackholeScope::new(prefixes).unwrap()
}

/// RFC 7999 §3.3 condition 2 plus an authorized scope, for peer `peer`.
fn agree(state: &mut super::DaemonState, peer: std::net::IpAddr, prefixes: &[&str]) {
    state.set_blackhole_scope(peer, Some(&scope(prefixes)));
}

// ── Authorization ────────────────────────────────────────────────────────────

/// Authorized /32 and /128 host blackholes are honored even though the peer's
/// import default is Reject (RFC 8212's eBGP default): the agreement and scope
/// are the authorization. They program one null route each, never enter the
/// Loc-RIB, and are never exported to other peers (RFC 7999 §3.2).
#[test]
fn authorized_host_blackholes_are_honored_under_reject_default_and_never_exported() {
    let (mut state, mut receivers, fib) = established_gr();
    state.set_import_default(a(), DefaultAction::Reject);
    agree(&mut state, a(), &SCOPE);
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));

    assert_eq!(bh4(&fib), vec![(p4(HOST_V4), true)]);
    assert_eq!(bh6(&fib), vec![(p6(HOST_V6), true)]);
    assert!(state.rib.loc_rib.best(&p4(HOST_V4)).is_none());
    assert!(state.rib.loc_rib_v6.best(&p6(HOST_V6)).is_none());
    for peer in [PEER_B, PEER_C] {
        let sent = sent_to(&mut state, &mut receivers, peer);
        assert!(!announces4(&sent, HOST_V4), "exported to {peer}: {sent:?}");
        assert!(!announces6(&sent, HOST_V6), "exported to {peer}: {sent:?}");
    }
}

/// RFC 7999 §3.3 condition 1: a prefix outside the authorized scope, and one
/// *shorter* than the authorized prefix (not "covered by an equal or shorter
/// prefix"), are refused with no FIB effect — in both families.
#[test]
fn blackholes_outside_the_authorized_scope_are_denied() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    drain(&mut state, &mut receivers);

    for prefix in ["198.51.100.1/32", "192.0.2.0/23", "192.0.0.0/16"] {
        state.on_route_update(a(), v4_update(prefix, &[BH]));
    }
    for prefix in [
        "2001:db8:aaaa::1/128",
        "2001:db8:ffff::/47",
        "2001:db8::/32",
    ] {
        state.on_route_update(a(), v6_update(prefix, &[BH]));
    }

    assert!(bh4(&fib).is_empty(), "{:?}", bh4(&fib));
    assert!(bh6(&fib).is_empty(), "{:?}", bh6(&fib));
    assert_eq!(state.rib.loc_rib.len() + state.rib.loc_rib_v6.len(), 0);
}

/// RFC 7999 §3.3 condition 2: another peer's agreement does not carry over to
/// a session that has none.
#[test]
fn agreement_is_per_session() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, b(), &SCOPE); // B agreed; A did not.
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));

    assert!(bh4(&fib).is_empty() && bh6(&fib).is_empty());
}

/// RFC 7999 §3.3: origin validation must not "inadvertently block legitimate
/// announcements carrying the BLACKHOLE community". The ROA covers the /24 and
/// /48 with `maxLength` equal to the prefix length, so an *ordinary* host route
/// is RPKI-Invalid (RFC 6811 §2: longer than maxLength) and rejected — the
/// control — while the authorized BLACKHOLE host route is honored.
#[test]
fn authorized_blackholes_are_exempt_from_origin_validation() {
    let (mut state, mut receivers, fib) = established_gr();
    let rtr = pathvector_rpki::for_testing(
        [(Ipv4Addr::new(192, 0, 2, 0), 24, 24, AS_A)],
        [(
            Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 0),
            48,
            48,
            AS_A,
        )],
    );
    state.install_rpki_import_terms(&rtr);
    agree(&mut state, a(), &SCOPE);
    drain(&mut state, &mut receivers);

    // Control: untagged host routes inside the ROA are Invalid and rejected.
    state.on_route_update(a(), v4_update(HOST_V4_2, &[]));
    state.on_route_update(a(), v6_update(HOST_V6_2, &[]));
    assert!(
        state.rib.loc_rib.best(&p4(HOST_V4_2)).is_none(),
        "control: ROV must reject the over-long unicast host route"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(HOST_V6_2)).is_none(),
        "control (v6)"
    );

    // The same shape, BLACKHOLE-tagged, is honored.
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    assert_eq!(
        bh4(&fib),
        vec![(p4(HOST_V4), true)],
        "ROV blocked the IPv4 blackhole"
    );
    assert_eq!(
        bh6(&fib),
        vec![(p6(HOST_V6), true)],
        "ROV blocked the IPv6 blackhole"
    );
}

/// RFC 9234 §5: "If a route with the OTC Attribute is received from a Customer
/// [...] then it is a route leak and MUST be considered ineligible." The ROV
/// exemption does not extend to a leak: a BLACKHOLE request carrying OTC from
/// our Customer is refused; the same request without OTC is honored.
#[test]
fn route_leak_blackhole_request_is_still_ineligible() {
    let (mut state, mut receivers, fib) = established_gr();
    // A is our Customer (we are its Provider): leak detection applies.
    super::install_otc_import_term(
        state.import_policies.get_mut(&a()).unwrap(),
        Role::Provider,
        Asn::new(AS_A),
    );
    std::sync::Arc::make_mut(&mut state.rib)
        .peer_roles
        .insert(a(), Role::Provider);
    agree(&mut state, a(), &SCOPE);
    drain(&mut state, &mut receivers);

    let mut leaked = v4_update(HOST_V4, &[BH]);
    leaked
        .attributes
        .push(PathAttribute::OnlyToCustomer(Asn::new(64999)));
    state.on_route_update(a(), leaked);
    assert!(
        bh4(&fib).is_empty(),
        "a leaked blackhole request was honored"
    );

    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    assert_eq!(bh4(&fib), vec![(p4(HOST_V4), true)]);
}

// ── Re-evaluation: policy change, revocation, RPKI ──────────────────────────

/// "Accepted blackholes remain blackholes across re-evaluation": policy-default
/// changes and ROA-cache changes re-judge the Adj-RIB-In, and the authorized
/// blackhole stays a blackhole — no duplicate install, no withdrawal, never a
/// Loc-RIB entry, never an export. Both families.
#[test]
fn accepted_blackholes_remain_blackholes_across_reevaluation() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    drain(&mut state, &mut receivers);
    let installs4 = bh4(&fib);
    let installs6 = bh6(&fib);
    assert_eq!((installs4.len(), installs6.len()), (1, 1), "precondition");

    let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
    state.install_rpki_import_terms(&rtr);
    for default in [
        DefaultAction::Accept,
        DefaultAction::Reject,
        DefaultAction::Accept,
    ] {
        state.set_import_default(a(), default);
        // A ROA now makes everything under 192.0.2.0/24 Invalid for AS_A.
        rtr.insert_roa_v4(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 99_999);
        state.reevaluate_all_import_policies();
    }

    assert_eq!(
        bh4(&fib),
        installs4,
        "IPv4 null route churned during re-evaluation"
    );
    assert_eq!(
        bh6(&fib),
        installs6,
        "IPv6 null route churned during re-evaluation"
    );
    assert!(state.rib.loc_rib.best(&p4(HOST_V4)).is_none());
    assert!(state.rib.loc_rib_v6.best(&p6(HOST_V6)).is_none());
    for peer in [PEER_B, PEER_C] {
        let sent = sent_to(&mut state, &mut receivers, peer);
        assert!(
            !announces4(&sent, HOST_V4) && !announces6(&sent, HOST_V6),
            "{sent:?}"
        );
    }
}

/// Revocation: removing the agreement re-evaluates the Adj-RIB-In, and the
/// null routes — which have no Loc-RIB entry to withdraw — are removed. No
/// kernel entry is left behind; re-granting restores them without the peer
/// re-announcing; narrowing the scope removes only what falls outside it.
#[test]
fn revoking_or_narrowing_the_agreement_removes_null_routes_without_leaving_stale_ones() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    drain(&mut state, &mut receivers);

    state.set_blackhole_scope(a(), None);
    assert_eq!(
        bh4(&fib),
        vec![(p4(HOST_V4), true), (p4(HOST_V4), false)],
        "IPv4 null route not removed on revocation"
    );
    assert_eq!(bh6(&fib), vec![(p6(HOST_V6), true), (p6(HOST_V6), false)]);
    assert_eq!(state.blackholes.v4.len() + state.blackholes.v6.len(), 0);
    assert!(
        state.rib.loc_rib.best(&p4(HOST_V4)).is_none(),
        "revoked ≠ unicast"
    );

    agree(&mut state, a(), &SCOPE);
    assert_eq!(
        bh4(&fib).last(),
        Some(&(p4(HOST_V4), true)),
        "re-grant restores"
    );
    assert_eq!(bh6(&fib).last(), Some(&(p6(HOST_V6), true)));

    // Narrow the scope to the IPv6 prefix only: the IPv4 null route goes, the
    // IPv6 one stays.
    let v4_before = bh4(&fib).len();
    let v6_before = bh6(&fib).len();
    agree(&mut state, a(), &["2001:db8:ffff::/48"]);
    assert_eq!(bh4(&fib).len(), v4_before + 1);
    assert_eq!(bh4(&fib).last(), Some(&(p4(HOST_V4), false)));
    assert_eq!(
        bh6(&fib).len(),
        v6_before,
        "the IPv6 prefix is still authorized"
    );
}

/// A later ordinary announcement of the same prefix supersedes the blackhole
/// request (RFC 4271 §9: "the new route SHALL replace the older route in the
/// Adj-RIB-In, thus implicitly withdrawing the older route from service"): the
/// null route goes, and the replacement is judged as ordinary unicast.
#[test]
fn unicast_replacement_of_a_blackhole_removes_the_null_route() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), v4_update(HOST_V4, &[]));
    state.on_route_update(a(), v6_update(HOST_V6, &[]));

    assert_eq!(bh4(&fib).last(), Some(&(p4(HOST_V4), false)));
    assert_eq!(bh6(&fib).last(), Some(&(p6(HOST_V6), false)));
    assert_eq!(
        state.rib.loc_rib.best_peer(&p4(HOST_V4)),
        Some(PeerId::from(a()))
    );
    assert_eq!(
        state.rib.loc_rib_v6.best_peer(&p6(HOST_V6)),
        Some(PeerId::from(a()))
    );
}

// ── Multi-peer ownership of a kernel null route ──────────────────────────────

/// A kernel null route is per prefix, not per peer. Two peers asking for the
/// same prefix share one route; it is withdrawn only when the last one lets go,
/// and a peer whose request was *denied* can never remove another's.
#[test]
fn null_route_is_shared_and_withdrawn_only_by_the_last_holder() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    agree(&mut state, b(), &SCOPE);
    // C never agreed.
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(b(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(c(), v4_update(HOST_V4, &[BH]));
    assert_eq!(
        bh4(&fib),
        vec![(p4(HOST_V4), true)],
        "one install for three requests"
    );

    // The denied peer's withdrawal removes nothing.
    state.on_route_update(c(), v4_withdraw(HOST_V4));
    assert_eq!(bh4(&fib).len(), 1);

    state.on_route_update(a(), v4_withdraw(HOST_V4));
    assert_eq!(bh4(&fib).len(), 1, "B still holds the prefix");

    state.on_route_update(b(), v4_withdraw(HOST_V4));
    assert_eq!(bh4(&fib), vec![(p4(HOST_V4), true), (p4(HOST_V4), false)]);
}

/// While a blackhole holds a prefix, the kernel entry is the null route: a
/// unicast best-path change for the same prefix is not programmed over it. When
/// the blackhole goes, the Loc-RIB's best route is programmed again — "no
/// contradictory kernel entries" (issue #81).
#[test]
fn unicast_best_path_changes_never_overwrite_a_held_null_route() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    state.on_route_update(c(), v4_update(HOST_V4, &[]));
    drain(&mut state, &mut receivers);
    assert!(
        state.rib.loc_rib.best(&p4(HOST_V4)).is_some(),
        "C's unicast route"
    );

    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    assert_eq!(bh4(&fib), vec![(p4(HOST_V4), true)]);
    assert!(
        state.rib.loc_rib.best(&p4(HOST_V4)).is_some(),
        "C's unicast candidate stays in the Loc-RIB (only A's candidate is evicted)"
    );
    fib.v4.lock().unwrap().clear();

    // C re-announces with a different MED: a best-path change for the prefix.
    let mut changed = v4_update(HOST_V4, &[]);
    changed.attributes.push(PathAttribute::Med(7));
    state.on_route_update(c(), changed);
    assert!(
        fib.v4_changes()
            .iter()
            .all(|ch| !matches!(ch, BestPathChange::Announced(..))),
        "a unicast route was programmed over the null route: {:?}",
        fib.v4_changes()
    );

    state.on_route_update(a(), v4_withdraw(HOST_V4));
    assert_eq!(bh4(&fib).last(), Some(&(p4(HOST_V4), false)));
    assert!(
        fib.v4_changes()
            .iter()
            .any(|ch| matches!(ch, BestPathChange::Announced(n, _) if *n == p4(HOST_V4))),
        "C's unicast route must be programmed again once the null route is gone"
    );
}

// ── Session lifecycle ────────────────────────────────────────────────────────

/// A clean session end releases every null route the peer held, both families,
/// and leaves another peer's untouched.
#[test]
fn clean_session_end_removes_the_peers_null_routes() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    agree(&mut state, b(), &SCOPE);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    state.on_route_update(b(), v4_update(HOST_V4_2, &[BH]));
    drain(&mut state, &mut receivers);

    state.on_terminated(
        a(),
        pathvector_session::transport::TerminationReason::OperatorStop,
        false,
    );

    assert_eq!(
        bh4(&fib).iter().filter(|(_, up)| !*up).collect::<Vec<_>>(),
        [&(p4(HOST_V4), false)]
    );
    assert_eq!(bh6(&fib).last(), Some(&(p6(HOST_V6), false)));
    assert!(
        state.blackholes.v4.is_blackholed(&p4(HOST_V4_2)),
        "B's null route survives"
    );
}

/// Full Graceful Restart lifecycle for blackholes (RFC 4724 §4.2): null routes
/// are retained while the window is open ("MUST retain the routes [...] MUST
/// NOT differentiate between stale and other routing information during
/// forwarding"), stay blackholes (never unicast) through stale marking, are
/// kept when the peer re-announces them, and at End-of-RIB "any routes from
/// the peer that are still marked as stale" are removed — including their null
/// routes. IPv4 and IPv6.
#[test]
fn graceful_restart_retains_refreshes_and_sweeps_null_routes() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    for (v4, v6) in [(HOST_V4, HOST_V6), (HOST_V4_2, HOST_V6_2)] {
        state.on_route_update(a(), v4_update(v4, &[BH]));
        state.on_route_update(a(), v6_update(v6, &[BH]));
    }
    drain(&mut state, &mut receivers);
    let (n4, n6) = (bh4(&fib).len(), bh6(&fib).len());
    assert_eq!((n4, n6), (2, 2), "precondition: four null routes");

    // Unclean drop: retained, still blackholes, nothing churns.
    drop_a(&mut state);
    assert!(state.gr.deadlines.contains_key(&a()));
    assert_eq!(
        (bh4(&fib).len(), bh6(&fib).len()),
        (n4, n6),
        "null routes withdrawn at drop"
    );
    assert_eq!(
        state.rib.loc_rib.len() + state.rib.loc_rib_v6.len(),
        0,
        "never unicast"
    );
    assert!(state.blackholes.v4.is_blackholed(&p4(HOST_V4)));

    // Re-establish; the peer refreshes one prefix per family only.
    reestablish_a(&mut state);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    assert_eq!(
        (bh4(&fib).len(), bh6(&fib).len()),
        (n4, n6),
        "refresh must not churn"
    );

    state.on_route_update(a(), eor_v4());
    state.on_route_update(a(), eor_v6());

    assert_eq!(
        bh4(&fib).last(),
        Some(&(p4(HOST_V4_2), false)),
        "stale IPv4 null route swept"
    );
    assert_eq!(
        bh6(&fib).last(),
        Some(&(p6(HOST_V6_2), false)),
        "stale IPv6 null route swept"
    );
    assert!(
        state.blackholes.v4.is_blackholed(&p4(HOST_V4)),
        "refreshed route kept"
    );
    assert!(state.blackholes.v6.is_blackholed(&p6(HOST_V6)));
    assert!(!state.blackholes.v4.is_blackholed(&p4(HOST_V4_2)));
    assert_eq!(state.rib.loc_rib.len() + state.rib.loc_rib_v6.len(), 0);
}

/// RFC 4724 §4.2: "If the session does not get re-established within the
/// 'Restart Time' [...] the Receiving Speaker MUST delete all the stale routes
/// from the peer that it is retaining." That includes the null routes.
#[test]
fn graceful_restart_expiry_removes_null_routes() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    drain(&mut state, &mut receivers);
    drop_a(&mut state);

    state.on_gr_deadline_expired(a());

    assert_eq!(bh4(&fib).last(), Some(&(p4(HOST_V4), false)));
    assert_eq!(bh6(&fib).last(), Some(&(p6(HOST_V6), false)));
    assert_eq!(state.blackholes.v4.len() + state.blackholes.v6.len(), 0);
}

/// Revoking the agreement *during* the GR window removes the retained null
/// routes at once: retained routes are re-judged by the same pipeline, so
/// "retained" never means "still authorized".
#[test]
fn revocation_during_the_gr_window_removes_retained_null_routes() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    drain(&mut state, &mut receivers);
    drop_a(&mut state);

    state.set_blackhole_scope(a(), None);

    assert_eq!(bh4(&fib).last(), Some(&(p4(HOST_V4), false)));
    assert_eq!(bh6(&fib).last(), Some(&(p6(HOST_V6), false)));
}

/// A withdrawal of a blackhole by the peer (WITHDRAWN ROUTES and MP_UNREACH)
/// removes the null route, and a denied request that was never installed
/// removes nothing.
#[test]
fn explicit_withdrawal_removes_the_null_route() {
    let (mut state, mut receivers, fib) = established_gr();
    agree(&mut state, a(), &SCOPE);
    state.on_route_update(a(), v4_update(HOST_V4, &[BH]));
    state.on_route_update(a(), v6_update(HOST_V6, &[BH]));
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), v4_withdraw(HOST_V4));
    state.on_route_update(a(), v6_withdraw(HOST_V6));

    assert_eq!(bh4(&fib), vec![(p4(HOST_V4), true), (p4(HOST_V4), false)]);
    assert_eq!(bh6(&fib), vec![(p6(HOST_V6), true), (p6(HOST_V6), false)]);
}

// ── Configuration → agreement ────────────────────────────────────────────────

fn peer_config(
    address: std::net::IpAddr,
    scope: Option<BlackholeScope>,
) -> crate::config::PeerConfig {
    crate::config::PeerConfig {
        address,
        port: 179,
        remote_as: AS_A,
        import_default: Some(crate::config::ImportDefault::Reject),
        export_default: Some(crate::config::ExportDefault::Accept),
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
        blackhole_authorized_prefixes: scope,
    }
}

/// The configured `blackhole_authorized_prefixes` becomes the session's
/// agreement for peers present at startup and for peers added at runtime, and
/// removing a peer removes it. A peer without the setting is denied (RFC 7999
/// §4).
#[test]
fn configuration_becomes_the_session_agreement() {
    let with = std::net::IpAddr::V4(PEER_A);
    let without = std::net::IpAddr::V4(PEER_B);
    let added = std::net::IpAddr::V4(PEER_C);
    let state = super::DaemonState::new(
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        None,
        &[
            peer_config(with, Some(scope(&SCOPE))),
            peer_config(without, None),
        ],
        std::collections::HashMap::new(),
        vec![],
    );
    assert!(!state.blackhole_sessions[&with].v4.is_denied());
    assert!(state.blackhole_sessions[&without].v4.is_denied());

    let mut state = state;
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    assert!(state.add_peer(&peer_config(added, Some(scope(&SCOPE))), tx));
    assert!(!state.blackhole_sessions[&added].v4.is_denied());
    assert!(state.remove_peer(added));
    assert!(!state.blackhole_sessions.contains_key(&added));
}

// ── Model property test of the classification pipeline ──────────────────────

mod model {
    //! Relations, not examples. For any interleaving of announcements (plain or
    //! BLACKHOLE-tagged, in or out of scope) and withdrawals from peers with
    //! different agreements and import defaults:
    //!
    //! 1. a BLACKHOLE-tagged route is never a Loc-RIB candidate (never unicast);
    //! 2. the null-route book holds exactly the (peer, prefix) pairs whose
    //!    stored route classifies as an authorized blackhole — no stale kernel
    //!    entry, none missing;
    //! 3. re-evaluation equals fresh import: rebuilding the Loc-RIB and book
    //!    from the final Adj-RIBs-In yields the state arrival produced;
    //! 4. re-evaluation is idempotent: a second pass leaves the state as it was
    //!    and emits no null-route change.

    use std::collections::BTreeSet;

    use pathvector_policy::{DefaultAction, Policy};
    use pathvector_rib::oracle::AlwaysReachable;
    use pathvector_rib::{AdjRibIn, LocRib, PeerId, Route, RouteBuilder};
    use pathvector_types::{AsPath, Asn, Community, NextHop, Nlri, Origin};
    use proptest::prelude::*;

    use super::super::blackhole::{BlackholeAgreement, BlackholeBook, carries_blackhole_community};
    use super::super::import::{
        ImportDecision, ImportPipeline, ImportTally, import_announcement, reapply_import_policy,
        withdraw_route,
    };
    use super::super::ingress::IngressGate;
    use crate::blackhole::{BlackholeScope, ScopeFamily};

    const PEERS: usize = 3;

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Announce { tagged: bool },
        Withdraw,
    }

    #[derive(Clone, Copy, Debug)]
    struct Step {
        peer: usize,
        prefix: usize,
        op: Op,
    }

    fn step() -> impl Strategy<Value = Step> {
        (
            0..PEERS,
            0..5usize,
            prop_oneof![
                3 => any::<bool>().prop_map(|tagged| Op::Announce { tagged }),
                1 => Just(Op::Withdraw),
            ],
        )
            .prop_map(|(peer, prefix, op)| Step { peer, prefix, op })
    }

    fn peer_id(i: usize) -> PeerId {
        PeerId::from(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            0,
            0,
            10 + u8::try_from(i).unwrap(),
        )))
    }

    /// Peer 0: agreed (whole scope), Accept. Peer 1: no agreement, Accept.
    /// Peer 2: agreed for a narrower scope, import default Reject.
    fn agreement<A: ScopeFamily>(peer: usize, scopes: &[&str; 2]) -> BlackholeAgreement<A> {
        match peer {
            0 => BlackholeAgreement::agreed(BlackholeScope::new([scopes[0]]).unwrap()),
            2 => BlackholeAgreement::agreed(BlackholeScope::new([scopes[1]]).unwrap()),
            _ => BlackholeAgreement::denied(),
        }
    }

    fn policy<A: ScopeFamily>(peer: usize) -> Policy<Route<A>> {
        Policy::new(if peer == 2 {
            DefaultAction::Reject
        } else {
            DefaultAction::Accept
        })
    }

    fn route<A: ScopeFamily>(nlri: Nlri<A>, peer: usize, tagged: bool, nh: NextHop) -> Route<A> {
        let mut b = RouteBuilder::new(
            nlri,
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(64_500 + u32::try_from(peer).unwrap())]),
        )
        .next_hop(nh);
        if tagged {
            b = b.community(Community::BLACKHOLE);
        }
        b.build()
    }

    /// Snapshot of everything the pipeline owns.
    #[derive(Debug, PartialEq)]
    struct Snapshot<A: ScopeFamily> {
        candidates: BTreeSet<(Nlri<A>, PeerId, bool)>,
        held: BTreeSet<(Nlri<A>, PeerId)>,
    }

    fn snapshot<A: ScopeFamily>(
        loc_rib: &LocRib<A>,
        book: &BlackholeBook<A>,
        universe: &[Nlri<A>],
    ) -> Snapshot<A> {
        let mut candidates = BTreeSet::new();
        let mut held = BTreeSet::new();
        for n in universe {
            if let Some(c) = loc_rib.candidates(n) {
                for (p, r) in c {
                    candidates.insert((*n, p, carries_blackhole_community(r)));
                }
            }
            for i in 0..PEERS {
                if book.holds(peer_id(i), n) {
                    held.insert((*n, peer_id(i)));
                }
            }
        }
        Snapshot { candidates, held }
    }

    fn run<A: ScopeFamily>(
        steps: &[Step],
        universe: &[Nlri<A>],
        scopes: &[&str; 2],
        nh: NextHop,
    ) -> Result<(), TestCaseError> {
        let agreements: Vec<BlackholeAgreement<A>> =
            (0..PEERS).map(|p| agreement(p, scopes)).collect();
        let policies: Vec<Policy<Route<A>>> = (0..PEERS).map(policy).collect();
        let mut adj: Vec<AdjRibIn<A>> = (0..PEERS).map(|p| AdjRibIn::new(peer_id(p))).collect();
        let mut loc_rib = LocRib::<A>::new();
        let mut book = BlackholeBook::<A>::default();
        let mut tally = ImportTally::default();

        for s in steps {
            let nlri = universe[s.prefix];
            let pipeline = ImportPipeline {
                policy: &policies[s.peer],
                blackhole: &agreements[s.peer],
            };
            match s.op {
                Op::Announce { tagged } => {
                    let _ = import_announcement(
                        peer_id(s.peer),
                        route(nlri, s.peer, tagged, nh),
                        &mut adj[s.peer],
                        &mut loc_rib,
                        &mut book,
                        &pipeline,
                        &AlwaysReachable,
                        &mut tally,
                    );
                }
                Op::Withdraw => {
                    let _ = withdraw_route(
                        peer_id(s.peer),
                        &nlri,
                        &mut adj[s.peer],
                        &mut loc_rib,
                        &mut book,
                        &AlwaysReachable,
                    );
                }
            }
        }
        let arrived = snapshot(&loc_rib, &book, universe);

        // 1. never unicast.
        prop_assert!(
            arrived.candidates.iter().all(|(_, _, tagged)| !tagged),
            "a BLACKHOLE-tagged route is a Loc-RIB candidate: {:?}",
            arrived.candidates
        );

        // 2. the book is exactly the authorized stored requests.
        let gate = IngressGate::new(65_001, None, None, None);
        let mut expected = BTreeSet::new();
        for (i, a) in adj.iter().enumerate() {
            let pipeline = ImportPipeline {
                policy: &policies[i],
                blackhole: &agreements[i],
            };
            for (n, r) in a.routes() {
                if matches!(
                    pipeline.classify_gated(&gate, r),
                    ImportDecision::Blackhole(_)
                ) {
                    expected.insert((*n, peer_id(i)));
                }
            }
        }
        prop_assert_eq!(
            &arrived.held,
            &expected,
            "book ≠ authorized stored requests"
        );

        // 3. re-evaluation equals fresh import.
        let mut fresh_loc = LocRib::<A>::new();
        let mut fresh_book = BlackholeBook::<A>::default();
        for (i, a) in adj.iter().enumerate() {
            let pipeline = ImportPipeline {
                policy: &policies[i],
                blackhole: &agreements[i],
            };
            let _ = reapply_import_policy(
                peer_id(i),
                a,
                &mut fresh_loc,
                &mut fresh_book,
                &pipeline,
                &gate,
                &AlwaysReachable,
            );
        }
        prop_assert_eq!(
            &snapshot(&fresh_loc, &fresh_book, universe),
            &arrived,
            "fresh import ≠ incremental arrival"
        );

        // 4. idempotent: a second pass over the same state changes nothing.
        for (i, a) in adj.iter().enumerate() {
            let pipeline = ImportPipeline {
                policy: &policies[i],
                blackhole: &agreements[i],
            };
            let fx = reapply_import_policy(
                peer_id(i),
                a,
                &mut fresh_loc,
                &mut fresh_book,
                &pipeline,
                &gate,
                &AlwaysReachable,
            );
            // (Re-inserting the selected route legitimately reports `Announced`
            // — "the current winner's route was replaced" — so idempotence is
            // asserted on state and null-route changes, not on that report.)
            prop_assert!(
                fx.blackhole.is_empty(),
                "second pass changed null routes: {:?}",
                fx.blackhole
            );
        }
        prop_assert_eq!(
            &snapshot(&fresh_loc, &fresh_book, universe),
            &arrived,
            "second pass changed the state"
        );
        Ok(())
    }

    fn v4_universe() -> Vec<Nlri<std::net::Ipv4Addr>> {
        [
            "192.0.2.1/32",    // inside both scopes
            "192.0.2.200/32",  // inside the wide scope only
            "198.51.100.5/32", // outside every scope
            "192.0.2.0/24",    // equal to the wide scope
            "192.0.0.0/16",    // shorter than every scope
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
    }

    fn v6_universe() -> Vec<Nlri<std::net::Ipv6Addr>> {
        [
            "2001:db8:ffff::1/128",
            "2001:db8:ffff::2:1/128",
            "2001:db8:aaaa::5/128",
            "2001:db8:ffff::/48",
            "2001:db8::/32",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn ipv4_pipeline_invariants(steps in proptest::collection::vec(step(), 1..60)) {
            // Peer 0's scope is the /24; peer 2's is the first host's /30.
            run(
                &steps,
                &v4_universe(),
                &["192.0.2.0/24", "192.0.2.0/30"],
                NextHop::V4(std::net::Ipv4Addr::new(192, 0, 2, 254)),
            )?;
        }

        #[test]
        fn ipv6_pipeline_invariants(steps in proptest::collection::vec(step(), 1..60)) {
            run(
                &steps,
                &v6_universe(),
                &["2001:db8:ffff::/48", "2001:db8:ffff::/120"],
                NextHop::V6("2001:db8::1".parse().unwrap()),
            )?;
        }
    }
}
