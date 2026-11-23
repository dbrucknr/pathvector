// daemon/import_reject_tests.rs — issue #80: a replacement UPDATE that import
// policy rejects must withdraw the peer's previously accepted candidate.
//
// RFC 4271 §9: "if the NLRI of the new route is identical to the one the route
// currently has stored in the Adj-RIB-In, then the new route SHALL replace the
// older route in the Adj-RIB-In, thus implicitly withdrawing the older route
// from service." / "Once the BGP speaker updates the Adj-RIB-In, the speaker
// SHALL run its Decision Process."
//
// RFC 4271 §9.1: the degree-of-preference function returns "a value denoting
// that this route is ineligible to be installed in Loc-RIB and will be
// excluded from the next phase of route selection."
//
// RFC 4271 §9.1.1: "If the return value indicates the route is ineligible,
// the route MAY NOT serve as an input to the next phase of route selection".
//
// RFC 4271 §9.1.2: "The Phase 2 process considers all routes that are
// eligible in the Adj-RIBs-In." … "The local speaker SHALL then install that
// route in the Loc-RIB, replacing any route to the same destination that is
// currently being held in the Loc-RIB."
//
// RFC 4271 §9.2: "All newly installed routes and all newly unfeasible routes
// for which there is no replacement route SHALL be advertised to its peers by
// means of an UPDATE message."
//
// RFC 9234 §3 defines "route is ineligible" with RFC 4271's meaning, and §5
// says a leaked route "MUST be considered ineligible". RFC 6811 ROV Invalid is
// rejected by the import term `install_rpki_import_terms` installs.
//
// RFC 7606 does not apply: it "partially revises the error handling for UPDATE
// messages" (§1) and never mentions policy. Every UPDATE here is well formed.
//
// So the peer's *latest* advertisement is the only one that may be a
// candidate. When policy finds it ineligible, the peer has no candidate for
// that prefix — the older accepted route must not stay selected or advertised.
// The rejected replacement stays in Adj-RIB-In (pre-policy) so that a later
// policy or ROA change re-evaluates it, not the superseded route.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pathvector_policy::{CommunityCondition, DefaultAction, Policy, Reject, Term};
use pathvector_rib::oracle::AlwaysReachable;
use pathvector_rib::{AdjRibIn, BestPathChange, LocRib, PeerId, Route};
use pathvector_session::message::{
    MpReachNlri, MpUnreachNlri, PathAttribute, Prefix, UpdateMessage,
};
use pathvector_types::{AfiSafi, AsPath, Asn, Community, NextHop, Nlri, Origin, PeerType, Role};
use proptest::prelude::*;

use super::DaemonState;
use super::import::reapply_import_policy;
use super::install_otc_import_term;
use super::last_feasible_tests::{
    AS_A, AS_C, LOCAL_AS, PEER_A, PEER_B, PEER_C, RESOLVABLE_V4, RESOLVABLE_V4_ALT, RESOLVABLE_V6,
    announces_v4, announces_v6, drain, established, n4, n6, sent_to, withdraws_v4, withdraws_v6,
};
use super::route::handle_update;
use crate::daemon::tests::with_recording_fib;

/// Community that the import term installed by [`reject_tagged`] rejects —
/// the reproduction from issue #80.
const REJECT_TAG: Community = Community::from_parts(65002, 99);

/// Installs "community `REJECT_TAG` ⇒ Reject" on `peer`'s import policies for
/// both families, leaving the Accept default in place.
fn reject_tagged(state: &mut DaemonState, peer: Ipv4Addr) {
    let ip = IpAddr::V4(peer);
    state
        .import_policies
        .get_mut(&ip)
        .unwrap()
        .add_term(Term::new(CommunityCondition::new(REJECT_TAG), Reject));
    state
        .import_policies_v6
        .get_mut(&ip)
        .unwrap()
        .add_term(Term::new(CommunityCondition::new(REJECT_TAG), Reject));
}

fn path(asns: &[u32]) -> PathAttribute {
    PathAttribute::AsPath(AsPath::from_sequence(
        asns.iter().copied().map(Asn::new).collect(),
    ))
}

/// IPv4 announcement of `n4()` with `extra` attributes appended.
fn v4(asns: &[u32], next_hop: Ipv4Addr, extra: &[PathAttribute]) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        path(asns),
        PathAttribute::NextHop(next_hop),
    ];
    attributes.extend_from_slice(extra);
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![n4()],
    }
}

/// IPv6 announcement of `n6()` (`MP_REACH_NLRI`) with `extra` attributes.
fn v6(asns: &[u32], next_hop: Ipv6Addr, extra: &[PathAttribute]) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        path(asns),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6(next_hop),
            prefixes: vec![Prefix::V6(n6())],
        }),
    ];
    attributes.extend_from_slice(extra);
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![],
    }
}

fn tagged() -> [PathAttribute; 1] {
    [PathAttribute::Communities(vec![REJECT_TAG])]
}

fn as_path_of<A: pathvector_types::IpAddress>(route: Option<&Route<A>>) -> Option<AsPath> {
    route.map(|r| (*r.as_path).clone())
}

fn candidate_peers_v4(state: &DaemonState) -> Vec<PeerId> {
    let mut peers: Vec<PeerId> = state
        .rib
        .loc_rib
        .candidates(&n4())
        .map(|c| c.into_keys().collect())
        .unwrap_or_default();
    peers.sort();
    peers
}

fn candidate_peers_v6(state: &DaemonState) -> Vec<PeerId> {
    let mut peers: Vec<PeerId> = state
        .rib
        .loc_rib_v6
        .candidates(&n6())
        .map(|c| c.into_keys().collect())
        .unwrap_or_default();
    peers.sort();
    peers
}

fn pid(ip: Ipv4Addr) -> PeerId {
    PeerId::from(IpAddr::V4(ip))
}

// ── Sole candidate: rejection ⇒ withdrawal everywhere ────────────────────────

/// IPv4, the reproduction from issue #80. A's accepted route is selected and
/// advertised to B; A then replaces it with a route import policy rejects.
/// A has no eligible route left (§9.1.1), so nothing is (§9.1.2): the FIB gets
/// exactly one `Withdrawn`, B gets the prefix in WITHDRAWN ROUTES (§9.2), and
/// A's Adj-RIB-In holds the *rejected replacement* (§9), not the old route.
#[test]
fn rejected_replacement_of_sole_best_withdraws_from_fib_and_peers_v4() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &[]));
    assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
    assert!(state.rib.loc_rib.best(&n4()).is_some());
    fib.v4.lock().unwrap().clear();

    let notification =
        state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &tagged()));

    assert!(notification.is_none(), "policy rejection is not an error");
    assert!(
        state.rib.loc_rib.best(&n4()).is_none(),
        "RFC 4271 §9: the replacement implicitly withdraws the older route"
    );
    assert!(
        candidate_peers_v4(&state).is_empty(),
        "RFC 4271 §9.1.1: an ineligible route may not be a Phase 2 input"
    );
    assert_eq!(
        fib.v4_changes(),
        vec![BestPathChange::Withdrawn(n4())],
        "the FIB must remove the superseded route"
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        withdraws_v4(&to_b) && !announces_v4(&to_b),
        "RFC 4271 §9.2: B must get the prefix in WITHDRAWN ROUTES, got {to_b:?}"
    );
    assert!(state.adj_ribs_out[&IpAddr::V4(PEER_B)].get(&n4()).is_none());
    let stored = state.adj_ribs_in[&IpAddr::V4(PEER_A)].get(&n4()).unwrap();
    assert!(
        stored.rare_or_default().communities.contains(&REJECT_TAG),
        "RFC 4271 §9: Adj-RIB-In must hold the replacement, not the old route"
    );
}

/// IPv6 counterpart: the withdrawal must reach B as `MP_UNREACH_NLRI`.
#[test]
fn rejected_replacement_of_sole_best_withdraws_from_fib_and_peers_v6() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &[]));
    assert!(announces_v6(&sent_to(&mut state, &mut receivers, PEER_B)));
    assert!(state.rib.loc_rib_v6.best(&n6()).is_some());
    fib.v6.lock().unwrap().clear();

    let notification =
        state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &tagged()));

    assert!(notification.is_none());
    assert!(state.rib.loc_rib_v6.best(&n6()).is_none());
    assert!(candidate_peers_v6(&state).is_empty());
    assert_eq!(
        fib.v6.lock().unwrap().clone(),
        vec![BestPathChange::Withdrawn(n6())]
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        withdraws_v6(&to_b) && !announces_v6(&to_b),
        "RFC 4271 §9.2: B must get the prefix in MP_UNREACH_NLRI, got {to_b:?}"
    );
    assert!(
        state.adj_ribs_out_v6[&IpAddr::V4(PEER_B)]
            .get(&n6())
            .is_none()
    );
    let stored = state.adj_ribs_in_v6[&IpAddr::V4(PEER_A)]
        .get(&n6())
        .unwrap();
    assert!(stored.rare_or_default().communities.contains(&REJECT_TAG));
}

// ── Another peer's route takes over ──────────────────────────────────────────

/// IPv4: A (shorter AS_PATH) beats C until A's replacement is rejected. Phase 2
/// must then install C's route (§9.1.2), the FIB must switch to C's next hop,
/// and B must never see a withdrawal: a replacement route exists (§9.2).
#[test]
fn rejected_replacement_promotes_other_peers_route_v4() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &[]));
    state.on_route_update(
        IpAddr::V4(PEER_C),
        v4(&[AS_C, 65005], RESOLVABLE_V4_ALT, &[]),
    );
    assert_eq!(state.rib.loc_rib.best_peer(&n4()), Some(pid(PEER_A)));
    drain(&mut state, &mut receivers);
    fib.v4.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &tagged()));

    assert_eq!(state.rib.loc_rib.best_peer(&n4()), Some(pid(PEER_C)));
    assert_eq!(candidate_peers_v4(&state), vec![pid(PEER_C)]);
    let changes = fib.v4_changes();
    assert!(
        matches!(changes.as_slice(),
            [BestPathChange::Announced(n, r)]
                if *n == n4() && r.next_hop == Some(NextHop::V4(RESOLVABLE_V4_ALT))),
        "FIB must switch to C's next hop, got {changes:?}"
    );
    // B (eBGP) was sent A's path moments ago, so the replacement itself is held
    // by MinRouteAdvertisementIntervalTimer (§9.2.1.1). What matters here is
    // that no withdrawal goes out and B's Adj-RIB-Out already holds C's path.
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(!withdraws_v4(&to_b), "a replacement exists; got {to_b:?}");
    assert_eq!(
        as_path_of(state.adj_ribs_out[&IpAddr::V4(PEER_B)].get(&n4())),
        Some(AsPath::from_sequence(vec![
            Asn::new(LOCAL_AS),
            Asn::new(AS_C),
            Asn::new(65005)
        ])),
        "B's Adj-RIB-Out must hold C's path"
    );
}

/// IPv6 counterpart (no MRAI on the IPv6 path): B receives C's path as a
/// replacement announcement, never a withdrawal.
#[test]
fn rejected_replacement_promotes_other_peers_route_v6() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);
    let fib = with_recording_fib(&mut state);
    let alt: Ipv6Addr = "2001:db8::4".parse().unwrap();

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &[]));
    state.on_route_update(IpAddr::V4(PEER_C), v6(&[AS_C, 65005], alt, &[]));
    assert_eq!(state.rib.loc_rib_v6.best_peer(&n6()), Some(pid(PEER_A)));
    drain(&mut state, &mut receivers);
    fib.v6.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &tagged()));

    assert_eq!(state.rib.loc_rib_v6.best_peer(&n6()), Some(pid(PEER_C)));
    assert_eq!(candidate_peers_v6(&state), vec![pid(PEER_C)]);
    let changes = fib.v6.lock().unwrap().clone();
    assert!(
        matches!(changes.as_slice(),
            [BestPathChange::Announced(n, r)] if *n == n6() && r.next_hop == Some(NextHop::V6(alt))),
        "FIB must switch to C's next hop, got {changes:?}"
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        announces_v6(&to_b) && !withdraws_v6(&to_b),
        "B must receive C's path as a replacement, got {to_b:?}"
    );
}

// ── Rejected replacement of a non-selected candidate: no churn ───────────────

/// IPv4: C is best; A's longer path is an accepted but losing candidate. A's
/// rejected replacement must remove A's candidate (§9.1.1) without touching
/// the selected route: no FIB change and nothing sent to B (§9.2 only sends
/// "newly installed" or "newly unfeasible" routes; neither exists here).
#[test]
fn rejected_replacement_of_losing_candidate_causes_no_churn_v4() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_C), v4(&[AS_C], RESOLVABLE_V4_ALT, &[]));
    state.on_route_update(
        IpAddr::V4(PEER_A),
        v4(&[AS_A, 65005, 65006], RESOLVABLE_V4, &[]),
    );
    assert_eq!(state.rib.loc_rib.best_peer(&n4()), Some(pid(PEER_C)));
    assert_eq!(candidate_peers_v4(&state).len(), 2);
    drain(&mut state, &mut receivers);
    fib.v4.lock().unwrap().clear();

    state.on_route_update(
        IpAddr::V4(PEER_A),
        v4(&[AS_A, 65005, 65006], RESOLVABLE_V4, &tagged()),
    );

    assert_eq!(
        candidate_peers_v4(&state),
        vec![pid(PEER_C)],
        "RFC 4271 §9.1.1: A's superseded route must not stay a candidate"
    );
    assert_eq!(state.rib.loc_rib.best_peer(&n4()), Some(pid(PEER_C)));
    assert!(
        fib.v4_changes()
            .iter()
            .all(|c| *c == BestPathChange::Unchanged),
        "best path did not change, got {:?}",
        fib.v4_changes()
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        !withdraws_v4(&to_b) && !announces_v4(&to_b),
        "no spurious churn, got {to_b:?}"
    );
}

/// IPv6 counterpart.
#[test]
fn rejected_replacement_of_losing_candidate_causes_no_churn_v6() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);
    let fib = with_recording_fib(&mut state);
    let alt: Ipv6Addr = "2001:db8::4".parse().unwrap();

    state.on_route_update(IpAddr::V4(PEER_C), v6(&[AS_C], alt, &[]));
    state.on_route_update(
        IpAddr::V4(PEER_A),
        v6(&[AS_A, 65005, 65006], RESOLVABLE_V6, &[]),
    );
    assert_eq!(state.rib.loc_rib_v6.best_peer(&n6()), Some(pid(PEER_C)));
    drain(&mut state, &mut receivers);
    fib.v6.lock().unwrap().clear();

    state.on_route_update(
        IpAddr::V4(PEER_A),
        v6(&[AS_A, 65005, 65006], RESOLVABLE_V6, &tagged()),
    );

    assert_eq!(candidate_peers_v6(&state), vec![pid(PEER_C)]);
    assert!(
        fib.v6
            .lock()
            .unwrap()
            .iter()
            .all(|c| *c == BestPathChange::Unchanged)
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(!withdraws_v6(&to_b) && !announces_v6(&to_b), "got {to_b:?}");
}

// ── Rejected → accepted ──────────────────────────────────────────────────────

/// IPv4: a rejected first advertisement installs nothing; an accepted
/// replacement from the same peer is then installed and advertised (§9, §9.2).
#[test]
fn accepted_replacement_of_rejected_route_is_installed_v4() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &tagged()));
    assert!(state.rib.loc_rib.best(&n4()).is_none());
    assert!(
        fib.v4_changes()
            .iter()
            .all(|c| *c == BestPathChange::Unchanged)
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(!withdraws_v4(&to_b) && !announces_v4(&to_b), "got {to_b:?}");

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &[]));

    assert_eq!(state.rib.loc_rib.best_peer(&n4()), Some(pid(PEER_A)));
    assert!(matches!(
        fib.v4_changes().last(),
        Some(BestPathChange::Announced(n, _)) if *n == n4()
    ));
    assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
}

/// IPv6 counterpart.
#[test]
fn accepted_replacement_of_rejected_route_is_installed_v6() {
    let (mut state, mut receivers) = established();
    reject_tagged(&mut state, PEER_A);

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &tagged()));
    assert!(state.rib.loc_rib_v6.best(&n6()).is_none());
    assert!(!announces_v6(&sent_to(&mut state, &mut receivers, PEER_B)));

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &[]));

    assert_eq!(state.rib.loc_rib_v6.best_peer(&n6()), Some(pid(PEER_A)));
    assert!(announces_v6(&sent_to(&mut state, &mut receivers, PEER_B)));
}

// ── RFC 6811 ROV Invalid replacement, then re-evaluation ─────────────────────

/// IPv4: the ROA authorises AS_A for `n4()`. A's first route (origin AS_A) is
/// Valid; its replacement (origin 65099) is Invalid and rejected by the ROV
/// term, so the old route is withdrawn. When a ROA for 65099 then appears,
/// re-evaluation must install the *replacement* — proof that Adj-RIB-In kept
/// the latest advertisement (§9) and not the superseded one.
#[test]
fn rov_invalid_replacement_withdraws_and_reevaluates_replacement_v4() {
    let (mut state, mut receivers) = established();
    let rtr = pathvector_rpki::for_testing([(Ipv4Addr::new(10, 0, 0, 0), 8, 8, AS_A)], []);
    state.install_rpki_import_terms(&rtr);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &[]));
    assert!(state.rib.loc_rib.best(&n4()).is_some(), "Valid is accepted");
    assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
    fib.v4.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A, 65099], RESOLVABLE_V4, &[]));

    assert!(
        state.rib.loc_rib.best(&n4()).is_none(),
        "the ROV-Invalid replacement withdraws A's Valid route"
    );
    assert_eq!(fib.v4_changes(), vec![BestPathChange::Withdrawn(n4())]);
    assert!(withdraws_v4(&sent_to(&mut state, &mut receivers, PEER_B)));

    rtr.insert_roa_v4(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 65099);
    state.reevaluate_all_import_policies();

    assert_eq!(
        as_path_of(state.rib.loc_rib.best(&n4())),
        Some(AsPath::from_sequence(vec![Asn::new(AS_A), Asn::new(65099)])),
        "re-evaluation must judge the replacement, not the superseded route"
    );
}

/// IPv6 counterpart.
#[test]
fn rov_invalid_replacement_withdraws_and_reevaluates_replacement_v6() {
    let (mut state, mut receivers) = established();
    let prefix: Ipv6Addr = "2001:db8:1::".parse().unwrap();
    let rtr = pathvector_rpki::for_testing([], [(prefix, 48, 48, AS_A)]);
    state.install_rpki_import_terms(&rtr);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &[]));
    assert!(state.rib.loc_rib_v6.best(&n6()).is_some());
    drain(&mut state, &mut receivers);
    fib.v6.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A, 65099], RESOLVABLE_V6, &[]));

    assert!(state.rib.loc_rib_v6.best(&n6()).is_none());
    assert_eq!(
        fib.v6.lock().unwrap().clone(),
        vec![BestPathChange::Withdrawn(n6())]
    );
    assert!(withdraws_v6(&sent_to(&mut state, &mut receivers, PEER_B)));

    rtr.insert_roa_v6(prefix, 48, 48, 65099);
    state.reevaluate_all_import_policies();

    assert_eq!(
        as_path_of(state.rib.loc_rib_v6.best(&n6())),
        Some(AsPath::from_sequence(vec![Asn::new(AS_A), Asn::new(65099)]))
    );
}

// ── RFC 9234 §5 OTC leak replacement ─────────────────────────────────────────

/// Installs the RFC 9234 ingress terms for "we are A's Provider", i.e. A is
/// our Customer: §5 rule 1, "If a route with the OTC Attribute is received
/// from a Customer … it is a route leak and MUST be considered ineligible".
fn a_is_customer(state: &mut DaemonState) {
    let ip = IpAddr::V4(PEER_A);
    install_otc_import_term(
        state.import_policies.get_mut(&ip).unwrap(),
        Role::Provider,
        Asn::new(AS_A),
    );
    install_otc_import_term(
        state.import_policies_v6.get_mut(&ip).unwrap(),
        Role::Provider,
        Asn::new(AS_A),
    );
}

/// IPv4: a Customer's route is accepted, then replaced by the same route
/// carrying OTC — a leak, ineligible per RFC 9234 §5 — so the old route must
/// be withdrawn rather than stay selected and advertised.
#[test]
fn otc_leak_replacement_withdraws_old_route_v4() {
    let (mut state, mut receivers) = established();
    a_is_customer(&mut state);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4, &[]));
    assert!(state.rib.loc_rib.best(&n4()).is_some());
    assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
    fib.v4.lock().unwrap().clear();

    state.on_route_update(
        IpAddr::V4(PEER_A),
        v4(
            &[AS_A],
            RESOLVABLE_V4,
            &[PathAttribute::OnlyToCustomer(Asn::new(65077))],
        ),
    );

    assert!(state.rib.loc_rib.best(&n4()).is_none());
    assert_eq!(fib.v4_changes(), vec![BestPathChange::Withdrawn(n4())]);
    assert!(withdraws_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
}

/// IPv6 counterpart.
#[test]
fn otc_leak_replacement_withdraws_old_route_v6() {
    let (mut state, mut receivers) = established();
    a_is_customer(&mut state);
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6, &[]));
    assert!(state.rib.loc_rib_v6.best(&n6()).is_some());
    drain(&mut state, &mut receivers);
    fib.v6.lock().unwrap().clear();

    state.on_route_update(
        IpAddr::V4(PEER_A),
        v6(
            &[AS_A],
            RESOLVABLE_V6,
            &[PathAttribute::OnlyToCustomer(Asn::new(65077))],
        ),
    );

    assert!(state.rib.loc_rib_v6.best(&n6()).is_none());
    assert_eq!(
        fib.v6.lock().unwrap().clone(),
        vec![BestPathChange::Withdrawn(n6())]
    );
    assert!(withdraws_v6(&sent_to(&mut state, &mut receivers, PEER_B)));
}

// ── Model property test ──────────────────────────────────────────────────────

/// One step of the model test: `peer` sends `prefix` (of `family`) either a
/// withdrawal or an announcement that import policy rejects iff `rejected`.
#[derive(Clone, Debug)]
struct Step {
    peer: usize,
    prefix: usize,
    v6: bool,
    kind: Kind,
}

#[derive(Clone, Debug)]
enum Kind {
    Announce { rejected: bool, path_len: usize },
    Withdraw,
}

fn step() -> impl Strategy<Value = Step> {
    let kind = prop_oneof![
        3 => (any::<bool>(), 1usize..4)
            .prop_map(|(rejected, path_len)| Kind::Announce { rejected, path_len }),
        1 => Just(Kind::Withdraw),
    ];
    (0usize..3, 0usize..3, any::<bool>(), kind).prop_map(|(peer, prefix, v6, kind)| Step {
        peer,
        prefix,
        v6,
        kind,
    })
}

const MODEL_LOCAL_AS: u32 = 64512;

fn model_peer(i: usize) -> PeerId {
    PeerId::from(IpAddr::V4(Ipv4Addr::new(
        10,
        1,
        0,
        u8::try_from(i).unwrap() + 1,
    )))
}

fn model_v4(i: usize) -> Nlri<Ipv4Addr> {
    Nlri::new(Ipv4Addr::new(203, 0, u8::try_from(i).unwrap(), 0), 24).unwrap()
}

fn model_v6(i: usize) -> Nlri<Ipv6Addr> {
    Nlri::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0x10, u16::try_from(i).unwrap(), 0, 0, 0, 0),
        64,
    )
    .unwrap()
}

/// Builds the UPDATE for `s`. The MED carries `seq`, so every advertisement is
/// distinguishable and the test can tell the latest from a superseded one.
fn model_update(s: &Step, seq: u32) -> UpdateMessage {
    let Kind::Announce { rejected, path_len } = s.kind else {
        return if s.v6 {
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    prefixes: vec![Prefix::V6(model_v6(s.prefix))],
                })],
                announced: vec![],
            }
        } else {
            UpdateMessage {
                withdrawn: vec![model_v4(s.prefix)],
                attributes: vec![],
                announced: vec![],
            }
        };
    };
    let first_as = 65100 + u32::try_from(s.peer).unwrap();
    let asns: Vec<u32> = std::iter::once(first_as)
        .chain((1..path_len).map(|k| 65200 + u32::try_from(k).unwrap()))
        .collect();
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        path(&asns),
        PathAttribute::Med(seq),
    ];
    if rejected {
        attributes.push(PathAttribute::Communities(vec![REJECT_TAG]));
    }
    if s.v6 {
        attributes.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
            prefixes: vec![Prefix::V6(model_v6(s.prefix))],
        }));
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![],
        }
    } else {
        attributes.push(PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)));
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![model_v4(s.prefix)],
        }
    }
}

/// `(v6, prefix) → peer → MED (sequence number)`.
type Model = HashMap<(bool, usize), HashMap<usize, u32>>;

fn med_of<A: pathvector_types::IpAddress>(r: &Route<A>) -> u32 {
    r.med.map(pathvector_types::Med::as_u32).unwrap()
}

/// Checks one prefix of the real RIBs against both models.
#[allow(clippy::too_many_arguments)]
fn check_prefix<A: pathvector_types::IpAddress>(
    nlri: &Nlri<A>,
    key: (bool, usize),
    loc_rib: &LocRib<A>,
    adj: &[AdjRibIn<A>],
    accepted: &Model,
    latest: &Model,
) -> Result<(), TestCaseError> {
    let want: HashMap<PeerId, u32> = accepted
        .get(&key)
        .map(|m| m.iter().map(|(&p, &seq)| (model_peer(p), seq)).collect())
        .unwrap_or_default();
    let got: HashMap<PeerId, u32> = loc_rib
        .candidates(nlri)
        .map(|c| c.into_iter().map(|(p, r)| (p, med_of(r))).collect())
        .unwrap_or_default();
    prop_assert_eq!(
        &got,
        &want,
        "Loc-RIB candidates for {} must be the latest accepted advertisement per peer",
        nlri
    );
    prop_assert_eq!(
        loc_rib.best(nlri).is_some(),
        !want.is_empty(),
        "with every next hop reachable, a best route exists iff a candidate does"
    );
    for (i, adj_rib_in) in adj.iter().enumerate() {
        let want_raw = latest.get(&key).and_then(|m| m.get(&i)).copied();
        prop_assert_eq!(
            adj_rib_in.get(nlri).map(med_of),
            want_raw,
            "Adj-RIB-In of peer {} for {} must hold its latest advertisement, accepted or not",
            i,
            nlri
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Model test for issue #80, over both families and three peers × three
    /// prefixes. After every UPDATE, for every prefix:
    ///
    /// 1. Loc-RIB candidates == the latest advertisement of each peer whose
    ///    latest advertisement passed import policy (RFC 4271 §9 implicit
    ///    withdrawal + §9.1.1 ineligibility), identified by MED = sequence
    ///    number so a superseded route can never pass for the latest one;
    /// 2. a best route exists iff such a candidate exists (§9.1.2);
    /// 3. each peer's Adj-RIB-In holds its latest advertisement whether or
    ///    not policy accepted it (§9; kept for soft reconfiguration).
    ///
    /// Finally, re-running import policy over every Adj-RIB-In
    /// (`reapply_import_policy{,_v6}`) must leave the Loc-RIB unchanged:
    /// initial import and re-evaluation must agree.
    #[test]
    fn prop_loc_rib_candidates_are_latest_accepted_advertisement_per_peer(
        steps in prop::collection::vec(step(), 1..48)
    ) {
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        policy.add_term(Term::new(CommunityCondition::new(REJECT_TAG), Reject));
        let mut policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
        policy_v6.add_term(Term::new(CommunityCondition::new(REJECT_TAG), Reject));

        let mut loc_rib: LocRib<Ipv4Addr> = LocRib::new();
        let mut loc_rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut adj: Vec<AdjRibIn<Ipv4Addr>> = (0..3).map(|i| AdjRibIn::new(model_peer(i))).collect();
        let mut adj_v6: Vec<AdjRibIn<Ipv6Addr>> =
            (0..3).map(|i| AdjRibIn::new(model_peer(i))).collect();
        let mut accepted: Model = HashMap::new();
        let mut latest: Model = HashMap::new();

        for (seq, s) in steps.iter().enumerate() {
            let seq = u32::try_from(seq).unwrap();
            let key = (s.v6, s.prefix);
            match s.kind {
                Kind::Announce { rejected, .. } => {
                    latest.entry(key).or_default().insert(s.peer, seq);
                    if rejected {
                        accepted.entry(key).or_default().remove(&s.peer);
                    } else {
                        accepted.entry(key).or_default().insert(s.peer, seq);
                    }
                }
                Kind::Withdraw => {
                    latest.entry(key).or_default().remove(&s.peer);
                    accepted.entry(key).or_default().remove(&s.peer);
                }
            }

            let result = handle_update(
                model_peer(s.peer),
                model_update(s, seq),
                &mut adj[s.peer],
                &mut loc_rib,
                &mut adj_v6[s.peer],
                &mut loc_rib_v6,
                &policy,
                &policy_v6,
                PeerType::External,
                None,
                &AlwaysReachable,
                &AlwaysReachable,
                MODEL_LOCAL_AS,
                None,
                None,
                None,
            );
            prop_assert!(result.notification.is_none());

            for p in 0..3 {
                check_prefix(&model_v4(p), (false, p), &loc_rib, &adj, &accepted, &latest)?;
                check_prefix(&model_v6(p), (true, p), &loc_rib_v6, &adj_v6, &accepted, &latest)?;
            }
        }

        let before: Vec<_> = loc_rib.best_routes().map(|(n, r)| (n, r.clone())).collect();
        let before_v6: Vec<_> = loc_rib_v6.best_routes().map(|(n, r)| (n, r.clone())).collect();
        for i in 0..3 {
            let _ = reapply_import_policy(model_peer(i), &adj[i], &mut loc_rib, &policy, &AlwaysReachable);
            let _ = reapply_import_policy(
                model_peer(i), &adj_v6[i], &mut loc_rib_v6, &policy_v6, &AlwaysReachable,
            );
        }
        for p in 0..3 {
            check_prefix(&model_v4(p), (false, p), &loc_rib, &adj, &accepted, &latest)?;
            check_prefix(&model_v6(p), (true, p), &loc_rib_v6, &adj_v6, &accepted, &latest)?;
        }
        let mut after: Vec<_> = loc_rib.best_routes().map(|(n, r)| (n, r.clone())).collect();
        let mut after_v6: Vec<_> = loc_rib_v6.best_routes().map(|(n, r)| (n, r.clone())).collect();
        let mut before = before;
        let mut before_v6 = before_v6;
        before.sort_by_key(|(n, _)| *n);
        after.sort_by_key(|(n, _)| *n);
        before_v6.sort_by_key(|(n, _)| *n);
        after_v6.sort_by_key(|(n, _)| *n);
        prop_assert_eq!(after, before, "re-evaluation must agree with initial import");
        prop_assert_eq!(after_v6, before_v6);
    }
}
