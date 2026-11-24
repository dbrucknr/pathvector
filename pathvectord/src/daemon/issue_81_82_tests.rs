// daemon/issue_81_82_tests.rs — regression tests for the four defects reported
// in issues #81 (BLACKHOLE authorization) and #82 (import eligibility and
// transformations through Graceful Restart).
//
// Every test here uses only the daemon's pre-existing public-to-the-crate
// surface (`on_route_update`, `on_terminated`, `set_import_default`, a
// recording FIB) and **no** BLACKHOLE-agreement configuration, so the file
// compiles and runs unchanged against the pre-fix tree. The branch history
// records which of these failed there:
//
//   #81-1  BLACKHOLE + import default Reject programs a null route
//   #81-2  BLACKHOLE under Accept is imported as unicast by re-evaluation
//   #82-b  a stored BLACKHOLE route enters the Loc-RIB as unicast at GR stale
//          marking
//
// The two #82 defects as originally reported — a policy-rejected route
// entering the Loc-RIB, and LOCAL_PREF lost, at stale marking — had already
// been fixed on main by #139/#140 (stale marking re-judges routes through
// `ImportDecision`); the tests for them are kept as the regression pins the
// issue asked for, and now go through the same pipeline as everything else.
//
// The RFC clauses each test proves:
//
// * RFC 7999 §3.3: "BGP speakers in a bilateral peering relationship using the
//   BLACKHOLE community MUST only accept and honor BGP announcements carrying
//   the BLACKHOLE community under the two following conditions: [prefix
//   authorized] [and] the receiving party agreed to honor the BLACKHOLE
//   community on the particular BGP session." With no such agreement
//   configured here, nothing is honored.
// * RFC 4724 §4.2: the Receiving Speaker "MUST retain the routes received from
//   the peer [...] and MUST mark them as stale routing information"; retention
//   is not eligibility (RFC 4271 §9.1.1–§9.1.2).
// * RFC 9234 §5: a route leaked from a Customer "MUST be considered
//   ineligible"; ingress OTC attachment must survive.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pathvector_policy::{Accept, ActionSequence, AnyCondition, DefaultAction, SetLocalPref, Term};
use pathvector_rib::Staleness;
use pathvector_session::message::{
    Capability, GracefulRestartFamily, MpReachNlri, MpUnreachNlri, PathAttribute, Prefix,
    UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{
    AfiSafi, AsPath, Asn, Community, LocalPref, NextHop, Nlri, Origin, PeerType, Role,
};

use super::DaemonState;
use super::last_feasible_tests::{
    AS_A, AS_B, AS_C, LOCAL_AS, PEER_A, PEER_B, PEER_C, RESOLVABLE_V4, RESOLVABLE_V6, Receivers,
    drain, sent_to,
};
use crate::daemon::tests::{RecordingFib, make_state, with_recording_fib};

/// Shared fixtures, reused by `blackhole_tests`.
pub(super) mod support {
    use super::*;
    use std::sync::Arc;

    pub(crate) fn p4(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    pub(crate) fn p6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    pub(crate) fn a() -> IpAddr {
        IpAddr::V4(PEER_A)
    }
    pub(crate) fn b() -> IpAddr {
        IpAddr::V4(PEER_B)
    }
    pub(crate) fn c() -> IpAddr {
        IpAddr::V4(PEER_C)
    }

    /// Peers A, B and C established over eBGP with IPv4 + IPv6 unicast, every
    /// import/export default Accept (`make_state`), and a recording FIB.
    /// A advertises Graceful Restart (restart time 120 s, forwarding preserved)
    /// for both families, so an unclean drop of A enters the GR window.
    pub(crate) fn established_gr() -> (DaemonState, Receivers, Arc<RecordingFib>) {
        let (mut state, mut receivers) =
            make_state(LOCAL_AS, &[(a(), AS_A), (b(), AS_B), (c(), AS_C)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let fib = with_recording_fib(&mut state);
        let mp = [
            Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        ];
        let mut a_caps = mp.to_vec();
        a_caps.push(Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: [AfiSafi::IPV4_UNICAST, AfiSafi::IPV6_UNICAST]
                .into_iter()
                .map(|afi_safi| GracefulRestartFamily {
                    afi_safi,
                    forwarding_preserved: true,
                })
                .collect(),
        });
        state.on_established(a(), PEER_A, PeerType::External, AS_A, 90, &a_caps, None);
        for (ip, asn) in [(PEER_B, AS_B), (PEER_C, AS_C)] {
            state.on_established(IpAddr::V4(ip), ip, PeerType::External, asn, 90, &mp, None);
        }
        drain(&mut state, &mut receivers);
        (state, receivers, fib)
    }

    /// Re-establishes A after an unclean drop, advertising the same GR
    /// capability (RFC 4724 §4.2 re-establishment).
    pub(crate) fn reestablish_a(state: &mut DaemonState) {
        let mut caps = vec![
            Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        ];
        caps.push(Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: [AfiSafi::IPV4_UNICAST, AfiSafi::IPV6_UNICAST]
                .into_iter()
                .map(|afi_safi| GracefulRestartFamily {
                    afi_safi,
                    forwarding_preserved: true,
                })
                .collect(),
        });
        state.on_established(a(), PEER_A, PeerType::External, AS_A, 90, &caps, None);
    }

    pub(crate) fn drop_a(state: &mut DaemonState) {
        state.on_terminated(a(), TerminationReason::Unclean, false);
    }

    fn path(asn: u32) -> PathAttribute {
        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(asn)]))
    }

    /// An IPv4 announcement of `prefix` from peer A.
    pub(crate) fn v4_update(prefix: &str, communities: &[Community]) -> UpdateMessage {
        let mut attributes = vec![
            PathAttribute::Origin(Origin::Igp),
            path(AS_A),
            PathAttribute::NextHop(RESOLVABLE_V4),
        ];
        if !communities.is_empty() {
            attributes.push(PathAttribute::Communities(communities.to_vec()));
        }
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![p4(prefix)],
        }
    }

    /// An IPv6 announcement of `prefix` from peer A (MP_REACH_NLRI).
    pub(crate) fn v6_update(prefix: &str, communities: &[Community]) -> UpdateMessage {
        let mut attributes = vec![
            PathAttribute::Origin(Origin::Igp),
            path(AS_A),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(RESOLVABLE_V6),
                prefixes: vec![Prefix::V6(p6(prefix))],
            }),
        ];
        if !communities.is_empty() {
            attributes.push(PathAttribute::Communities(communities.to_vec()));
        }
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![],
        }
    }

    pub(crate) fn v4_withdraw(prefix: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![p4(prefix)],
            attributes: vec![],
            announced: vec![],
        }
    }

    pub(crate) fn v6_withdraw(prefix: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![Prefix::V6(p6(prefix))],
            })],
            announced: vec![],
        }
    }

    /// RFC 4724 §2: the IPv4 End-of-RIB marker.
    pub(crate) fn eor_v4() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        }
    }

    /// RFC 4724 §2: the IPv6 unicast End-of-RIB marker.
    pub(crate) fn eor_v6() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![],
            })],
            announced: vec![],
        }
    }

    /// Recorded IPv4 null-route calls: `(prefix, installed)`.
    pub(crate) fn bh4(fib: &RecordingFib) -> Vec<(Nlri<Ipv4Addr>, bool)> {
        fib.blackhole_v4.lock().unwrap().clone()
    }

    /// Recorded IPv6 null-route calls: `(prefix, installed)`.
    pub(crate) fn bh6(fib: &RecordingFib) -> Vec<(Nlri<Ipv6Addr>, bool)> {
        fib.blackhole_v6.lock().unwrap().clone()
    }

    /// `true` when `msgs` announce `prefix` (IPv4, classic NLRI field).
    pub(crate) fn announces4(msgs: &[UpdateMessage], prefix: &str) -> bool {
        let n = p4(prefix);
        msgs.iter().any(|m| m.announced.contains(&n))
    }

    /// `true` when `msgs` announce `prefix` (IPv6, MP_REACH_NLRI).
    pub(crate) fn announces6(msgs: &[UpdateMessage], prefix: &str) -> bool {
        let n = p6(prefix);
        msgs.iter().any(|m| {
            m.attributes.iter().any(|a| {
                matches!(a, PathAttribute::MpReachNlri(mp)
                    if mp.prefixes.contains(&Prefix::V6(n)))
            })
        })
    }
}

use support::*;

/// A prefix for ordinary unicast, and host prefixes for blackhole requests.
const UNICAST_V4: &str = "10.0.0.0/8";
const UNICAST_V6: &str = "2001:db8:1::/48";
const HOST_V4: &str = "192.0.2.77/32";
const HOST_V6: &str = "2001:db8:ffff::77/128";

// ── #81 ──────────────────────────────────────────────────────────────────────

/// Issue #81, reproduction 1. RFC 7999 §3.3: a BLACKHOLE announcement may be
/// honored only if the session agreed to it; no agreement exists here, and the
/// peer's import default is Reject. "Presence of the community" must not be
/// "sufficient authorization to affect forwarding": no null route, no Loc-RIB
/// entry, no unicast export — for IPv4 and IPv6.
#[test]
fn reject_default_blackhole_announcement_has_no_fib_effect() {
    let (mut state, mut receivers, fib) = established_gr();
    state.set_import_default(a(), DefaultAction::Reject);
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), v4_update(HOST_V4, &[Community::BLACKHOLE]));
    state.on_route_update(a(), v6_update(HOST_V6, &[Community::BLACKHOLE]));

    assert!(
        bh4(&fib).is_empty(),
        "IPv4 null route programmed: {:?}",
        bh4(&fib)
    );
    assert!(
        bh6(&fib).is_empty(),
        "IPv6 null route programmed: {:?}",
        bh6(&fib)
    );
    assert!(state.rib.loc_rib.best(&p4(HOST_V4)).is_none());
    assert!(state.rib.loc_rib_v6.best(&p6(HOST_V6)).is_none());
    assert!(
        !announces4(&sent_to(&mut state, &mut receivers, PEER_B), HOST_V4),
        "a blackhole must never be exported as unicast"
    );
}

/// Issue #81, reproduction 2. Under Accept, a BLACKHOLE route is absent from
/// the Loc-RIB; re-evaluating the import policy (`set_import_default(Accept)`)
/// must not import the stored raw route as an ordinary unicast candidate, and
/// must not export it.
#[test]
fn reevaluation_never_imports_a_blackhole_route_as_unicast() {
    let (mut state, mut receivers, fib) = established_gr();
    state.on_route_update(a(), v4_update(HOST_V4, &[Community::BLACKHOLE]));
    state.on_route_update(a(), v6_update(HOST_V6, &[Community::BLACKHOLE]));
    assert!(
        state.rib.loc_rib.best(&p4(HOST_V4)).is_none(),
        "precondition"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(HOST_V6)).is_none(),
        "precondition"
    );
    drain(&mut state, &mut receivers);

    state.set_import_default(a(), DefaultAction::Accept);
    state.reevaluate_all_import_policies();

    assert!(
        state.rib.loc_rib.best(&p4(HOST_V4)).is_none(),
        "re-evaluation imported a BLACKHOLE route as unicast (IPv4)"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(HOST_V6)).is_none(),
        "re-evaluation imported a BLACKHOLE route as unicast (IPv6)"
    );
    assert!(
        !announces4(&sent_to(&mut state, &mut receivers, PEER_B), HOST_V4),
        "a blackhole must never be exported as unicast"
    );
    assert!(
        fib.v4_changes().iter().all(
            |c| !matches!(c, pathvector_rib::BestPathChange::Announced(n, _) if *n == p4(HOST_V4))
        ),
        "the unicast forwarding route must not be programmed for a blackhole prefix"
    );
}

// ── #82 ──────────────────────────────────────────────────────────────────────

/// Issue #82, reproduction 1 (pinned; already fixed on main by #139/#140).
/// RFC 4724 §4.2 retains and stale-marks routes; "retained" does not make a
/// policy-rejected route eligible (RFC 4271 §9.1.1). With import default
/// Reject, the route is never in the Loc-RIB — not before, and not after the
/// peer drops and the routes are stale-marked.
#[test]
fn graceful_restart_does_not_admit_a_policy_rejected_route() {
    let (mut state, mut receivers, fib) = established_gr();
    state.set_import_default(a(), DefaultAction::Reject);
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), v4_update(UNICAST_V4, &[]));
    state.on_route_update(a(), v6_update(UNICAST_V6, &[]));
    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none(),
        "precondition"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(UNICAST_V6)).is_none(),
        "precondition"
    );

    drop_a(&mut state);

    assert!(
        state.gr.deadlines.contains_key(&a()),
        "entered the GR window"
    );
    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none(),
        "stale marking admitted a rejected IPv4 route"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(UNICAST_V6)).is_none(),
        "stale marking admitted a rejected IPv6 route"
    );
    assert!(
        fib.v4_changes()
            .iter()
            .all(|c| !matches!(c, pathvector_rib::BestPathChange::Announced(..))),
        "a rejected route was programmed into the FIB"
    );
    assert!(
        fib.v6
            .lock()
            .unwrap()
            .iter()
            .all(|c| !matches!(c, pathvector_rib::BestPathChange::Announced(..))),
        "a rejected IPv6 route was programmed into the FIB"
    );
    assert!(!announces4(
        &sent_to(&mut state, &mut receivers, PEER_B),
        UNICAST_V4
    ));
}

/// Issue #82, reproduction 2 (pinned; already fixed on main). A policy term
/// sets LOCAL_PREF 300; the post-policy route in the Loc-RIB carries it, and
/// stale marking must keep it (RFC 4271 §9.1.1: Phase 1 output is the
/// post-policy degree of preference) — and the route is marked stale
/// (RFC 4724 §4.2) without a preference change (RFC 9494 §1).
#[test]
fn graceful_restart_preserves_local_pref_set_by_import_policy() {
    let (mut state, mut receivers, _fib) = established_gr();
    state
        .import_policies
        .get_mut(&a())
        .unwrap()
        .add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LocalPref::new(300)))
                .then(Accept),
        ));
    state
        .import_policies_v6
        .get_mut(&a())
        .unwrap()
        .add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LocalPref::new(300)))
                .then(Accept),
        ));

    state.on_route_update(a(), v4_update(UNICAST_V4, &[]));
    state.on_route_update(a(), v6_update(UNICAST_V6, &[]));
    assert_eq!(
        state
            .rib
            .loc_rib
            .best(&p4(UNICAST_V4))
            .and_then(|r| r.local_pref),
        Some(LocalPref::new(300)),
        "precondition: policy applied on arrival"
    );
    drain(&mut state, &mut receivers);

    drop_a(&mut state);

    let v4 = state.rib.loc_rib.best(&p4(UNICAST_V4)).expect("retained");
    assert_eq!(
        v4.local_pref,
        Some(LocalPref::new(300)),
        "IPv4 LOCAL_PREF lost"
    );
    assert_eq!(v4.staleness, Staleness::GrStale);
    let v6 = state
        .rib
        .loc_rib_v6
        .best(&p6(UNICAST_V6))
        .expect("retained");
    assert_eq!(
        v6.local_pref,
        Some(LocalPref::new(300)),
        "IPv6 LOCAL_PREF lost"
    );
    assert_eq!(v6.staleness, Staleness::GrStale);
}

/// Issue #82, the BLACKHOLE half: a BLACKHOLE route in the Adj-RIB-In must not
/// enter the Loc-RIB as unicast when stale marking re-imports the peer's
/// routes (default import is Accept here, so the raw route *would* pass
/// ordinary policy).
#[test]
fn graceful_restart_never_turns_a_blackhole_route_into_unicast() {
    let (mut state, mut receivers, _fib) = established_gr();
    state.on_route_update(a(), v4_update(HOST_V4, &[Community::BLACKHOLE]));
    state.on_route_update(a(), v6_update(HOST_V6, &[Community::BLACKHOLE]));
    drain(&mut state, &mut receivers);

    drop_a(&mut state);

    assert!(
        state.rib.loc_rib.best(&p4(HOST_V4)).is_none(),
        "stale marking imported a BLACKHOLE route as IPv4 unicast"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(HOST_V6)).is_none(),
        "stale marking imported a BLACKHOLE route as IPv6 unicast"
    );
    assert!(!announces4(
        &sent_to(&mut state, &mut receivers, PEER_B),
        HOST_V4
    ));
}

/// RFC 9234 §5: "If a route with the OTC Attribute is received from a Customer
/// or an RS-Client, then it is a route leak and MUST be considered
/// ineligible." Stale marking must not make the leaked route eligible, and
/// must keep the OTC the ingress term attached to a legitimate one.
#[test]
fn graceful_restart_keeps_otc_leak_rejection_and_ingress_otc_attachment() {
    // Peer A is our Customer (we are its Provider): leak detection applies.
    let (mut state, mut receivers, _fib) = established_gr();
    super::install_otc_import_term(
        state.import_policies.get_mut(&a()).unwrap(),
        Role::Provider,
        Asn::new(AS_A),
    );
    super::install_otc_import_term(
        state.import_policies_v6.get_mut(&a()).unwrap(),
        Role::Provider,
        Asn::new(AS_A),
    );
    let mut leaked = v4_update(UNICAST_V4, &[]);
    leaked
        .attributes
        .push(PathAttribute::OnlyToCustomer(Asn::new(64999)));
    state.on_route_update(a(), leaked);
    let mut leaked6 = v6_update(UNICAST_V6, &[]);
    leaked6
        .attributes
        .push(PathAttribute::OnlyToCustomer(Asn::new(64999)));
    state.on_route_update(a(), leaked6);
    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none(),
        "precondition"
    );
    drain(&mut state, &mut receivers);

    drop_a(&mut state);

    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none(),
        "stale marking admitted an OTC route leak (IPv4)"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(UNICAST_V6)).is_none(),
        "stale marking admitted an OTC route leak (IPv6)"
    );

    // Peer B is our Provider (we are its Customer): the ingress term attaches
    // OTC = B's ASN, and that must survive stale marking.
    let (mut state, mut receivers, _fib) = established_gr();
    super::install_otc_import_term(
        state.import_policies.get_mut(&a()).unwrap(),
        Role::Customer,
        Asn::new(AS_A),
    );
    super::install_otc_import_term(
        state.import_policies_v6.get_mut(&a()).unwrap(),
        Role::Customer,
        Asn::new(AS_A),
    );
    state.on_route_update(a(), v4_update(UNICAST_V4, &[]));
    state.on_route_update(a(), v6_update(UNICAST_V6, &[]));
    assert_eq!(
        state
            .rib
            .loc_rib
            .best(&p4(UNICAST_V4))
            .and_then(|r| r.rare_or_default().otc),
        Some(Asn::new(AS_A)),
        "precondition: ingress OTC attached"
    );
    drain(&mut state, &mut receivers);

    drop_a(&mut state);

    assert_eq!(
        state
            .rib
            .loc_rib
            .best(&p4(UNICAST_V4))
            .and_then(|r| r.rare_or_default().otc),
        Some(Asn::new(AS_A)),
        "IPv4 ingress OTC lost across stale marking"
    );
    assert_eq!(
        state
            .rib
            .loc_rib_v6
            .best(&p6(UNICAST_V6))
            .and_then(|r| r.rare_or_default().otc),
        Some(Asn::new(AS_A)),
        "IPv6 ingress OTC lost across stale marking"
    );
}

/// RFC 6811 ROV rejection (an import-policy term) is not bypassed by stale
/// marking: an Invalid route stays out of the Loc-RIB through the GR window.
#[test]
fn graceful_restart_keeps_rov_rejection() {
    let (mut state, mut receivers, _fib) = established_gr();
    // ROAs authorize a different origin AS for both prefixes: A's routes are
    // Invalid (RFC 6811 §2).
    let rtr = pathvector_rpki::for_testing(
        [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99_999)],
        [(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
            48,
            48,
            99_999,
        )],
    );
    state.install_rpki_import_terms(&rtr);
    state.on_route_update(a(), v4_update(UNICAST_V4, &[]));
    state.on_route_update(a(), v6_update(UNICAST_V6, &[]));
    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none(),
        "precondition"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(UNICAST_V6)).is_none(),
        "precondition"
    );
    drain(&mut state, &mut receivers);

    drop_a(&mut state);

    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none(),
        "stale marking admitted an RPKI-Invalid IPv4 route"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(UNICAST_V6)).is_none(),
        "stale marking admitted an RPKI-Invalid IPv6 route"
    );
}

/// An accepted, policy-transformed route is retained through the whole GR
/// lifecycle and then swept: marked stale at the drop (RFC 4724 §4.2), kept
/// while the window is open, replaced when the peer re-announces, and any
/// route not refreshed is removed at End-of-RIB — "it MUST immediately remove
/// any routes from the peer that are still marked as stale for that address
/// family". Both families.
#[test]
fn graceful_restart_lifecycle_retains_refreshes_and_sweeps() {
    let (mut state, mut receivers, _fib) = established_gr();
    let (kept4, gone4) = ("10.1.0.0/16", "10.2.0.0/16");
    let (kept6, gone6) = ("2001:db8:11::/48", "2001:db8:22::/48");
    for prefix in [kept4, gone4] {
        state.on_route_update(a(), v4_update(prefix, &[]));
    }
    for prefix in [kept6, gone6] {
        state.on_route_update(a(), v6_update(prefix, &[]));
    }
    drain(&mut state, &mut receivers);

    // Drop: every route is retained, stale, and still exported to B.
    drop_a(&mut state);
    for prefix in [kept4, gone4] {
        let r = state.rib.loc_rib.best(&p4(prefix)).expect("retained (v4)");
        assert_eq!(r.staleness, Staleness::GrStale, "{prefix}");
    }
    for prefix in [kept6, gone6] {
        let r = state
            .rib
            .loc_rib_v6
            .best(&p6(prefix))
            .expect("retained (v6)");
        assert_eq!(r.staleness, Staleness::GrStale, "{prefix}");
    }

    // Re-establish; the peer refreshes one prefix per family, then sends EOR.
    reestablish_a(&mut state);
    state.on_route_update(a(), v4_update(kept4, &[]));
    state.on_route_update(a(), v6_update(kept6, &[]));
    assert_eq!(
        state.rib.loc_rib.best(&p4(kept4)).map(|r| r.staleness),
        Some(Staleness::Fresh),
        "the refreshed route replaces the stale one"
    );
    assert!(
        state.rib.loc_rib.best(&p4(gone4)).is_some(),
        "stale until EOR"
    );
    drain(&mut state, &mut receivers);

    state.on_route_update(a(), eor_v4());
    state.on_route_update(a(), eor_v6());

    assert!(state.rib.loc_rib.best(&p4(kept4)).is_some());
    assert!(state.rib.loc_rib_v6.best(&p6(kept6)).is_some());
    assert!(
        state.rib.loc_rib.best(&p4(gone4)).is_none(),
        "IPv4 route not refreshed before EOR must be swept"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(gone6)).is_none(),
        "IPv6 route not refreshed before EOR must be swept"
    );
    // The withdrawal reaches B.
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        to_b.iter().any(|m| m.withdrawn.contains(&p4(gone4))),
        "B was not told the swept IPv4 route is gone: {to_b:?}"
    );
}

/// RFC 4724 §4.2: "If the session does not get re-established within the
/// 'Restart Time' [...] the Receiving Speaker MUST delete all the stale routes
/// from the peer that it is retaining."
#[test]
fn graceful_restart_deadline_expiry_deletes_retained_routes() {
    let (mut state, mut receivers, _fib) = established_gr();
    state.on_route_update(a(), v4_update(UNICAST_V4, &[]));
    state.on_route_update(a(), v6_update(UNICAST_V6, &[]));
    drain(&mut state, &mut receivers);
    drop_a(&mut state);
    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_some(),
        "precondition"
    );

    state.on_gr_deadline_expired(a());

    assert!(state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none());
    assert!(state.rib.loc_rib_v6.best(&p6(UNICAST_V6)).is_none());
}

/// RFC 4724 §4.2: the Receiving Speaker retains routes only "for all the
/// address families that were previously received in the Graceful Restart
/// Capability". A family the peer did not list is flushed like any other
/// unclean loss — Adj-RIB-In *and* Loc-RIB — while the listed family is kept.
#[test]
fn graceful_restart_flushes_families_the_peer_did_not_advertise() {
    let (mut state, mut receivers) = make_state(LOCAL_AS, &[(a(), AS_A), (b(), AS_B)]);
    let mp = [
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    let mut a_caps = mp.to_vec();
    a_caps.push(Capability::GracefulRestart {
        restart_flags: 0,
        restart_time: 120,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV6_UNICAST, // IPv4 is NOT listed
            forwarding_preserved: true,
        }],
    });
    state.on_established(a(), PEER_A, PeerType::External, AS_A, 90, &a_caps, None);
    state.on_established(b(), PEER_B, PeerType::External, AS_B, 90, &mp, None);
    drain(&mut state, &mut receivers);
    state.on_route_update(a(), v4_update(UNICAST_V4, &[]));
    state.on_route_update(a(), v6_update(UNICAST_V6, &[]));
    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_some(),
        "precondition"
    );
    drain(&mut state, &mut receivers);

    drop_a(&mut state);

    assert!(
        state.gr.deadlines.contains_key(&a()),
        "precondition: GR window open"
    );
    assert!(
        state.rib.loc_rib_v6.best(&p6(UNICAST_V6)).is_some(),
        "the advertised family is retained"
    );
    assert!(
        state.rib.loc_rib.best(&p4(UNICAST_V4)).is_none(),
        "the family not covered by the GR capability must be flushed from the Loc-RIB"
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        to_b.iter().any(|m| m.withdrawn.contains(&p4(UNICAST_V4))),
        "B must be told the flushed IPv4 route is gone: {to_b:?}"
    );
}
