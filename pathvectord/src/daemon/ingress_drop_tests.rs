// daemon/ingress_drop_tests.rs — issue #138: an announcement dropped *before*
// import policy (AS_PATH loop, AS 0, invalid NEXT_HOP) must still withdraw the
// older route the same peer advertised for the same NLRI.
//
// RFC 4271 §9: "if the NLRI of the new route is identical to the one the route
// currently has stored in the Adj-RIB-In, then the new route SHALL replace the
// older route in the Adj-RIB-In, thus implicitly withdrawing the older route
// from service." / "Once the BGP speaker updates the Adj-RIB-In, the speaker
// SHALL run its Decision Process."
//
// AS loop — RFC 4271 §9.1.2: "If the AS_PATH attribute of a BGP route
// contains an AS loop, the BGP route should be excluded from the Phase 2
// decision function." RFC 5065 §4: "A BGP speaker receiving an AS_PATH
// attribute containing an autonomous system matching its own AS Confederation
// Identifier SHALL treat the path in the same fashion as if it had received a
// path containing its own AS number." The route is *ineligible*, not
// malformed, so it replaces the older route in the Adj-RIB-In (§9) and is not
// a Phase 2 input: the peer is left with no candidate.
//
// Syntactically incorrect NEXT_HOP — RFC 4271 §6.3: "Syntactic correctness
// means that the NEXT_HOP attribute represents a valid IP host address."
// RFC 7606 §3(e): "'Treat-as-withdraw' MUST be used for the cases that specify
// a session reset and involve any of the attributes ORIGIN, AS_PATH, NEXT_HOP,
// MULTI_EXIT_DISC, or LOCAL_PREF." RFC 7606 §2: the routes are handled "just
// as if they had been listed in the WITHDRAWN ROUTES field", "thus causing
// them to be removed from the Adj-RIB-In". The session stays up.
//
// AS 0 — RFC 7607 §2 delegates malformed handling to RFC 7606, so the same
// treat-as-withdraw applies.
//
// Semantically incorrect NEXT_HOP (the receiver's own address) — RFC 4271
// §6.3 (a): "It MUST NOT be the IP address of the receiving speaker." ... "the
// error SHOULD be logged, and the route SHOULD be ignored. In this case, a
// NOTIFICATION message SHOULD NOT be sent, and the connection SHOULD NOT be
// closed." No session reset is specified, so RFC 7606 §3(e) does not apply.
// "Ignored" is read as "not used", like an ineligible route: the route still
// supersedes the older one (§9), which must not stay in service.
//
// Each test asserts the Adj-RIB-In outcome its RFC reading requires: removed
// for treat-as-withdraw, holding the dropped replacement for an ineligible
// route.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use pathvector_policy::{DefaultAction, Policy};
use pathvector_rib::oracle::AlwaysReachable;
use pathvector_rib::{AdjRibIn, BestPathChange, LocRib, PeerId, Route};
use pathvector_session::message::{
    MpReachNlri, MpUnreachNlri, PathAttribute, Prefix, UpdateMessage,
};
use pathvector_types::{AfiSafi, AsPath, Asn, Community, NextHop, Nlri, Origin, PeerType};
use proptest::prelude::*;

use super::DaemonState;
use super::blackhole::BlackholeChange;
use super::ingress::IngressGate;
use super::last_feasible_tests::{
    AS_A, AS_C, LOCAL_AS, PEER_A, PEER_B, PEER_C, RESOLVABLE_V4, RESOLVABLE_V4_ALT, RESOLVABLE_V6,
    Receivers, announces_v4, announces_v6, drain, established, n4, n6, sent_to, withdraws_v4,
    withdraws_v6,
};
use super::route::handle_update;
use crate::daemon::tests::with_recording_fib;

/// Confederation Identifier of the local speaker in the confederation cases.
const CONFED_ID: u32 = 65100;
/// The address the daemon has toward PEER_A (RFC 4271 §6.3 (a)).
const OWN_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// `established()` configures this as the daemon's IPv6 address.
const OWN_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff);
const ALT_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 4);

/// A fault that gets an announcement dropped before import policy.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Local AS in AS_PATH (RFC 4271 §9.1.2). Ineligible.
    AsLoop,
    /// Confederation Identifier in AS_PATH (RFC 5065 §4). Ineligible.
    ConfedLoop,
    /// AS 0 in AS_PATH (RFC 7607). Treat-as-withdraw.
    AsZero,
    /// NEXT_HOP is not a valid host address (RFC 4271 §6.3). Treat-as-withdraw.
    BadNextHop(IpAddr),
    /// NEXT_HOP is the receiver's own address (RFC 4271 §6.3 (a)). Ineligible.
    OwnNextHop,
}

impl Fault {
    /// Whether the dropped replacement stays in the Adj-RIB-In (an ineligible
    /// route, RFC 4271 §9) rather than being removed (treat-as-withdraw,
    /// RFC 7606 §2).
    fn retained(self) -> bool {
        matches!(self, Self::AsLoop | Self::ConfedLoop | Self::OwnNextHop)
    }

    fn prepare(self, state: &mut DaemonState) {
        let rib = Arc::make_mut(&mut state.rib);
        rib.local_addrs
            .insert(IpAddr::V4(PEER_A), IpAddr::V4(OWN_V4));
        if matches!(self, Self::ConfedLoop) {
            rib.confederation_id = Some(CONFED_ID);
        }
    }

    fn asns(self) -> Vec<u32> {
        match self {
            Self::AsLoop => vec![AS_A, LOCAL_AS],
            Self::ConfedLoop => vec![AS_A, CONFED_ID],
            Self::AsZero => vec![AS_A, 0],
            Self::BadNextHop(_) | Self::OwnNextHop => vec![AS_A],
        }
    }

    fn next_hop_v4(self) -> Ipv4Addr {
        match self {
            Self::BadNextHop(IpAddr::V4(a)) => a,
            Self::OwnNextHop => OWN_V4,
            Self::BadNextHop(IpAddr::V6(_)) => panic!("IPv6 next hop on an IPv4 case"),
            _ => RESOLVABLE_V4,
        }
    }

    fn next_hop_v6(self) -> Ipv6Addr {
        match self {
            Self::BadNextHop(IpAddr::V6(a)) => a,
            Self::OwnNextHop => OWN_V6,
            Self::BadNextHop(IpAddr::V4(_)) => panic!("IPv4 next hop on an IPv6 case"),
            _ => RESOLVABLE_V6,
        }
    }

    /// The dropped IPv4 replacement for `n4()`.
    fn update_v4(self) -> UpdateMessage {
        v4(&self.asns(), self.next_hop_v4())
    }

    /// The dropped IPv6 replacement for `n6()`.
    fn update_v6(self) -> UpdateMessage {
        v6(&self.asns(), self.next_hop_v6())
    }
}

fn v4_faults() -> Vec<Fault> {
    vec![
        Fault::AsLoop,
        Fault::ConfedLoop,
        Fault::AsZero,
        Fault::BadNextHop(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Fault::BadNextHop(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Fault::BadNextHop(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 5))),
        Fault::BadNextHop(IpAddr::V4(Ipv4Addr::BROADCAST)),
        Fault::OwnNextHop,
    ]
}

fn v6_faults() -> Vec<Fault> {
    vec![
        Fault::AsLoop,
        Fault::ConfedLoop,
        Fault::AsZero,
        Fault::BadNextHop(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        Fault::BadNextHop(IpAddr::V6("ff02::1".parse().unwrap())),
        Fault::OwnNextHop,
    ]
}

fn path(asns: &[u32]) -> PathAttribute {
    PathAttribute::AsPath(AsPath::from_sequence(
        asns.iter().copied().map(Asn::new).collect(),
    ))
}

fn v4(asns: &[u32], next_hop: Ipv4Addr) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            path(asns),
            PathAttribute::NextHop(next_hop),
        ],
        announced: vec![n4()],
    }
}

fn v6(asns: &[u32], next_hop: Ipv6Addr) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            path(asns),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(next_hop),
                prefixes: vec![Prefix::V6(n6())],
            }),
        ],
        announced: vec![],
    }
}

fn pid(ip: Ipv4Addr) -> PeerId {
    PeerId::from(IpAddr::V4(ip))
}

fn candidates_v4(state: &DaemonState) -> Vec<PeerId> {
    candidates(&state.rib.loc_rib, &n4())
}

fn candidates_v6(state: &DaemonState) -> Vec<PeerId> {
    candidates(&state.rib.loc_rib_v6, &n6())
}

fn candidates<A: pathvector_types::IpAddress>(loc_rib: &LocRib<A>, nlri: &Nlri<A>) -> Vec<PeerId> {
    let mut peers: Vec<PeerId> = loc_rib
        .candidates(nlri)
        .map(|c| c.into_keys().collect())
        .unwrap_or_default();
    peers.sort();
    peers
}

/// Asserts what A's Adj-RIB-In holds for `n4()` after `fault`'s replacement.
fn assert_adj_rib_in_v4(state: &DaemonState, fault: Fault) {
    let stored = state.adj_ribs_in[&IpAddr::V4(PEER_A)].get(&n4());
    if fault.retained() {
        let route = stored.unwrap_or_else(|| {
            panic!("{fault:?}: RFC 4271 §9: the ineligible replacement supersedes the old route")
        });
        assert_eq!(
            route.as_path.to_string(),
            AsPath::from_sequence(fault.asns().into_iter().map(Asn::new).collect()).to_string(),
            "{fault:?}: Adj-RIB-In must hold the replacement, not the superseded route"
        );
    } else {
        assert!(
            stored.is_none(),
            "{fault:?}: RFC 7606 §2: treat-as-withdraw removes the route from the Adj-RIB-In"
        );
    }
}

fn assert_adj_rib_in_v6(state: &DaemonState, fault: Fault) {
    let stored = state.adj_ribs_in_v6[&IpAddr::V4(PEER_A)].get(&n6());
    if fault.retained() {
        let route = stored.unwrap_or_else(|| {
            panic!("{fault:?}: RFC 4271 §9: the ineligible replacement supersedes the old route")
        });
        assert_eq!(
            route.as_path.to_string(),
            AsPath::from_sequence(fault.asns().into_iter().map(Asn::new).collect()).to_string(),
            "{fault:?}: Adj-RIB-In must hold the replacement, not the superseded route"
        );
    } else {
        assert!(
            stored.is_none(),
            "{fault:?}: RFC 7606 §2: treat-as-withdraw removes the route from the Adj-RIB-In"
        );
    }
}

// ── Sole best route replaced ⇒ withdrawal everywhere ─────────────────────────

/// IPv4: A's accepted route is selected and advertised to B; A then sends a
/// replacement that is dropped before import policy. A has no eligible route
/// left, so the FIB gets exactly one `Withdrawn` and B gets the prefix in
/// WITHDRAWN ROUTES (RFC 4271 §9.2). No NOTIFICATION: the session stays up.
#[test]
fn dropped_replacement_of_sole_best_withdraws_from_fib_and_peers_v4() {
    for fault in v4_faults() {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);
        let fib = with_recording_fib(&mut state);

        state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
        assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
        assert!(state.rib.loc_rib.best(&n4()).is_some());
        fib.v4.lock().unwrap().clear();

        let notification = state.on_route_update(IpAddr::V4(PEER_A), fault.update_v4());

        assert!(notification.is_none(), "{fault:?}: no session reset");
        assert!(
            state.rib.loc_rib.best(&n4()).is_none(),
            "{fault:?}: RFC 4271 §9: the replacement implicitly withdraws the older route"
        );
        assert!(candidates_v4(&state).is_empty(), "{fault:?}");
        assert_eq!(
            fib.v4_changes(),
            vec![BestPathChange::Withdrawn(n4())],
            "{fault:?}: the FIB must remove the superseded route"
        );
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(
            withdraws_v4(&to_b) && !announces_v4(&to_b),
            "{fault:?}: RFC 4271 §9.2: B must get WITHDRAWN ROUTES, got {to_b:?}"
        );
        assert!(
            state.adj_ribs_out[&IpAddr::V4(PEER_B)].get(&n4()).is_none(),
            "{fault:?}"
        );
        assert_adj_rib_in_v4(&state, fault);
    }
}

/// IPv6 counterpart: the withdrawal must reach B as `MP_UNREACH_NLRI`.
#[test]
fn dropped_replacement_of_sole_best_withdraws_from_fib_and_peers_v6() {
    for fault in v6_faults() {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);
        let fib = with_recording_fib(&mut state);

        state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
        assert!(announces_v6(&sent_to(&mut state, &mut receivers, PEER_B)));
        assert!(state.rib.loc_rib_v6.best(&n6()).is_some());
        fib.v6.lock().unwrap().clear();

        let notification = state.on_route_update(IpAddr::V4(PEER_A), fault.update_v6());

        assert!(notification.is_none(), "{fault:?}: no session reset");
        assert!(state.rib.loc_rib_v6.best(&n6()).is_none(), "{fault:?}");
        assert!(candidates_v6(&state).is_empty(), "{fault:?}");
        assert_eq!(
            fib.v6.lock().unwrap().clone(),
            vec![BestPathChange::Withdrawn(n6())],
            "{fault:?}"
        );
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(
            withdraws_v6(&to_b) && !announces_v6(&to_b),
            "{fault:?}: RFC 4271 §9.2: B must get MP_UNREACH_NLRI, got {to_b:?}"
        );
        assert!(
            state.adj_ribs_out_v6[&IpAddr::V4(PEER_B)]
                .get(&n6())
                .is_none(),
            "{fault:?}"
        );
        assert_adj_rib_in_v6(&state, fault);
    }
}

// ── Another peer's route takes over ──────────────────────────────────────────

/// IPv4: A (shorter AS_PATH) beats C until A's replacement is dropped. Phase 2
/// must then install C's route (§9.1.2), the FIB must switch to C's next hop,
/// and B must never see a withdrawal: a replacement route exists (§9.2).
#[test]
fn dropped_replacement_promotes_other_peers_route_v4() {
    for fault in v4_faults() {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);
        let fib = with_recording_fib(&mut state);

        state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
        state.on_route_update(
            IpAddr::V4(PEER_C),
            v4(&[AS_C, 65005, 65006], RESOLVABLE_V4_ALT),
        );
        assert_eq!(state.rib.loc_rib.best_peer(&n4()), Some(pid(PEER_A)));
        drain(&mut state, &mut receivers);
        fib.v4.lock().unwrap().clear();

        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v4());

        assert_eq!(
            state.rib.loc_rib.best_peer(&n4()),
            Some(pid(PEER_C)),
            "{fault:?}"
        );
        assert_eq!(candidates_v4(&state), vec![pid(PEER_C)], "{fault:?}");
        let changes = fib.v4_changes();
        assert!(
            matches!(changes.as_slice(),
                [BestPathChange::Announced(n, r)]
                    if *n == n4() && r.next_hop == Some(NextHop::V4(RESOLVABLE_V4_ALT))),
            "{fault:?}: FIB must switch to C's next hop, got {changes:?}"
        );
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(
            !withdraws_v4(&to_b),
            "{fault:?}: a replacement exists (RFC 4271 §9.2); got {to_b:?}"
        );
        assert_adj_rib_in_v4(&state, fault);
    }
}

/// IPv6 counterpart.
#[test]
fn dropped_replacement_promotes_other_peers_route_v6() {
    for fault in v6_faults() {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);
        let fib = with_recording_fib(&mut state);

        state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
        state.on_route_update(IpAddr::V4(PEER_C), v6(&[AS_C, 65005, 65006], ALT_V6));
        assert_eq!(state.rib.loc_rib_v6.best_peer(&n6()), Some(pid(PEER_A)));
        drain(&mut state, &mut receivers);
        fib.v6.lock().unwrap().clear();

        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v6());

        assert_eq!(
            state.rib.loc_rib_v6.best_peer(&n6()),
            Some(pid(PEER_C)),
            "{fault:?}"
        );
        assert_eq!(candidates_v6(&state), vec![pid(PEER_C)], "{fault:?}");
        let changes = fib.v6.lock().unwrap().clone();
        assert!(
            matches!(changes.as_slice(),
                [BestPathChange::Announced(n, r)]
                    if *n == n6() && r.next_hop == Some(NextHop::V6(ALT_V6))),
            "{fault:?}: FIB must switch to C's next hop, got {changes:?}"
        );
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(!withdraws_v6(&to_b), "{fault:?}: got {to_b:?}");
        assert_adj_rib_in_v6(&state, fault);
    }
}

// ── No earlier route ⇒ nothing changes ───────────────────────────────────────

/// IPv4: A never advertised the prefix; C's route is selected. A's dropped
/// announcement must change nothing: no FIB change, nothing sent to B, and C's
/// route (another peer's) is left alone.
#[test]
fn dropped_announcement_without_earlier_route_is_a_no_op_v4() {
    for fault in v4_faults() {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);
        let fib = with_recording_fib(&mut state);

        state.on_route_update(IpAddr::V4(PEER_C), v4(&[AS_C], RESOLVABLE_V4_ALT));
        drain(&mut state, &mut receivers);
        fib.v4.lock().unwrap().clear();

        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v4());

        assert_eq!(
            state.rib.loc_rib.best_peer(&n4()),
            Some(pid(PEER_C)),
            "{fault:?}: C's route must be untouched"
        );
        assert_eq!(candidates_v4(&state), vec![pid(PEER_C)], "{fault:?}");
        assert!(
            fib.v4_changes()
                .iter()
                .all(|c| *c == BestPathChange::Unchanged),
            "{fault:?}: no FIB change, got {:?}",
            fib.v4_changes()
        );
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(
            !withdraws_v4(&to_b) && !announces_v4(&to_b),
            "{fault:?}: nothing spurious, got {to_b:?}"
        );
        assert_adj_rib_in_v4(&state, fault);
    }
}

/// IPv6 counterpart.
#[test]
fn dropped_announcement_without_earlier_route_is_a_no_op_v6() {
    for fault in v6_faults() {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);
        let fib = with_recording_fib(&mut state);

        state.on_route_update(IpAddr::V4(PEER_C), v6(&[AS_C], ALT_V6));
        drain(&mut state, &mut receivers);
        fib.v6.lock().unwrap().clear();

        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v6());

        assert_eq!(
            state.rib.loc_rib_v6.best_peer(&n6()),
            Some(pid(PEER_C)),
            "{fault:?}"
        );
        assert_eq!(candidates_v6(&state), vec![pid(PEER_C)], "{fault:?}");
        assert!(
            fib.v6
                .lock()
                .unwrap()
                .iter()
                .all(|c| *c == BestPathChange::Unchanged),
            "{fault:?}"
        );
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(
            !withdraws_v6(&to_b) && !announces_v6(&to_b),
            "{fault:?}: got {to_b:?}"
        );
        assert_adj_rib_in_v6(&state, fault);
    }
}

// ── Several NLRI in one UPDATE: only the dropped ones are withdrawn ──────────

fn n4b() -> Nlri<Ipv4Addr> {
    "11.0.0.0/8".parse().unwrap()
}

fn n6b() -> Nlri<Ipv6Addr> {
    "2001:db8:2::/48".parse().unwrap()
}

/// One UPDATE carries a classic IPv4 NLRI (`n4()`), a valid MP_REACH_NLRI IPv4
/// NLRI (`n4b()`) and a valid MP_REACH_NLRI IPv6 NLRI (`n6()`), with a NEXT_HOP
/// attribute of 0.0.0.0. RFC 4271 §6.3 makes that "syntactically incorrect";
/// RFC 7606 §3(e) turns the reset into treat-as-withdraw, and §2 defines
/// treat-as-withdraw for the UPDATE: every route it contains is withdrawn.
/// A had earlier routes for all three; none may survive (Codex review of #139).
#[test]
fn invalid_next_hop_attribute_withdraws_every_nlri_of_the_update() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);
    let mp_v4 = |nh: Ipv4Addr| {
        PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV4_UNICAST,
            next_hop: NextHop::V4(nh),
            prefixes: vec![Prefix::V4(n4b())],
        })
    };
    let mp_v6 = |nh: Ipv6Addr| {
        PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6(nh),
            prefixes: vec![Prefix::V6(n6())],
        })
    };
    let update = |classic_nh: Ipv4Addr| UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            path(&[AS_A]),
            PathAttribute::NextHop(classic_nh),
            mp_v4(RESOLVABLE_V4_ALT),
            mp_v6(RESOLVABLE_V6),
        ],
        announced: vec![n4()],
    };

    state.on_route_update(IpAddr::V4(PEER_A), update(RESOLVABLE_V4));
    assert!(state.rib.loc_rib.best(&n4()).is_some());
    assert!(state.rib.loc_rib.best(&n4b()).is_some());
    assert!(state.rib.loc_rib_v6.best(&n6()).is_some());
    drain(&mut state, &mut receivers);
    fib.v4.lock().unwrap().clear();
    fib.v6.lock().unwrap().clear();

    let notification = state.on_route_update(IpAddr::V4(PEER_A), update(Ipv4Addr::UNSPECIFIED));

    assert!(notification.is_none(), "RFC 7606: the session stays up");
    assert!(state.rib.loc_rib.best(&n4()).is_none());
    assert!(
        state.rib.loc_rib.best(&n4b()).is_none(),
        "RFC 7606 §2: the MP_REACH IPv4 NLRI of the same UPDATE is withdrawn too"
    );
    assert!(
        state.rib.loc_rib_v6.best(&n6()).is_none(),
        "RFC 7606 §2: the MP_REACH IPv6 NLRI of the same UPDATE is withdrawn too"
    );
    let a = &state.adj_ribs_in[&IpAddr::V4(PEER_A)];
    assert!(a.get(&n4()).is_none() && a.get(&n4b()).is_none());
    assert!(
        state.adj_ribs_in_v6[&IpAddr::V4(PEER_A)]
            .get(&n6())
            .is_none()
    );
    let changes = fib.v4_changes();
    assert!(
        changes.contains(&BestPathChange::Withdrawn(n4())),
        "{changes:?}"
    );
    assert!(
        changes.contains(&BestPathChange::Withdrawn(n4b())),
        "{changes:?}"
    );
    assert_eq!(
        fib.v6.lock().unwrap().clone(),
        vec![BestPathChange::Withdrawn(n6())]
    );
}

/// An invalid *MP_REACH_NLRI* next hop is not the NEXT_HOP attribute, so it
/// stays scoped to that attribute's own NLRI: a valid classic NLRI in the same
/// UPDATE is replaced normally.
#[test]
fn invalid_mp_reach_next_hop_withdraws_only_its_own_nlri_v4_good_v6_bad() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
    drain(&mut state, &mut receivers);
    fib.v4.lock().unwrap().clear();
    fib.v6.lock().unwrap().clear();

    let mut mixed = v4(&[AS_A], RESOLVABLE_V4_ALT);
    mixed
        .attributes
        .push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6(Ipv6Addr::UNSPECIFIED),
            prefixes: vec![Prefix::V6(n6())],
        }));
    state.on_route_update(IpAddr::V4(PEER_A), mixed);

    assert!(
        state.rib.loc_rib_v6.best(&n6()).is_none(),
        "the IPv6 route with the unspecified next hop is withdrawn"
    );
    assert_eq!(
        fib.v6.lock().unwrap().clone(),
        vec![BestPathChange::Withdrawn(n6())]
    );
    assert_eq!(
        state.rib.loc_rib.best(&n4()).and_then(|r| r.next_hop),
        Some(NextHop::V4(RESOLVABLE_V4_ALT)),
        "the IPv4 route in the same UPDATE is replaced normally"
    );
    assert!(withdraws_v6(&sent_to(&mut state, &mut receivers, PEER_B)));
}

/// An AS-loop UPDATE announcing two prefixes. A had an earlier route for the
/// first only, C holds the second. The first is withdrawn; the second (no
/// earlier route from A) is a no-op and C's route stays selected.
#[test]
fn loop_update_with_several_nlri_withdraws_only_prefixes_with_an_earlier_route() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
    let mut c_route = v4(&[AS_C], RESOLVABLE_V4_ALT);
    c_route.announced = vec![n4b()];
    state.on_route_update(IpAddr::V4(PEER_C), c_route);
    drain(&mut state, &mut receivers);
    fib.v4.lock().unwrap().clear();

    let mut looped = Fault::AsLoop.update_v4();
    looped.announced = vec![n4(), n4b()];
    state.on_route_update(IpAddr::V4(PEER_A), looped);

    assert!(state.rib.loc_rib.best(&n4()).is_none());
    assert_eq!(
        state.rib.loc_rib.best_peer(&n4b()),
        Some(pid(PEER_C)),
        "C's route for the second prefix is untouched"
    );
    let changes = fib.v4_changes();
    assert!(changes.contains(&BestPathChange::Withdrawn(n4())));
    assert!(
        !changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(n) if *n == n4b())),
        "got {changes:?}"
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(withdraws_v4(&to_b));
    assert!(
        !to_b.iter().any(|m| m.withdrawn.contains(&n4b())),
        "got {to_b:?}"
    );
}

/// IPv6: one MP_REACH_NLRI with two prefixes and a looped AS_PATH. A had an
/// earlier route for the first only.
#[test]
fn loop_update_with_several_v6_nlri_withdraws_only_prefixes_with_an_earlier_route() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
    state.on_route_update(
        IpAddr::V4(PEER_C),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                path(&[AS_C]),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6(ALT_V6),
                    prefixes: vec![Prefix::V6(n6b())],
                }),
            ],
            announced: vec![],
        },
    );
    drain(&mut state, &mut receivers);
    fib.v6.lock().unwrap().clear();

    let mut looped = Fault::AsLoop.update_v6();
    for attr in &mut looped.attributes {
        if let PathAttribute::MpReachNlri(mp) = attr {
            mp.prefixes = vec![Prefix::V6(n6()), Prefix::V6(n6b())];
        }
    }
    state.on_route_update(IpAddr::V4(PEER_A), looped);

    assert!(state.rib.loc_rib_v6.best(&n6()).is_none());
    assert_eq!(state.rib.loc_rib_v6.best_peer(&n6b()), Some(pid(PEER_C)));
    let changes = fib.v6.lock().unwrap().clone();
    assert!(changes.contains(&BestPathChange::Withdrawn(n6())));
    assert!(
        !changes
            .iter()
            .any(|c| matches!(c, BestPathChange::Withdrawn(n) if *n == n6b())),
        "got {changes:?}"
    );
}

// ── Re-evaluation must not resurrect an ineligible replacement ───────────────

/// An ineligible replacement stays in Adj-RIB-In (RFC 4271 §9). Soft
/// reconfiguration re-judges that route (RFC 4271 §9.1.1), so re-evaluation
/// must reach the same verdict as arrival: still ineligible, still no
/// candidate. Otherwise a ROA or default-policy change would install a looped
/// route.
#[test]
fn reevaluation_keeps_an_ineligible_replacement_out_of_the_loc_rib() {
    for fault in [Fault::AsLoop, Fault::ConfedLoop, Fault::OwnNextHop] {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);

        state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
        state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v4());
        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v6());
        drain(&mut state, &mut receivers);
        assert!(state.rib.loc_rib.best(&n4()).is_none(), "{fault:?}");
        assert!(state.rib.loc_rib_v6.best(&n6()).is_none(), "{fault:?}");

        state.reevaluate_all_import_policies();

        assert!(
            state.rib.loc_rib.best(&n4()).is_none(),
            "{fault:?}: re-evaluation installed an ineligible IPv4 route"
        );
        assert!(
            state.rib.loc_rib_v6.best(&n6()).is_none(),
            "{fault:?}: re-evaluation installed an ineligible IPv6 route"
        );
    }
}

/// Once A sends an eligible route again it is installed (ineligible → eligible).
#[test]
fn eligible_replacement_of_a_dropped_route_is_installed() {
    for fault in v4_faults() {
        let (mut state, mut receivers) = established();
        fault.prepare(&mut state);

        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v4());
        assert!(state.rib.loc_rib.best(&n4()).is_none(), "{fault:?}");
        drain(&mut state, &mut receivers);

        state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));

        assert_eq!(
            state.rib.loc_rib.best_peer(&n4()),
            Some(pid(PEER_A)),
            "{fault:?}"
        );
        assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
    }
}

// ── RFC 7999 BLACKHOLE interaction ───────────────────────────────────────────

/// A's earlier route for `n4()` carried BLACKHOLE (kernel null route, kept out
/// of the Loc-RIB). A dropped replacement supersedes it (RFC 4271 §9), so the
/// null route must be reported for removal like any other withdrawal.
#[test]
fn dropped_replacement_of_a_blackhole_route_withdraws_the_null_route() {
    for fault in [
        Fault::AsLoop,
        Fault::BadNextHop(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    ] {
        let policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
        let peer = pid(PEER_A);
        let mut adj = AdjRibIn::new(peer);
        let mut adj_v6 = AdjRibIn::new(peer);
        let mut loc: LocRib<Ipv4Addr> = LocRib::new();
        let mut loc_v6: LocRib<Ipv6Addr> = LocRib::new();

        let mut blackhole = v4(&[AS_A], RESOLVABLE_V4);
        blackhole
            .attributes
            .push(PathAttribute::Communities(vec![Community::BLACKHOLE]));
        let mut books = super::BlackholeBooks::default();
        let first = run_agreed(
            &mut adj,
            &mut adj_v6,
            &mut loc,
            &mut loc_v6,
            &policy,
            &policy_v6,
            &mut books,
            blackhole,
        );
        assert_eq!(first.v4.blackhole, vec![BlackholeChange::Install(n4())]);

        let second = run_agreed(
            &mut adj,
            &mut adj_v6,
            &mut loc,
            &mut loc_v6,
            &policy,
            &policy_v6,
            &mut books,
            fault.update_v4(),
        );

        assert_eq!(
            second.v4.blackhole,
            vec![BlackholeChange::Withdraw(n4())],
            "{fault:?}: RFC 4271 §9: the superseded blackhole must be withdrawn"
        );
    }
}

/// Runs one UPDATE from peer A on a session that agreed to honor BLACKHOLE for
/// `10.0.0.0/8` / `2001:db8::/32` (RFC 7999 §3.3), with the null-route books
/// supplied.
#[allow(clippy::too_many_arguments)]
fn run_agreed(
    adj: &mut AdjRibIn<Ipv4Addr>,
    adj_v6: &mut AdjRibIn<Ipv6Addr>,
    loc: &mut LocRib<Ipv4Addr>,
    loc_v6: &mut LocRib<Ipv6Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    policy_v6: &Policy<Route<Ipv6Addr>>,
    books: &mut super::BlackholeBooks,
    msg: UpdateMessage,
) -> super::route::UpdateResult {
    let scope = crate::blackhole::BlackholeScope::new(["10.0.0.0/8", "2001:db8::/32"]).unwrap();
    super::route::process_update(
        pid(PEER_A),
        msg,
        adj,
        loc,
        adj_v6,
        loc_v6,
        policy,
        policy_v6,
        PeerType::External,
        None,
        &AlwaysReachable,
        &AlwaysReachable,
        LOCAL_AS,
        Some(CONFED_ID),
        Some(OWN_V4),
        Some(OWN_V6),
        &super::PeerBlackhole::from_config(Some(&scope), None),
        books,
    )
}

// ── Graceful Restart must not resurrect ineligible routes ────────────────────

/// A, B and C established; A advertises Graceful Restart for IPv4 and IPv6
/// unicast, so an unclean drop retains its routes (RFC 4724 §4.2), and our
/// session address toward A is `OWN_V4`.
fn established_gr() -> (DaemonState, Receivers) {
    use pathvector_session::message::{Capability, GracefulRestartFamily};
    let (mut state, mut receivers) = crate::daemon::tests::make_state(
        LOCAL_AS,
        &[
            (IpAddr::V4(PEER_A), AS_A),
            (IpAddr::V4(PEER_B), super::last_feasible_tests::AS_B),
            (IpAddr::V4(PEER_C), AS_C),
        ],
    );
    state.set_oracles(
        super::last_feasible_tests::FixedOracle,
        super::last_feasible_tests::FixedOracle,
    );
    Arc::make_mut(&mut state.rib).local_ipv6 = Some(OWN_V6);
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
    state.on_established(
        IpAddr::V4(PEER_A),
        PEER_A,
        PeerType::External,
        AS_A,
        90,
        &a_caps,
        Some(IpAddr::V4(OWN_V4)),
    );
    for (ip, asn) in [(PEER_B, super::last_feasible_tests::AS_B), (PEER_C, AS_C)] {
        state.on_established(IpAddr::V4(ip), ip, PeerType::External, asn, 90, &mp, None);
    }
    drain(&mut state, &mut receivers);
    (state, receivers)
}

/// RFC 4724 §4.2 retains and marks stale the routes received from the peer; it
/// does not make an ineligible one eligible. A's AS-looped or own-NEXT_HOP
/// replacement sits in the Adj-RIB-In (ineligible, RFC 4271 §9.1.2 / §6.3 (a));
/// when A drops uncleanly, stale marking must not install it, even though
/// teardown has by then forgotten the local address (Codex review of #139).
#[test]
fn graceful_restart_does_not_resurrect_ineligible_routes() {
    for fault in [Fault::AsLoop, Fault::ConfedLoop, Fault::OwnNextHop] {
        let (mut state, mut receivers) = established_gr();
        fault.prepare(&mut state);
        let fib = with_recording_fib(&mut state);

        state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
        state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v4());
        state.on_route_update(IpAddr::V4(PEER_A), fault.update_v6());
        drain(&mut state, &mut receivers);
        assert!(state.rib.loc_rib.best(&n4()).is_none(), "{fault:?}");
        assert!(state.rib.loc_rib_v6.best(&n6()).is_none(), "{fault:?}");
        fib.v4.lock().unwrap().clear();
        fib.v6.lock().unwrap().clear();

        state.on_terminated(
            IpAddr::V4(PEER_A),
            pathvector_session::transport::TerminationReason::Unclean,
            true,
        );

        assert!(
            state.gr.deadlines.contains_key(&IpAddr::V4(PEER_A)),
            "{fault:?}: precondition: the drop entered the GR window"
        );
        assert!(
            state.rib.loc_rib.best(&n4()).is_none(),
            "{fault:?}: stale marking installed an ineligible IPv4 route"
        );
        assert!(
            state.rib.loc_rib_v6.best(&n6()).is_none(),
            "{fault:?}: stale marking installed an ineligible IPv6 route"
        );
        assert!(
            fib.v4_changes()
                .iter()
                .all(|c| !matches!(c, BestPathChange::Announced(..))),
            "{fault:?}"
        );
        assert!(
            fib.v6
                .lock()
                .unwrap()
                .iter()
                .all(|c| !matches!(c, BestPathChange::Announced(..))),
            "{fault:?}"
        );
    }
}

/// Counterpart: an *eligible* route is still retained and stays selected.
#[test]
fn graceful_restart_still_retains_eligible_routes() {
    let (mut state, _receivers) = established_gr();
    Fault::OwnNextHop.prepare(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
    state.on_terminated(
        IpAddr::V4(PEER_A),
        pathvector_session::transport::TerminationReason::Unclean,
        true,
    );

    assert_eq!(state.rib.loc_rib.best_peer(&n4()), Some(pid(PEER_A)));
    assert_eq!(state.rib.loc_rib_v6.best_peer(&n6()), Some(pid(PEER_A)));
}

/// The same re-judging applies to a route that import policy rejected (it is
/// kept in the Adj-RIB-In for soft reconfiguration): stale marking goes through
/// `ImportDecision`, not around it.
#[test]
fn graceful_restart_does_not_resurrect_policy_rejected_routes() {
    let (mut state, mut receivers) = established_gr();
    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
    state.set_import_default(IpAddr::V4(PEER_A), DefaultAction::Reject);
    drain(&mut state, &mut receivers);
    assert!(state.rib.loc_rib.best(&n4()).is_none());

    state.on_terminated(
        IpAddr::V4(PEER_A),
        pathvector_session::transport::TerminationReason::Unclean,
        true,
    );

    assert!(state.rib.loc_rib.best(&n4()).is_none());
    assert!(state.rib.loc_rib_v6.best(&n6()).is_none());
}

/// Soft reconfiguration during the GR window (a ROA-cache change, a new import
/// default) re-judges the retained routes. Teardown forgets the live session's
/// local address, but RFC 4271 §6.3 (a) still forbids installing a route whose
/// NEXT_HOP is our own address, so it must stay rejected (Codex review of #139).
#[test]
fn own_next_hop_stays_rejected_through_soft_reconfiguration_in_the_gr_window() {
    let (mut state, mut receivers) = established_gr();

    state.on_route_update(IpAddr::V4(PEER_A), v4(&[AS_A], RESOLVABLE_V4));
    state.on_route_update(IpAddr::V4(PEER_A), Fault::OwnNextHop.update_v4());
    drain(&mut state, &mut receivers);
    assert!(state.rib.loc_rib.best(&n4()).is_none());

    state.on_terminated(
        IpAddr::V4(PEER_A),
        pathvector_session::transport::TerminationReason::Unclean,
        true,
    );
    assert!(state.gr.deadlines.contains_key(&IpAddr::V4(PEER_A)));
    assert!(
        !state.rib.local_addrs.contains_key(&IpAddr::V4(PEER_A)),
        "precondition: teardown forgot the live session's local address"
    );
    assert!(state.rib.loc_rib.best(&n4()).is_none());

    state.reevaluate_all_import_policies();

    assert!(
        state.rib.loc_rib.best(&n4()).is_none(),
        "RFC 4271 §6.3 (a): re-evaluation installed a route whose NEXT_HOP is our own address"
    );
}

/// RFC 4760 §3: an UPDATE "that carries no NLRI, other than the one encoded in
/// the MP_REACH_NLRI attribute, SHOULD NOT carry the NEXT_HOP attribute. If
/// such a message contains the NEXT_HOP attribute, the BGP speaker that
/// receives the message SHOULD ignore this attribute." An unused classic
/// NEXT_HOP of 0.0.0.0 must therefore not withdraw the valid MP_REACH routes
/// (Codex review of #139). Once the classic NLRI field uses it, it applies
/// (`invalid_next_hop_attribute_withdraws_every_nlri_of_the_update`).
#[test]
fn unused_classic_next_hop_is_ignored_when_mp_reach_is_the_only_nlri() {
    let (mut state, mut receivers) = established();
    let alt_v6: Ipv6Addr = "2001:db8::44".parse().unwrap();

    state.on_route_update(IpAddr::V4(PEER_A), v6(&[AS_A], RESOLVABLE_V6));
    state.on_route_update(
        IpAddr::V4(PEER_A),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                path(&[AS_A]),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    next_hop: NextHop::V4(RESOLVABLE_V4),
                    prefixes: vec![Prefix::V4(n4())],
                }),
            ],
            announced: vec![],
        },
    );
    drain(&mut state, &mut receivers);

    let mut replacement = v6(&[AS_A], alt_v6);
    replacement
        .attributes
        .push(PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED));
    replacement
        .attributes
        .push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV4_UNICAST,
            next_hop: NextHop::V4(RESOLVABLE_V4_ALT),
            prefixes: vec![Prefix::V4(n4())],
        }));
    state.on_route_update(IpAddr::V4(PEER_A), replacement);

    assert_eq!(
        state.rib.loc_rib_v6.best(&n6()).and_then(|r| r.next_hop),
        Some(NextHop::V6(alt_v6)),
        "RFC 4760 §3: the unused NEXT_HOP is ignored; the IPv6 route is replaced"
    );
    assert_eq!(
        state.rib.loc_rib.best(&n4()).and_then(|r| r.next_hop),
        Some(NextHop::V4(RESOLVABLE_V4_ALT)),
        "RFC 4760 §3: the MP_REACH IPv4 route is replaced too"
    );
}

// ── A dropped BLACKHOLE announcement never owns a null route ─────────────────

/// An ineligible announcement installs no kernel null route. The daemon's
/// record of who owns a null route is the blackhole book, not the BLACKHOLE
/// tag on a stored route, so keeping the dropped replacement in the
/// Adj-RIB-In (RFC 4271 §9, RFC 7999 §3.3 "store all BGP updates … carrying
/// the BLACKHOLE community") cannot let A's later withdrawal delete C's active
/// null route for the same prefix (Codex review of #139, now fixed
/// structurally).
#[test]
fn dropped_blackhole_announcement_owns_no_null_route_and_its_withdrawal_removes_none() {
    let policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
    let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
    for fault in [Fault::AsLoop, Fault::OwnNextHop] {
        let mut adj = AdjRibIn::new(pid(PEER_A));
        let mut adj_v6 = AdjRibIn::new(pid(PEER_A));
        let mut loc: LocRib<Ipv4Addr> = LocRib::new();
        let mut loc_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut books = super::BlackholeBooks::default();

        // C already holds a null route for the same prefix.
        let scope = crate::blackhole::BlackholeScope::new(["10.0.0.0/8"]).unwrap();
        let c_claim = super::blackhole::BlackholeAgreement::<Ipv4Addr>::agreed(scope)
            .authorize(
                &pathvector_rib::RouteBuilder::new(n4(), Origin::Igp, AsPath::new())
                    .community(Community::BLACKHOLE)
                    .build(),
            )
            .unwrap();
        assert!(books.v4.claim(pid(PEER_C), c_claim).is_some());

        let mut tagged = fault.update_v4();
        tagged
            .attributes
            .push(PathAttribute::Communities(vec![Community::BLACKHOLE]));
        let first = run_agreed(
            &mut adj,
            &mut adj_v6,
            &mut loc,
            &mut loc_v6,
            &policy,
            &policy_v6,
            &mut books,
            tagged,
        );
        assert!(
            first.v4.blackhole.is_empty(),
            "{fault:?}: no null route for an ineligible announcement"
        );
        assert!(!books.v4.holds(pid(PEER_A), &n4()), "{fault:?}");

        let withdraw = UpdateMessage {
            withdrawn: vec![n4()],
            attributes: vec![],
            announced: vec![],
        };
        let second = run_agreed(
            &mut adj,
            &mut adj_v6,
            &mut loc,
            &mut loc_v6,
            &policy,
            &policy_v6,
            &mut books,
            withdraw,
        );
        assert!(
            second.v4.blackhole.is_empty(),
            "{fault:?}: withdrawing a never-installed route must not delete a null route"
        );
        assert!(
            books.v4.holds(pid(PEER_C), &n4()),
            "{fault:?}: C's null route survives"
        );
    }
}

// ── Model property test ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Kind {
    /// A valid announcement import policy accepts.
    Accepted,
    /// AS_PATH carries the local AS: ineligible, replaces the old route.
    Loop,
    /// Own address as NEXT_HOP: ineligible, replaces the old route.
    OwnNextHop,
    /// Unspecified NEXT_HOP: treat-as-withdraw, removed from Adj-RIB-In.
    BadNextHop,
    /// AS 0 in AS_PATH: treat-as-withdraw.
    AsZero,
    Withdraw,
}

#[derive(Clone, Debug)]
struct Step {
    peer: usize,
    prefix: usize,
    v6: bool,
    kind: Kind,
}

fn step() -> impl Strategy<Value = Step> {
    let kind = prop_oneof![
        4 => Just(Kind::Accepted),
        2 => Just(Kind::Loop),
        1 => Just(Kind::OwnNextHop),
        1 => Just(Kind::BadNextHop),
        1 => Just(Kind::AsZero),
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
const MODEL_OWN_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);
const MODEL_OWN_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, 1);

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

/// Builds the UPDATE for `s`; MED carries `seq` so each advertisement is
/// distinguishable.
fn model_update(s: &Step, seq: u32) -> UpdateMessage {
    if matches!(s.kind, Kind::Withdraw) {
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
    }
    let first_as = 65100 + u32::try_from(s.peer).unwrap();
    let asns: Vec<u32> = match s.kind {
        Kind::Loop => vec![first_as, MODEL_LOCAL_AS],
        Kind::AsZero => vec![first_as, 0],
        _ => vec![first_as],
    };
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        path(&asns),
        PathAttribute::Med(seq),
    ];
    if s.v6 {
        let nh = match s.kind {
            Kind::OwnNextHop => MODEL_OWN_V6,
            Kind::BadNextHop => Ipv6Addr::UNSPECIFIED,
            _ => "2001:db8::1".parse().unwrap(),
        };
        attributes.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6(nh),
            prefixes: vec![Prefix::V6(model_v6(s.prefix))],
        }));
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![],
        }
    } else {
        let nh = match s.kind {
            Kind::OwnNextHop => MODEL_OWN_V4,
            Kind::BadNextHop => Ipv4Addr::UNSPECIFIED,
            _ => Ipv4Addr::new(192, 0, 2, 1),
        };
        attributes.push(PathAttribute::NextHop(nh));
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![model_v4(s.prefix)],
        }
    }
}

/// `(v6, prefix) → peer → MED (sequence number)`.
type Model = std::collections::HashMap<(bool, usize), std::collections::HashMap<usize, u32>>;

fn med_of<A: pathvector_types::IpAddress>(r: &Route<A>) -> u32 {
    r.med.map(pathvector_types::Med::as_u32).unwrap()
}

fn check_prefix<A: pathvector_types::IpAddress>(
    nlri: &Nlri<A>,
    key: (bool, usize),
    loc_rib: &LocRib<A>,
    adj: &[AdjRibIn<A>],
    candidates_model: &Model,
    adj_model: &Model,
) -> Result<(), TestCaseError> {
    let want: std::collections::HashMap<PeerId, u32> = candidates_model
        .get(&key)
        .map(|m| m.iter().map(|(&p, &seq)| (model_peer(p), seq)).collect())
        .unwrap_or_default();
    let got: std::collections::HashMap<PeerId, u32> = loc_rib
        .candidates(nlri)
        .map(|c| c.into_iter().map(|(p, r)| (p, med_of(r))).collect())
        .unwrap_or_default();
    prop_assert_eq!(
        &got,
        &want,
        "Loc-RIB candidates for {} must be the latest eligible advertisement per peer",
        nlri
    );
    prop_assert_eq!(loc_rib.best(nlri).is_some(), !want.is_empty());
    for (i, adj_rib_in) in adj.iter().enumerate() {
        let want_raw = adj_model.get(&key).and_then(|m| m.get(&i)).copied();
        prop_assert_eq!(
            adj_rib_in.get(nlri).map(med_of),
            want_raw,
            "Adj-RIB-In of peer {} for {}: ineligible routes are kept, treat-as-withdraw routes are not",
            i,
            nlri
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Model test for issue #138, over both families, three peers and three
    /// prefixes. Announcements are accepted, ineligible (AS loop, own
    /// NEXT_HOP: RFC 4271 §9.1.2 / §6.3), treat-as-withdraw (unspecified
    /// NEXT_HOP, AS 0: RFC 7606 §3(e) / RFC 7607), or plain withdrawals.
    /// After every UPDATE:
    ///
    /// 1. Loc-RIB candidates == the latest advertisement of each peer whose
    ///    latest advertisement was accepted (RFC 4271 §9 + §9.1.2); any other
    ///    latest advertisement leaves the peer with no candidate;
    /// 2. Adj-RIB-In holds the latest advertisement unless it was a
    ///    treat-as-withdraw (RFC 7606 §2) or a withdrawal.
    ///
    /// Re-evaluating every Adj-RIB-In afterwards (soft reconfiguration) must
    /// leave the Loc-RIB unchanged.
    #[test]
    fn prop_dropped_announcements_leave_the_peer_with_no_candidate(
        steps in prop::collection::vec(step(), 1..48)
    ) {
        let policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
        let gate = IngressGate::new(MODEL_LOCAL_AS, None, Some(MODEL_OWN_V4), Some(MODEL_OWN_V6));

        let mut loc_rib: LocRib<Ipv4Addr> = LocRib::new();
        let mut loc_rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut adj: Vec<AdjRibIn<Ipv4Addr>> = (0..3).map(|i| AdjRibIn::new(model_peer(i))).collect();
        let mut adj_v6: Vec<AdjRibIn<Ipv6Addr>> =
            (0..3).map(|i| AdjRibIn::new(model_peer(i))).collect();
        let mut candidates_model: Model = Model::new();
        let mut adj_model: Model = Model::new();

        for (seq, s) in steps.iter().enumerate() {
            let seq = u32::try_from(seq).unwrap();
            let key = (s.v6, s.prefix);
            let cands = candidates_model.entry(key).or_default();
            let adjs = adj_model.entry(key).or_default();
            match s.kind {
                Kind::Accepted => {
                    cands.insert(s.peer, seq);
                    adjs.insert(s.peer, seq);
                }
                Kind::Loop | Kind::OwnNextHop => {
                    cands.remove(&s.peer);
                    adjs.insert(s.peer, seq);
                }
                Kind::BadNextHop | Kind::AsZero | Kind::Withdraw => {
                    cands.remove(&s.peer);
                    adjs.remove(&s.peer);
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
                Some(MODEL_OWN_V4),
                Some(MODEL_OWN_V6),
            );
            prop_assert!(result.notification.is_none());

            for p in 0..3 {
                check_prefix(&model_v4(p), (false, p), &loc_rib, &adj, &candidates_model, &adj_model)?;
                check_prefix(&model_v6(p), (true, p), &loc_rib_v6, &adj_v6, &candidates_model, &adj_model)?;
            }
        }

        let mut before: Vec<_> = loc_rib.best_routes().map(|(n, r)| (n, r.clone())).collect();
        let mut before_v6: Vec<_> = loc_rib_v6.best_routes().map(|(n, r)| (n, r.clone())).collect();
        for i in 0..3 {
            let _ = super::import::reapply_without_blackholes(
                model_peer(i), &adj[i], &mut loc_rib, &policy, &gate, &AlwaysReachable,
            );
            let _ = super::import::reapply_without_blackholes(
                model_peer(i), &adj_v6[i], &mut loc_rib_v6, &policy_v6, &gate, &AlwaysReachable,
            );
        }
        for p in 0..3 {
            check_prefix(&model_v4(p), (false, p), &loc_rib, &adj, &candidates_model, &adj_model)?;
            check_prefix(&model_v6(p), (true, p), &loc_rib_v6, &adj_v6, &candidates_model, &adj_model)?;
        }
        let mut after: Vec<_> = loc_rib.best_routes().map(|(n, r)| (n, r.clone())).collect();
        let mut after_v6: Vec<_> = loc_rib_v6.best_routes().map(|(n, r)| (n, r.clone())).collect();
        before.sort_by_key(|(n, _)| *n);
        after.sort_by_key(|(n, _)| *n);
        before_v6.sort_by_key(|(n, _)| *n);
        after_v6.sort_by_key(|(n, _)| *n);
        prop_assert_eq!(after, before, "re-evaluation must agree with arrival");
        prop_assert_eq!(after_v6, before_v6);
    }
}
