// daemon/last_feasible_tests.rs — issue #67: an UPDATE that removes the last
// feasible path must reach the FIB and every peer as a withdrawal.
//
// RFC 4271 §9: "if the NLRI of the new route is identical to the one the route
// currently has stored in the Adj-RIB-In, then the new route SHALL replace the
// older route in the Adj-RIB-In, thus implicitly withdrawing the older route
// from service."
//
// RFC 4271 §9.1.2: "If the NEXT_HOP attribute of a BGP route depicts an
// address that is not resolvable [...] the BGP route MUST be excluded from the
// Phase 2 decision function." / "Unresolvable routes SHALL be removed from the
// Loc-RIB and the routing table.  However, corresponding unresolvable routes
// SHOULD be kept in the Adj-RIBs-In (in case they become resolvable)."
//
// RFC 4271 §9.1.3: "If a route in Loc-RIB is excluded from a particular
// Adj-RIB-Out, the previously advertised route in that Adj-RIB-Out MUST be
// withdrawn from service by means of an UPDATE message (see 9.2)."
//
// RFC 4271 §9.2: "All newly installed routes and all newly unfeasible routes
// for which there is no replacement route SHALL be advertised to its peers by
// means of an UPDATE message."
//
// Every test uses one fixed next-hop oracle for its whole duration: the
// reachable → unreachable transition is caused by the replacement UPDATE's
// NEXT_HOP, never by `on_fib_change`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use pathvector_rib::BestPathChange;
use pathvector_rib::oracle::NextHopOracle;
use pathvector_session::message::{Capability, MpReachNlri, PathAttribute, Prefix, UpdateMessage};
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};
use tokio::sync::mpsc;

use super::{DaemonState, MRAI};
use crate::daemon::tests::{make_state, with_recording_fib};

pub(super) const LOCAL_AS: u32 = 65001;
/// Source of the route under test.
pub(super) const PEER_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub(super) const AS_A: u32 = 65002;
/// Observer: receives whatever the daemon advertises.
pub(super) const PEER_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
pub(super) const AS_B: u32 = 65003;
/// Second source offering a feasible, less-preferred alternative.
pub(super) const PEER_C: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
pub(super) const AS_C: u32 = 65004;

pub(super) const RESOLVABLE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub(super) const RESOLVABLE_V4_ALT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 4);
const UNRESOLVABLE_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 99);
pub(super) const RESOLVABLE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const UNRESOLVABLE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 0x99);

/// Fixed oracle: every next-hop resolves except the two `UNRESOLVABLE_*`
/// addresses.
pub(super) struct FixedOracle;

impl NextHopOracle for FixedOracle {
    fn is_reachable(&self, nh: &NextHop) -> bool {
        !matches!(nh, NextHop::V4(a) if *a == UNRESOLVABLE_V4)
            && !matches!(nh, NextHop::V6(a) if *a == UNRESOLVABLE_V6)
    }

    fn igp_metric(&self, _: &NextHop) -> Option<u32> {
        None
    }
}

pub(super) type Receivers = HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>;

pub(super) fn n4() -> Nlri<Ipv4Addr> {
    "10.0.0.0/8".parse().unwrap()
}

pub(super) fn n6() -> Nlri<Ipv6Addr> {
    "2001:db8:1::/48".parse().unwrap()
}

/// Builds a daemon with peers A, B and C established (all eBGP, IPv4 + IPv6
/// unicast) and the fixed oracle installed. Returns the drained receivers.
pub(super) fn established() -> (DaemonState, Receivers) {
    let (mut state, mut receivers) = make_state(
        LOCAL_AS,
        &[
            (IpAddr::V4(PEER_A), AS_A),
            (IpAddr::V4(PEER_B), AS_B),
            (IpAddr::V4(PEER_C), AS_C),
        ],
    );
    state.set_oracles(FixedOracle, FixedOracle);
    std::sync::Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());

    let caps = [
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    for (ip, asn) in [(PEER_A, AS_A), (PEER_B, AS_B), (PEER_C, AS_C)] {
        state.on_established(IpAddr::V4(ip), ip, PeerType::External, asn, 90, &caps, None);
    }
    drain(&mut state, &mut receivers);
    (state, receivers)
}

pub(super) fn drain(state: &mut DaemonState, receivers: &mut Receivers) {
    state.flush_pending();
    for rx in receivers.values_mut() {
        while rx.try_recv().is_ok() {}
    }
}

/// Flushes the outbound coalescing buffers, then returns every UPDATE queued
/// for `peer`.
pub(super) fn sent_to(
    state: &mut DaemonState,
    receivers: &mut Receivers,
    peer: Ipv4Addr,
) -> Vec<UpdateMessage> {
    state.flush_pending();
    let rx = receivers.get_mut(&IpAddr::V4(peer)).unwrap();
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// Simulates the MRAI timer arm in `run_with` once B's
/// MinRouteAdvertisementIntervalTimer has expired (RFC 4271 §9.2.1.1: "the
/// last route selected SHALL be advertised at the end of
/// MinRouteAdvertisementIntervalTimer").
pub(super) fn expire_mrai(state: &mut DaemonState) {
    let past = Instant::now()
        .checked_sub(MRAI + Duration::from_secs(1))
        .expect("monotonic clock far enough from its epoch");
    state.mrai.backdate_peer(IpAddr::V4(PEER_B), past);
    state.mrai_v6.backdate_peer(IpAddr::V4(PEER_B), past);
    state.flush_mrai_pending();
}

fn announce_v4(path: &[u32], next_hop: Ipv4Addr) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(
                path.iter().copied().map(Asn::new).collect(),
            )),
            PathAttribute::NextHop(next_hop),
        ],
        announced: vec![n4()],
    }
}

fn announce_v6(path: &[u32], next_hop: Ipv6Addr) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(
                path.iter().copied().map(Asn::new).collect(),
            )),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(next_hop),
                prefixes: vec![Prefix::V6(n6())],
            }),
        ],
        announced: vec![],
    }
}

pub(super) fn withdraws_v4(msgs: &[UpdateMessage]) -> bool {
    msgs.iter().any(|m| m.withdrawn.contains(&n4()))
}

pub(super) fn announces_v4(msgs: &[UpdateMessage]) -> bool {
    msgs.iter().any(|m| m.announced.contains(&n4()))
}

pub(super) fn withdraws_v6(msgs: &[UpdateMessage]) -> bool {
    msgs.iter().flat_map(|m| &m.attributes).any(|a| {
        matches!(a, PathAttribute::MpUnreachNlri(u)
            if u.afi_safi == AfiSafi::IPV6_UNICAST && u.prefixes.contains(&Prefix::V6(n6())))
    })
}

pub(super) fn announces_v6(msgs: &[UpdateMessage]) -> bool {
    msgs.iter().flat_map(|m| &m.attributes).any(|a| {
        matches!(a, PathAttribute::MpReachNlri(r)
            if r.afi_safi == AfiSafi::IPV6_UNICAST && r.prefixes.contains(&Prefix::V6(n6())))
    })
}

/// IPv4: A's sole selected route is replaced by one whose NEXT_HOP is
/// unresolvable. The FIB must receive exactly one `Withdrawn`, B must receive
/// the prefix in WITHDRAWN ROUTES, B's Adj-RIB-Out must drop it, and the
/// unresolvable route must stay in A's Adj-RIB-In (§9.1.2 SHOULD).
#[test]
fn unresolvable_replacement_of_sole_best_withdraws_from_fib_and_peers_v4() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[AS_A], RESOLVABLE_V4));
    assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
    assert!(state.rib.loc_rib.best(&n4()).is_some());
    fib.v4.lock().unwrap().clear();

    let notification =
        state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[AS_A], UNRESOLVABLE_V4));

    assert!(
        notification.is_none(),
        "a well-formed UPDATE must not reset the session"
    );
    assert_eq!(
        fib.v4_changes(),
        vec![BestPathChange::Withdrawn(n4())],
        "RFC 4271 §9.1.2: the route SHALL be removed from the routing table"
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        withdraws_v4(&to_b) && !announces_v4(&to_b),
        "RFC 4271 §9.2: B must get the prefix in WITHDRAWN ROUTES, got {to_b:?}"
    );
    assert!(state.rib.loc_rib.best(&n4()).is_none());
    assert!(state.adj_ribs_out[&IpAddr::V4(PEER_B)].get(&n4()).is_none());
    assert_eq!(
        state.adj_ribs_in[&IpAddr::V4(PEER_A)]
            .get(&n4())
            .and_then(|r| r.next_hop),
        Some(NextHop::V4(UNRESOLVABLE_V4)),
        "RFC 4271 §9.1.2: unresolvable routes SHOULD be kept in the Adj-RIBs-In"
    );
}

/// IPv6 counterpart: the withdrawal must reach the FIB and B as
/// `MP_UNREACH_NLRI` (RFC 4760 §4).
#[test]
fn unresolvable_replacement_of_sole_best_withdraws_from_fib_and_peers_v6() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[AS_A], RESOLVABLE_V6));
    assert!(announces_v6(&sent_to(&mut state, &mut receivers, PEER_B)));
    assert!(state.rib.loc_rib_v6.best(&n6()).is_some());
    fib.v6.lock().unwrap().clear();

    let notification =
        state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[AS_A], UNRESOLVABLE_V6));

    assert!(notification.is_none());
    assert_eq!(
        fib.v6.lock().unwrap().clone(),
        vec![BestPathChange::Withdrawn(n6())],
        "RFC 4271 §9.1.2: the route SHALL be removed from the routing table"
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        withdraws_v6(&to_b) && !announces_v6(&to_b),
        "RFC 4271 §9.2: B must get the prefix in MP_UNREACH_NLRI, got {to_b:?}"
    );
    assert!(state.rib.loc_rib_v6.best(&n6()).is_none());
    assert!(
        state.adj_ribs_out_v6[&IpAddr::V4(PEER_B)]
            .get(&n6())
            .is_none()
    );
    assert!(
        state.adj_ribs_in_v6[&IpAddr::V4(PEER_A)]
            .get(&n6())
            .is_some()
    );
}

/// IPv4 with a feasible alternative: A (shorter AS_PATH) wins over C until A's
/// replacement is unresolvable. The FIB must then install C's next hop and B
/// must receive a replacement announcement — never a withdrawal (§9.2 only
/// withdraws routes "for which there is no replacement route").
#[test]
fn unresolvable_replacement_promotes_feasible_alternative_v4() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[AS_A], RESOLVABLE_V4));
    state.on_route_update(
        IpAddr::V4(PEER_C),
        announce_v4(&[AS_C, 65005], RESOLVABLE_V4_ALT),
    );
    assert_eq!(
        state.rib.loc_rib.best(&n4()).and_then(|r| r.next_hop),
        Some(NextHop::V4(RESOLVABLE_V4)),
        "A's shorter AS_PATH must win before the replacement"
    );
    drain(&mut state, &mut receivers);
    fib.v4.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[AS_A], UNRESOLVABLE_V4));

    let changes = fib.v4_changes();
    assert!(
        matches!(changes.as_slice(),
            [BestPathChange::Announced(n, r)]
                if *n == n4() && r.next_hop == Some(NextHop::V4(RESOLVABLE_V4_ALT))),
        "FIB must switch to C's next hop, got {changes:?}"
    );
    // RFC 4271 §9.2: a replacement exists, so B must never see a withdrawal.
    // B (eBGP) was sent A's path moments ago, so the replacement itself is
    // held by MinRouteAdvertisementIntervalTimer (§9.2.1.1) and goes out when
    // the interval expires.
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(!withdraws_v4(&to_b), "a replacement exists; got {to_b:?}");
    assert!(state.has_mrai_pending(), "C's path must be held for B");

    expire_mrai(&mut state);
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        announces_v4(&to_b) && !withdraws_v4(&to_b),
        "B must receive C's path as a replacement at MRAI expiry, got {to_b:?}"
    );
    assert_eq!(
        state.adj_ribs_out[&IpAddr::V4(PEER_B)]
            .get(&n4())
            .map(|r| (*r.as_path).clone()),
        Some(AsPath::from_sequence(vec![
            Asn::new(LOCAL_AS),
            Asn::new(AS_C),
            Asn::new(65005)
        ])),
        "B's Adj-RIB-Out must hold C's path once it has been sent"
    );
}

/// IPv6 with a feasible alternative.
#[test]
fn unresolvable_replacement_promotes_feasible_alternative_v6() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);
    let alt: Ipv6Addr = "2001:db8::4".parse().unwrap();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[AS_A], RESOLVABLE_V6));
    state.on_route_update(IpAddr::V4(PEER_C), announce_v6(&[AS_C, 65005], alt));
    drain(&mut state, &mut receivers);
    fib.v6.lock().unwrap().clear();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[AS_A], UNRESOLVABLE_V6));

    let changes = fib.v6.lock().unwrap().clone();
    assert!(
        matches!(changes.as_slice(),
            [BestPathChange::Announced(n, r)] if *n == n6() && r.next_hop == Some(NextHop::V6(alt))),
        "FIB must switch to C's next hop, got {changes:?}"
    );
    // B (eBGP) was sent A's path moments ago, so the replacement is held by
    // MRAI (RFC 4271 §9.2.1.1; RFC 4760 gives MP_REACH_NLRI no exemption).
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(!withdraws_v6(&to_b), "a replacement exists; got {to_b:?}");

    expire_mrai(&mut state);
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(
        announces_v6(&to_b) && !withdraws_v6(&to_b),
        "B must receive C's path as a replacement at MRAI expiry, got {to_b:?}"
    );
}

/// No spurious withdrawal: a prefix whose only route was unresolvable from
/// the start was never installed or advertised, so neither the FIB nor B may
/// see a withdrawal when that route is replaced or withdrawn.
#[test]
fn never_feasible_prefix_produces_no_fib_or_peer_withdrawal_v4() {
    let (mut state, mut receivers) = established();
    let fib = with_recording_fib(&mut state);

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[AS_A], UNRESOLVABLE_V4));
    state.on_route_update(IpAddr::V4(PEER_C), announce_v4(&[AS_C], UNRESOLVABLE_V4));
    state.on_route_update(
        IpAddr::V4(PEER_A),
        UpdateMessage {
            withdrawn: vec![n4()],
            attributes: vec![],
            announced: vec![],
        },
    );

    assert!(
        fib.v4_changes()
            .iter()
            .all(|c| *c == BestPathChange::Unchanged),
        "nothing was installed, so nothing may be removed: {:?}",
        fib.v4_changes()
    );
    let to_b = sent_to(&mut state, &mut receivers, PEER_B);
    assert!(!withdraws_v4(&to_b) && !announces_v4(&to_b), "got {to_b:?}");
}
