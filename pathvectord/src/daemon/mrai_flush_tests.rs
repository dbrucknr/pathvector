// daemon/mrai_flush_tests.rs — RFC 4271 §9.2.1.1 MinRouteAdvertisementIntervalTimer:
// a replacement route suppressed by MRAI must actually reach the peer once the
// interval expires.
//
// RFC 4271 §9.2.1.1 (no later RFC amends this clause; checked 4724, 6286,
// 6608, 6793, 7606, 7607, 7705, 8212, 8654, 9072, 9687, 9774):
//
//   "Two UPDATE messages sent by a BGP speaker to a peer that advertise
//    feasible routes and/or withdrawal of unfeasible routes to some common
//    set of destinations MUST be separated by at least
//    MinRouteAdvertisementIntervalTimer."
//
//   "This procedure does not limit the rate of route selection, but only
//    the rate of route advertisement.  If new routes are selected multiple
//    times while awaiting the expiration of
//    MinRouteAdvertisementIntervalTimer, the last route selected SHALL be
//    advertised at the end of MinRouteAdvertisementIntervalTimer."
//
// The clause is per destination and says nothing about address family, and
// RFC 4760 (Multiprotocol Extensions) does not exempt MP_REACH_NLRI from it,
// so the same rules are asserted for IPv6 unicast.
//
// Withdrawals: RFC 4271 applies the interval to withdrawals too. RFC 1771
// §9.2.3.1 had exempted them ("To avoid long-lived black holes, the procedure
// does not apply to the explicit withdrawal of unfeasible routes"); RFC 4271
// dropped that sentence. pathvectord keeps the RFC 1771 behaviour on purpose
// (see `pathvectord/RFC.md` §9.2.1.1, ⚠️ row). The withdrawal tests below pin
// that documented deviation; they do not claim RFC 4271 requires it.
//
// The bug these tests pin: the replacement was committed to the peer's
// Adj-RIB-Out before the MRAI check, so when the deferred NLRI was re-propagated
// at expiry the Adj-RIB-Out diff yielded `NoChange` and the peer kept the stale
// path indefinitely.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use pathvector_session::message::{Capability, MpReachNlri, PathAttribute, Prefix, UpdateMessage};
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};
use tokio::sync::mpsc;

use super::{DaemonState, MRAI};
use crate::daemon::tests::make_state;

const LOCAL_AS: u32 = 65001;
/// Source of the route under test.
const PEER_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const AS_A: u32 = 65002;
/// eBGP observer: receives whatever the daemon advertises (MRAI applies).
const PEER_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const AS_B: u32 = 65003;
/// iBGP observer (MRAI does not apply).
const PEER_I: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

/// Extra ASNs that distinguish successive replacement routes on the wire.
const R2_MARK: u32 = 65010;
const R3_MARK: u32 = 65020;

const NH_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NH_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

type Receivers = HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>;

fn n4() -> Nlri<Ipv4Addr> {
    "10.0.0.0/8".parse().unwrap()
}

fn n6() -> Nlri<Ipv6Addr> {
    "2001:db8:1::/48".parse().unwrap()
}

/// Peers A and B established as eBGP and I as iBGP, IPv4 + IPv6 unicast;
/// receivers drained.
fn established() -> (DaemonState, Receivers) {
    let (mut state, mut receivers) = make_state(
        LOCAL_AS,
        &[
            (IpAddr::V4(PEER_A), AS_A),
            (IpAddr::V4(PEER_B), AS_B),
            (IpAddr::V4(PEER_I), LOCAL_AS),
        ],
    );
    std::sync::Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    let caps = [
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    for (ip, asn) in [(PEER_A, AS_A), (PEER_B, AS_B)] {
        state.on_established(IpAddr::V4(ip), ip, PeerType::External, asn, 90, &caps, None);
    }
    state.on_established(
        IpAddr::V4(PEER_I),
        PEER_I,
        PeerType::Internal,
        LOCAL_AS,
        90,
        &caps,
        None,
    );
    state.flush_pending();
    for rx in receivers.values_mut() {
        while rx.try_recv().is_ok() {}
    }
    (state, receivers)
}

/// Flushes the coalescing buffers and returns every UPDATE queued for `peer`.
fn sent_to(
    state: &mut DaemonState,
    receivers: &mut Receivers,
    peer: Ipv4Addr,
) -> Vec<UpdateMessage> {
    state.flush_pending();
    let rx = receivers.get_mut(&IpAddr::V4(peer)).unwrap();
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

fn sent_to_b(state: &mut DaemonState, receivers: &mut Receivers) -> Vec<UpdateMessage> {
    sent_to(state, receivers, PEER_B)
}

/// Simulates the MRAI timer arm in `run_with` after B's interval has expired
/// for every destination: back-date B's last-sent stamps past the window, then
/// run the same `flush_mrai_pending` → `flush_pending` sequence the event loop
/// runs.
fn expire_mrai_and_flush(state: &mut DaemonState) {
    let past = Instant::now()
        .checked_sub(MRAI + Duration::from_secs(1))
        .expect("monotonic clock far enough from its epoch");
    state.mrai.backdate_peer(IpAddr::V4(PEER_B), past);
    state.mrai_v6.backdate_peer(IpAddr::V4(PEER_B), past);
    state.flush_mrai_pending();
    state.flush_pending();
}

fn path(extra: &[u32]) -> AsPath {
    AsPath::from_sequence(
        std::iter::once(AS_A)
            .chain(extra.iter().copied())
            .map(Asn::new)
            .collect(),
    )
}

fn announce_v4(extra: &[u32]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(path(extra)),
            PathAttribute::NextHop(NH_V4),
        ],
        announced: vec![n4()],
    }
}

fn withdraw_v4() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![n4()],
        attributes: vec![],
        announced: vec![],
    }
}

fn announce_v6(extra: &[u32]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(path(extra)),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(NH_V6),
                prefixes: vec![Prefix::V6(n6())],
            }),
        ],
        announced: vec![],
    }
}

fn withdraw_v6() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::MpUnreachNlri(
            pathvector_session::message::MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![Prefix::V6(n6())],
            },
        )],
        announced: vec![],
    }
}

fn as_path_of(msg: &UpdateMessage) -> Option<&AsPath> {
    msg.attributes.iter().find_map(|a| match a {
        PathAttribute::AsPath(p) => Some(p),
        _ => None,
    })
}

/// The AS_PATHs of every UPDATE that announces `n4()`.
fn announced_paths_v4(msgs: &[UpdateMessage]) -> Vec<AsPath> {
    msgs.iter()
        .filter(|m| m.announced.contains(&n4()))
        .filter_map(|m| as_path_of(m).cloned())
        .collect()
}

fn withdraws_v4(msgs: &[UpdateMessage]) -> bool {
    msgs.iter().any(|m| m.withdrawn.contains(&n4()))
}

/// The AS_PATHs of every UPDATE whose MP_REACH_NLRI announces `n6()`.
fn announced_paths_v6(msgs: &[UpdateMessage]) -> Vec<AsPath> {
    msgs.iter()
        .filter(|m| {
            m.attributes.iter().any(|a| {
                matches!(a, PathAttribute::MpReachNlri(r)
                    if r.afi_safi == AfiSafi::IPV6_UNICAST
                        && r.prefixes.contains(&Prefix::V6(n6())))
            })
        })
        .filter_map(|m| as_path_of(m).cloned())
        .collect()
}

fn withdraws_v6(msgs: &[UpdateMessage]) -> bool {
    msgs.iter().flat_map(|m| &m.attributes).any(|a| {
        matches!(a, PathAttribute::MpUnreachNlri(u)
            if u.afi_safi == AfiSafi::IPV6_UNICAST && u.prefixes.contains(&Prefix::V6(n6())))
    })
}

fn carries(path: &AsPath, mark: u32) -> bool {
    path.contains(Asn::new(mark))
}

// ── IPv4 ─────────────────────────────────────────────────────────────────────

/// §9.2.1.1: a replacement selected inside the interval is held back, and
/// "the last route selected SHALL be advertised at the end of
/// MinRouteAdvertisementIntervalTimer". Before the fix B never received it.
#[test]
fn suppressed_replacement_is_sent_when_mrai_expires_v4() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    let first = sent_to_b(&mut state, &mut rx);
    assert_eq!(
        announced_paths_v4(&first).len(),
        1,
        "R1 reaches B: {first:?}"
    );

    // Replacement inside the interval: the MUST-separate rule holds it back.
    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[R2_MARK]));
    let during = sent_to_b(&mut state, &mut rx);
    assert!(
        during.is_empty(),
        "a second advertisement of the same destination inside MRAI must be deferred: {during:?}"
    );

    // A flush tick before the interval has elapsed releases nothing.
    state.flush_mrai_pending();
    let early = sent_to_b(&mut state, &mut rx);
    assert!(
        early.is_empty(),
        "nothing may be released before expiry: {early:?}"
    );

    expire_mrai_and_flush(&mut state);
    let after = sent_to_b(&mut state, &mut rx);
    let paths = announced_paths_v4(&after);
    assert_eq!(
        paths.len(),
        1,
        "the replacement must be advertised exactly once at expiry: {after:?}"
    );
    assert!(
        carries(&paths[0], R2_MARK),
        "the advertised route must be the replacement, not the stale R1: {:?}",
        paths[0]
    );
    assert!(
        !state.has_mrai_pending(),
        "nothing left pending after release"
    );
}

/// §9.2.1.1: "If new routes are selected multiple times while awaiting the
/// expiration [...], the last route selected SHALL be advertised" — R3, not
/// R2, and only once.
#[test]
fn last_route_selected_during_window_is_the_one_sent_v4() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    sent_to_b(&mut state, &mut rx);

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[R2_MARK]));
    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[R3_MARK]));
    assert!(sent_to_b(&mut state, &mut rx).is_empty());

    expire_mrai_and_flush(&mut state);
    let after = sent_to_b(&mut state, &mut rx);
    let paths = announced_paths_v4(&after);
    assert_eq!(paths.len(), 1, "one advertisement at expiry: {after:?}");
    assert!(
        carries(&paths[0], R3_MARK) && !carries(&paths[0], R2_MARK),
        "the last route selected (R3) must be the one advertised: {:?}",
        paths[0]
    );
}

/// Selection flips to R2 and back to R1 inside the interval. The last route
/// selected is R1, which B already holds: B must never be sent R2, and its
/// Adj-RIB-Out must still describe R1.
#[test]
fn replacement_reverted_within_window_never_sends_intermediate_v4() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    sent_to_b(&mut state, &mut rx);

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[R2_MARK]));
    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    expire_mrai_and_flush(&mut state);
    let msgs = sent_to_b(&mut state, &mut rx);
    assert!(
        announced_paths_v4(&msgs)
            .iter()
            .all(|p| !carries(p, R2_MARK)),
        "B must never be sent the intermediate R2: {msgs:?}"
    );
    let held = state.adj_ribs_out[&IpAddr::V4(PEER_B)]
        .get(&n4())
        .expect("B still holds R1");
    assert!(!carries(&held.as_path, R2_MARK));
}

/// Design invariant (not an RFC clause): while a replacement is held back,
/// B's Adj-RIB-Out — which feeds `show adj-rib-out` and the advertised-prefix
/// counters — describes the route B actually has, R1.
#[test]
fn adj_rib_out_holds_route_actually_sent_while_suppressed_v4() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    sent_to_b(&mut state, &mut rx);
    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[R2_MARK]));
    sent_to_b(&mut state, &mut rx);

    let held = state.adj_ribs_out[&IpAddr::V4(PEER_B)]
        .get(&n4())
        .expect("B's Adj-RIB-Out still holds a route for the prefix");
    assert!(
        !carries(&held.as_path, R2_MARK),
        "Adj-RIB-Out must not claim R2 was sent: {:?}",
        held.as_path
    );

    expire_mrai_and_flush(&mut state);
    let held = state.adj_ribs_out[&IpAddr::V4(PEER_B)].get(&n4()).unwrap();
    assert!(carries(&held.as_path, R2_MARK), "R2 recorded once sent");
}

/// Documented deviation (RFC 1771 §9.2.3.1 behaviour, see module header): a
/// withdrawal inside the interval is sent immediately.
#[test]
fn withdrawal_within_window_is_sent_immediately_v4() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    sent_to_b(&mut state, &mut rx);

    state.on_route_update(IpAddr::V4(PEER_A), withdraw_v4());
    let msgs = sent_to_b(&mut state, &mut rx);
    assert!(
        withdraws_v4(&msgs),
        "withdrawal sent without waiting: {msgs:?}"
    );
    assert!(state.adj_ribs_out[&IpAddr::V4(PEER_B)].get(&n4()).is_none());
}

/// R1 sent, R2 held back by MRAI, then the destination becomes unfeasible.
/// B must get the withdrawal and nothing else — the held-back R2 must not be
/// resurrected when the interval later expires.
#[test]
fn suppressed_replacement_then_withdrawal_sends_only_withdrawal_v4() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    sent_to_b(&mut state, &mut rx);
    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[R2_MARK]));
    assert!(sent_to_b(&mut state, &mut rx).is_empty());

    state.on_route_update(IpAddr::V4(PEER_A), withdraw_v4());
    let msgs = sent_to_b(&mut state, &mut rx);
    assert!(withdraws_v4(&msgs), "withdrawal must reach B: {msgs:?}");
    assert!(
        announced_paths_v4(&msgs).is_empty(),
        "no announcement alongside the withdrawal: {msgs:?}"
    );
    assert!(!state.has_mrai_pending(), "withdrawal cancels the deferral");

    expire_mrai_and_flush(&mut state);
    let later = sent_to_b(&mut state, &mut rx);
    assert!(
        later.is_empty(),
        "the withdrawn destination must not be re-advertised at expiry: {later:?}"
    );
}

/// §9.2.1.1 option (b): "the procedure describe in this section SHOULD NOT
/// apply to routes sent to internal peers". An iBGP peer gets the replacement
/// immediately while the eBGP peer B is held back.
#[test]
fn ibgp_peer_is_not_rate_limited_v4() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[]));
    assert_eq!(
        announced_paths_v4(&sent_to(&mut state, &mut rx, PEER_I)).len(),
        1
    );
    sent_to_b(&mut state, &mut rx);

    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(&[R2_MARK]));
    let to_i = sent_to(&mut state, &mut rx, PEER_I);
    let paths = announced_paths_v4(&to_i);
    assert!(
        paths.len() == 1 && carries(&paths[0], R2_MARK),
        "iBGP peer gets the replacement without waiting: {to_i:?}"
    );
    assert!(
        sent_to_b(&mut state, &mut rx).is_empty(),
        "eBGP peer B is held back"
    );
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────

/// Same §9.2.1.1 requirements via MP_REACH_NLRI. Before the fix the IPv6 path
/// applied no interval at all, so the replacement went out immediately.
#[test]
fn suppressed_replacement_is_sent_when_mrai_expires_v6() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[]));
    let first = sent_to_b(&mut state, &mut rx);
    assert_eq!(
        announced_paths_v6(&first).len(),
        1,
        "R1 reaches B: {first:?}"
    );

    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[R2_MARK]));
    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[R3_MARK]));
    let during = sent_to_b(&mut state, &mut rx);
    assert!(
        announced_paths_v6(&during).is_empty(),
        "a second IPv6 advertisement of the same destination inside MRAI must be deferred: {during:?}"
    );

    expire_mrai_and_flush(&mut state);
    let after = sent_to_b(&mut state, &mut rx);
    let paths = announced_paths_v6(&after);
    assert_eq!(paths.len(), 1, "one advertisement at expiry: {after:?}");
    assert!(
        carries(&paths[0], R3_MARK),
        "the last route selected (R3) must be the one advertised: {:?}",
        paths[0]
    );
    assert!(!state.has_mrai_pending());
}

/// Documented deviation, IPv6: withdrawal inside the interval goes out now.
#[test]
fn withdrawal_within_window_is_sent_immediately_v6() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[]));
    sent_to_b(&mut state, &mut rx);

    state.on_route_update(IpAddr::V4(PEER_A), withdraw_v6());
    let msgs = sent_to_b(&mut state, &mut rx);
    assert!(
        withdraws_v6(&msgs),
        "withdrawal sent without waiting: {msgs:?}"
    );
}

/// IPv6: R2 held back, then withdrawn — only the withdrawal reaches B.
#[test]
fn suppressed_replacement_then_withdrawal_sends_only_withdrawal_v6() {
    let (mut state, mut rx) = established();

    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[]));
    sent_to_b(&mut state, &mut rx);
    state.on_route_update(IpAddr::V4(PEER_A), announce_v6(&[R2_MARK]));
    assert!(announced_paths_v6(&sent_to_b(&mut state, &mut rx)).is_empty());

    state.on_route_update(IpAddr::V4(PEER_A), withdraw_v6());
    let msgs = sent_to_b(&mut state, &mut rx);
    assert!(withdraws_v6(&msgs), "withdrawal must reach B: {msgs:?}");
    assert!(announced_paths_v6(&msgs).is_empty());
    assert!(!state.has_mrai_pending());

    expire_mrai_and_flush(&mut state);
    assert!(sent_to_b(&mut state, &mut rx).is_empty());
}
