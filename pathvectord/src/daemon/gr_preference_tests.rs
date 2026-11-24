// daemon/gr_preference_tests.rs — issue #68: a route retained during
// conventional Graceful Restart keeps its ordinary preference.
//
// RFC 4724 §4.2 (Receiving Speaker): "it MUST retain the routes received from
// the peer for all the address families that were previously received in the
// Graceful Restart Capability and MUST mark them as stale routing
// information. [...] The router MUST NOT differentiate between stale and other
// routing information during forwarding." RFC 8538 §4.1 restates the last
// sentence unchanged.
//
// RFC 9494 §1: "in LLGR, routes are 'depreferenced'; that is, they are
// treated as least preferred. Contrarily, in conventional GR, route
// preference is not affected." and "In the case of Graceful Restart, the
// trade-off between advertising new route status (at the cost of routing
// churn) and not advertising it [...] is resolved in favor of not
// advertising." pathvectord does not implement LLGR, so every retained route
// here is conventional-GR stale.
//
// RFC 4724 §4.2 also fixes how a retained route leaves: "The Receiving Speaker
// MUST replace the stale routes by the routing updates received from the
// peer. Once the End-of-RIB marker for an address family is received from the
// peer, it MUST immediately remove any routes from the peer that are still
// marked as stale for that address family." and "If the session does not get
// re-established within the 'Restart Time' [...] the Receiving Speaker MUST
// delete all the stale routes from the peer that it is retaining."
//
// Topology: two iBGP sources (so LOCAL_PREF is honoured) and one eBGP
// observer that receives whatever the daemon advertises. The GR-capable
// source A carries the more-preferred route (LOCAL_PREF 300) and sits on the
// *higher* peer address, so only LOCAL_PREF — never the final peer-address
// tie-breaker — can make it win.
//
// Import is accept-all with no transformations, so the pre-policy routes that
// stale marking reinserts into Loc-RIB equal the post-policy ones. That keeps
// these tests about the selector and the outbound path only; reinsertion that
// bypasses import policy is issue #82.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pathvector_rib::{BestPathChange, PeerId, Staleness};
use pathvector_session::message::{
    Capability, GracefulRestartFamily, MpReachNlri, PathAttribute, Prefix, UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AfiSafi, AsPath, Asn, LocalPref, NextHop, Nlri, Origin, PeerType};
use tokio::sync::mpsc;

use super::DaemonState;
use crate::daemon::tests::{make_state, with_recording_fib};

const LOCAL_AS: u32 = 65001;
/// GR-capable iBGP source of the preferred route (LOCAL_PREF 300).
const PEER_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
/// Non-GR iBGP source of the fresh, less-preferred alternative (LOCAL_PREF 100).
const PEER_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// eBGP observer.
const OBSERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const OBSERVER_AS: u32 = 65009;

/// Origin AS behind A — visible in what the observer receives.
const ORIGIN_A: u32 = 65100;
/// Origin AS behind B.
const ORIGIN_B: u32 = 65200;
const NEXT_HOP_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NEXT_HOP_B: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

const RESTART_TIME: u16 = 120;

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn gr_caps(families: &[AfiSafi]) -> Vec<Capability> {
    vec![
        Capability::FourByteAsn(LOCAL_AS),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: RESTART_TIME,
            families: families
                .iter()
                .map(|&afi_safi| GracefulRestartFamily {
                    afi_safi,
                    forwarding_preserved: true,
                })
                .collect(),
        },
    ]
}

fn ibgp_announce(origin_as: u32, next_hop: Ipv4Addr, lp: u32, prefixes: &[&str]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(origin_as)])),
            PathAttribute::NextHop(next_hop),
            PathAttribute::LocalPref(lp),
        ],
        announced: prefixes.iter().map(|s| nlri(s)).collect(),
    }
}

fn announce_a(prefixes: &[&str]) -> UpdateMessage {
    ibgp_announce(ORIGIN_A, NEXT_HOP_A, 300, prefixes)
}

fn announce_b(prefixes: &[&str]) -> UpdateMessage {
    ibgp_announce(ORIGIN_B, NEXT_HOP_B, 100, prefixes)
}

fn eor_v4() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    }
}

fn establish_a(state: &mut DaemonState) {
    state.on_established(
        IpAddr::V4(PEER_A),
        PEER_A,
        PeerType::Internal,
        LOCAL_AS,
        90,
        &gr_caps(&[AfiSafi::IPV4_UNICAST, AfiSafi::IPV6_UNICAST]),
        None,
    );
}

/// A (GR), B (no GR), and the observer, all Established; both sources
/// announce `prefixes`; every queue drained.
fn setup(prefixes: &[&str]) -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let (mut state, mut rxs) = make_state(
        LOCAL_AS,
        &[
            (IpAddr::V4(PEER_A), LOCAL_AS),
            (IpAddr::V4(PEER_B), LOCAL_AS),
            (IpAddr::V4(OBSERVER), OBSERVER_AS),
        ],
    );
    establish_a(&mut state);
    state.on_established(
        IpAddr::V4(PEER_B),
        PEER_B,
        PeerType::Internal,
        LOCAL_AS,
        90,
        &[Capability::FourByteAsn(LOCAL_AS)],
        None,
    );
    state.on_established(
        IpAddr::V4(OBSERVER),
        OBSERVER,
        PeerType::External,
        OBSERVER_AS,
        90,
        &[Capability::FourByteAsn(OBSERVER_AS)],
        None,
    );
    state.on_route_update(IpAddr::V4(PEER_A), announce_a(prefixes));
    state.on_route_update(IpAddr::V4(PEER_B), announce_b(prefixes));
    state.flush_pending();
    drain(&mut rxs);
    (state, rxs)
}

fn drain(rxs: &mut HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    for rx in rxs.values_mut() {
        while rx.try_recv().is_ok() {}
    }
}

fn observer_rx(
    rxs: &mut HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>,
) -> &mut mpsc::Receiver<UpdateMessage> {
    rxs.get_mut(&IpAddr::V4(OBSERVER)).unwrap()
}

/// Every UPDATE queued for the observer.
fn received(rx: &mut mpsc::Receiver<UpdateMessage>) -> Vec<UpdateMessage> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// The `AS_PATH` of the first queued UPDATE that announces `prefix`.
fn announced_as_path(msgs: &[UpdateMessage], prefix: Nlri<Ipv4Addr>) -> Option<AsPath> {
    msgs.iter()
        .find(|m| m.announced.contains(&prefix))
        .and_then(|m| {
            m.attributes.iter().find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p.clone()),
                _ => None,
            })
        })
}

fn fib_next_hops(changes: &[BestPathChange<Ipv4Addr>], prefix: Nlri<Ipv4Addr>) -> Vec<NextHop> {
    changes
        .iter()
        .filter_map(|c| match c {
            BestPathChange::Announced(n, r) if *n == prefix => r.next_hop,
            _ => None,
        })
        .collect()
}

fn fib_withdrew(changes: &[BestPathChange<Ipv4Addr>], prefix: Nlri<Ipv4Addr>) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, BestPathChange::Withdrawn(n) if *n == prefix))
}

/// Issue #68 acceptance case, through the daemon: A's LOCAL_PREF-300 route
/// is selected, A's session drops uncleanly, and B's fresh LOCAL_PREF-100
/// route is available. RFC 9494 §1 ("route preference is not affected") and
/// RFC 4724 §4.2 ("MUST NOT differentiate [...] during forwarding") → A's
/// retained route stays selected and stays in the FIB.
#[test]
fn conventional_gr_keeps_stale_higher_local_pref_route_selected() {
    let prefix = nlri("10.0.0.0/8");
    let (mut state, _rxs) = setup(&["10.0.0.0/8"]);
    assert_eq!(
        state.rib.loc_rib.best_peer(&prefix).map(PeerId::ip),
        Some(IpAddr::V4(PEER_A)),
        "precondition: LOCAL_PREF 300 wins while both sessions are up"
    );
    let fib = with_recording_fib(&mut state);

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    assert!(
        state.gr.deadlines.contains_key(&IpAddr::V4(PEER_A)),
        "precondition: the unclean drop entered the GR window"
    );
    let best = state.rib.loc_rib.best(&prefix).expect("route retained");
    assert_eq!(
        state.rib.loc_rib.best_peer(&prefix).map(PeerId::ip),
        Some(IpAddr::V4(PEER_A)),
        "the retained LOCAL_PREF-300 route must stay selected over the fresh LOCAL_PREF-100 one"
    );
    assert_eq!(best.staleness, Staleness::GrStale, "it is marked stale");
    assert_eq!(best.local_pref, Some(LocalPref::new(300)));

    let changes = fib.v4_changes();
    assert!(
        !fib_next_hops(&changes, prefix).contains(&NextHop::V4(NEXT_HOP_B)),
        "forwarding must not move to B's next hop because A's route is stale: {changes:?}"
    );
    assert!(
        !fib_withdrew(&changes, prefix),
        "the prefix must stay installed"
    );
}

/// RFC 9494 §1: in conventional GR the trade-off "is resolved in favor of not
/// advertising". Marking the selected route stale must not send the observer
/// a different path (or anything at all) for the prefix.
#[test]
fn conventional_gr_stale_marking_does_not_readvertise_when_an_alternative_exists() {
    let prefix = nlri("10.0.0.0/8");
    let (mut state, mut rxs) = setup(&["10.0.0.0/8"]);
    let before = state.adj_ribs_out[&IpAddr::V4(OBSERVER)]
        .get(&prefix)
        .cloned()
        .expect("observer was sent A's route");

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
    state.flush_pending();

    let msgs = received(observer_rx(&mut rxs));
    assert!(
        msgs.is_empty(),
        "no UPDATE may be sent when a route is merely marked stale: {msgs:?}"
    );
    assert_eq!(
        state.adj_ribs_out[&IpAddr::V4(OBSERVER)].get(&prefix),
        Some(&before),
        "Adj-RIB-Out still holds exactly what was advertised"
    );
}

/// The sole-candidate case. Selection cannot change here, so this isolates
/// the outbound side: staleness is local state that is never encoded on the
/// wire, so the advertised copy must compare equal to what was already sent
/// and no duplicate UPDATE may go out.
#[test]
fn stale_marking_of_sole_route_sends_no_duplicate_update() {
    let prefix = nlri("172.16.0.0/12");
    let (mut state, mut rxs) = setup(&[]);
    state.on_route_update(IpAddr::V4(PEER_A), announce_a(&["172.16.0.0/12"]));
    state.flush_pending();
    assert!(
        announced_as_path(&received(observer_rx(&mut rxs)), prefix).is_some(),
        "precondition: observer was sent A's route"
    );

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
    state.flush_pending();

    assert_eq!(
        state.rib.loc_rib.best(&prefix).map(|r| r.staleness),
        Some(Staleness::GrStale)
    );
    let msgs = received(observer_rx(&mut rxs));
    assert!(msgs.is_empty(), "duplicate UPDATE sent: {msgs:?}");
}

/// IPv6 counterpart of `stale_marking_of_sole_route_sends_no_duplicate_update`
/// (outbound `prepare_outbound_v6`).
#[test]
fn stale_marking_of_sole_v6_route_sends_no_duplicate_update() {
    let prefix: Nlri<Ipv6Addr> = "2001:db8:68::/48".parse().unwrap();
    let (mut state, mut rxs) = make_state(
        LOCAL_AS,
        &[
            (IpAddr::V4(PEER_A), LOCAL_AS),
            (IpAddr::V4(OBSERVER), OBSERVER_AS),
        ],
    );
    std::sync::Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    establish_a(&mut state);
    state.on_established(
        IpAddr::V4(OBSERVER),
        OBSERVER,
        PeerType::External,
        OBSERVER_AS,
        90,
        &[
            Capability::FourByteAsn(OBSERVER_AS),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        ],
        None,
    );
    drain(&mut rxs);
    state.on_route_update(
        IpAddr::V4(PEER_A),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(ORIGIN_A)])),
                PathAttribute::LocalPref(300),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(prefix)],
                }),
            ],
            announced: vec![],
        },
    );
    state.flush_pending();
    assert!(
        !received(observer_rx(&mut rxs)).is_empty(),
        "precondition: observer was sent A's v6 route"
    );

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
    state.flush_pending();

    assert_eq!(
        state.rib.loc_rib_v6.best(&prefix).map(|r| r.staleness),
        Some(Staleness::GrStale)
    );
    let msgs = received(observer_rx(&mut rxs));
    assert!(msgs.is_empty(), "duplicate v6 UPDATE sent: {msgs:?}");
}

/// RFC 4724 §4.2: "If the session does not get re-established within the
/// 'Restart Time' [...] the Receiving Speaker MUST delete all the stale routes
/// from the peer". Once A's retained route is deleted, selection falls back
/// to B's fresh route, the FIB follows, and the observer is sent B's path.
#[test]
fn restart_time_expiry_falls_back_to_the_fresh_alternative() {
    let prefix = nlri("10.0.0.0/8");
    let (mut state, mut rxs) = setup(&["10.0.0.0/8"]);
    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
    state.flush_pending();
    drain(&mut rxs);
    let fib = with_recording_fib(&mut state);
    // Keep MRAI from deferring the replacement past this test's horizon.
    state.mrai_last_sent.clear();

    state.gr.deadlines.remove(&IpAddr::V4(PEER_A));
    state.on_gr_deadline_expired(IpAddr::V4(PEER_A));
    state.flush_pending();

    let best = state.rib.loc_rib.best(&prefix).expect("B's route remains");
    assert_eq!(
        state.rib.loc_rib.best_peer(&prefix).map(PeerId::ip),
        Some(IpAddr::V4(PEER_B))
    );
    assert_eq!(best.staleness, Staleness::Fresh);
    assert_eq!(
        fib_next_hops(&fib.v4_changes(), prefix).last(),
        Some(&NextHop::V4(NEXT_HOP_B)),
        "FIB must move to B's next hop"
    );
    let path = announced_as_path(&received(observer_rx(&mut rxs)), prefix)
        .expect("observer must be sent the replacement path");
    assert!(
        path.to_string().contains(&ORIGIN_B.to_string()),
        "observer must now see B's path, got {path}"
    );
}

/// RFC 4724 §4.2: "The Receiving Speaker MUST replace the stale routes by the
/// routing updates received from the peer. Once the End-of-RIB marker [...] is
/// received from the peer, it MUST immediately remove any routes from the
/// peer that are still marked as stale".
///
/// A retains two prefixes, re-establishes, re-announces only one, then sends
/// End-of-RIB. Until End-of-RIB both retained routes stay selected on their
/// LOCAL_PREF; the re-announced one becomes fresh; End-of-RIB removes the
/// other, and only then does selection fall back to B for it.
#[test]
fn reannouncement_replaces_stale_route_and_end_of_rib_removes_the_rest() {
    let refreshed = nlri("10.0.0.0/8");
    let unrefreshed = nlri("172.16.0.0/12");
    let (mut state, _rxs) = setup(&["10.0.0.0/8", "172.16.0.0/12"]);
    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    establish_a(&mut state);
    state.on_route_update(IpAddr::V4(PEER_A), announce_a(&["10.0.0.0/8"]));

    for (prefix, staleness) in [
        (refreshed, Staleness::Fresh),
        (unrefreshed, Staleness::GrStale),
    ] {
        assert_eq!(
            state.rib.loc_rib.best_peer(&prefix).map(PeerId::ip),
            Some(IpAddr::V4(PEER_A)),
            "{prefix}: A's LOCAL_PREF-300 route stays selected before End-of-RIB"
        );
        assert_eq!(
            state.rib.loc_rib.best(&prefix).map(|r| r.staleness),
            Some(staleness),
            "{prefix}"
        );
    }

    state.on_route_update(IpAddr::V4(PEER_A), eor_v4());

    assert_eq!(
        state.rib.loc_rib.best_peer(&refreshed).map(PeerId::ip),
        Some(IpAddr::V4(PEER_A)),
        "the refreshed route survives End-of-RIB"
    );
    assert_eq!(
        state.rib.loc_rib.best_peer(&unrefreshed).map(PeerId::ip),
        Some(IpAddr::V4(PEER_B)),
        "End-of-RIB removes A's unrefreshed stale route; B's route takes over"
    );
    assert!(
        state
            .rib
            .loc_rib
            .best_routes()
            .all(|(_, r)| r.staleness == Staleness::Fresh),
        "no stale route may remain after End-of-RIB"
    );
}
