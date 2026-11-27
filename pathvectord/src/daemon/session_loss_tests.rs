// daemon/session_loss_tests.rs — issue #160: losing a session must withdraw or
// replace the lost peer's routes at every other peer, in both address families,
// and tell `WatchRoutes` subscribers.
//
// RFC 4271 §3.1: "the BGP speaker connection can be closed, which implicitly
// removes all routes the pair of speakers had advertised to each other from
// service."
//
// RFC 4271 §8.2.2: on leaving Established the local system "deletes all routes
// associated with this connection".
//
// RFC 4271 §9.2: "All newly installed routes and all newly unfeasible routes
// for which there is no replacement route SHALL be advertised to its peers by
// means of an UPDATE message."
//
// RFC 4760 §4: MP_UNREACH_NLRI lists "the routes that are being withdrawn from
// service". §8: a speaker determines through Capability Advertisement whether
// it can use Multiprotocol Extensions with a peer.
//
// RFC 4271 §9.1.3: "If a route in Loc-RIB is excluded from a particular
// Adj-RIB-Out, the previously advertised route in that Adj-RIB-Out MUST be
// withdrawn from service by means of an UPDATE message".
//
// RFC 4456 §6: "A route from a Non-Client IBGP peer: Reflect to all the
// Clients."
//
// RFC 4724 §4.2: "If the session does not get re-established within the
// "Restart Time" that the peer advertised previously, the Receiving Speaker
// MUST delete all the stale routes from the peer that it is retaining."

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;

use pathvector_session::message::{Capability, GracefulRestartFamily};
use pathvector_session::message::{
    CeaseError, MpReachNlri, MpUnreachNlri, NotificationError, NotificationMessage, PathAttribute,
    Prefix, UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};
use tokio::sync::broadcast;

use super::last_feasible_tests::{
    AS_A, AS_C, FixedOracle, LOCAL_AS, PEER_A, PEER_B, PEER_C, RESOLVABLE_V4, RESOLVABLE_V6,
    Receivers, announces_v4, announces_v6, drain, established, n4, n6, sent_to, withdraws_v4,
    withdraws_v6,
};
use super::tests::make_state;
use super::{DaemonState, handle_session_terminated};
use crate::proto;

/// A second IPv6 prefix, only ever announced by `PEER_C`.
fn other_n6() -> Nlri<Ipv6Addr> {
    "2001:db8:2::/48".parse().unwrap()
}

fn announce(prefix: Nlri<Ipv6Addr>, path: &[u32]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(
                path.iter().copied().map(Asn::new).collect(),
            )),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(RESOLVABLE_V6),
                prefixes: vec![Prefix::V6(prefix)],
            }),
        ],
        announced: vec![],
    }
}

/// RFC 4724 §2: the IPv6 End-of-RIB marker is an UPDATE holding only an empty
/// `MP_UNREACH_NLRI`.
fn end_of_rib_v6() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            prefixes: vec![],
        })],
        announced: vec![],
    }
}

fn feed(state: &mut DaemonState, peer: std::net::Ipv4Addr, msg: UpdateMessage) {
    assert!(state.on_route_update(IpAddr::V4(peer), msg).is_none());
}

/// `PEER_A` supplies the best path for `n6()`; with `alternative`, `PEER_C`
/// also holds a longer, less-preferred one. B has been sent A's route.
fn seeded(alternative: bool) -> (DaemonState, Receivers) {
    let (mut state, mut rx) = established();
    feed(&mut state, PEER_A, announce(n6(), &[AS_A]));
    if alternative {
        feed(&mut state, PEER_C, announce(n6(), &[AS_C, 65300, 65301]));
    }
    let before = sent_to(&mut state, &mut rx, PEER_B);
    assert!(
        announces_v6(&before),
        "precondition: B holds the IPv6 route"
    );
    drain(&mut state, &mut rx);
    (state, rx)
}

/// The `AS_PATH` of the `MP_REACH_NLRI` UPDATE advertising `n6()`.
fn advertised_path(msgs: &[UpdateMessage]) -> Vec<u32> {
    let msg = msgs
        .iter()
        .find(|m| announces_v6(std::slice::from_ref(m)))
        .expect("a replacement MP_REACH_NLRI");
    msg.attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(p) => Some(
                p.segments()
                    .iter()
                    .flat_map(|s| s.asns().iter().map(|a| a.as_u32()))
                    .collect(),
            ),
            _ => None,
        })
        .expect("AS_PATH accompanies MP_REACH_NLRI")
}

/// Every queued `RouteEvent` for `prefix`, as `(type, winning peer address)`.
fn route_events(
    events: &mut broadcast::Receiver<proto::RouteEvent>,
    prefix: Nlri<Ipv6Addr>,
) -> Vec<(proto::RouteEventType, String)> {
    let wanted = prefix.to_string();
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|e| {
            let kind = proto::RouteEventType::try_from(e.r#type).unwrap();
            match (&e.route, &e.withdrawn_prefix) {
                (Some(r), _) if r.prefix == wanted => Some((kind, r.peer_address.clone())),
                (None, Some(p)) if *p == wanted => Some((kind, String::new())),
                _ => None,
            }
        })
        .collect()
}

fn withdrawn_event() -> Vec<(proto::RouteEventType, String)> {
    vec![(proto::RouteEventType::Withdrawn, String::new())]
}

fn announced_event(peer: std::net::Ipv4Addr) -> Vec<(proto::RouteEventType, String)> {
    vec![(proto::RouteEventType::Announced, peer.to_string())]
}

// ── Session loss without Graceful Restart ───────────────────────────────────

/// Unclean loss and a received NOTIFICATION both reach the same flush.
#[test]
fn session_loss_withdraws_v6_from_every_peer() {
    let reasons = [
        TerminationReason::Unclean,
        TerminationReason::OperatorStop,
        TerminationReason::Notification(NotificationMessage {
            error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
            data: vec![],
        }),
    ];
    for reason in reasons {
        let (mut state, mut rx) = seeded(false);

        state.on_terminated(IpAddr::V4(PEER_A), reason.clone(), true);

        assert_eq!(state.rib.loc_rib_v6.len(), 0);
        for observer in [PEER_B, PEER_C] {
            let msgs = sent_to(&mut state, &mut rx, observer);
            assert!(
                withdraws_v6(&msgs),
                "{reason:?}: {observer} not sent MP_UNREACH_NLRI: {msgs:?}"
            );
            assert!(!announces_v6(&msgs), "{reason:?}: {msgs:?}");
        }
        let b = IpAddr::V4(PEER_B);
        assert_eq!(state.adj_ribs_out_v6[&b].len(), 0);
        assert_eq!(state.rib.prefixes_advertised[&b], 0);
    }
}

#[test]
fn session_loss_advertises_the_v6_replacement() {
    let (mut state, mut rx) = seeded(true);

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(
        announces_v6(&to_b),
        "B not sent the new best path: {to_b:?}"
    );
    assert_eq!(advertised_path(&to_b), [LOCAL_AS, AS_C, 65300, 65301]);

    // C now supplies the best path, so the route it was advertised earlier has
    // no replacement toward C and must be withdrawn (RFC 4271 §9.1.3).
    let to_c = sent_to(&mut state, &mut rx, PEER_C);
    assert!(withdraws_v6(&to_c), "{to_c:?}");
    assert!(!announces_v6(&to_c), "{to_c:?}");
}

/// RFC 4760 §8: a peer that did not negotiate IPv6 unicast gets no MP-BGP
/// attributes.
#[test]
fn session_loss_sends_no_v6_update_to_a_v4_only_peer() {
    let (mut state, mut rx) = established();
    state.on_established(
        IpAddr::V4(PEER_B),
        PEER_B,
        PeerType::External,
        super::last_feasible_tests::AS_B,
        90,
        &[Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)],
        None,
    );
    feed(&mut state, PEER_A, announce(n6(), &[AS_A]));
    drain(&mut state, &mut rx);

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    assert!(sent_to(&mut state, &mut rx, PEER_B).is_empty());
    assert!(withdraws_v6(&sent_to(&mut state, &mut rx, PEER_C)));
}

/// The `Terminated` of a peer being removed withdraws its routes at once; the
/// purge of all per-peer state follows on `Retired`.
#[test]
fn remove_peer_withdraws_v6() {
    let (mut state, mut rx) = seeded(false);
    let mut events = state.route_tx.subscribe();
    state.pending_removal.insert(IpAddr::V4(PEER_A));

    let refresh = handle_session_terminated(
        &mut state,
        IpAddr::V4(PEER_A),
        TerminationReason::OperatorStop,
        &Mutex::new(HashMap::new()),
    );

    assert!(refresh.is_none(), "a removed peer gets no new capabilities");
    assert!(withdraws_v6(&sent_to(&mut state, &mut rx, PEER_B)));
    assert_eq!(route_events(&mut events, n6()), withdrawn_event());
}

#[test]
fn session_loss_emits_v6_withdrawn_route_event() {
    let (mut state, _rx) = seeded(false);
    let mut events = state.route_tx.subscribe();

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    assert_eq!(route_events(&mut events, n6()), withdrawn_event());
}

#[test]
fn session_loss_emits_v6_announced_route_event_for_the_replacement() {
    let (mut state, _rx) = seeded(true);
    let mut events = state.route_tx.subscribe();

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    assert_eq!(route_events(&mut events, n6()), announced_event(PEER_C));
}

/// A prefix the lost peer never supplied has not changed, so nothing is said
/// about it (RFC 4271 §9.2 advertises newly installed and newly unfeasible
/// routes only).
#[test]
fn session_loss_leaves_other_peers_v6_routes_alone() {
    let (mut state, mut rx) = seeded(false);
    feed(&mut state, PEER_C, announce(other_n6(), &[AS_C]));
    drain(&mut state, &mut rx);
    let mut events = state.route_tx.subscribe();

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    let other = Prefix::V6(other_n6());
    for msg in sent_to(&mut state, &mut rx, PEER_B) {
        for attr in &msg.attributes {
            match attr {
                PathAttribute::MpReachNlri(r) => assert!(!r.prefixes.contains(&other)),
                PathAttribute::MpUnreachNlri(u) => assert!(!u.prefixes.contains(&other)),
                _ => {}
            }
        }
    }
    assert_eq!(route_events(&mut events, other_n6()), []);
}

// ── Session loss against buffered and reflected routes ──────────────────────

fn announce_v4(path: &[u32]) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(
                path.iter().copied().map(Asn::new).collect(),
            )),
            PathAttribute::NextHop(RESOLVABLE_V4),
        ],
        announced: vec![n4()],
    }
}

/// Whether a receiver applying `msgs` in order ends up holding the prefix that
/// `announces` and `withdraws` look for.
fn holds(
    msgs: &[UpdateMessage],
    announces: fn(&[UpdateMessage]) -> bool,
    withdraws: fn(&[UpdateMessage]) -> bool,
) -> bool {
    msgs.iter().fold(false, |held, msg| {
        let msg = std::slice::from_ref(msg);
        announces(msg) || (held && !withdraws(msg))
    })
}

/// `PEER_A`'s announcement is still buffered, as in one event-loop batch, when
/// its session is lost. B must not be left holding the route (RFC 4271 §3.1,
/// §9.2).
#[test]
fn session_loss_is_not_undone_by_a_buffered_v4_announcement() {
    let (mut state, mut rx) = established();
    feed(&mut state, PEER_A, announce_v4(&[AS_A]));

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    let msgs = sent_to(&mut state, &mut rx, PEER_B);
    assert!(!holds(&msgs, announces_v4, withdraws_v4), "{msgs:?}");
}

#[test]
fn session_loss_is_not_undone_by_a_buffered_v6_announcement() {
    let (mut state, mut rx) = established();
    feed(&mut state, PEER_A, announce(n6(), &[AS_A]));

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    let msgs = sent_to(&mut state, &mut rx, PEER_B);
    assert!(!holds(&msgs, announces_v6, withdraws_v6), "{msgs:?}");
}

/// A route reflector with an eBGP peer A, supplying the best paths, and
/// non-client iBGP peers B and C. C also offers both prefixes, and B has been
/// sent A's routes.
fn reflector_with_non_client_alternative() -> (DaemonState, Receivers) {
    let peers = [(PEER_A, AS_A), (PEER_B, LOCAL_AS), (PEER_C, LOCAL_AS)];
    let (mut state, mut rx) = make_state(LOCAL_AS, &peers.map(|(p, a)| (IpAddr::V4(p), a)));
    state.set_oracles(FixedOracle, FixedOracle);
    let rib = std::sync::Arc::make_mut(&mut state.rib);
    rib.local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    // Naming a client elsewhere makes this speaker a reflector.
    rib.rr_clients.insert("10.0.0.99".parse().unwrap());
    let caps = [
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    for (ip, asn) in peers {
        let kind = if asn == LOCAL_AS {
            PeerType::Internal
        } else {
            PeerType::External
        };
        state.on_established(IpAddr::V4(ip), ip, kind, asn, 90, &caps, None);
    }
    drain(&mut state, &mut rx);
    feed(&mut state, PEER_A, announce_v4(&[AS_A]));
    feed(&mut state, PEER_C, announce_v4(&[65100, 65101]));
    feed(&mut state, PEER_A, announce(n6(), &[AS_A]));
    feed(&mut state, PEER_C, announce(n6(), &[65100, 65101]));
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(
        announces_v4(&to_b) && announces_v6(&to_b),
        "precondition: B holds A's routes"
    );
    drain(&mut state, &mut rx);
    (state, rx)
}

/// The replacement comes from a non-client, so B, also a non-client, is not
/// sent it (RFC 4456 §6) and has A's route withdrawn (RFC 4271 §9.1.3).
#[test]
fn session_loss_withdraws_v4_from_a_non_client_excluded_from_the_replacement() {
    let (mut state, mut rx) = reflector_with_non_client_alternative();

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    let msgs = sent_to(&mut state, &mut rx, PEER_B);
    assert!(!announces_v4(&msgs) && withdraws_v4(&msgs), "{msgs:?}");
}

#[test]
fn session_loss_withdraws_v6_from_a_non_client_excluded_from_the_replacement() {
    let (mut state, mut rx) = reflector_with_non_client_alternative();

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    let msgs = sent_to(&mut state, &mut rx, PEER_B);
    assert!(!announces_v6(&msgs) && withdraws_v6(&msgs), "{msgs:?}");
}

// ── Graceful Restart teardown paths ─────────────────────────────────────────

/// Re-establishes `PEER_A` advertising Graceful Restart for `families`.
fn establish_a_with_gr(state: &mut DaemonState, families: &[AfiSafi]) {
    let caps = [
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: families
                .iter()
                .map(|&afi_safi| GracefulRestartFamily {
                    afi_safi,
                    forwarding_preserved: true,
                })
                .collect(),
        },
    ];
    state.on_established(
        IpAddr::V4(PEER_A),
        PEER_A,
        PeerType::External,
        AS_A,
        90,
        &caps,
        None,
    );
}

/// [`seeded`], with `PEER_A` Graceful-Restart capable for `families`.
fn seeded_gr(families: &[AfiSafi], alternative: bool) -> (DaemonState, Receivers) {
    let (mut state, mut rx) = established();
    establish_a_with_gr(&mut state, families);
    feed(&mut state, PEER_A, announce(n6(), &[AS_A]));
    if alternative {
        feed(&mut state, PEER_C, announce(n6(), &[AS_C, 65300, 65301]));
    }
    drain(&mut state, &mut rx);
    (state, rx)
}

/// A family outside the peer's Graceful Restart capability is flushed at once.
#[test]
fn gr_uncovered_v6_flush_emits_withdrawn_route_event() {
    let (mut state, mut rx) = seeded_gr(&[AfiSafi::IPV4_UNICAST], false);
    let mut events = state.route_tx.subscribe();

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    assert!(withdraws_v6(&sent_to(&mut state, &mut rx, PEER_B)));
    assert_eq!(route_events(&mut events, n6()), withdrawn_event());
}

/// Entering GR helper mode re-evaluates the retained routes and reports them to
/// `WatchRoutes`, as it does for IPv4. The route stays selected.
#[test]
fn gr_stale_marking_emits_v6_route_event() {
    let (mut state, _rx) = seeded_gr(&[AfiSafi::IPV6_UNICAST], false);
    let mut events = state.route_tx.subscribe();

    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);

    assert_eq!(state.rib.loc_rib_v6.len(), 1);
    assert_eq!(route_events(&mut events, n6()), announced_event(PEER_A));
}

#[test]
fn gr_deadline_expiry_withdraws_v6_and_emits_route_event() {
    let (mut state, mut rx) = seeded_gr(&[AfiSafi::IPV6_UNICAST], false);
    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
    drain(&mut state, &mut rx);
    let mut events = state.route_tx.subscribe();

    state.on_gr_deadline_expired(IpAddr::V4(PEER_A));

    assert!(withdraws_v6(&sent_to(&mut state, &mut rx, PEER_B)));
    assert_eq!(route_events(&mut events, n6()), withdrawn_event());
}

#[test]
fn gr_deadline_expiry_replaces_v6_and_emits_route_event() {
    let (mut state, mut rx) = seeded_gr(&[AfiSafi::IPV6_UNICAST], true);
    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
    drain(&mut state, &mut rx);
    let mut events = state.route_tx.subscribe();

    state.on_gr_deadline_expired(IpAddr::V4(PEER_A));

    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert_eq!(advertised_path(&to_b), [LOCAL_AS, AS_C, 65300, 65301]);
    assert_eq!(route_events(&mut events, n6()), announced_event(PEER_C));
}

/// RFC 4724 §4.2: stale routes not refreshed before the End-of-RIB marker are
/// removed.
#[test]
fn gr_end_of_rib_prune_of_v6_emits_withdrawn_route_event() {
    let (mut state, mut rx) = seeded_gr(&[AfiSafi::IPV6_UNICAST], false);
    state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
    establish_a_with_gr(&mut state, &[AfiSafi::IPV6_UNICAST]);
    drain(&mut state, &mut rx);
    let mut events = state.route_tx.subscribe();

    feed(&mut state, PEER_A, end_of_rib_v6());

    assert!(withdraws_v6(&sent_to(&mut state, &mut rx, PEER_B)));
    assert_eq!(route_events(&mut events, n6()), withdrawn_event());
}
