// daemon/rr_split_horizon_tests.rs — issue #168: the route-reflector non-client
// split-horizon rule holds on every path that sends a route to a peer.
//
// RFC 4456 §6: "A route from a Non-Client IBGP peer: Reflect to all the
// Clients." / "A route from a Client peer: Reflect to all the Non-Client peers
// and also to the Client peers."  A route from one non-client therefore never
// goes to another non-client.
//
// RFC 4271 §9.1.3: "If a route in Loc-RIB is excluded from a particular
// Adj-RIB-Out, the previously advertised route in that Adj-RIB-Out MUST be
// withdrawn from service by means of an UPDATE message (see 9.2)."
//
// Each send path is tested for IPv4 and IPv6, in one or both directions:
// "suppressed" (a non-client's route must not be advertised to a non-client)
// and "withdrawn" (a non-client that holds a client's route must be sent a
// withdrawal once a non-client's path replaces it). Every "suppressed" test
// also checks that the client did get the route, so the path under test really
// ran.
//
// IPv6 session loss without Graceful Restart sends nothing at all until issue
// #160 is fixed, so the IPv6 teardown cases here go through the flush of a
// family the Graceful Restart capability does not cover.

use std::net::{IpAddr, Ipv4Addr};

use pathvector_policy::DefaultAction;
use pathvector_rib::RouteBuilder;
use pathvector_session::message::{
    Capability, GracefulRestartFamily, MpReachNlri, MpUnreachNlri, PathAttribute, Prefix,
    UpdateMessage,
};
use pathvector_session::transport::TerminationReason;
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Origin, PeerType};
use tokio::sync::mpsc;

use super::DaemonState;
use super::last_feasible_tests::{
    FixedOracle, LOCAL_AS, PEER_A, PEER_B, PEER_C, RESOLVABLE_V4, RESOLVABLE_V6, Receivers,
    announces_v4, announces_v6, drain, n4, n6, sent_to, withdraws_v4, withdraws_v6,
};
use super::tests::make_state;

// PEER_A, PEER_B and PEER_C are non-clients; B is the observer.

/// The reflector's only client.
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

const BOTH: &[AfiSafi] = &[AfiSafi::IPV4_UNICAST, AfiSafi::IPV6_UNICAST];

/// The capabilities a peer opens with; `gr` lists the families it asks the
/// reflector to retain across a restart.
fn caps(gr: &[AfiSafi]) -> Vec<Capability> {
    let mut caps = vec![
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ];
    if !gr.is_empty() {
        caps.push(Capability::GracefulRestart {
            restart_flags: 0,
            restart_time: 120,
            families: gr
                .iter()
                .map(|&afi_safi| GracefulRestartFamily {
                    afi_safi,
                    forwarding_preserved: true,
                })
                .collect(),
        });
    }
    caps
}

fn establish(state: &mut DaemonState, peer: Ipv4Addr, gr: &[AfiSafi]) {
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::Internal,
        LOCAL_AS,
        90,
        &caps(gr),
        None,
    );
}

/// Route reflector with non-clients A, B, C and one client, all established.
/// `gr_peer` opens with Graceful Restart for the given families.
fn reflector(gr_peer: Option<(Ipv4Addr, &[AfiSafi])>) -> (DaemonState, Receivers) {
    let peers = [PEER_A, PEER_B, PEER_C, CLIENT];
    let (mut state, mut rx) = make_state(LOCAL_AS, &peers.map(|p| (IpAddr::V4(p), LOCAL_AS)));
    state.set_oracles(FixedOracle, FixedOracle);
    let rib = std::sync::Arc::make_mut(&mut state.rib);
    rib.local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    rib.rr_clients.insert(IpAddr::V4(CLIENT));
    for ip in peers {
        let gr = match gr_peer {
            Some((peer, families)) if peer == ip => families,
            _ => &[],
        };
        establish(&mut state, ip, gr);
    }
    drain(&mut state, &mut rx);
    (state, rx)
}

fn path(len: u32) -> PathAttribute {
    PathAttribute::AsPath(AsPath::from_sequence(
        (0..len).map(|i| Asn::new(65100 + i)).collect(),
    ))
}

/// Announces both test prefixes from `peer` with an AS_PATH of `len` ASes, so
/// a shorter path is preferred.
fn announce_both(state: &mut DaemonState, peer: Ipv4Addr, len: u32) {
    let v4 = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            path(len),
            PathAttribute::NextHop(RESOLVABLE_V4),
        ],
        announced: vec![n4()],
    };
    let v6 = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            path(len),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                next_hop: NextHop::V6(RESOLVABLE_V6),
                prefixes: vec![Prefix::V6(n6())],
            }),
        ],
        announced: vec![],
    };
    for msg in [v4, v6] {
        assert!(state.on_route_update(IpAddr::V4(peer), msg).is_none());
    }
}

/// Sends both address families' End-of-RIB markers from `peer` (RFC 4724 §2).
fn send_eor(state: &mut DaemonState, peer: Ipv4Addr) {
    let v4 = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    };
    let v6 = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            prefixes: vec![],
        })],
        announced: vec![],
    };
    for msg in [v4, v6] {
        assert!(state.on_route_update(IpAddr::V4(peer), msg).is_none());
    }
}

fn lose(state: &mut DaemonState, peer: Ipv4Addr) {
    state.on_terminated(IpAddr::V4(peer), TerminationReason::Unclean, true);
}

/// Number of routes in `peer`'s IPv4 and IPv6 Adj-RIBs-Out.
fn held(state: &DaemonState, peer: Ipv4Addr) -> (usize, usize) {
    let ip = IpAddr::V4(peer);
    (
        state.adj_ribs_out[&ip].len(),
        state.adj_ribs_out_v6[&ip].len(),
    )
}

/// The client's paths are preferred over non-client A's, so non-client B has
/// been sent the client's routes. `gr` is the client's Graceful Restart set.
fn client_best_non_client_backup(gr: &[AfiSafi]) -> (DaemonState, Receivers) {
    let (mut state, mut rx) = reflector((!gr.is_empty()).then_some((CLIENT, gr)));
    announce_both(&mut state, CLIENT, 1);
    announce_both(&mut state, PEER_A, 2);
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(
        announces_v4(&to_b) && announces_v6(&to_b),
        "precondition: B holds the client's routes: {to_b:?}"
    );
    drain(&mut state, &mut rx);
    (state, rx)
}

/// Non-clients A (preferred) and C both offer both prefixes, so non-client B
/// has been sent nothing. `gr` is A's Graceful Restart set.
fn two_non_client_paths(gr: &[AfiSafi]) -> (DaemonState, Receivers) {
    let (mut state, mut rx) = reflector((!gr.is_empty()).then_some((PEER_A, gr)));
    announce_both(&mut state, PEER_A, 1);
    announce_both(&mut state, PEER_C, 2);
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(to_b.is_empty(), "control: nothing reflected to B: {to_b:?}");
    drain(&mut state, &mut rx);
    (state, rx)
}

fn assert_withdrawn_v4(state: &mut DaemonState, rx: &mut Receivers) {
    let to_b = sent_to(state, rx, PEER_B);
    assert!(withdraws_v4(&to_b), "B not sent a withdrawal: {to_b:?}");
    assert!(!announces_v4(&to_b), "{to_b:?}");
    assert_eq!(held(state, PEER_B).0, 0, "B's Adj-RIB-Out");
}

fn assert_withdrawn_v6(to_b: &[UpdateMessage], state: &DaemonState) {
    assert!(withdraws_v6(to_b), "B not sent a withdrawal: {to_b:?}");
    assert!(!announces_v6(to_b), "{to_b:?}");
    assert_eq!(held(state, PEER_B).1, 0, "B's Adj-RIB-Out");
}

fn assert_withdrawn_both(state: &mut DaemonState, rx: &mut Receivers) {
    let to_b = sent_to(state, rx, PEER_B);
    assert!(
        withdraws_v4(&to_b),
        "B not sent an IPv4 withdrawal: {to_b:?}"
    );
    assert!(!announces_v4(&to_b), "{to_b:?}");
    assert_eq!(held(state, PEER_B).0, 0, "B's IPv4 Adj-RIB-Out");
    assert_withdrawn_v6(&to_b, state);
}

fn assert_nothing_for_b(state: &mut DaemonState, rx: &mut Receivers) {
    let to_b = sent_to(state, rx, PEER_B);
    assert!(
        !announces_v4(&to_b) && !announces_v6(&to_b),
        "non-client route reflected to a non-client: {to_b:?}"
    );
    assert_eq!(held(state, PEER_B), (0, 0), "B's Adj-RIBs-Out");
}

fn assert_client_sent_both(state: &mut DaemonState, rx: &mut Receivers) {
    let to_client = sent_to(state, rx, CLIENT);
    assert!(
        announces_v4(&to_client) && announces_v6(&to_client),
        "the client must still be sent the replacement: {to_client:?}"
    );
}

// ── Incremental propagation ──────────────────────────────────────────────────

#[test]
fn update_taking_over_from_client_withdraws_v4_and_v6() {
    let (mut state, mut rx) = reflector(None);
    announce_both(&mut state, CLIENT, 2);
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(announces_v4(&to_b) && announces_v6(&to_b), "{to_b:?}");
    announce_both(&mut state, PEER_A, 1);
    assert_withdrawn_both(&mut state, &mut rx);
}

// ── Opening table dump ───────────────────────────────────────────────────────

/// A non-client that connects while another non-client's routes are retained
/// for Graceful Restart: the source has no session, but is still a non-client.
#[test]
fn dump_during_non_client_restart_suppresses_stale_routes_v4_and_v6() {
    let (mut state, mut rx) = reflector(Some((PEER_A, BOTH)));
    announce_both(&mut state, PEER_A, 1);
    lose(&mut state, PEER_B);
    lose(&mut state, CLIENT);
    lose(&mut state, PEER_A);
    drain(&mut state, &mut rx);

    establish(&mut state, PEER_B, &[]);
    establish(&mut state, CLIENT, &[]);

    assert_nothing_for_b(&mut state, &mut rx);
    assert_client_sent_both(&mut state, &mut rx);
}

// ── Session loss ─────────────────────────────────────────────────────────────

#[test]
fn session_loss_suppresses_non_client_replacement_v4() {
    let (mut state, mut rx) = two_non_client_paths(&[]);
    lose(&mut state, PEER_A);
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(!announces_v4(&to_b), "{to_b:?}");
    assert_eq!(held(&state, PEER_B).0, 0);
    assert!(announces_v4(&sent_to(&mut state, &mut rx, CLIENT)));
}

#[test]
fn session_loss_withdraws_when_non_client_takes_over_v4() {
    let (mut state, mut rx) = client_best_non_client_backup(&[]);
    lose(&mut state, CLIENT);
    assert_withdrawn_v4(&mut state, &mut rx);
}

/// A restarts with Graceful Restart for IPv4 only, so its IPv6 routes are
/// flushed at once (RFC 4724 §4.2).
#[test]
fn uncovered_family_flush_suppresses_non_client_replacement_v6() {
    let (mut state, mut rx) = two_non_client_paths(&[AfiSafi::IPV4_UNICAST]);
    lose(&mut state, PEER_A);
    assert_nothing_for_b(&mut state, &mut rx);
    assert!(announces_v6(&sent_to(&mut state, &mut rx, CLIENT)));
}

#[test]
fn uncovered_family_flush_withdraws_when_non_client_takes_over_v6() {
    let (mut state, mut rx) = client_best_non_client_backup(&[AfiSafi::IPV4_UNICAST]);
    lose(&mut state, CLIENT);
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert_withdrawn_v6(&to_b, &state);
}

#[test]
fn uncovered_family_flush_withdraws_when_non_client_takes_over_v4() {
    let (mut state, mut rx) = client_best_non_client_backup(&[AfiSafi::IPV6_UNICAST]);
    lose(&mut state, CLIENT);
    assert_withdrawn_v4(&mut state, &mut rx);
}

// ── Graceful Restart: stale marking ──────────────────────────────────────────

#[test]
fn stale_marking_suppresses_non_client_routes_v4_and_v6() {
    let (mut state, mut rx) = two_non_client_paths(BOTH);
    lose(&mut state, PEER_A);
    assert_nothing_for_b(&mut state, &mut rx);
    assert_eq!(held(&state, CLIENT), (1, 1), "control");
}

// ── Graceful Restart: deadline expiry ────────────────────────────────────────

#[test]
fn gr_expiry_suppresses_non_client_replacement_v4_and_v6() {
    let (mut state, mut rx) = two_non_client_paths(BOTH);
    lose(&mut state, PEER_A);
    drain(&mut state, &mut rx);
    state.on_gr_deadline_expired(IpAddr::V4(PEER_A));
    assert_nothing_for_b(&mut state, &mut rx);
    assert_client_sent_both(&mut state, &mut rx);
}

#[test]
fn gr_expiry_withdraws_when_non_client_takes_over_v4_and_v6() {
    let (mut state, mut rx) = client_best_non_client_backup(BOTH);
    lose(&mut state, CLIENT);
    drain(&mut state, &mut rx);
    assert_eq!(held(&state, PEER_B), (1, 1), "retained while stale");
    state.on_gr_deadline_expired(IpAddr::V4(CLIENT));
    assert_withdrawn_both(&mut state, &mut rx);
}

// ── Graceful Restart: End-of-RIB prune ───────────────────────────────────────

/// `peer` restarts, comes back, and ends its table without re-announcing.
fn restart_without_readvertising(state: &mut DaemonState, rx: &mut Receivers, peer: Ipv4Addr) {
    lose(state, peer);
    establish(state, peer, BOTH);
    drain(state, rx);
    send_eor(state, peer);
}

#[test]
fn eor_prune_suppresses_non_client_replacement_v4_and_v6() {
    let (mut state, mut rx) = two_non_client_paths(BOTH);
    restart_without_readvertising(&mut state, &mut rx, PEER_A);
    assert_nothing_for_b(&mut state, &mut rx);
    assert_client_sent_both(&mut state, &mut rx);
}

#[test]
fn eor_prune_withdraws_when_non_client_takes_over_v4_and_v6() {
    let (mut state, mut rx) = client_best_non_client_backup(BOTH);
    restart_without_readvertising(&mut state, &mut rx, CLIENT);
    assert_withdrawn_both(&mut state, &mut rx);
}

// ── Export-policy change ─────────────────────────────────────────────────────

#[test]
fn export_policy_change_suppresses_non_client_routes_v4_and_v6() {
    let (mut state, mut rx) = two_non_client_paths(&[]);
    state.set_export_default(IpAddr::V4(PEER_B), DefaultAction::Accept);
    assert_nothing_for_b(&mut state, &mut rx);

    // Control: the same re-evaluation does send them to the client.
    state.set_export_default(IpAddr::V4(CLIENT), DefaultAction::Reject);
    drain(&mut state, &mut rx);
    state.set_export_default(IpAddr::V4(CLIENT), DefaultAction::Accept);
    assert_client_sent_both(&mut state, &mut rx);
}

// ── What the rule must not exclude ───────────────────────────────────────────

/// RFC 4456 §6: a client's route is reflected to non-clients, on a path other
/// than incremental propagation too.
#[test]
fn client_replacement_is_still_sent_to_non_client_v4_and_v6() {
    let (mut state, mut rx) = reflector(Some((PEER_A, BOTH)));
    announce_both(&mut state, PEER_A, 1);
    announce_both(&mut state, CLIENT, 2);
    drain(&mut state, &mut rx);
    lose(&mut state, PEER_A);
    drain(&mut state, &mut rx);
    state.on_gr_deadline_expired(IpAddr::V4(PEER_A));
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(announces_v4(&to_b) && announces_v6(&to_b), "{to_b:?}");
}

/// A locally originated route is not "a route from an IBGP peer" (RFC 4456
/// §6), so a non-client is sent it.
#[test]
fn locally_originated_routes_are_still_sent_to_non_client_v4_and_v6() {
    let (mut state, mut rx) = reflector(None);
    state.originate_route(
        RouteBuilder::new(n4(), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(RESOLVABLE_V4))
            .peer_type(PeerType::Local)
            .build(),
    );
    state.originate_route_v6(
        RouteBuilder::new(n6(), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6(RESOLVABLE_V6))
            .peer_type(PeerType::Local)
            .build(),
    );
    let to_b = sent_to(&mut state, &mut rx, PEER_B);
    assert!(announces_v4(&to_b) && announces_v6(&to_b), "{to_b:?}");
}

// ── Peers reached over IPv6 ──────────────────────────────────────────────────

/// The rule does not depend on the address family of the sessions themselves.
#[test]
fn non_clients_on_ipv6_transport_are_not_reflected_to_each_other() {
    let source: IpAddr = "2001:db8::2".parse().unwrap();
    let observer: IpAddr = "2001:db8::3".parse().unwrap();
    let client: IpAddr = "2001:db8::5".parse().unwrap();
    let peers = [source, observer, client];
    let (mut state, mut rx) = make_state(LOCAL_AS, &peers.map(|p| (p, LOCAL_AS)));
    state.set_oracles(FixedOracle, FixedOracle);
    let rib = std::sync::Arc::make_mut(&mut state.rib);
    rib.local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    rib.rr_clients.insert(client);
    for (n, ip) in (2..).zip(peers) {
        state.on_established(
            ip,
            Ipv4Addr::new(10, 0, 0, n),
            PeerType::Internal,
            LOCAL_AS,
            90,
            &caps(&[]),
            None,
        );
    }

    let v4 = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            path(1),
            PathAttribute::NextHop(RESOLVABLE_V4),
        ],
        announced: vec![n4()],
    };
    assert!(state.on_route_update(source, v4).is_none());
    state.flush_pending();

    let drain_one = |rx: &mut mpsc::Receiver<UpdateMessage>| -> Vec<UpdateMessage> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    };
    let to_observer = drain_one(rx.get_mut(&observer).unwrap());
    assert!(!announces_v4(&to_observer), "{to_observer:?}");
    assert!(announces_v4(&drain_one(rx.get_mut(&client).unwrap())));
}
