// daemon/outbound_order_tests.rs — issue #159: applying the UPDATEs a peer was
// sent, in order, must leave it holding exactly the Adj-RIB-Out.
//
// RFC 4271 §3.1: "Changing the attribute(s) of a route is accomplished by
// advertising a replacement route.  The replacement route carries new
// (changed) attributes and has the same address prefix as the original route."
// A withdrawal likewise marks the route "as being no longer available for
// use".  Both act on whatever the receiver got before them, so an older
// advertisement sent *after* either one undoes it.
//
// RFC 4271 §9.2: "All newly installed routes and all newly unfeasible routes
// for which there is no replacement route SHALL be advertised to its peers by
// means of an UPDATE message."
//
// RFC 4760 §3: "The next hop information carried in the MP_REACH_NLRI path
// attribute defines the Network Layer address of the router that SHOULD be
// used as the next hop to the destinations listed in the MP_NLRI attribute in
// the UPDATE message." — so prefixes with different next hops cannot share one.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use pathvector_session::message::{
    Capability, GracefulRestartFamily, MpReachNlri, MpUnreachNlri, PathAttribute, Prefix,
    UpdateMessage,
};
use pathvector_session::transport::{SessionEvent, TerminationReason};
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};
use proptest::prelude::*;
use tokio::sync::{RwLock, mpsc};

use super::DaemonState;
use super::last_feasible_tests::{
    AS_A, AS_B, FixedOracle, LOCAL_AS, PEER_A, PEER_B, RESOLVABLE_V4, RESOLVABLE_V4_ALT,
    RESOLVABLE_V6, Receivers, drain, expire_mrai, sent_to,
};
use crate::daemon::tests::make_state;
use crate::outbound::{PrefixDecision, PrefixDecisionV6, flush_updates, flush_updates_v6};

const RESOLVABLE_V6_ALT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 4);

/// The receiving peer under test.
#[derive(Debug, Clone, Copy)]
enum Observer {
    Ebgp,
    Ibgp,
}

const OBSERVERS: [Observer; 2] = [Observer::Ebgp, Observer::Ibgp];

#[derive(Debug, Clone, Copy)]
enum Family {
    V4,
    V6,
}

const FAMILIES: [Family; 2] = [Family::V4, Family::V6];

fn multiprotocol_caps() -> Vec<Capability> {
    vec![
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ]
}

/// A daemon with source peer A (eBGP, with `a_caps`) and observer B.
fn net_with(observer: Observer, a_caps: &[Capability]) -> (DaemonState, Receivers) {
    let (b_as, b_type) = match observer {
        Observer::Ebgp => (AS_B, PeerType::External),
        Observer::Ibgp => (LOCAL_AS, PeerType::Internal),
    };
    let (mut state, mut rx) = make_state(
        LOCAL_AS,
        &[(IpAddr::V4(PEER_A), AS_A), (IpAddr::V4(PEER_B), b_as)],
    );
    state.set_oracles(FixedOracle, FixedOracle);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    state.on_established(
        IpAddr::V4(PEER_A),
        PEER_A,
        PeerType::External,
        AS_A,
        90,
        a_caps,
        None,
    );
    state.on_established(
        IpAddr::V4(PEER_B),
        PEER_B,
        b_type,
        b_as,
        90,
        &multiprotocol_caps(),
        None,
    );
    drain(&mut state, &mut rx);
    (state, rx)
}

fn net(observer: Observer) -> (DaemonState, Receivers) {
    net_with(observer, &multiprotocol_caps())
}

fn prefix_v4(idx: u8) -> Nlri<Ipv4Addr> {
    format!("10.{idx}.0.0/16").parse().unwrap()
}

fn prefix_v6(idx: u8) -> Nlri<Ipv6Addr> {
    format!("2001:db8:{idx}::/48").parse().unwrap()
}

/// An UPDATE from A announcing prefix `idx`. `attrs` selects the `AS_PATH`,
/// `next_hop` one of two resolvable next hops.
fn announce(family: Family, idx: u8, attrs: u8, next_hop: u8) -> UpdateMessage {
    let path = PathAttribute::AsPath(AsPath::from_sequence(vec![
        Asn::new(AS_A),
        Asn::new(65100 + u32::from(attrs)),
    ]));
    let mut attributes = vec![PathAttribute::Origin(Origin::Igp), path];
    let mut announced = vec![];
    match family {
        Family::V4 => {
            attributes.push(PathAttribute::NextHop(
                [RESOLVABLE_V4, RESOLVABLE_V4_ALT][usize::from(next_hop)],
            ));
            announced.push(prefix_v4(idx));
        }
        Family::V6 => attributes.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6([RESOLVABLE_V6, RESOLVABLE_V6_ALT][usize::from(next_hop)]),
            prefixes: vec![Prefix::V6(prefix_v6(idx))],
        })),
    }
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced,
    }
}

fn withdraw(family: Family, idx: u8) -> UpdateMessage {
    let (withdrawn, attributes) = match family {
        Family::V4 => (vec![prefix_v4(idx)], vec![]),
        Family::V6 => (
            vec![],
            vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![Prefix::V6(prefix_v6(idx))],
            })],
        ),
    };
    UpdateMessage {
        withdrawn,
        attributes,
        announced: vec![],
    }
}

fn feed(state: &mut DaemonState, msg: UpdateMessage) {
    assert!(state.on_route_update(IpAddr::V4(PEER_A), msg).is_none());
}

/// What a receiver holds after applying `msgs` in order: prefix -> attributes
/// (for IPv6, including the `MP_REACH_NLRI` next hop).
fn view(msgs: &[UpdateMessage]) -> BTreeMap<String, String> {
    let mut held = BTreeMap::new();
    for msg in msgs {
        for nlri in &msg.withdrawn {
            held.remove(&nlri.to_string());
        }
        let attrs: Vec<_> = msg
            .attributes
            .iter()
            .filter(|a| {
                !matches!(
                    a,
                    PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_)
                )
            })
            .collect();
        for attribute in &msg.attributes {
            match attribute {
                PathAttribute::MpUnreachNlri(unreach) => {
                    for prefix in &unreach.prefixes {
                        held.remove(&format!("{prefix:?}"));
                    }
                }
                PathAttribute::MpReachNlri(reach) => {
                    for prefix in &reach.prefixes {
                        held.insert(
                            format!("{prefix:?}"),
                            format!("{:?} {attrs:?}", reach.next_hop),
                        );
                    }
                }
                _ => {}
            }
        }
        for nlri in &msg.announced {
            held.insert(nlri.to_string(), format!("{attrs:?}"));
        }
    }
    held
}

/// The view B must hold: each Adj-RIB-Out route, encoded on its own so that no
/// batching or grouping can influence the expectation.
fn adj_rib_out_view(state: &DaemonState) -> BTreeMap<String, String> {
    let peer = IpAddr::V4(PEER_B);
    let peer_type = state.rib.peer_types[&peer];
    let four_byte = state.four_byte_peers.contains(&peer);
    let (tx, mut rx) = mpsc::channel(256);
    for (_, route) in state.adj_ribs_out[&peer].routes() {
        let decision = PrefixDecision::Announce(route.clone());
        assert!(flush_updates(
            peer,
            vec![decision],
            4096,
            &tx,
            peer_type,
            four_byte
        ));
    }
    for (_, route) in state.adj_ribs_out_v6[&peer].routes() {
        let decision = PrefixDecisionV6::Announce(route.clone());
        assert!(flush_updates_v6(
            peer,
            vec![decision],
            4096,
            &tx,
            peer_type,
            four_byte
        ));
    }
    let msgs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    view(&msgs)
}

/// Feeds `updates` with no flush in between, then checks what B holds against
/// the Adj-RIB-Out and returns it.
fn run_batch(observer: Observer, updates: Vec<UpdateMessage>) -> BTreeMap<String, String> {
    let (mut state, mut rx) = net(observer);
    for update in updates {
        feed(&mut state, update);
    }
    let held = view(&sent_to(&mut state, &mut rx, PEER_B));
    assert_eq!(held, adj_rib_out_view(&state), "{observer:?}");
    held
}

#[test]
fn announce_then_withdraw_in_one_batch_leaves_nothing() {
    for observer in OBSERVERS {
        for family in FAMILIES {
            let held = run_batch(
                observer,
                vec![announce(family, 1, 0, 0), withdraw(family, 1)],
            );
            assert!(held.is_empty(), "{observer:?} {family:?}: {held:?}");
        }
    }
}

#[test]
fn withdraw_then_announce_in_one_batch_leaves_the_new_route() {
    for observer in OBSERVERS {
        for family in FAMILIES {
            let (mut state, mut rx) = net(observer);
            feed(&mut state, announce(family, 1, 0, 0));
            let mut msgs = sent_to(&mut state, &mut rx, PEER_B);
            feed(&mut state, withdraw(family, 1));
            feed(&mut state, announce(family, 1, 1, 0));
            msgs.extend(sent_to(&mut state, &mut rx, PEER_B));

            let held = view(&msgs);
            assert_eq!(held.len(), 1, "{observer:?} {family:?}");
            assert_eq!(held, adj_rib_out_view(&state), "{observer:?} {family:?}");
        }
    }
}

/// Prefix 2 opens the attribute group that prefix 1's replacement joins, so
/// that group is sent ahead of prefix 1's older announcement.
///
/// An iBGP peer gets the replacement directly. For an eBGP peer MRAI holds a
/// plain replacement back, so the second sequence withdraws in between (a
/// withdrawal is not delayed, and restarts the destination's interval).
#[test]
fn replaced_announcement_sharing_a_group_leaves_the_replacement() {
    for observer in OBSERVERS {
        for family in FAMILIES {
            let replaced = vec![
                announce(family, 2, 1, 0),
                announce(family, 1, 0, 0),
                announce(family, 1, 1, 0),
            ];
            let mut with_withdrawal = replaced.clone();
            with_withdrawal.insert(2, withdraw(family, 1));

            for updates in [replaced, with_withdrawal] {
                run_batch(observer, updates);
            }
        }
    }
}

/// An identical re-announcement yields `NoChange`; the buffered announcement
/// it follows must still be sent.
#[test]
fn no_change_does_not_discard_a_pending_announcement() {
    for observer in OBSERVERS {
        for family in FAMILIES {
            let update = announce(family, 1, 0, 0);
            let held = run_batch(observer, vec![update.clone(), update]);
            assert_eq!(held.len(), 1, "{observer:?} {family:?}");
        }
    }
}

/// RFC 4271 §9.2.1.1: MRAI holds the replacement back (`NoChange`), so the
/// first route goes now and "the last route selected SHALL be advertised at the
/// end of MinRouteAdvertisementIntervalTimer".
#[test]
fn mrai_hold_does_not_discard_the_pending_announcement() {
    for family in FAMILIES {
        let (mut state, mut rx) = net(Observer::Ebgp);
        feed(&mut state, announce(family, 1, 0, 0));
        feed(&mut state, announce(family, 1, 1, 0));
        let mut msgs = sent_to(&mut state, &mut rx, PEER_B);
        let first = view(&msgs);
        assert_eq!(first.len(), 1, "{family:?}");
        assert_eq!(first, adj_rib_out_view(&state), "{family:?}");

        expire_mrai(&mut state);
        state.flush_mrai_pending();
        msgs.extend(sent_to(&mut state, &mut rx, PEER_B));
        let last = view(&msgs);
        assert_ne!(first, last, "{family:?}");
        assert_eq!(last, adj_rib_out_view(&state), "{family:?}");
    }
}

/// RFC 4760 §3: prefixes with equal attributes but different next hops must
/// each be advertised with their own. An iBGP peer sees next hops unchanged.
#[test]
fn v6_prefixes_with_different_next_hops_keep_their_own() {
    let held = run_batch(
        Observer::Ibgp,
        vec![announce(Family::V6, 1, 0, 0), announce(Family::V6, 2, 0, 1)],
    );
    assert_eq!(held.len(), 2);
}

/// A teardown sends its withdrawals itself rather than leaving them for the
/// end-of-batch flush; they must not overtake the buffered announcement.
#[test]
fn session_loss_does_not_overtake_a_pending_announcement() {
    for observer in OBSERVERS {
        let (mut state, mut rx) = net(observer);
        feed(&mut state, announce(Family::V4, 1, 0, 0));
        state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
        let held = view(&sent_to(&mut state, &mut rx, PEER_B));
        assert!(held.is_empty(), "{observer:?}: {held:?}");
        assert_eq!(held, adj_rib_out_view(&state), "{observer:?}");
    }
}

/// IPv6 form of the above, through a path that does withdraw IPv6 at once: a
/// Graceful Restart peer whose capability covers only IPv4 (RFC 4724 §4.2)
/// has its IPv6 routes removed when the session drops.
#[test]
fn gr_family_flush_does_not_overtake_a_pending_v6_announcement() {
    let mut a_caps = multiprotocol_caps();
    a_caps.push(Capability::GracefulRestart {
        restart_flags: 0,
        restart_time: 120,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: true,
        }],
    });
    for observer in OBSERVERS {
        let (mut state, mut rx) = net_with(observer, &a_caps);
        feed(&mut state, announce(Family::V6, 1, 0, 0));
        state.on_terminated(IpAddr::V4(PEER_A), TerminationReason::Unclean, true);
        assert_eq!(state.rib.loc_rib_v6.len(), 0, "precondition");
        let held = view(&sent_to(&mut state, &mut rx, PEER_B));
        assert!(held.is_empty(), "{observer:?}: {held:?}");
        assert_eq!(held, adj_rib_out_view(&state), "{observer:?}");
    }
}

/// Runs `events` from peer A through the real event loop, all already queued so
/// that they are coalesced into one batch. Returns what B was sent.
async fn run_queued(
    state: DaemonState,
    mut rx: Receivers,
    events: Vec<SessionEvent>,
) -> (Arc<RwLock<DaemonState>>, Vec<UpdateMessage>) {
    let state = Arc::new(RwLock::new(state));
    let (tx, event_rx) = mpsc::channel(16);
    for event in events {
        tx.send((IpAddr::V4(PEER_A), event)).await.unwrap();
    }
    drop(tx);
    super::run_event_loop(
        event_rx,
        Arc::clone(&state),
        Arc::new(Mutex::new(std::collections::HashMap::new())),
        None,
    )
    .await;
    let receiver = rx.get_mut(&IpAddr::V4(PEER_B)).unwrap();
    let msgs = std::iter::from_fn(|| receiver.try_recv().ok()).collect();
    (state, msgs)
}

#[tokio::test]
async fn event_loop_announce_then_withdraw() {
    for observer in OBSERVERS {
        for family in FAMILIES {
            let (state, rx) = net(observer);
            let events = vec![
                SessionEvent::RouteUpdate(announce(family, 1, 0, 0)),
                SessionEvent::RouteUpdate(withdraw(family, 1)),
            ];
            let (state, msgs) = run_queued(state, rx, events).await;
            let held = view(&msgs);
            assert!(held.is_empty(), "{observer:?} {family:?}: {held:?}");
            assert_eq!(held, adj_rib_out_view(&*state.read().await));
        }
    }
}

#[tokio::test]
async fn event_loop_announce_then_session_loss() {
    for observer in OBSERVERS {
        let (state, rx) = net(observer);
        let events = vec![
            SessionEvent::RouteUpdate(announce(Family::V4, 1, 0, 0)),
            SessionEvent::Terminated(TerminationReason::Unclean),
        ];
        let (state, msgs) = run_queued(state, rx, events).await;
        let held = view(&msgs);
        assert!(held.is_empty(), "{observer:?}: {held:?}");
        assert_eq!(held, adj_rib_out_view(&*state.read().await));
    }
}

#[derive(Debug, Clone)]
enum Op {
    Announce { idx: u8, attrs: u8, next_hop: u8 },
    Withdraw { idx: u8 },
    Flush,
    ExpireMrai,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0u8..3, 0u8..3, 0u8..2).prop_map(|(idx, attrs, next_hop)| Op::Announce {
            idx,
            attrs,
            next_hop
        }),
        3 => (0u8..3).prop_map(|idx| Op::Withdraw { idx }),
        1 => Just(Op::Flush),
        1 => Just(Op::ExpireMrai),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// After every flush, everything B has been sent so far, applied in order,
    /// matches its Adj-RIB-Out — whatever the batch contained.
    #[test]
    fn sent_updates_always_match_adj_rib_out(
        ops in proptest::collection::vec((any::<bool>(), op()), 1..40),
        observer in prop_oneof![Just(Observer::Ebgp), Just(Observer::Ibgp)],
    ) {
        let (mut state, mut rx) = net(observer);
        let mut msgs = Vec::new();
        for (is_v6, op) in ops.into_iter().chain([(false, Op::Flush)]) {
            let family = if is_v6 { Family::V6 } else { Family::V4 };
            match op {
                Op::Announce { idx, attrs, next_hop } => {
                    feed(&mut state, announce(family, idx, attrs, next_hop));
                }
                Op::Withdraw { idx } => feed(&mut state, withdraw(family, idx)),
                Op::ExpireMrai => {
                    expire_mrai(&mut state);
                    state.flush_mrai_pending();
                }
                Op::Flush => {
                    msgs.extend(sent_to(&mut state, &mut rx, PEER_B));
                    prop_assert_eq!(view(&msgs), adj_rib_out_view(&state));
                }
            }
        }
    }
}
