// daemon/rr_reflection_tests.rs — issues #177 and #135: a route reflector adds
// ORIGINATOR_ID and CLUSTER_LIST when it reflects a route, not when it
// receives one.
//
// RFC 4456 §8: ORIGINATOR_ID "will be created by an RR in reflecting a route.
// This attribute will carry the BGP Identifier of the originator of the route
// in the local AS.  A BGP speaker SHOULD NOT create an ORIGINATOR_ID attribute
// if one already exists." And: "When an RR reflects a route, it MUST prepend
// the local CLUSTER_ID to the CLUSTER_LIST.  If the CLUSTER_LIST is empty, it
// MUST create a new one."
//
// RFC 4456 §5: reflection is "the operation of a BGP speaker advertising an
// IBGP learned route to another IBGP peer".
//
// RFC 4271 §3.2: "The Adj-RIBs-In contains unprocessed routing information
// that has been advertised to the local BGP speaker by its peers."
//
// RFC 4271 §4.3: "An UPDATE message might advertise only routes that are to be
// withdrawn from service, in which case the message will not include path
// attributes or Network Layer Reachability Information." RFC 4760 §4: "An
// UPDATE message that contains the MP_UNREACH_NLRI is not required to carry
// any other path attributes."
//
// RFC 7606 §5.2 resets the session only for an UPDATE that, as received, "does
// contain path attributes other than MP_UNREACH_NLRI and doesn't encode any
// reachable NLRI" and has an attribute error.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use pathvector_rib::PeerId;
use pathvector_session::message::{
    Capability, MpReachNlri, MpUnreachNlri, NotificationError, PathAttribute, Prefix,
    UpdateMessage, UpdateMsgError,
};
use pathvector_session::transport::{SessionEvent, TerminationReason};
use pathvector_types::{AfiSafi, AsPath, AsPathSegment, Asn, NextHop, Origin, PeerType};
use tokio::sync::{RwLock, mpsc};

use super::DaemonState;
use super::last_feasible_tests::{n4, n6};
use crate::daemon::tests::make_rr_state;

const LOCAL_AS: u32 = 65001;
const CLUSTER_ID: u32 = 99;
/// Route-reflector clients. Their BGP Identifiers differ from their session
/// addresses so ORIGINATOR_ID cannot be satisfied by the wrong one.
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CLIENT_ID: Ipv4Addr = Ipv4Addr::new(2, 2, 2, 2);
const CLIENT_2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const CLIENT_2_ID: Ipv4Addr = Ipv4Addr::new(3, 3, 3, 3);
const NON_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
const NON_CLIENT_ID: Ipv4Addr = Ipv4Addr::new(4, 4, 4, 4);

const NEXT_HOP_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NEXT_HOP_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

type Receivers = HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>;

fn caps() -> [Capability; 3] {
    [
        Capability::FourByteAsn(LOCAL_AS),
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Family {
    V4,
    /// IPv4 unicast carried in `MP_REACH_NLRI` / `MP_UNREACH_NLRI`.
    V4Mp,
    V6,
}

const FAMILIES: [Family; 3] = [Family::V4, Family::V4Mp, Family::V6];

fn establish(state: &mut DaemonState, ip: Ipv4Addr, id: Ipv4Addr, peer_type: PeerType) {
    state.on_established(IpAddr::V4(ip), id, peer_type, LOCAL_AS, 90, &caps(), None);
}

fn drain(state: &mut DaemonState, rxs: &mut Receivers) {
    state.flush_pending();
    for rx in rxs.values_mut() {
        while rx.try_recv().is_ok() {}
    }
}

/// A reflector with two clients and one non-client, all Established.
fn rr_setup() -> (DaemonState, Receivers) {
    let (mut state, mut rxs) =
        make_rr_state(LOCAL_AS, CLUSTER_ID, &[CLIENT, CLIENT_2], &[NON_CLIENT]);
    Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    for (ip, id) in [
        (CLIENT, CLIENT_ID),
        (CLIENT_2, CLIENT_2_ID),
        (NON_CLIENT, NON_CLIENT_ID),
    ] {
        establish(&mut state, ip, id, PeerType::Internal);
    }
    drain(&mut state, &mut rxs);
    (state, rxs)
}

fn announce_with(family: Family, extra: &[PathAttribute]) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65100)])),
        PathAttribute::LocalPref(100),
    ];
    attributes.extend_from_slice(extra);
    let mut announced = vec![];
    match family {
        Family::V4 => {
            attributes.push(PathAttribute::NextHop(NEXT_HOP_V4));
            announced.push(n4());
        }
        Family::V4Mp => attributes.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV4_UNICAST,
            next_hop: NextHop::V4(NEXT_HOP_V4),
            prefixes: vec![Prefix::V4(n4())],
        })),
        Family::V6 => attributes.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6(NEXT_HOP_V6),
            prefixes: vec![Prefix::V6(n6())],
        })),
    }
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced,
    }
}

fn announce(family: Family) -> UpdateMessage {
    announce_with(family, &[])
}

/// A withdraw-only UPDATE (RFC 4271 §4.3 / RFC 4760 §4).
fn withdraw(family: Family) -> UpdateMessage {
    let mp = |afi_safi, prefix| {
        vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi_safi,
            prefixes: vec![prefix],
        })]
    };
    let (withdrawn, attributes) = match family {
        Family::V4 => (vec![n4()], vec![]),
        Family::V4Mp => (vec![], mp(AfiSafi::IPV4_UNICAST, Prefix::V4(n4()))),
        Family::V6 => (vec![], mp(AfiSafi::IPV6_UNICAST, Prefix::V6(n6()))),
    };
    UpdateMessage {
        withdrawn,
        attributes,
        announced: vec![],
    }
}

fn carries_announcement(msg: &UpdateMessage, family: Family) -> bool {
    match family {
        Family::V4 | Family::V4Mp => msg.announced.contains(&n4()),
        Family::V6 => msg.attributes.iter().any(|a| {
            matches!(a, PathAttribute::MpReachNlri(mp) if mp.prefixes.contains(&Prefix::V6(n6())))
        }),
    }
}

fn carries_withdrawal(msg: &UpdateMessage, family: Family) -> bool {
    match family {
        Family::V4 | Family::V4Mp => msg.withdrawn.contains(&n4()),
        Family::V6 => msg.attributes.iter().any(|a| {
            matches!(a, PathAttribute::MpUnreachNlri(mp) if mp.prefixes.contains(&Prefix::V6(n6())))
        }),
    }
}

fn sent_to(state: &mut DaemonState, rxs: &mut Receivers, peer: Ipv4Addr) -> Vec<UpdateMessage> {
    state.flush_pending();
    let rx = rxs.get_mut(&IpAddr::V4(peer)).unwrap();
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// The single announcement of `family`'s prefix among the UPDATEs sent to `peer`.
fn advertised_to(
    state: &mut DaemonState,
    rxs: &mut Receivers,
    peer: Ipv4Addr,
    family: Family,
) -> UpdateMessage {
    let msgs = sent_to(state, rxs, peer);
    let mut found = msgs.iter().filter(|m| carries_announcement(m, family));
    let msg = found
        .next()
        .unwrap_or_else(|| panic!("{family:?}: announcement to {peer} expected, got {msgs:?}"));
    assert!(found.next().is_none(), "{family:?}: {msgs:?}");
    msg.clone()
}

/// `(ORIGINATOR_ID, CLUSTER_LIST)` as carried by a wire UPDATE.
fn rr_attrs_of(msg: &UpdateMessage) -> (Option<Ipv4Addr>, Option<Vec<u32>>) {
    let originator = msg.attributes.iter().find_map(|a| match a {
        PathAttribute::OriginatorId(id) => Some(*id),
        _ => None,
    });
    let cluster_list = msg.attributes.iter().find_map(|a| match a {
        PathAttribute::ClusterList(list) => Some(list.clone()),
        _ => None,
    });
    (originator, cluster_list)
}

/// `(ORIGINATOR_ID, CLUSTER_LIST)` of the route stored from `source`, checked
/// to be identical in the Adj-RIB-In and the Loc-RIB.
fn stored_rr_attrs(
    state: &DaemonState,
    source: Ipv4Addr,
    family: Family,
) -> (Option<Ipv4Addr>, Vec<u32>) {
    let source = IpAddr::V4(source);
    let (adj_in, loc) = match family {
        Family::V4 | Family::V4Mp => {
            let adj_in = state.adj_ribs_in[&source].get(&n4()).expect("Adj-RIB-In");
            let loc = state.rib.loc_rib.best(&n4()).expect("Loc-RIB");
            (
                (
                    adj_in.originator_id(),
                    adj_in.rare_or_default().cluster_list.clone(),
                ),
                (
                    loc.originator_id(),
                    loc.rare_or_default().cluster_list.clone(),
                ),
            )
        }
        Family::V6 => {
            let adj_in = state.adj_ribs_in_v6[&source]
                .get(&n6())
                .expect("Adj-RIB-In");
            let loc = state.rib.loc_rib_v6.best(&n6()).expect("Loc-RIB");
            (
                (
                    adj_in.originator_id(),
                    adj_in.rare_or_default().cluster_list.clone(),
                ),
                (
                    loc.originator_id(),
                    loc.rare_or_default().cluster_list.clone(),
                ),
            )
        }
    };
    assert_eq!(adj_in, loc);
    adj_in
}

fn is_installed(state: &DaemonState, source: Ipv4Addr, family: Family) -> bool {
    let source = IpAddr::V4(source);
    match family {
        Family::V4 | Family::V4Mp => {
            state.adj_ribs_in[&source].get(&n4()).is_some()
                || state.rib.loc_rib.best(&n4()).is_some()
        }
        Family::V6 => {
            state.adj_ribs_in_v6[&source].get(&n6()).is_some()
                || state.rib.loc_rib_v6.best(&n6()).is_some()
        }
    }
}

// ── Issue #177: withdraw-only UPDATEs on a route reflector ─────────────────

#[test]
fn withdraw_only_update_from_ibgp_peer_is_accepted_by_a_reflector() {
    for (source, observer) in [(CLIENT, CLIENT_2), (NON_CLIENT, CLIENT)] {
        for family in FAMILIES {
            let (mut state, mut rxs) = rr_setup();
            assert!(
                state
                    .on_route_update(IpAddr::V4(source), announce(family))
                    .is_none()
            );
            advertised_to(&mut state, &mut rxs, observer, family);

            let notification = state.on_route_update(IpAddr::V4(source), withdraw(family));

            assert!(
                notification.is_none(),
                "{family:?} from {source}: {notification:?}"
            );
            assert!(!is_installed(&state, source, family), "{family:?} {source}");
            let msgs = sent_to(&mut state, &mut rxs, observer);
            assert!(
                msgs.iter().any(|m| carries_withdrawal(m, family)),
                "{family:?} from {source}: {msgs:?}"
            );
        }
    }
}

/// Through the event loop: no NOTIFICATION or Stop reaches the session task,
/// and the other client is sent the withdrawal.
#[tokio::test]
async fn withdrawal_through_run_event_loop_keeps_the_reflector_session_up() {
    for source in [CLIENT, NON_CLIENT] {
        for family in FAMILIES {
            let (mut state, mut rxs) = rr_setup();
            state.on_route_update(IpAddr::V4(source), announce(family));
            drain(&mut state, &mut rxs);

            let state = Arc::new(RwLock::new(state));
            let (command_tx, mut commands) = mpsc::channel(4);
            let stop_senders = Arc::new(Mutex::new(HashMap::from([(
                IpAddr::V4(source),
                command_tx,
            )])));
            let (tx, events) = mpsc::channel(4);
            tx.send((
                IpAddr::V4(source),
                SessionEvent::RouteUpdate(withdraw(family)),
            ))
            .await
            .unwrap();
            drop(tx);

            super::run_event_loop(events, Arc::clone(&state), stop_senders, None).await;

            let command = commands.try_recv().ok();
            assert!(command.is_none(), "{family:?} from {source}: {command:?}");
            assert!(!is_installed(&*state.read().await, source, family));
            let rx = rxs.get_mut(&IpAddr::V4(CLIENT_2)).unwrap();
            let msgs: Vec<UpdateMessage> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
            assert!(
                msgs.iter().any(|m| carries_withdrawal(m, family)),
                "{family:?} from {source}: {msgs:?}"
            );
        }
    }
}

/// RFC 7606 §5.2 still applies to what the peer really sent: attributes, no
/// reachable NLRI, and no ORIGIN.
#[test]
fn received_attributes_without_nlri_or_origin_still_reset_the_session() {
    for source in [CLIENT, NON_CLIENT] {
        for attribute in [
            PathAttribute::LocalPref(100),
            PathAttribute::OriginatorId(NON_CLIENT_ID),
            PathAttribute::ClusterList(vec![7]),
        ] {
            for family in FAMILIES {
                let (mut state, _rxs) = rr_setup();
                let mut update = withdraw(family);
                update.attributes.push(attribute.clone());

                let notification = state
                    .on_route_update(IpAddr::V4(source), update)
                    .unwrap_or_else(|| panic!("{family:?} {attribute:?}: reset expected"));

                assert_eq!(
                    notification.error,
                    NotificationError::UpdateMessage(UpdateMsgError::MissingWellKnownAttribute)
                );
                assert_eq!(notification.data, vec![1], "ORIGIN type code");
            }
        }
    }
}

// ── Issue #135: attributes are added on reflection ─────────────────────────

#[test]
fn reflector_stores_a_route_as_received_and_adds_attributes_on_reflection() {
    // (source, source BGP ID, destination)
    for (source, source_id, observer) in [
        (CLIENT, CLIENT_ID, CLIENT_2),
        (CLIENT, CLIENT_ID, NON_CLIENT),
        (NON_CLIENT, NON_CLIENT_ID, CLIENT),
    ] {
        for family in FAMILIES {
            let (mut state, mut rxs) = rr_setup();

            state.on_route_update(IpAddr::V4(source), announce(family));

            assert_eq!(stored_rr_attrs(&state, source, family), (None, vec![]));
            let msg = advertised_to(&mut state, &mut rxs, observer, family);
            assert_eq!(
                rr_attrs_of(&msg),
                (Some(source_id), Some(vec![CLUSTER_ID])),
                "{family:?} {source} → {observer}"
            );
        }
    }
}

#[test]
fn reflector_prepends_to_a_received_cluster_list_and_keeps_originator_id() {
    let originator = Ipv4Addr::new(9, 9, 9, 9);
    for family in FAMILIES {
        let (mut state, mut rxs) = rr_setup();
        let received = [
            PathAttribute::OriginatorId(originator),
            PathAttribute::ClusterList(vec![100]),
        ];

        state.on_route_update(IpAddr::V4(CLIENT), announce_with(family, &received));

        assert_eq!(
            stored_rr_attrs(&state, CLIENT, family),
            (Some(originator), vec![100])
        );
        let msg = advertised_to(&mut state, &mut rxs, CLIENT_2, family);
        assert_eq!(
            rr_attrs_of(&msg),
            (Some(originator), Some(vec![CLUSTER_ID, 100])),
            "{family:?}"
        );
    }
}

/// A table dump to a newly Established peer is a reflection too.
#[test]
fn table_dump_from_a_reflector_carries_the_reflection_attributes() {
    for family in FAMILIES {
        let (mut state, mut rxs) = make_rr_state(LOCAL_AS, CLUSTER_ID, &[CLIENT, CLIENT_2], &[]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish(&mut state, CLIENT, CLIENT_ID, PeerType::Internal);
        state.on_route_update(IpAddr::V4(CLIENT), announce(family));
        drain(&mut state, &mut rxs);

        establish(&mut state, CLIENT_2, CLIENT_2_ID, PeerType::Internal);

        let msg = advertised_to(&mut state, &mut rxs, CLIENT_2, family);
        assert_eq!(
            rr_attrs_of(&msg),
            (Some(CLIENT_ID), Some(vec![CLUSTER_ID])),
            "{family:?}"
        );
    }
}

/// When the best path moves to another client, even with otherwise identical
/// attributes, the replacement carries the new originator and the local
/// CLUSTER_ID exactly once. Covers the re-advertisement on session loss.
///
/// IPv4 only: IPv6 re-advertisement on session loss is issue #160.
#[test]
fn replacement_after_session_loss_carries_the_new_originator() {
    let (mut state, mut rxs) = rr_setup();
    state.on_route_update(IpAddr::V4(CLIENT), announce(Family::V4));
    state.on_route_update(IpAddr::V4(CLIENT_2), announce(Family::V4));
    // RFC 4271 §9.1.2.2 (f): CLIENT's identifier is lower.
    let msg = advertised_to(&mut state, &mut rxs, NON_CLIENT, Family::V4);
    assert_eq!(rr_attrs_of(&msg), (Some(CLIENT_ID), Some(vec![CLUSTER_ID])));

    state.on_terminated(IpAddr::V4(CLIENT), TerminationReason::Unclean, true);

    let msg = advertised_to(&mut state, &mut rxs, NON_CLIENT, Family::V4);
    assert_eq!(
        rr_attrs_of(&msg),
        (Some(CLIENT_2_ID), Some(vec![CLUSTER_ID]))
    );
}

/// The Adj-RIB-Out holds the route as advertised, so selecting it again sends
/// nothing and never prepends the CLUSTER_ID twice.
#[test]
fn repeating_an_announcement_does_not_re_advertise_the_reflected_route() {
    for family in FAMILIES {
        let (mut state, mut rxs) = rr_setup();
        state.on_route_update(IpAddr::V4(CLIENT), announce(family));
        advertised_to(&mut state, &mut rxs, CLIENT_2, family);

        state.on_route_update(IpAddr::V4(CLIENT), announce(family));

        let msgs = sent_to(&mut state, &mut rxs, CLIENT_2);
        assert!(msgs.is_empty(), "{family:?}: {msgs:?}");
    }
}

/// RFC 4456 §5: only an iBGP-learned route is "reflected". The reflector's own
/// routes and eBGP-learned routes gain neither attribute.
#[test]
fn routes_that_are_not_reflected_gain_no_reflection_attributes() {
    let external = Ipv4Addr::new(10, 0, 0, 4);
    for family in FAMILIES {
        let (mut state, mut rxs) = make_rr_state(LOCAL_AS, CLUSTER_ID, &[CLIENT], &[external]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish(&mut state, CLIENT, CLIENT_ID, PeerType::Internal);
        establish(&mut state, external, NON_CLIENT_ID, PeerType::External);
        drain(&mut state, &mut rxs);

        state.on_route_update(IpAddr::V4(external), announce(family));

        let msg = advertised_to(&mut state, &mut rxs, CLIENT, family);
        assert_eq!(rr_attrs_of(&msg), (None, None), "{family:?} eBGP-learned");
    }

    let (mut state, mut rxs) = rr_setup();
    state.originate_route(
        pathvector_rib::RouteBuilder::new(n4(), Origin::Igp, AsPath::new())
            .peer_type(PeerType::Local)
            .next_hop(NextHop::V4(NEXT_HOP_V4))
            .build(),
    );
    let msg = advertised_to(&mut state, &mut rxs, CLIENT, Family::V4);
    assert_eq!(rr_attrs_of(&msg), (None, None), "locally originated");
}

/// RFC 4456 §9: "the CLUSTER_LIST length is zero if a route does not carry the
/// CLUSTER_LIST attribute." Being a reflector must not lengthen the list of a
/// received route: an `Internal` and a `ConfedMember` route tied through step
/// (f) both have length zero, so step (g), the lower peer address, decides.
#[test]
fn being_a_reflector_does_not_lengthen_the_received_cluster_list_for_selection() {
    let confed = Ipv4Addr::new(10, 0, 0, 4);
    let shared_id = Ipv4Addr::new(5, 5, 5, 5);
    let (mut state, _rxs) = make_rr_state(LOCAL_AS, CLUSTER_ID, &[CLIENT], &[confed]);
    establish(&mut state, CLIENT, shared_id, PeerType::Internal);
    establish(&mut state, confed, shared_id, PeerType::ConfedMember);

    let mut from_confed = announce(Family::V4);
    from_confed.attributes[1] = PathAttribute::AsPath(AsPath::from_segments(vec![
        AsPathSegment::ConfedSequence(vec![Asn::new(65200)]),
        AsPathSegment::Sequence(vec![Asn::new(65100)]),
    ]));
    state.on_route_update(IpAddr::V4(confed), from_confed);
    state.on_route_update(IpAddr::V4(CLIENT), announce(Family::V4));

    assert_eq!(
        state.rib.loc_rib.best_peer(&n4()).map(PeerId::ip),
        Some(IpAddr::V4(CLIENT))
    );
}

/// RFC 4456 §8: ORIGINATOR_ID "will carry the BGP Identifier of the originator
/// of the route". Without that identifier the route cannot be reflected; the
/// reflector must not put its own there, which every receiver would then
/// attribute to this speaker.
#[test]
fn a_route_with_no_known_originator_is_not_reflected() {
    let (mut state, mut rxs) = rr_setup();
    Arc::make_mut(&mut state.rib)
        .peer_bgp_ids
        .remove(&IpAddr::V4(CLIENT));
    for family in FAMILIES {
        state.on_route_update(IpAddr::V4(CLIENT), announce(family));
        assert!(is_installed(&state, CLIENT, family));
        let msgs = sent_to(&mut state, &mut rxs, CLIENT_2);
        assert!(msgs.is_empty(), "{family:?}: {msgs:?}");
    }
}
