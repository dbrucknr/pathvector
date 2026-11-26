// daemon/rr_tie_break_tests.rs — issue #69: reflected-route tie-breakers,
// end to end through UPDATE ingestion.
//
// RFC 4456 §9 modifies the RFC 4271 §9.1.2.2 tie-breakers:
//
//   "If a route carries the ORIGINATOR_ID attribute, then in Step f) the
//    ORIGINATOR_ID SHOULD be treated as the BGP Identifier of the BGP speaker
//    that has advertised the route.
//
//    In addition, the following rule SHOULD be inserted between Steps f) and
//    g): a BGP Speaker SHOULD prefer a route with the shorter CLUSTER_LIST
//    length.  The CLUSTER_LIST length is zero if a route does not carry the
//    CLUSTER_LIST attribute."
//
// The selector reads both attributes from the stored route, so these tests
// prove that ingestion stores them as received — on the IPv4 *and* IPv6
// paths — and that the Loc-RIB then selects by them.
//
// RFC 7606 §7.9 / §7.10 revise RFC 4456's error handling: "if the
// ORIGINATOR_ID [CLUSTER_LIST] attribute is received from an external
// neighbor, it SHALL be discarded using the approach of 'attribute
// discard'". Once these attributes decide selection, an eBGP peer that sends
// them would otherwise be able to win the step-(f) tie-break with a forged
// ORIGINATOR_ID — a well-formed, policy-violating input.
//
// Topology (non-RR tests): this speaker is a client of two route reflectors.
// RR_A has the *lower* peer address and the *lower* BGP Identifier, so the
// pre-fix selector — which compared the reflectors' own identifiers, then
// peer addresses — always picked A. Every expectation that B wins can only
// come from ORIGINATOR_ID or CLUSTER_LIST.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pathvector_rib::PeerId;
use pathvector_session::message::{Capability, MpReachNlri, PathAttribute, Prefix, UpdateMessage};
use pathvector_types::{AfiSafi, AsPath, AsPathSegment, Asn, NextHop, Nlri, Origin, PeerType};
use tokio::sync::mpsc;

use super::DaemonState;
use crate::daemon::tests::{make_rr_state, make_state};

const LOCAL_AS: u32 = 65001;
/// Route reflector A: lower peer address, lower BGP Identifier.
const RR_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const RR_A_ID: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// Route reflector B: higher peer address, higher BGP Identifier.
const RR_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const RR_B_ID: Ipv4Addr = Ipv4Addr::new(2, 2, 2, 2);

/// Origin AS behind both reflected routes (same `AS_PATH`, so step (a) ties).
const ORIGIN_AS: u32 = 65100;

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn caps() -> Vec<Capability> {
    vec![
        Capability::FourByteAsn(LOCAL_AS),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
    ]
}

/// RR_A and RR_B Established as iBGP peers with their BGP Identifiers.
fn setup() -> (DaemonState, HashMap<IpAddr, mpsc::Receiver<UpdateMessage>>) {
    let (mut state, rxs) = make_state(
        LOCAL_AS,
        &[(IpAddr::V4(RR_A), LOCAL_AS), (IpAddr::V4(RR_B), LOCAL_AS)],
    );
    for (ip, id) in [(RR_A, RR_A_ID), (RR_B, RR_B_ID)] {
        state.on_established(
            IpAddr::V4(ip),
            id,
            PeerType::Internal,
            LOCAL_AS,
            90,
            &caps(),
            None,
        );
    }
    (state, rxs)
}

/// The RFC 4456 attributes a reflected route carries (`None`/empty = absent).
fn rr_attrs(originator_id: Option<Ipv4Addr>, cluster_list: &[u32]) -> Vec<PathAttribute> {
    let mut attrs = Vec::new();
    if let Some(id) = originator_id {
        attrs.push(PathAttribute::OriginatorId(id));
    }
    if !cluster_list.is_empty() {
        attrs.push(PathAttribute::ClusterList(cluster_list.to_vec()));
    }
    attrs
}

/// An IPv4 announcement tied through RFC 4271 §9.1.2.2 (e) with every other
/// one from this helper: same `LOCAL_PREF`, `AS_PATH`, ORIGIN, no MED.
fn announce_v4(
    prefix: &str,
    next_hop: Ipv4Addr,
    originator_id: Option<Ipv4Addr>,
    cluster_list: &[u32],
) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(ORIGIN_AS)])),
        PathAttribute::NextHop(next_hop),
        PathAttribute::LocalPref(100),
    ];
    attributes.extend(rr_attrs(originator_id, cluster_list));
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![nlri(prefix)],
    }
}

/// The IPv6 (`MP_REACH_NLRI`, RFC 4760) counterpart of [`announce_v4`].
fn announce_v6(
    prefix: Nlri<Ipv6Addr>,
    next_hop: Ipv6Addr,
    originator_id: Option<Ipv4Addr>,
    cluster_list: &[u32],
) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(ORIGIN_AS)])),
        PathAttribute::LocalPref(100),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6(next_hop),
            prefixes: vec![Prefix::V6(prefix)],
        }),
    ];
    attributes.extend(rr_attrs(originator_id, cluster_list));
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![],
    }
}

/// Issue #69 acceptance case 1, through ingestion. RR_A (BGP Identifier
/// 1.1.1.1) reflects a route with `ORIGINATOR_ID` 9.9.9.9; RR_B (2.2.2.2)
/// reflects one with `ORIGINATOR_ID` 3.3.3.3. RFC 4456 §9: step (f) compares
/// 9.9.9.9 with 3.3.3.3, so B's route is selected. Checked in both arrival
/// orders, since Loc-RIB re-selects on every insert.
#[test]
fn reflected_routes_are_selected_by_originator_id_not_reflector_id() {
    let prefix = nlri("192.0.2.0/24");
    let a = || {
        announce_v4(
            "192.0.2.0/24",
            Ipv4Addr::new(192, 0, 2, 1),
            Some(Ipv4Addr::new(9, 9, 9, 9)),
            &[100],
        )
    };
    let b = || {
        announce_v4(
            "192.0.2.0/24",
            Ipv4Addr::new(192, 0, 2, 2),
            Some(Ipv4Addr::new(3, 3, 3, 3)),
            &[200],
        )
    };
    for a_first in [true, false] {
        let (mut state, _rxs) = setup();
        if a_first {
            state.on_route_update(IpAddr::V4(RR_A), a());
            state.on_route_update(IpAddr::V4(RR_B), b());
        } else {
            state.on_route_update(IpAddr::V4(RR_B), b());
            state.on_route_update(IpAddr::V4(RR_A), a());
        }
        state.flush_pending();

        // Ingestion stored the attributes exactly as received.
        let stored_a = state.adj_ribs_in[&IpAddr::V4(RR_A)].get(&prefix).unwrap();
        assert_eq!(stored_a.peer_bgp_id, Some(RR_A_ID));
        assert_eq!(stored_a.originator_id(), Some(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(stored_a.cluster_list_len(), 1);

        assert_eq!(
            state.rib.loc_rib.best_peer(&prefix).map(PeerId::ip),
            Some(IpAddr::V4(RR_B)),
            "RFC 4456 §9: ORIGINATOR_ID 3.3.3.3 < 9.9.9.9 (a_first = {a_first})"
        );
        let best = state.rib.loc_rib.best(&prefix).unwrap();
        assert_eq!(
            best.effective_router_id().get(),
            Some(Ipv4Addr::new(3, 3, 3, 3))
        );
    }
}

/// Issue #69 acceptance case 2, through ingestion. Both reflected routes
/// carry `ORIGINATOR_ID` 9.9.9.9, so step (f) ties; RFC 4456 §9's inserted
/// step prefers B's one-entry `CLUSTER_LIST` over A's two-entry list, before
/// step (g) — which would have picked A's lower peer address.
#[test]
fn shorter_cluster_list_is_selected_before_peer_address() {
    let prefix = nlri("198.51.100.0/24");
    let (mut state, _rxs) = setup();
    state.on_route_update(
        IpAddr::V4(RR_A),
        announce_v4(
            "198.51.100.0/24",
            Ipv4Addr::new(192, 0, 2, 1),
            Some(Ipv4Addr::new(9, 9, 9, 9)),
            &[100, 300],
        ),
    );
    state.on_route_update(
        IpAddr::V4(RR_B),
        announce_v4(
            "198.51.100.0/24",
            Ipv4Addr::new(192, 0, 2, 2),
            Some(Ipv4Addr::new(9, 9, 9, 9)),
            &[200],
        ),
    );
    state.flush_pending();

    assert_eq!(
        state.rib.loc_rib.best_peer(&prefix).map(PeerId::ip),
        Some(IpAddr::V4(RR_B)),
        "RFC 4456 §9: shorter CLUSTER_LIST wins when ORIGINATOR_IDs tie"
    );
    assert_eq!(
        state.rib.loc_rib.best(&prefix).unwrap().cluster_list_len(),
        1
    );
}

/// The IPv6 path used to drop `ORIGINATOR_ID` and `CLUSTER_LIST` entirely, so
/// RFC 4456 §9 could never apply to IPv6 routes. Same scenario as the IPv4
/// acceptance case, carried in `MP_REACH_NLRI`.
#[test]
fn ipv6_reflected_routes_store_rr_attributes_and_select_by_originator_id() {
    let prefix: Nlri<Ipv6Addr> = "2001:db8:69::/48".parse().unwrap();
    let (mut state, _rxs) = setup();
    state.on_route_update(
        IpAddr::V4(RR_A),
        announce_v6(
            prefix,
            "2001:db8::a".parse().unwrap(),
            Some(Ipv4Addr::new(9, 9, 9, 9)),
            &[100, 300],
        ),
    );
    state.on_route_update(
        IpAddr::V4(RR_B),
        announce_v6(
            prefix,
            "2001:db8::b".parse().unwrap(),
            Some(Ipv4Addr::new(3, 3, 3, 3)),
            &[200],
        ),
    );
    state.flush_pending();

    let stored_a = state.adj_ribs_in_v6[&IpAddr::V4(RR_A)]
        .get(&prefix)
        .expect("A's IPv6 route stored");
    assert_eq!(stored_a.originator_id(), Some(Ipv4Addr::new(9, 9, 9, 9)));
    assert_eq!(stored_a.rare_or_default().cluster_list, vec![100, 300]);

    assert_eq!(
        state.rib.loc_rib_v6.best_peer(&prefix).map(PeerId::ip),
        Some(IpAddr::V4(RR_B)),
        "RFC 4456 §9 applies to IPv6 routes: ORIGINATOR_ID 3.3.3.3 < 9.9.9.9"
    );
}

/// RFC 7606 §7.9 / §7.10: `ORIGINATOR_ID` and `CLUSTER_LIST` from an external
/// neighbor "SHALL be discarded using the approach of 'attribute discard'"
/// — the route itself is kept. Checked on both address families, and on
/// selection: two eBGP peers in the same neighbor AS tie through (e); the
/// attacker forges `ORIGINATOR_ID` 0.0.0.1 and a `CLUSTER_LIST`, but
/// with the attribute discarded step (f) compares the real BGP Identifiers
/// and the honest peer (lower identifier) wins.
#[test]
fn ebgp_originator_id_and_cluster_list_are_discarded() {
    assert_rr_attributes_discarded_from(PeerType::External);
}

/// A confederation Member-AS peer is in "a different Autonomous System"
/// (RFC 4271 §1.1 "External peer"), and RFC 5065 grants it no exception for
/// these attributes (only LOCAL_PREF, §5.2, and path selection, §5.3), so
/// RFC 7606 §7.9 / §7.10 discard applies too — mirroring the outbound side,
/// which strips them toward `ConfedMember` peers.
#[test]
fn confed_member_originator_id_and_cluster_list_are_discarded() {
    assert_rr_attributes_discarded_from(PeerType::ConfedMember);
}

fn assert_rr_attributes_discarded_from(peer_type: PeerType) {
    const NEIGHBOR_AS: u32 = 65200;
    let honest = Ipv4Addr::new(10, 0, 1, 2);
    let honest_id = Ipv4Addr::new(5, 5, 5, 5);
    let attacker = Ipv4Addr::new(10, 0, 1, 3);
    let attacker_id = Ipv4Addr::new(6, 6, 6, 6);
    let prefix = nlri("203.0.113.0/24");
    let prefix_v6: Nlri<Ipv6Addr> = "2001:db8:7606::/48".parse().unwrap();

    let (mut state, _rxs) = make_state(
        LOCAL_AS,
        &[
            (IpAddr::V4(honest), NEIGHBOR_AS),
            (IpAddr::V4(attacker), NEIGHBOR_AS),
        ],
    );
    for (ip, id) in [(honest, honest_id), (attacker, attacker_id)] {
        state.on_established(
            IpAddr::V4(ip),
            id,
            peer_type,
            NEIGHBOR_AS,
            90,
            &[
                Capability::FourByteAsn(NEIGHBOR_AS),
                Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
            ],
            None,
        );
    }
    // RFC 5065 §5.3 / RFC 7606 §5: a Member-AS peer's AS_PATH must begin
    // with its AS_CONFED_SEQUENCE, or the UPDATE is treated as withdrawn.
    let path = || {
        PathAttribute::AsPath(if peer_type == PeerType::ConfedMember {
            AsPath::from_segments(vec![
                AsPathSegment::ConfedSequence(vec![Asn::new(NEIGHBOR_AS)]),
                AsPathSegment::Sequence(vec![Asn::new(ORIGIN_AS)]),
            ])
        } else {
            AsPath::from_sequence(vec![Asn::new(NEIGHBOR_AS)])
        })
    };
    let v4 = |next_hop: Ipv4Addr, forged: bool| {
        let mut attributes = vec![
            PathAttribute::Origin(Origin::Igp),
            path(),
            PathAttribute::NextHop(next_hop),
        ];
        if forged {
            attributes.extend(rr_attrs(Some(Ipv4Addr::new(0, 0, 0, 1)), &[7]));
        }
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![prefix],
        }
    };

    // The honest route arrives first. If a second boundary fell between the
    // two inserts, step 9 (oldest eBGP route, External only) would also pick
    // the honest route, so the selection assertion below can never fail
    // spuriously; the stored-attribute assertions are deterministic.
    state.on_route_update(IpAddr::V4(honest), v4(honest, false));
    state.on_route_update(IpAddr::V4(attacker), v4(attacker, true));
    state.on_route_update(
        IpAddr::V4(attacker),
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                path(),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::66".parse().unwrap()),
                    prefixes: vec![Prefix::V6(prefix_v6)],
                }),
                PathAttribute::OriginatorId(Ipv4Addr::new(0, 0, 0, 1)),
                PathAttribute::ClusterList(vec![7]),
            ],
            announced: vec![],
        },
    );
    state.flush_pending();

    let stored = state.adj_ribs_in[&IpAddr::V4(attacker)]
        .get(&prefix)
        .expect("attribute discard keeps the route");
    assert_eq!(stored.peer_type, peer_type, "precondition");
    assert_eq!(
        stored.originator_id(),
        None,
        "RFC 7606 §7.9 ({peer_type:?})"
    );
    assert_eq!(
        stored.cluster_list_len(),
        0,
        "RFC 7606 §7.10 ({peer_type:?})"
    );
    assert_eq!(stored.effective_router_id().get(), Some(attacker_id));

    let stored_v6 = state.adj_ribs_in_v6[&IpAddr::V4(attacker)]
        .get(&prefix_v6)
        .expect("attribute discard keeps the IPv6 route");
    assert_eq!(stored_v6.originator_id(), None, "RFC 7606 §7.9 (IPv6)");
    assert_eq!(stored_v6.cluster_list_len(), 0, "RFC 7606 §7.10 (IPv6)");

    assert_eq!(
        state.rib.loc_rib.best_peer(&prefix).map(PeerId::ip),
        Some(IpAddr::V4(honest)),
        "a forged {peer_type:?} ORIGINATOR_ID must not win step (f)"
    );
}

/// RFC 4456 §8: "When an RR reflects a route, it MUST prepend the local
/// `CLUSTER_ID` to the `CLUSTER_LIST`", and the `ORIGINATOR_ID` "will be created
/// by an RR in reflecting a route". A reflected IPv6 route once left this RR
/// without either attribute, defeating RFC 4456 loop detection downstream.
/// The other client must receive both.
#[test]
fn ipv6_route_reflected_to_another_client_carries_originator_id_and_cluster_list() {
    let cluster_id: u32 = 69;
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let other = Ipv4Addr::new(10, 0, 0, 3);
    let prefix: Nlri<Ipv6Addr> = "2001:db8:4456::/48".parse().unwrap();
    let (mut state, mut rxs) = make_rr_state(LOCAL_AS, cluster_id, &[client, other], &[]);
    std::sync::Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
    for ip in [client, other] {
        state.on_established(
            IpAddr::V4(ip),
            ip,
            PeerType::Internal,
            LOCAL_AS,
            90,
            &caps(),
            None,
        );
    }
    for rx in rxs.values_mut() {
        while rx.try_recv().is_ok() {}
    }

    state.on_route_update(
        IpAddr::V4(client),
        announce_v6(prefix, "2001:db8::2".parse().unwrap(), None, &[]),
    );
    state.flush_pending();

    let rx = rxs.get_mut(&IpAddr::V4(other)).unwrap();
    let msgs: Vec<UpdateMessage> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let reflected = msgs
        .iter()
        .find(|m| {
            m.attributes.iter().any(|a| {
                matches!(a, PathAttribute::MpReachNlri(mp)
                    if mp.prefixes.contains(&Prefix::V6(prefix)))
            })
        })
        .unwrap_or_else(|| panic!("reflected IPv6 UPDATE expected, got {msgs:?}"));
    assert!(
        reflected
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == client)),
        "reflected IPv6 route must carry ORIGINATOR_ID = client's BGP ID: {reflected:?}"
    );
    assert!(
        reflected.attributes.iter().any(
            |a| matches!(a, PathAttribute::ClusterList(list) if list.first() == Some(&cluster_id))
        ),
        "reflected IPv6 route must carry our CLUSTER_ID first in CLUSTER_LIST: {reflected:?}"
    );
}
