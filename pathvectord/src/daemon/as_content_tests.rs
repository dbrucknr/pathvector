// daemon/as_content_tests.rs — issues #110 and #111, end to end: wire bytes →
// message decoder → established session FSM → daemon import → FIB and peers.
//
// RFC 9774 §3: "BGP speakers: MUST NOT advertise BGP UPDATE messages
// containing AS_SETs or AS_CONFED_SETs and MUST use the "treat-as-withdraw"
// error handling behavior per [RFC7606] upon reception of BGP UPDATE messages
// containing AS_SETs or AS_CONFED_SETs in the AS_PATH or AS4_PATH".
//
// RFC 7607 §2: AS 0 in AS_PATH is malformed (RFC 7606: treat-as-withdraw);
// in AGGREGATOR it is attribute discard.
//
// RFC 7606 §2, treat-as-withdraw: the UPDATE's routes are handled "just as if
// they had been listed in the WITHDRAWN ROUTES field [...] thus causing them
// to be removed from the Adj-RIB-In". So the older route the peer advertised
// for the same prefix must leave service, and what the UPDATE itself withdraws
// is withdrawn too.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pathvector_rib::RouteBuilder;
use pathvector_session::fsm::{Fsm, FsmConfig, FsmInput, FsmOutput, State};
use pathvector_session::message::{
    AsnWidth, BgpMessage, Capability, MAX_LEN_EXTENDED, MpReachNlri, MpUnreachNlri, OpenMessage,
    PathAttribute, Prefix, UpdateMessage,
};
use pathvector_types::{
    AfiSafi, Aggregator, AsPath, AsPathSegment, Asn, NextHop, Nlri, Origin, PeerType,
};

use super::DaemonState;
use super::last_feasible_tests::{
    AS_A, AS_B, PEER_A, PEER_B, RESOLVABLE_V4, RESOLVABLE_V6, Receivers, announces_v4,
    announces_v6, drain, established, n4, n6, sent_to, withdraws_v4, withdraws_v6,
};

/// A second prefix A advertises first and withdraws alongside the bad UPDATE.
fn other4() -> Nlri<Ipv4Addr> {
    "172.16.0.0/12".parse().unwrap()
}

fn other6() -> Nlri<Ipv6Addr> {
    "2001:db8:2::/48".parse().unwrap()
}

fn asns(v: &[u32]) -> Vec<Asn> {
    v.iter().copied().map(Asn::new).collect()
}

fn seq(v: &[u32]) -> AsPathSegment {
    AsPathSegment::Sequence(asns(v))
}

/// An established session FSM for A, as the transport would drive it.
fn session() -> Fsm {
    let mut fsm = Fsm::new(FsmConfig {
        local_as: 65001,
        public_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        capabilities: vec![],
        required_capabilities: vec![],
        peer_as: Some(AS_A),
        confederation_member: false,
    });
    fsm.process(FsmInput::ManualStart);
    fsm.process(FsmInput::TcpConnected);
    fsm.process(FsmInput::MessageReceived(BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: u16::try_from(AS_A).unwrap(),
        hold_time: 90,
        bgp_id: PEER_A,
        capabilities: vec![Capability::FourByteAsn(AS_A)],
    })));
    fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
    assert_eq!(fsm.state(), State::Established);
    fsm
}

/// Puts `update` on the wire and takes it back up the whole receive path.
fn receive(state: &mut DaemonState, width: AsnWidth, update: UpdateMessage) {
    let wire = BgpMessage::Update(update).encode_with(width);
    let decoded = BgpMessage::decode_with_limit_and_caps(&wire, MAX_LEN_EXTENDED, width).unwrap();
    let mut fsm = session();
    let outputs = fsm.process(FsmInput::MessageReceived(decoded));
    assert_eq!(fsm.state(), State::Established, "no session reset");
    for output in outputs {
        if let FsmOutput::RouteUpdate(update) = output {
            let notification = state.on_route_update(IpAddr::V4(PEER_A), update);
            assert!(notification.is_none(), "{notification:?}");
        }
    }
}

/// An UPDATE announcing `n4()` with `path_attrs`.
fn announce_v4(path_attrs: Vec<PathAttribute>) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::NextHop(RESOLVABLE_V4),
    ];
    attributes.extend(path_attrs);
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![n4()],
    }
}

/// An UPDATE announcing `n6()` with `path_attrs`.
fn announce_v6(path_attrs: Vec<PathAttribute>) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV6_UNICAST,
            next_hop: NextHop::V6(RESOLVABLE_V6),
            prefixes: vec![Prefix::V6(n6())],
        }),
    ];
    attributes.extend(path_attrs);
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![],
    }
}

/// A prohibited replacement for an installed route.
#[derive(Clone, Copy, Debug)]
enum Fault {
    AsSet,
    /// On a confederation-member session with an otherwise well-formed path
    /// (RFC 5065 §5 leading AS_CONFED_SEQUENCE).
    ConfedSet,
    /// An AS_SET that only AS4_PATH carries, from a two-octet peer.
    AsSetInAs4Path,
    AsZero,
}

const FAULTS: [Fault; 4] = [
    Fault::AsSet,
    Fault::ConfedSet,
    Fault::AsSetInAs4Path,
    Fault::AsZero,
];

impl Fault {
    fn width(self) -> AsnWidth {
        match self {
            Self::AsSetInAs4Path => AsnWidth::Two,
            _ => AsnWidth::Four,
        }
    }

    /// The path A advertises before the fault, valid on this session.
    fn clean(self) -> AsPath {
        match self {
            Self::ConfedSet => AsPath::from_segments(vec![
                AsPathSegment::ConfedSequence(asns(&[AS_A])),
                seq(&[64_999]),
            ]),
            _ => AsPath::from_sequence(asns(&[AS_A])),
        }
    }

    fn attributes(self) -> Vec<PathAttribute> {
        let path = |segments| PathAttribute::AsPath(AsPath::from_segments(segments));
        match self {
            Self::AsSet => vec![path(vec![
                seq(&[AS_A]),
                AsPathSegment::Set(asns(&[64_998, 64_999])),
            ])],
            Self::ConfedSet => vec![path(vec![
                AsPathSegment::ConfedSequence(asns(&[AS_A])),
                AsPathSegment::ConfedSet(asns(&[64_998])),
                seq(&[64_999]),
            ])],
            Self::AsSetInAs4Path => vec![
                path(vec![seq(&[AS_A, 23456])]),
                PathAttribute::As4Path(AsPath::from_segments(vec![AsPathSegment::Set(asns(&[
                    131_072,
                ]))])),
            ],
            Self::AsZero => vec![path(vec![seq(&[AS_A, 0])])],
        }
    }

    fn prepare(self, state: &mut DaemonState) {
        if matches!(self, Self::ConfedSet) {
            std::sync::Arc::make_mut(&mut state.rib).confederation_id = Some(65100);
            let caps = [
                Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
                Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
            ];
            state.on_established(
                IpAddr::V4(PEER_A),
                PEER_A,
                PeerType::ConfedMember,
                AS_A,
                90,
                &caps,
                None,
            );
        }
    }
}

fn setup(fault: Fault) -> (DaemonState, Receivers) {
    let (mut state, mut receivers) = established();
    fault.prepare(&mut state);
    drain(&mut state, &mut receivers);
    (state, receivers)
}

#[test]
fn prohibited_replacement_removes_the_installed_v4_route() {
    for fault in FAULTS {
        let (mut state, mut receivers) = setup(fault);
        let clean = vec![PathAttribute::AsPath(fault.clean())];
        receive(&mut state, fault.width(), announce_v4(clean.clone()));
        let mut second = announce_v4(clean);
        second.announced = vec![other4()];
        receive(&mut state, fault.width(), second);
        assert!(
            announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)),
            "{fault:?}"
        );
        assert!(state.rib.loc_rib.best(&n4()).is_some(), "{fault:?}");
        assert!(state.rib.loc_rib.best(&other4()).is_some(), "{fault:?}");

        // Replaces n4(), and withdraws other4() in the same UPDATE.
        let mut bad = announce_v4(fault.attributes());
        bad.withdrawn = vec![other4()];
        receive(&mut state, fault.width(), bad);

        for nlri in [n4(), other4()] {
            assert!(
                state.rib.loc_rib.best(&nlri).is_none(),
                "{fault:?}: {nlri} still selected"
            );
            assert!(
                state.adj_ribs_in[&IpAddr::V4(PEER_A)].get(&nlri).is_none(),
                "{fault:?}: {nlri} still in Adj-RIB-In"
            );
        }
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(
            withdraws_v4(&to_b) && !announces_v4(&to_b),
            "{fault:?}: {to_b:?}"
        );
    }
}

#[test]
fn prohibited_replacement_removes_the_installed_v6_route() {
    for fault in FAULTS {
        let (mut state, mut receivers) = setup(fault);
        let clean = vec![PathAttribute::AsPath(fault.clean())];
        receive(&mut state, fault.width(), announce_v6(clean.clone()));
        let mut second = announce_v6(clean);
        let PathAttribute::MpReachNlri(mp) = &mut second.attributes[1] else {
            unreachable!()
        };
        mp.prefixes = vec![Prefix::V6(other6())];
        receive(&mut state, fault.width(), second);
        assert!(
            announces_v6(&sent_to(&mut state, &mut receivers, PEER_B)),
            "{fault:?}"
        );
        assert!(state.rib.loc_rib_v6.best(&other6()).is_some(), "{fault:?}");

        // Replaces n6(), and withdraws other6() through MP_UNREACH_NLRI.
        let mut bad = announce_v6(fault.attributes());
        bad.attributes
            .push(PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![Prefix::V6(other6())],
            }));
        receive(&mut state, fault.width(), bad);

        for nlri in [n6(), other6()] {
            assert!(
                state.rib.loc_rib_v6.best(&nlri).is_none(),
                "{fault:?}: {nlri} still selected"
            );
            assert!(
                state.adj_ribs_in_v6[&IpAddr::V4(PEER_A)]
                    .get(&nlri)
                    .is_none(),
                "{fault:?}: {nlri} still in Adj-RIB-In"
            );
        }
        let to_b = sent_to(&mut state, &mut receivers, PEER_B);
        assert!(
            withdraws_v6(&to_b) && !announces_v6(&to_b),
            "{fault:?}: {to_b:?}"
        );
    }
}

/// RFC 7607 §2 with RFC 7606 §7.7: an AS 0 AGGREGATOR costs the attribute,
/// not the route.
#[test]
fn as_zero_aggregator_keeps_the_route_without_the_attribute() {
    let (mut state, _receivers) = established();
    let update = announce_v4(vec![
        PathAttribute::AsPath(AsPath::from_sequence(asns(&[AS_A]))),
        PathAttribute::Aggregator(Aggregator::new(Asn::ZERO, Ipv4Addr::new(10, 0, 0, 9))),
    ]);
    receive(&mut state, AsnWidth::Four, update);
    let best = state.rib.loc_rib.best(&n4()).expect("route installed");
    assert_eq!(best.rare_or_default().aggregator, None);
}

/// RFC 9774 §3 also covers routes that did not arrive over BGP: an injected
/// route with a set is not advertised.
#[test]
fn originated_route_with_a_set_is_not_advertised() {
    let (mut state, mut receivers) = established();
    let path = AsPath::from_segments(vec![AsPathSegment::Set(asns(&[AS_B + 1]))]);
    state.originate_route(
        RouteBuilder::new(n4(), Origin::Igp, path.clone())
            .peer_type(PeerType::Local)
            .build(),
    );
    state.originate_route_v6(
        RouteBuilder::new(n6(), Origin::Igp, path)
            .peer_type(PeerType::Local)
            .build(),
    );
    for peer in [PEER_A, PEER_B] {
        let sent = sent_to(&mut state, &mut receivers, peer);
        assert!(!announces_v4(&sent) && !announces_v6(&sent), "{sent:?}");
    }
}

/// Received routes with sets never reach the Loc-RIB through the session, and
/// the daemon's own gate holds for a session implementation that does not use
/// this codec.
#[test]
fn daemon_gate_withdraws_a_set_route_handed_in_directly() {
    let (mut state, mut receivers) = established();
    state.on_route_update(
        IpAddr::V4(PEER_A),
        announce_v4(vec![PathAttribute::AsPath(AsPath::from_sequence(asns(&[
            AS_A,
        ])))]),
    );
    assert!(announces_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
    state.on_route_update(IpAddr::V4(PEER_A), announce_v4(Fault::AsSet.attributes()));
    assert!(state.rib.loc_rib.best(&n4()).is_none());
    assert!(state.adj_ribs_in[&IpAddr::V4(PEER_A)].get(&n4()).is_none());
    assert!(withdraws_v4(&sent_to(&mut state, &mut receivers, PEER_B)));
}
