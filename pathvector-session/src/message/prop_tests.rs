use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_types::{
    Afi, AfiSafi, Aggregator, AsPath, AsPathSegment, Asn, Community, LargeCommunity, NextHop, Nlri,
    Origin, Safi,
};
use proptest::prelude::*;

use super::*;

// ── Primitive strategies ─────────────────────────────────────────────────

fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
    any::<[u8; 4]>().prop_map(Ipv4Addr::from)
}

fn arb_ipv6() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u8; 16]>().prop_map(Ipv6Addr::from)
}

fn arb_nlri_v4() -> impl Strategy<Value = Nlri<Ipv4Addr>> {
    (any::<[u8; 4]>(), 0u8..=32)
        .prop_map(|(addr, len)| Nlri::new(Ipv4Addr::from(addr), len).unwrap().masked())
}

fn arb_nlri_v6() -> impl Strategy<Value = Nlri<Ipv6Addr>> {
    (any::<[u8; 16]>(), 0u8..=128)
        .prop_map(|(addr, len)| Nlri::new(Ipv6Addr::from(addr), len).unwrap().masked())
}

fn arb_asn() -> impl Strategy<Value = Asn> {
    any::<u32>().prop_map(Asn::new)
}

fn arb_afi_safi() -> impl Strategy<Value = AfiSafi> {
    (any::<u16>(), any::<u8>()).prop_map(|(a, s)| AfiSafi::new(Afi::new(a), Safi::new(s)))
}

fn arb_origin() -> impl Strategy<Value = Origin> {
    prop_oneof![
        Just(Origin::Igp),
        Just(Origin::Egp),
        Just(Origin::Incomplete),
    ]
}

fn arb_as_path() -> impl Strategy<Value = AsPath> {
    prop_oneof![
        prop::collection::vec(arb_asn(), 1..5).prop_map(AsPath::from_sequence),
        prop::collection::vec(
            prop_oneof![
                prop::collection::vec(arb_asn(), 1..4).prop_map(AsPathSegment::Sequence),
                prop::collection::vec(arb_asn(), 1..4).prop_map(AsPathSegment::Set),
            ],
            1..3,
        )
        .prop_map(AsPath::from_segments),
    ]
}

fn arb_capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        arb_afi_safi().prop_map(Capability::MultiProtocol),
        Just(Capability::RouteRefresh),
        any::<u32>().prop_map(Capability::FourByteAsn),
        // restart_flags fits in 4 bits; restart_time in 12 bits — wire encoding truncates beyond these.
        (
            0u8..=15,
            0u16..=4095,
            prop::collection::vec(
                (arb_afi_safi(), any::<bool>()).prop_map(|(afi_safi, forwarding_preserved)| {
                    GracefulRestartFamily {
                        afi_safi,
                        forwarding_preserved,
                    }
                }),
                0..3,
            ),
        )
            .prop_map(|(restart_flags, restart_time, families)| {
                Capability::GracefulRestart {
                    restart_flags,
                    restart_time,
                    families,
                }
            }),
    ]
}

fn arb_path_attribute() -> impl Strategy<Value = PathAttribute> {
    prop_oneof![
        arb_origin().prop_map(PathAttribute::Origin),
        arb_as_path().prop_map(PathAttribute::AsPath),
        arb_ipv4().prop_map(PathAttribute::NextHop),
        any::<u32>().prop_map(PathAttribute::Med),
        any::<u32>().prop_map(PathAttribute::LocalPref),
        Just(PathAttribute::AtomicAggregate),
        (arb_asn(), arb_ipv4())
            .prop_map(|(asn, ip)| PathAttribute::Aggregator(Aggregator::new(asn, ip))),
        prop::collection::vec(any::<u32>().prop_map(Community::new), 0..5)
            .prop_map(PathAttribute::Communities),
        prop::collection::vec(
            (any::<u32>(), any::<u32>(), any::<u32>())
                .prop_map(|(ga, ld1, ld2)| LargeCommunity::new(ga, ld1, ld2)),
            0..5,
        )
        .prop_map(PathAttribute::LargeCommunities),
        (
            arb_ipv6().prop_map(NextHop::V6),
            prop::collection::vec(arb_nlri_v6().prop_map(Prefix::V6), 0..3),
        )
            .prop_map(
                |(next_hop, prefixes)| PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop,
                    prefixes,
                })
            ),
    ]
}

// ── Roundtrip properties ─────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_route_refresh_roundtrip(afi_safi in arb_afi_safi()) {
        let msg = BgpMessage::RouteRefresh(RouteRefreshMessage { afi_safi });
        prop_assert_eq!(BgpMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn prop_open_roundtrip(
        my_as     in any::<u16>(),
        hold_time in any::<u16>(),
        bgp_id    in arb_ipv4(),
        capabilities in prop::collection::vec(arb_capability(), 0..4),
    ) {
        let msg = BgpMessage::Open(OpenMessage { version: 4, my_as, hold_time, bgp_id, capabilities });
        prop_assert_eq!(BgpMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn prop_notification_roundtrip(
        error in prop_oneof![
            Just(NotificationError::HoldTimerExpired),
            Just(NotificationError::FsmError),
            prop_oneof![
                Just(MsgHeaderError::ConnectionNotSynchronized),
                Just(MsgHeaderError::BadMessageLength),
                Just(MsgHeaderError::BadMessageType),
                // Known subcodes: 1–3. Only generate subcodes the decoder won't
                // map to a named variant, so the Unknown arm round-trips.
                prop_oneof![Just(0u8), 4u8..=u8::MAX].prop_map(MsgHeaderError::Unknown),
            ].prop_map(NotificationError::MessageHeader),
            prop_oneof![
                Just(OpenMsgError::UnsupportedVersionNumber),
                Just(OpenMsgError::BadPeerAs),
                Just(OpenMsgError::BadBgpIdentifier),
                Just(OpenMsgError::UnsupportedOptionalParameter),
                Just(OpenMsgError::UnacceptableHoldTime),
                Just(OpenMsgError::UnsupportedCapability),
                // Known subcodes: 1, 2, 3, 4, 6, 7. Exclude those.
                prop_oneof![Just(0u8), Just(5u8), 8u8..=u8::MAX].prop_map(OpenMsgError::Unknown),
            ].prop_map(NotificationError::OpenMessage),
            prop_oneof![
                Just(UpdateMsgError::MalformedAttributeList),
                Just(UpdateMsgError::UnrecognizedWellKnownAttribute),
                Just(UpdateMsgError::MissingWellKnownAttribute),
                Just(UpdateMsgError::AttributeFlagsError),
                Just(UpdateMsgError::AttributeLengthError),
                Just(UpdateMsgError::InvalidOriginAttribute),
                Just(UpdateMsgError::InvalidNextHopAttribute),
                Just(UpdateMsgError::OptionalAttributeError),
                Just(UpdateMsgError::InvalidNetworkField),
                Just(UpdateMsgError::MalformedAsPath),
                // Known subcodes: 1–6, 8–11. Exclude those.
                prop_oneof![Just(0u8), Just(7u8), 12u8..=u8::MAX].prop_map(UpdateMsgError::Unknown),
            ].prop_map(NotificationError::UpdateMessage),
            prop_oneof![
                Just(CeaseError::MaximumNumberOfPrefixesReached),
                Just(CeaseError::AdministrativeShutdown),
                Just(CeaseError::PeerDeconfigured),
                Just(CeaseError::AdministrativeReset),
                Just(CeaseError::ConnectionRejected),
                Just(CeaseError::OtherConfigurationChange),
                Just(CeaseError::ConnectionCollisionResolution),
                Just(CeaseError::OutOfResources),
                Just(CeaseError::HardReset),
                Just(CeaseError::BfdDown),
                // Known subcodes: 1–10. Exclude those.
                prop_oneof![Just(0u8), 11u8..=u8::MAX].prop_map(CeaseError::Unknown),
            ].prop_map(NotificationError::Cease),
            // Top-level Unknown is only reachable for codes not in 1–6.
            (prop_oneof![Just(0u8), 7u8..=u8::MAX], any::<u8>())
                .prop_map(|(code, subcode)| NotificationError::Unknown { code, subcode }),
        ],
        data in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let msg = BgpMessage::Notification(NotificationMessage { error, data });
        prop_assert_eq!(BgpMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn prop_update_roundtrip(
        withdrawn   in prop::collection::vec(arb_nlri_v4(), 0..5),
        attributes  in prop::collection::vec(arb_path_attribute(), 0..5),
        announced   in prop::collection::vec(arb_nlri_v4(), 0..5),
    ) {
        // Deduplicate by type code — RFC 7606 §7.3 treats duplicate attributes
        // as errors, so the roundtrip only holds for well-formed messages.
        let mut seen = std::collections::HashSet::new();
        let attributes: Vec<_> = attributes
            .into_iter()
            .filter(|a| seen.insert(a.type_code()))
            .collect();
        let msg = BgpMessage::Update(UpdateMessage { withdrawn, attributes, announced });
        prop_assert_eq!(BgpMessage::decode(&msg.encode()).unwrap(), msg);
    }

    /// Decode must never panic on arbitrary input — only return Ok or Err.
    #[test]
    fn prop_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = BgpMessage::decode(&bytes);
    }
}
