use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::BytesMut;
use pathvector_types::{
    Afi, AfiSafi, Aggregator, AsPath, AsPathSegment, Asn, Community, LargeCommunity, NextHop, Nlri,
    Origin, Safi,
};
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

use super::BgpCodec;
use crate::message::{
    BgpMessage, Capability, CeaseError, GracefulRestartFamily, MpReachNlri, MsgHeaderError,
    NotificationError, NotificationMessage, OpenMessage, OpenMsgError, PathAttribute, Prefix,
    RouteRefreshMessage, UpdateMessage, UpdateMsgError,
};

fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
    any::<[u8; 4]>().prop_map(Ipv4Addr::from)
}

fn arb_ipv6() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u8; 16]>().prop_map(Ipv6Addr::from)
}

fn arb_asn() -> impl Strategy<Value = Asn> {
    any::<u32>().prop_map(Asn::new)
}

fn arb_afi_safi() -> impl Strategy<Value = AfiSafi> {
    (any::<u16>(), any::<u8>()).prop_map(|(a, s)| AfiSafi::new(Afi::new(a), Safi::new(s)))
}

fn arb_nlri_v4() -> impl Strategy<Value = Nlri<Ipv4Addr>> {
    (any::<[u8; 4]>(), 0u8..=32)
        .prop_map(|(addr, len)| Nlri::new(Ipv4Addr::from(addr), len).unwrap().masked())
}

fn arb_nlri_v6() -> impl Strategy<Value = Nlri<Ipv6Addr>> {
    (any::<[u8; 16]>(), 0u8..=128)
        .prop_map(|(addr, len)| Nlri::new(Ipv6Addr::from(addr), len).unwrap().masked())
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
        prop_oneof![
            Just(Origin::Igp),
            Just(Origin::Egp),
            Just(Origin::Incomplete),
        ]
        .prop_map(PathAttribute::Origin),
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
            .prop_map(|(next_hop, prefixes)| {
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop,
                    prefixes,
                })
            }),
    ]
}

fn arb_notification_error() -> impl Strategy<Value = NotificationError> {
    prop_oneof![
        Just(NotificationError::HoldTimerExpired),
        Just(NotificationError::FsmError),
        prop_oneof![
            Just(MsgHeaderError::ConnectionNotSynchronized),
            Just(MsgHeaderError::BadMessageLength),
            Just(MsgHeaderError::BadMessageType),
            prop_oneof![Just(0u8), 4u8..=u8::MAX].prop_map(MsgHeaderError::Unknown),
        ]
        .prop_map(NotificationError::MessageHeader),
        prop_oneof![
            Just(OpenMsgError::UnsupportedVersionNumber),
            Just(OpenMsgError::BadPeerAs),
            Just(OpenMsgError::BadBgpIdentifier),
            Just(OpenMsgError::UnsupportedOptionalParameter),
            Just(OpenMsgError::UnacceptableHoldTime),
            Just(OpenMsgError::UnsupportedCapability),
            prop_oneof![Just(0u8), Just(5u8), 8u8..=u8::MAX].prop_map(OpenMsgError::Unknown),
        ]
        .prop_map(NotificationError::OpenMessage),
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
            prop_oneof![Just(0u8), Just(7u8), 12u8..=u8::MAX].prop_map(UpdateMsgError::Unknown),
        ]
        .prop_map(NotificationError::UpdateMessage),
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
            prop_oneof![Just(0u8), 11u8..=u8::MAX].prop_map(CeaseError::Unknown),
        ]
        .prop_map(NotificationError::Cease),
        (prop_oneof![Just(0u8), 7u8..=u8::MAX], any::<u8>())
            .prop_map(|(code, subcode)| NotificationError::Unknown { code, subcode }),
    ]
}

fn arb_bgp_message() -> impl Strategy<Value = BgpMessage> {
    prop_oneof![
        Just(BgpMessage::Keepalive),
        (
            any::<u16>(),
            any::<u16>(),
            arb_ipv4(),
            prop::collection::vec(arb_capability(), 0..4),
        )
            .prop_map(|(my_as, hold_time, bgp_id, capabilities)| {
                BgpMessage::Open(OpenMessage {
                    version: 4,
                    my_as,
                    hold_time,
                    bgp_id,
                    capabilities,
                })
            }),
        (
            arb_notification_error(),
            prop::collection::vec(any::<u8>(), 0..16),
        )
            .prop_map(
                |(error, data)| BgpMessage::Notification(NotificationMessage { error, data })
            ),
        (
            prop::collection::vec(arb_nlri_v4(), 0..5),
            prop::collection::vec(arb_path_attribute(), 0..5),
            prop::collection::vec(arb_nlri_v4(), 0..5),
        )
            .prop_map(|(withdrawn, attributes, announced)| {
                // Deduplicate by type code so roundtrip holds (RFC 7606 §7.3
                // treats duplicates as errors, breaking the encode/decode invariant).
                let mut seen = std::collections::HashSet::new();
                let attributes: Vec<_> = attributes
                    .into_iter()
                    .filter(|a| seen.insert(a.type_code()))
                    .collect();
                BgpMessage::Update(UpdateMessage {
                    withdrawn,
                    attributes,
                    announced,
                })
            }),
        arb_afi_safi()
            .prop_map(|afi_safi| BgpMessage::RouteRefresh(RouteRefreshMessage { afi_safi })),
    ]
}

proptest! {
    /// Encode then decode via the codec produces the original message and
    /// leaves the buffer empty.
    #[test]
    fn prop_encode_decode_roundtrip(msg in arb_bgp_message()) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(decoded, msg);
        prop_assert_eq!(buf.len(), 0);
    }

    /// The decoder must never panic on arbitrary byte input.
    #[test]
    fn prop_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::from(bytes.as_slice());
        let _ = codec.decode(&mut buf);
    }

    /// Two messages concatenated in one buffer are decoded in order with exact
    /// byte consumption after each call.
    #[test]
    fn prop_back_to_back_messages_decode_in_order(
        first  in arb_bgp_message(),
        second in arb_bgp_message(),
    ) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::new();
        codec.encode(first.clone(), &mut buf).unwrap();
        codec.encode(second.clone(), &mut buf).unwrap();

        let got_first = codec.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(got_first, first);

        let got_second = codec.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(got_second, second);

        prop_assert_eq!(buf.len(), 0);
    }

    /// Every prefix strictly shorter than the full encoded message returns
    /// Ok(None) — the codec waits for more bytes rather than erroring.
    #[test]
    fn prop_partial_message_returns_none(msg in arb_bgp_message()) {
        let mut codec = BgpCodec;
        let full = msg.encode();
        for trunc_len in 0..full.len() {
            let mut buf = BytesMut::from(&full[..trunc_len]);
            prop_assert!(
                matches!(codec.decode(&mut buf), Ok(None)),
                "truncation at {trunc_len} of {} should return Ok(None)",
                full.len()
            );
        }
    }

    /// A length field outside [19, 4096] is rejected before the body arrives.
    #[test]
    fn prop_out_of_range_length_is_error(
        bad_len in prop_oneof![
            0u16..19u16,
            4097u16..=u16::MAX,
        ],
    ) {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::from([0xFF_u8; 16].as_slice()); // all-FF marker
        buf.extend_from_slice(&bad_len.to_be_bytes());
        buf.extend_from_slice(&[4u8]); // type byte (Keepalive)
        prop_assert!(codec.decode(&mut buf).is_err());
    }
}
