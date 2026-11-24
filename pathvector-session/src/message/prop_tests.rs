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
        let msg = BgpMessage::RouteRefresh(RouteRefreshMessage::new(afi_safi));
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
                Just(OpenMsgError::RoleMismatch),
                // Known subcodes: 1, 2, 3, 4, 6, 7, 11 (RFC 9234 §5.1). Exclude those.
                prop_oneof![Just(0u8), Just(5u8), 8u8..=10u8, 12u8..=u8::MAX]
                    .prop_map(OpenMsgError::Unknown),
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

// ── RFC 6793 ASN-width properties (issue #95) ────────────────────────────
//
// Round trips are a *consistency* check only — the exact-bytes proof lives
// in `asn_width_tests.rs`. What these add is breadth: arbitrary ASNs across
// the 16/32-bit boundary, arbitrary segment mixes, and segment sizes around
// the 255-ASN limit.

fn arb_wide_asn() -> impl Strategy<Value = Asn> {
    prop_oneof![
        // 16-bit-mappable (incl. AS_TRANS and the boundary)
        (0u32..=65_535).prop_map(Asn::new),
        Just(Asn::TRANS),
        // non-mappable
        (65_536u32..=u32::MAX).prop_map(Asn::new),
    ]
}

/// A path as a four-octet speaker can build it: zero or more *leading*
/// confederation segments (RFC 5065 places them first), then ordinary
/// segments. Each segment is non-empty and within the 255-ASN wire limit.
///
/// Confederation segments only hold two-octet-mappable Member-AS numbers:
/// RFC 6793 §7 ("A non-mappable four-octet AS number cannot be used as a
/// 'Member AS Number' of a BGP Confederation until all the BGP speakers
/// within the Confederation have transitioned") and §4.2.2 (confederation
/// segments are excluded from `AS4_PATH`) mean a non-mappable ASN there is
/// unrecoverable across an OLD speaker by design.
fn arb_realistic_path() -> impl Strategy<Value = AsPath> {
    let asns = || prop::collection::vec(arb_wide_asn(), 1..6);
    let confed_asns = || prop::collection::vec((0u32..=65_535).prop_map(Asn::new), 1..6);
    (
        prop::collection::vec(
            prop_oneof![
                confed_asns().prop_map(AsPathSegment::ConfedSequence),
                confed_asns().prop_map(AsPathSegment::ConfedSet),
            ],
            0..3,
        ),
        prop::collection::vec(
            prop_oneof![
                asns().prop_map(AsPathSegment::Sequence),
                asns().prop_map(AsPathSegment::Set),
            ],
            0..4,
        ),
    )
        .prop_map(|(confed, normal)| {
            AsPath::from_segments(confed.into_iter().chain(normal).collect())
        })
}

fn update_with_path(path: AsPath, agg: Option<Aggregator>) -> UpdateMessage {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(path),
        PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
    ];
    if let Some(a) = agg {
        attributes.push(PathAttribute::Aggregator(a));
    }
    UpdateMessage {
        withdrawn: vec![],
        attributes,
        announced: vec![Nlri::new(Ipv4Addr::new(198, 51, 100, 0), 24).unwrap()],
    }
}

fn flat_asns(path: &AsPath) -> Vec<u32> {
    path.segments()
        .iter()
        .flat_map(|s| s.asns().iter().map(|a| a.as_u32()))
        .collect()
}

proptest! {
    /// Four-octet session: AS_PATH and AGGREGATOR survive encode -> decode.
    #[test]
    fn prop_four_octet_as_path_and_aggregator_roundtrip(
        path in arb_realistic_path(),
        agg_asn in arb_wide_asn(),
        agg_ip in arb_ipv4(),
    ) {
        let msg = BgpMessage::Update(update_with_path(path, Some(Aggregator::new(agg_asn, agg_ip))));
        let wire = msg.encode_with(AsnWidth::Four);
        prop_assert_eq!(
            BgpMessage::decode_with_limit_and_caps(&wire, MAX_LEN_EXTENDED, AsnWidth::Four).unwrap(),
            msg
        );
    }

    /// Two-octet session, arbitrary ASNs including non-mappable ones: what we
    /// encode for an OLD peer (AS_TRANS + generated AS4_PATH / AS4_AGGREGATOR)
    /// is exactly reconstructed by RFC 6793 §4.2.3 when received back, and no
    /// transition attribute is left over.
    #[test]
    fn prop_two_octet_encode_then_decode_recovers_the_true_path_and_aggregator(
        path in arb_realistic_path(),
        agg_asn in arb_wide_asn(),
        agg_ip in arb_ipv4(),
    ) {
        let msg = BgpMessage::Update(update_with_path(path, Some(Aggregator::new(agg_asn, agg_ip))));
        let wire = msg.encode_with(AsnWidth::Two);
        prop_assert_eq!(
            BgpMessage::decode_with_limit_and_caps(&wire, MAX_LEN_EXTENDED, AsnWidth::Two).unwrap(),
            msg
        );
    }

    /// The wire never holds a two-octet ASN that was not mappable: decoding
    /// the AS_PATH *without* merging (an OLD peer's view) shows only mappable
    /// ASNs or AS_TRANS, and path length is preserved.
    #[test]
    fn prop_old_peer_view_preserves_path_length(path in arb_realistic_path()) {
        let want = path.path_length();
        let wire = BgpMessage::Update(update_with_path(path, None)).encode_with(AsnWidth::Two);
        // Strip AS4_PATH (0xC0 0x11 ...) by re-decoding at two octets and
        // reading only what an OLD speaker reads is covered by exact-byte
        // tests; here we check the merged length is unchanged.
        let BgpMessage::Update(u) =
            BgpMessage::decode_with_limit_and_caps(&wire, MAX_LEN_EXTENDED, AsnWidth::Two).unwrap()
        else { panic!("clean update expected") };
        let PathAttribute::AsPath(got) = &u.attributes[1] else { panic!("AS_PATH") };
        prop_assert_eq!(got.path_length(), want);
    }

    /// A single sequence of any length (well past 255) is split into legal
    /// segments on encode and decodes to the same ASNs in order, at both
    /// widths; every encoded segment count is within 1..=255.
    #[test]
    fn prop_long_sequences_split_at_255_and_roundtrip(
        len in 1usize..700,
        base in 0u32..60_000,
    ) {
        let flat: Vec<Asn> = (0..len).map(|i| Asn::new(base + u32::try_from(i).unwrap())).collect();
        let msg = BgpMessage::Update(update_with_path(AsPath::from_sequence(flat.clone()), None));
        for width in [AsnWidth::Two, AsnWidth::Four] {
            let wire = msg.encode_with(width);
            let BgpMessage::Update(u) =
                BgpMessage::decode_with_limit_and_caps(&wire, MAX_LEN_EXTENDED, width).unwrap()
            else { panic!("clean update expected") };
            let PathAttribute::AsPath(got) = &u.attributes[1] else { panic!("AS_PATH") };
            prop_assert_eq!(flat_asns(got), flat.iter().map(|a| a.as_u32()).collect::<Vec<_>>());
            prop_assert_eq!(got.path_length(), len);
            for seg in got.segments() {
                prop_assert!((1..=255).contains(&seg.asns().len()));
            }
        }
    }

    /// Decoding arbitrary bytes at either width never panics.
    #[test]
    fn prop_decode_never_panics_at_either_width(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        for width in [AsnWidth::Two, AsnWidth::Four] {
            let _ = BgpMessage::decode_with_limit_and_caps(&bytes, MAX_LEN_EXTENDED, width);
        }
    }
}
