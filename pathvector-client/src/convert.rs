//! Conversions from generated proto types to [`crate::types`] domain objects.

use std::net::IpAddr;

use crate::{
    error::ConvertError,
    proto,
    types::{
        Aggregator, AsSegment, AsSegmentType, LargeCommunity, Origin, OriginateRouteParams,
        PeerEvent, PeerEventType, PeerState, PeerType, Route, RouteEvent, RouteEventType,
        SessionState,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_addr(s: &str) -> Result<IpAddr, ConvertError> {
    s.parse()
        .map_err(|_| ConvertError::InvalidAddress(s.to_owned()))
}

fn parse_addr_opt(s: &str) -> Result<Option<IpAddr>, ConvertError> {
    if s.is_empty() {
        Ok(None)
    } else {
        s.parse()
            .map(Some)
            .map_err(|_| ConvertError::InvalidAddress(s.to_owned()))
    }
}

/// Parse a route peer address: "local" → None (locally originated route),
/// any other string → Some(IpAddr) or an error.
fn parse_route_peer(s: &str) -> Result<Option<IpAddr>, ConvertError> {
    if s == "local" {
        Ok(None)
    } else {
        parse_addr(s).map(Some)
    }
}

// ── SessionState ──────────────────────────────────────────────────────────────

impl TryFrom<i32> for SessionState {
    type Error = ConvertError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            // proto SessionState::SessionStateIdle = 1
            // proto SessionState::SessionStateUnspecified = 0  (treat as Idle)
            0 | 1 => Ok(Self::Idle),
            // proto SessionState::SessionStateEstablished = 2
            2 => Ok(Self::Established),
            other => Err(ConvertError::UnknownEnumValue("SessionState", other)),
        }
    }
}

// ── PeerType ──────────────────────────────────────────────────────────────────

fn peer_type_from_i32(value: i32) -> Option<PeerType> {
    match value {
        1 => Some(PeerType::External),
        2 => Some(PeerType::Internal),
        _ => None,
    }
}

impl TryFrom<i32> for PeerType {
    type Error = ConvertError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        peer_type_from_i32(value).ok_or(ConvertError::UnknownEnumValue("PeerType", value))
    }
}

// ── Origin ────────────────────────────────────────────────────────────────────

impl TryFrom<i32> for Origin {
    type Error = ConvertError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Igp),
            1 => Ok(Self::Egp),
            2 => Ok(Self::Incomplete),
            other => Err(ConvertError::UnknownEnumValue("Origin", other)),
        }
    }
}

// ── AsSegmentType ─────────────────────────────────────────────────────────────

impl TryFrom<i32> for AsSegmentType {
    type Error = ConvertError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Sequence),
            2 => Ok(Self::Set),
            3 => Ok(Self::ConfedSequence),
            4 => Ok(Self::ConfedSet),
            other => Err(ConvertError::UnknownEnumValue("AsSegmentType", other)),
        }
    }
}

// ── AsSegment ─────────────────────────────────────────────────────────────────

impl TryFrom<proto::AsSegment> for AsSegment {
    type Error = ConvertError;

    fn try_from(p: proto::AsSegment) -> Result<Self, Self::Error> {
        Ok(Self {
            kind: AsSegmentType::try_from(p.r#type)?,
            asns: p.asns,
        })
    }
}

// ── LargeCommunity ────────────────────────────────────────────────────────────

impl From<proto::LargeCommunity> for LargeCommunity {
    fn from(p: proto::LargeCommunity) -> Self {
        Self {
            global_admin: p.global_admin,
            local_data1: p.local_data1,
            local_data2: p.local_data2,
        }
    }
}

// ── Aggregator ────────────────────────────────────────────────────────────────

impl TryFrom<proto::Aggregator> for Aggregator {
    type Error = ConvertError;

    fn try_from(p: proto::Aggregator) -> Result<Self, Self::Error> {
        Ok(Self {
            asn: p.asn,
            address: parse_addr(&p.address)?,
        })
    }
}

// ── ExtendedCommunity ─────────────────────────────────────────────────────────

fn ext_community_from_bytes(b: Vec<u8>) -> Result<[u8; 8], ConvertError> {
    let len = b.len();
    b.try_into()
        .map_err(|_| ConvertError::BadExtendedCommunityLen(len))
}

// ── Route ─────────────────────────────────────────────────────────────────────

impl TryFrom<proto::Route> for Route {
    type Error = ConvertError;

    fn try_from(p: proto::Route) -> Result<Self, Self::Error> {
        let as_path = p
            .as_path
            .into_iter()
            .map(AsSegment::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let large_communities = p
            .large_communities
            .into_iter()
            .map(LargeCommunity::from)
            .collect();

        let extended_communities = p
            .extended_communities
            .into_iter()
            .map(ext_community_from_bytes)
            .collect::<Result<Vec<_>, _>>()?;

        let aggregator = p.aggregator.map(Aggregator::try_from).transpose()?;

        Ok(Self {
            prefix: p.prefix,
            peer_address: parse_route_peer(&p.peer_address)?,
            peer_type: PeerType::try_from(p.peer_type)?,
            next_hop: parse_addr_opt(&p.next_hop)?,
            as_path,
            origin: Origin::try_from(p.origin)?,
            local_pref: p.local_pref,
            med: p.med,
            communities: p.communities,
            large_communities,
            extended_communities,
            atomic_aggregate: p.atomic_aggregate,
            aggregator,
        })
    }
}

// ── PeerState ─────────────────────────────────────────────────────────────────

impl TryFrom<proto::PeerState> for PeerState {
    type Error = ConvertError;

    fn try_from(p: proto::PeerState) -> Result<Self, Self::Error> {
        Ok(Self {
            address: parse_addr(&p.address)?,
            remote_as: p.remote_as,
            local_as: p.local_as,
            session_state: SessionState::try_from(p.session_state)?,
            peer_type: peer_type_from_i32(p.peer_type),
            hold_time: p.hold_time,
            uptime_seconds: p.uptime_seconds,
            prefixes_received: p.prefixes_received,
            prefixes_accepted: p.prefixes_accepted,
            prefixes_advertised: p.prefixes_advertised,
        })
    }
}

// ── OriginateRouteParams → proto ──────────────────────────────────────────────

impl From<OriginateRouteParams> for proto::OriginateRouteRequest {
    fn from(p: OriginateRouteParams) -> Self {
        Self {
            prefix: p.prefix,
            next_hop: p.next_hop,
            origin: match p.origin {
                Origin::Igp => 0,
                Origin::Egp => 1,
                Origin::Incomplete => 2,
            },
            communities: p.communities,
            large_communities: p
                .large_communities
                .into_iter()
                .map(|lc| proto::LargeCommunity {
                    global_admin: lc.global_admin,
                    local_data1: lc.local_data1,
                    local_data2: lc.local_data2,
                })
                .collect(),
            extended_communities: p
                .extended_communities
                .into_iter()
                .map(|arr| arr.to_vec())
                .collect(),
            local_pref: p.local_pref,
            med: p.med,
        }
    }
}

// ── RouteEventType ────────────────────────────────────────────────────────────

impl TryFrom<i32> for RouteEventType {
    type Error = ConvertError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Current),
            2 => Ok(Self::EndInitial),
            3 => Ok(Self::Announced),
            4 => Ok(Self::Withdrawn),
            other => Err(ConvertError::UnknownEnumValue("RouteEventType", other)),
        }
    }
}

// ── RouteEvent ────────────────────────────────────────────────────────────────

impl TryFrom<proto::RouteEvent> for RouteEvent {
    type Error = ConvertError;

    fn try_from(p: proto::RouteEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            event_type: RouteEventType::try_from(p.r#type)?,
            route: p.route.map(Route::try_from).transpose()?,
            withdrawn_prefix: p.withdrawn_prefix,
        })
    }
}

// ── PeerEventType ─────────────────────────────────────────────────────────────

impl TryFrom<i32> for PeerEventType {
    type Error = ConvertError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Current),
            2 => Ok(Self::EndInitial),
            3 => Ok(Self::Changed),
            other => Err(ConvertError::UnknownEnumValue("PeerEventType", other)),
        }
    }
}

// ── PeerEvent ─────────────────────────────────────────────────────────────────

impl TryFrom<proto::PeerEvent> for PeerEvent {
    type Error = ConvertError;

    fn try_from(p: proto::PeerEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            event_type: PeerEventType::try_from(p.r#type)?,
            peer: p.peer.map(PeerState::try_from).transpose()?,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use proptest::prelude::*;

    use super::*;
    use crate::error::ConvertError;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal valid proto Route (all required fields populated, all
    /// optional fields absent) for use as a base in targeted tests.
    fn minimal_proto_route() -> proto::Route {
        proto::Route {
            prefix: "10.0.0.0/8".into(),
            peer_address: "192.0.2.1".into(),
            peer_type: 1, // External
            next_hop: String::new(),
            as_path: vec![],
            origin: 0, // Igp
            local_pref: None,
            med: None,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            atomic_aggregate: false,
            aggregator: None,
        }
    }

    /// Build a minimal valid proto PeerState.
    fn minimal_proto_peer_state() -> proto::PeerState {
        proto::PeerState {
            address: "192.0.2.1".into(),
            remote_as: 65001,
            local_as: 65000,
            session_state: 1, // Idle
            peer_type: 0,     // Unspecified → None
            hold_time: 0,
            uptime_seconds: 0,
            prefixes_received: 0,
            prefixes_accepted: 0,
            prefixes_advertised: 0,
        }
    }

    // ── parse_addr ────────────────────────────────────────────────────────────

    #[test]
    fn parse_addr_ipv4() {
        let ip = parse_addr("192.0.2.1").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn parse_addr_ipv6() {
        let ip = parse_addr("2001:db8::1").unwrap();
        assert_eq!(ip, IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn parse_addr_empty_is_error() {
        assert!(matches!(
            parse_addr(""),
            Err(ConvertError::InvalidAddress(s)) if s.is_empty()
        ));
    }

    #[test]
    fn parse_addr_garbage_is_error() {
        assert!(matches!(
            parse_addr("not-an-ip"),
            Err(ConvertError::InvalidAddress(_))
        ));
    }

    // ── parse_addr_opt ────────────────────────────────────────────────────────

    #[test]
    fn parse_addr_opt_empty_is_none() {
        assert_eq!(parse_addr_opt("").unwrap(), None);
    }

    #[test]
    fn parse_addr_opt_valid_ipv4() {
        let ip = parse_addr_opt("10.0.0.1").unwrap();
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn parse_addr_opt_valid_ipv6() {
        let ip = parse_addr_opt("::1").unwrap();
        assert_eq!(ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn parse_addr_opt_garbage_is_error() {
        assert!(matches!(
            parse_addr_opt("garbage"),
            Err(ConvertError::InvalidAddress(_))
        ));
    }

    // ── SessionState ──────────────────────────────────────────────────────────

    #[test]
    fn session_state_unspecified_maps_to_idle() {
        // Proto SESSION_STATE_UNSPECIFIED = 0. We treat it as Idle rather than
        // returning an error so that old/forward-compatible daemons don't break
        // the client.
        assert_eq!(SessionState::try_from(0).unwrap(), SessionState::Idle);
    }

    #[test]
    fn session_state_idle() {
        assert_eq!(SessionState::try_from(1).unwrap(), SessionState::Idle);
    }

    #[test]
    fn session_state_established() {
        assert_eq!(
            SessionState::try_from(2).unwrap(),
            SessionState::Established
        );
    }

    #[test]
    fn session_state_unknown_is_error() {
        for v in [3, 99, -1, i32::MAX, i32::MIN] {
            assert!(
                matches!(
                    SessionState::try_from(v),
                    Err(ConvertError::UnknownEnumValue("SessionState", _))
                ),
                "expected Err for SessionState discriminant {v}"
            );
        }
    }

    // ── PeerType ──────────────────────────────────────────────────────────────

    #[test]
    fn peer_type_external() {
        assert_eq!(PeerType::try_from(1).unwrap(), PeerType::External);
    }

    #[test]
    fn peer_type_internal() {
        assert_eq!(PeerType::try_from(2).unwrap(), PeerType::Internal);
    }

    /// Discriminant 0 is PEER_TYPE_UNSPECIFIED. Routes must have a concrete
    /// type, so this is an error via `TryFrom` — unlike `PeerState` where
    /// `peer_type_from_i32` returns `None` for unspecified.
    #[test]
    fn peer_type_unspecified_is_error_via_try_from() {
        assert!(matches!(
            PeerType::try_from(0),
            Err(ConvertError::UnknownEnumValue("PeerType", 0))
        ));
    }

    #[test]
    fn peer_type_unknown_is_error() {
        for v in [3, 99, -1, i32::MAX] {
            assert!(
                matches!(
                    PeerType::try_from(v),
                    Err(ConvertError::UnknownEnumValue("PeerType", _))
                ),
                "expected Err for PeerType discriminant {v}"
            );
        }
    }

    /// `peer_type_from_i32` is the fallible-to-option variant used for
    /// `PeerState`, where unspecified is valid (session not yet established).
    #[test]
    fn peer_type_from_i32_unspecified_is_none() {
        assert_eq!(peer_type_from_i32(0), None);
    }

    #[test]
    fn peer_type_from_i32_known_values() {
        assert_eq!(peer_type_from_i32(1), Some(PeerType::External));
        assert_eq!(peer_type_from_i32(2), Some(PeerType::Internal));
    }

    #[test]
    fn peer_type_from_i32_unknown_is_none() {
        for v in [3, 99, -1, i32::MAX] {
            assert_eq!(
                peer_type_from_i32(v),
                None,
                "expected None for unknown discriminant {v}"
            );
        }
    }

    // ── Origin ────────────────────────────────────────────────────────────────

    #[test]
    fn origin_all_known_values() {
        assert_eq!(Origin::try_from(0).unwrap(), Origin::Igp);
        assert_eq!(Origin::try_from(1).unwrap(), Origin::Egp);
        assert_eq!(Origin::try_from(2).unwrap(), Origin::Incomplete);
    }

    #[test]
    fn origin_unknown_is_error() {
        for v in [3, 99, -1, i32::MAX] {
            assert!(
                matches!(
                    Origin::try_from(v),
                    Err(ConvertError::UnknownEnumValue("Origin", _))
                ),
                "expected Err for Origin discriminant {v}"
            );
        }
    }

    // ── AsSegmentType ─────────────────────────────────────────────────────────

    #[test]
    fn as_segment_type_all_known_values() {
        assert_eq!(AsSegmentType::try_from(1).unwrap(), AsSegmentType::Sequence);
        assert_eq!(AsSegmentType::try_from(2).unwrap(), AsSegmentType::Set);
        assert_eq!(
            AsSegmentType::try_from(3).unwrap(),
            AsSegmentType::ConfedSequence
        );
        assert_eq!(
            AsSegmentType::try_from(4).unwrap(),
            AsSegmentType::ConfedSet
        );
    }

    /// Discriminant 0 is TYPE_UNSPECIFIED — the proto allows it but we reject
    /// it because a segment with no type is meaningless in path processing.
    #[test]
    fn as_segment_type_unspecified_is_error() {
        assert!(matches!(
            AsSegmentType::try_from(0),
            Err(ConvertError::UnknownEnumValue("AsSegmentType", 0))
        ));
    }

    #[test]
    fn as_segment_type_unknown_is_error() {
        for v in [5, 99, -1, i32::MAX] {
            assert!(
                matches!(
                    AsSegmentType::try_from(v),
                    Err(ConvertError::UnknownEnumValue("AsSegmentType", _))
                ),
                "expected Err for AsSegmentType discriminant {v}"
            );
        }
    }

    // ── ext_community_from_bytes ──────────────────────────────────────────────

    #[test]
    fn ext_community_exactly_8_bytes_ok() {
        let arr = ext_community_from_bytes(vec![0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert_eq!(arr, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn ext_community_preserves_byte_values() {
        let bytes = vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64];
        let arr = ext_community_from_bytes(bytes).unwrap();
        assert_eq!(arr[1], 0x02);
        assert_eq!(arr[7], 0x64);
    }

    #[test]
    fn ext_community_wrong_lengths_are_errors() {
        for len in [0usize, 1, 7, 9, 16, 100] {
            let bytes = vec![0u8; len];
            assert!(
                matches!(
                    ext_community_from_bytes(bytes),
                    Err(ConvertError::BadExtendedCommunityLen(n)) if n == len
                ),
                "expected Err for ext community of {len} bytes"
            );
        }
    }

    // ── AsSegment ─────────────────────────────────────────────────────────────

    #[test]
    fn as_segment_valid_sequence() {
        let p = proto::AsSegment {
            r#type: 1, // Sequence
            asns: vec![65000, 65001, 65002],
        };
        let seg = AsSegment::try_from(p).unwrap();
        assert_eq!(seg.kind, AsSegmentType::Sequence);
        assert_eq!(seg.asns, vec![65000, 65001, 65002]);
    }

    #[test]
    fn as_segment_invalid_type_is_error() {
        let p = proto::AsSegment {
            r#type: 0, // Unspecified
            asns: vec![65000],
        };
        assert!(matches!(
            AsSegment::try_from(p),
            Err(ConvertError::UnknownEnumValue("AsSegmentType", 0))
        ));
    }

    #[test]
    fn as_segment_empty_asns_is_valid() {
        let p = proto::AsSegment {
            r#type: 1,
            asns: vec![],
        };
        let seg = AsSegment::try_from(p).unwrap();
        assert!(seg.asns.is_empty());
    }

    // ── LargeCommunity ────────────────────────────────────────────────────────

    #[test]
    fn large_community_field_preservation() {
        let p = proto::LargeCommunity {
            global_admin: 65000,
            local_data1: 100,
            local_data2: 200,
        };
        let lc = LargeCommunity::from(p);
        assert_eq!(lc.global_admin, 65000);
        assert_eq!(lc.local_data1, 100);
        assert_eq!(lc.local_data2, 200);
    }

    #[test]
    fn large_community_max_values() {
        let p = proto::LargeCommunity {
            global_admin: u32::MAX,
            local_data1: u32::MAX,
            local_data2: u32::MAX,
        };
        let lc = LargeCommunity::from(p);
        assert_eq!(lc.global_admin, u32::MAX);
    }

    // ── Aggregator ────────────────────────────────────────────────────────────

    #[test]
    fn aggregator_valid_ipv4() {
        let p = proto::Aggregator {
            asn: 65001,
            address: "10.0.0.1".into(),
        };
        let agg = Aggregator::try_from(p).unwrap();
        assert_eq!(agg.asn, 65001);
        assert_eq!(agg.address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn aggregator_valid_ipv6() {
        let p = proto::Aggregator {
            asn: 65001,
            address: "2001:db8::1".into(),
        };
        let agg = Aggregator::try_from(p).unwrap();
        assert_eq!(agg.asn, 65001);
        assert!(matches!(agg.address, IpAddr::V6(_)));
    }

    #[test]
    fn aggregator_invalid_address_is_error() {
        let p = proto::Aggregator {
            asn: 65001,
            address: "not-an-ip".into(),
        };
        assert!(matches!(
            Aggregator::try_from(p),
            Err(ConvertError::InvalidAddress(_))
        ));
    }

    // ── Route ─────────────────────────────────────────────────────────────────

    #[test]
    fn route_minimal_valid() {
        let r = Route::try_from(minimal_proto_route()).unwrap();
        assert_eq!(r.prefix, "10.0.0.0/8");
        assert_eq!(r.peer_address, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert_eq!(r.peer_type, PeerType::External);
        assert_eq!(r.next_hop, None);
        assert!(r.as_path.is_empty());
        assert_eq!(r.origin, Origin::Igp);
        assert_eq!(r.local_pref, None);
        assert_eq!(r.med, None);
        assert!(r.communities.is_empty());
        assert!(r.large_communities.is_empty());
        assert!(r.extended_communities.is_empty());
        assert!(!r.atomic_aggregate);
        assert_eq!(r.aggregator, None);
    }

    #[test]
    fn route_with_next_hop() {
        let mut p = minimal_proto_route();
        p.next_hop = "10.0.0.254".into();
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.next_hop, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))));
    }

    #[test]
    fn route_with_local_pref_and_med() {
        let mut p = minimal_proto_route();
        p.local_pref = Some(100);
        p.med = Some(50);
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.local_pref, Some(100));
        assert_eq!(r.med, Some(50));
    }

    #[test]
    fn route_with_communities() {
        let mut p = minimal_proto_route();
        p.communities = vec![0x0001_0064, 0xFFFF_FFFE];
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.communities, vec![0x0001_0064, 0xFFFF_FFFE]);
    }

    #[test]
    fn route_with_large_communities() {
        let mut p = minimal_proto_route();
        p.large_communities = vec![proto::LargeCommunity {
            global_admin: 65000,
            local_data1: 1,
            local_data2: 2,
        }];
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.large_communities.len(), 1);
        assert_eq!(r.large_communities[0].global_admin, 65000);
    }

    #[test]
    fn route_with_extended_communities() {
        let mut p = minimal_proto_route();
        p.extended_communities = vec![vec![0, 2, 0, 0, 0, 0, 0, 100]];
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.extended_communities.len(), 1);
        assert_eq!(r.extended_communities[0], [0, 2, 0, 0, 0, 0, 0, 100]);
    }

    #[test]
    fn route_with_as_path() {
        let mut p = minimal_proto_route();
        p.as_path = vec![proto::AsSegment {
            r#type: 1, // Sequence
            asns: vec![65001, 65002],
        }];
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.as_path.len(), 1);
        assert_eq!(r.as_path[0].asns, vec![65001, 65002]);
    }

    #[test]
    fn route_with_aggregator() {
        let mut p = minimal_proto_route();
        p.aggregator = Some(proto::Aggregator {
            asn: 65001,
            address: "10.0.0.1".into(),
        });
        p.atomic_aggregate = true;
        let r = Route::try_from(p).unwrap();
        assert!(r.atomic_aggregate);
        let agg = r.aggregator.unwrap();
        assert_eq!(agg.asn, 65001);
    }

    #[test]
    fn route_ibgp_peer_type() {
        let mut p = minimal_proto_route();
        p.peer_type = 2; // Internal
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.peer_type, PeerType::Internal);
    }

    #[test]
    fn route_bad_peer_address_is_error() {
        let mut p = minimal_proto_route();
        p.peer_address = "bad".into();
        assert!(matches!(
            Route::try_from(p),
            Err(ConvertError::InvalidAddress(_))
        ));
    }

    #[test]
    fn route_local_peer_address_maps_to_none() {
        let mut p = minimal_proto_route();
        p.peer_address = "local".into();
        let r = Route::try_from(p).unwrap();
        assert_eq!(r.peer_address, None);
    }

    #[test]
    fn route_bad_next_hop_is_error() {
        let mut p = minimal_proto_route();
        p.next_hop = "bad-ip".into();
        assert!(matches!(
            Route::try_from(p),
            Err(ConvertError::InvalidAddress(_))
        ));
    }

    #[test]
    fn route_unspecified_peer_type_is_error() {
        // Routes must have a concrete peer type. PeerType::try_from(0) is Err.
        let mut p = minimal_proto_route();
        p.peer_type = 0;
        assert!(matches!(
            Route::try_from(p),
            Err(ConvertError::UnknownEnumValue("PeerType", 0))
        ));
    }

    #[test]
    fn route_unknown_origin_is_error() {
        let mut p = minimal_proto_route();
        p.origin = 99;
        assert!(matches!(
            Route::try_from(p),
            Err(ConvertError::UnknownEnumValue("Origin", 99))
        ));
    }

    #[test]
    fn route_bad_as_segment_type_is_error() {
        let mut p = minimal_proto_route();
        p.as_path = vec![proto::AsSegment {
            r#type: 0, // Unspecified
            asns: vec![65001],
        }];
        assert!(matches!(
            Route::try_from(p),
            Err(ConvertError::UnknownEnumValue("AsSegmentType", 0))
        ));
    }

    #[test]
    fn route_bad_extended_community_len_is_error() {
        let mut p = minimal_proto_route();
        p.extended_communities = vec![vec![0u8; 7]]; // 7 bytes — not 8
        assert!(matches!(
            Route::try_from(p),
            Err(ConvertError::BadExtendedCommunityLen(7))
        ));
    }

    #[test]
    fn route_bad_aggregator_address_is_error() {
        let mut p = minimal_proto_route();
        p.aggregator = Some(proto::Aggregator {
            asn: 1,
            address: "not-an-ip".into(),
        });
        assert!(matches!(
            Route::try_from(p),
            Err(ConvertError::InvalidAddress(_))
        ));
    }

    // ── PeerState ─────────────────────────────────────────────────────────────

    #[test]
    fn peer_state_minimal_valid() {
        let ps = PeerState::try_from(minimal_proto_peer_state()).unwrap();
        assert_eq!(ps.address, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(ps.remote_as, 65001);
        assert_eq!(ps.local_as, 65000);
        assert_eq!(ps.session_state, SessionState::Idle);
        assert_eq!(ps.peer_type, None); // unspecified
    }

    #[test]
    fn peer_state_established() {
        let mut p = minimal_proto_peer_state();
        p.session_state = 2; // Established
        p.peer_type = 1; // External
        p.hold_time = 90;
        p.uptime_seconds = 3600;
        let ps = PeerState::try_from(p).unwrap();
        assert_eq!(ps.session_state, SessionState::Established);
        assert_eq!(ps.peer_type, Some(PeerType::External));
        assert_eq!(ps.hold_time, 90);
        assert_eq!(ps.uptime_seconds, 3600);
    }

    #[test]
    fn peer_state_ibgp() {
        let mut p = minimal_proto_peer_state();
        p.session_state = 2;
        p.peer_type = 2; // Internal
        let ps = PeerState::try_from(p).unwrap();
        assert_eq!(ps.peer_type, Some(PeerType::Internal));
    }

    #[test]
    fn peer_state_prefix_counters() {
        let mut p = minimal_proto_peer_state();
        p.prefixes_received = 100;
        p.prefixes_accepted = 80;
        p.prefixes_advertised = 50;
        let ps = PeerState::try_from(p).unwrap();
        assert_eq!(ps.prefixes_received, 100);
        assert_eq!(ps.prefixes_accepted, 80);
        assert_eq!(ps.prefixes_advertised, 50);
    }

    #[test]
    fn peer_state_bad_address_is_error() {
        let mut p = minimal_proto_peer_state();
        p.address = "not-an-ip".into();
        assert!(matches!(
            PeerState::try_from(p),
            Err(ConvertError::InvalidAddress(_))
        ));
    }

    #[test]
    fn peer_state_unknown_session_state_is_error() {
        let mut p = minimal_proto_peer_state();
        p.session_state = 99;
        assert!(matches!(
            PeerState::try_from(p),
            Err(ConvertError::UnknownEnumValue("SessionState", 99))
        ));
    }

    /// Unknown peer_type discriminants in PeerState silently map to None
    /// (not an error) because the peer_type field is optional.
    #[test]
    fn peer_state_unknown_peer_type_maps_to_none() {
        let mut p = minimal_proto_peer_state();
        p.peer_type = 99;
        let ps = PeerState::try_from(p).unwrap();
        assert_eq!(ps.peer_type, None);
    }

    // ── Error Display ─────────────────────────────────────────────────────────

    #[test]
    fn convert_error_display_invalid_address() {
        let e = ConvertError::InvalidAddress("bad".into());
        assert_eq!(e.to_string(), r#"invalid IP address: "bad""#);
    }

    #[test]
    fn convert_error_display_unknown_enum() {
        let e = ConvertError::UnknownEnumValue("Origin", 99);
        assert_eq!(e.to_string(), "unknown Origin discriminant: 99");
    }

    #[test]
    fn convert_error_display_bad_ext_community() {
        let e = ConvertError::BadExtendedCommunityLen(7);
        assert_eq!(e.to_string(), "extended community must be 8 bytes, got 7");
    }

    // ── Proptest ──────────────────────────────────────────────────────────────

    proptest! {
        /// Any Vec<u8> of length != 8 must fail; length == 8 must succeed.
        #[test]
        fn prop_ext_community_succeeds_iff_exactly_8_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..=32)) {
            let len = bytes.len();
            let result = ext_community_from_bytes(bytes);
            if len == 8 {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(matches!(result, Err(ConvertError::BadExtendedCommunityLen(n)) if n == len));
            }
        }

        /// SessionState conversion must never panic and must succeed only for
        /// discriminants 0, 1, 2.
        #[test]
        fn prop_session_state_total(v: i32) {
            let result = SessionState::try_from(v);
            match v {
                0 | 1 => prop_assert_eq!(result.unwrap(), SessionState::Idle),
                2     => prop_assert_eq!(result.unwrap(), SessionState::Established),
                _     => prop_assert!(result.is_err()),
            }
        }

        /// Origin conversion must never panic and must succeed only for 0, 1, 2.
        #[test]
        fn prop_origin_total(v: i32) {
            let result = Origin::try_from(v);
            match v {
                0 => prop_assert_eq!(result.unwrap(), Origin::Igp),
                1 => prop_assert_eq!(result.unwrap(), Origin::Egp),
                2 => prop_assert_eq!(result.unwrap(), Origin::Incomplete),
                _ => prop_assert!(result.is_err()),
            }
        }

        /// AsSegmentType conversion must never panic; succeeds only for 1–4.
        #[test]
        fn prop_as_segment_type_total(v: i32) {
            let result = AsSegmentType::try_from(v);
            match v {
                1 => prop_assert_eq!(result.unwrap(), AsSegmentType::Sequence),
                2 => prop_assert_eq!(result.unwrap(), AsSegmentType::Set),
                3 => prop_assert_eq!(result.unwrap(), AsSegmentType::ConfedSequence),
                4 => prop_assert_eq!(result.unwrap(), AsSegmentType::ConfedSet),
                _ => prop_assert!(result.is_err()),
            }
        }

        /// PeerType try_from must never panic; succeeds only for 1 and 2.
        #[test]
        fn prop_peer_type_total(v: i32) {
            let result = PeerType::try_from(v);
            match v {
                1 => prop_assert_eq!(result.unwrap(), PeerType::External),
                2 => prop_assert_eq!(result.unwrap(), PeerType::Internal),
                _ => prop_assert!(result.is_err()),
            }
        }

        /// peer_type_from_i32 must never panic; returns None for anything
        /// other than 1 and 2.
        #[test]
        fn prop_peer_type_from_i32_total(v: i32) {
            let result = peer_type_from_i32(v);
            match v {
                1 => prop_assert_eq!(result, Some(PeerType::External)),
                2 => prop_assert_eq!(result, Some(PeerType::Internal)),
                _ => prop_assert_eq!(result, None),
            }
        }

        /// parse_addr must never panic, regardless of input.
        #[test]
        fn prop_parse_addr_never_panics(s in ".*") {
            let _ = parse_addr(&s);
        }

        /// parse_addr_opt must never panic; empty string always returns Ok(None).
        #[test]
        fn prop_parse_addr_opt_empty_always_none(s in ".*") {
            let _ = parse_addr_opt(&s);
        }

        #[test]
        fn prop_parse_addr_opt_empty_string_is_always_none(_: ()) {
            prop_assert_eq!(parse_addr_opt("").unwrap(), None);
        }

        /// A Route conversion with a valid peer_address, peer_type, and origin
        /// but an arbitrarily-lengthed extended community should succeed iff
        /// every byte slice is exactly 8 bytes.
        #[test]
        fn prop_route_ext_community_gatekeeping(
            lens in proptest::collection::vec(0usize..=16, 0..=8)
        ) {
            let mut p = minimal_proto_route();
            p.extended_communities = lens.iter().map(|&n| vec![0u8; n]).collect();
            let all_8 = lens.iter().all(|&n| n == 8);
            let result = Route::try_from(p);
            if all_8 {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(matches!(result, Err(ConvertError::BadExtendedCommunityLen(_))));
            }
        }
    }
}
