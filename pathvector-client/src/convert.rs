//! Conversions from generated proto types to [`crate::types`] domain objects.

use std::net::IpAddr;

use crate::{
    error::ConvertError,
    proto,
    types::{
        Aggregator, AsSegment, AsSegmentType, LargeCommunity, Origin, PeerState, PeerType, Route,
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
            peer_address: parse_addr(&p.peer_address)?,
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
