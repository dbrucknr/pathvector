use pathvector_types::{Afi, AfiSafi, Safi};

use super::error::CodecError;
use super::header::{MessageType, encode_header};
use super::{Cursor, Writer};

/// RFC 7313 Enhanced Route Refresh subtype.
///
/// The "reserved" byte in the RFC 2918 ROUTE-REFRESH body is repurposed
/// as a subtype to signal the start / end of a route refresh operation.
///
/// When a session supports the Enhanced Route Refresh capability, a receiver
/// can use `Begin` / `End` to know when a full re-advertisement is complete
/// so that stale routes can be purged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteRefreshSubtype {
    /// Normal ROUTE-REFRESH (RFC 2918 / RFC 7313 subtype 0).
    #[default]
    Refresh,
    /// Start of a route refresh burst (RFC 7313 subtype 1, `ORF_BEGIN`).
    BeginRefresh,
    /// End of a route refresh burst (RFC 7313 subtype 2, `ORF_END`).
    EndRefresh,
    /// Unknown subtype — preserved for forward compatibility.
    Unknown(u8),
}

impl RouteRefreshSubtype {
    pub(super) fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Refresh,
            1 => Self::BeginRefresh,
            2 => Self::EndRefresh,
            _ => Self::Unknown(v),
        }
    }

    pub(super) fn as_u8(self) -> u8 {
        match self {
            Self::Refresh => 0,
            Self::BeginRefresh => 1,
            Self::EndRefresh => 2,
            Self::Unknown(v) => v,
        }
    }
}

/// A BGP ROUTE-REFRESH message (type 5, RFC 2918 / RFC 7313).
///
/// Requests the peer to re-advertise all routes for the given address family
/// without tearing down the session. Requires both sides to have negotiated
/// the Route Refresh capability during OPEN.
///
/// `subtype` is set to [`RouteRefreshSubtype::Refresh`] for a standard
/// RFC 2918 request. Use [`RouteRefreshSubtype::BeginRefresh`] and
/// [`RouteRefreshSubtype::EndRefresh`] when the Enhanced Route Refresh
/// capability (RFC 7313) has been negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    pub afi_safi: AfiSafi,
    /// RFC 7313 subtype (encoded in the previously-reserved byte).
    pub subtype: RouteRefreshSubtype,
}

impl RouteRefreshMessage {
    /// Create a standard RFC 2918 ROUTE-REFRESH request.
    #[must_use]
    pub fn new(afi_safi: AfiSafi) -> Self {
        Self {
            afi_safi,
            subtype: RouteRefreshSubtype::Refresh,
        }
    }

    pub(super) fn decode(cur: &mut Cursor<'_>) -> Result<Self, CodecError> {
        let afi = Afi::new(cur.read_u16()?);
        let subtype = RouteRefreshSubtype::from_u8(cur.read_u8()?);
        let safi = Safi::new(cur.read_u8()?);
        Ok(Self {
            afi_safi: AfiSafi::new(afi, safi),
            subtype,
        })
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        body.put_u16(self.afi_safi.afi.as_u16());
        body.put_u8(self.subtype.as_u8());
        body.put_u8(self.afi_safi.safi.as_u8());
        let body = body.finish();

        let mut w = Writer::new();
        encode_header(&mut w, MessageType::RouteRefresh, body.len());
        w.put_slice(&body);
        w.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: &RouteRefreshMessage) -> RouteRefreshMessage {
        let encoded = msg.encode();
        let mut cur = Cursor::new(&encoded[19..]);
        RouteRefreshMessage::decode(&mut cur).unwrap()
    }

    // ── RFC 2918 baseline ─────────────────────────────────────────────────────

    #[test]
    fn test_ipv4_unicast_roundtrip() {
        let msg = RouteRefreshMessage::new(AfiSafi::IPV4_UNICAST);
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_ipv6_unicast_roundtrip() {
        let msg = RouteRefreshMessage::new(AfiSafi::IPV6_UNICAST);
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_evpn_roundtrip() {
        let msg = RouteRefreshMessage::new(AfiSafi::EVPN);
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_encoded_length() {
        // header(19) + AFI(2) + subtype(1) + SAFI(1) = 23 bytes.
        let msg = RouteRefreshMessage::new(AfiSafi::IPV4_UNICAST);
        assert_eq!(msg.encode().len(), 23);
    }

    #[test]
    fn test_known_wire_bytes_rfc2918() {
        // IPv4 unicast: AFI=0x0001, subtype=0x00 (Refresh), SAFI=0x01
        let msg = RouteRefreshMessage::new(AfiSafi::IPV4_UNICAST);
        let encoded = msg.encode();
        assert_eq!(&encoded[19..], &[0x00, 0x01, 0x00, 0x01]);
    }

    // ── RFC 7313 Enhanced Route Refresh subtypes ──────────────────────────────

    #[test]
    fn test_begin_refresh_roundtrip() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV4_UNICAST,
            subtype: RouteRefreshSubtype::BeginRefresh,
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_end_refresh_roundtrip() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV4_UNICAST,
            subtype: RouteRefreshSubtype::EndRefresh,
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_unknown_subtype_preserved() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV6_UNICAST,
            subtype: RouteRefreshSubtype::Unknown(42),
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_begin_refresh_wire_byte_is_1() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV4_UNICAST,
            subtype: RouteRefreshSubtype::BeginRefresh,
        };
        let encoded = msg.encode();
        // bytes [19..]: AFI(2) + subtype(1) + SAFI(1)
        // subtype byte is encoded[21]
        assert_eq!(encoded[21], 1);
    }

    #[test]
    fn test_end_refresh_wire_byte_is_2() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV4_UNICAST,
            subtype: RouteRefreshSubtype::EndRefresh,
        };
        assert_eq!(msg.encode()[21], 2);
    }

    #[test]
    fn test_subtype_default_is_refresh() {
        assert_eq!(RouteRefreshSubtype::default(), RouteRefreshSubtype::Refresh);
    }
}
