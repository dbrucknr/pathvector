use pathvector_types::{Afi, AfiSafi, Safi};

use super::error::CodecError;
use super::header::{MessageType, encode_header};
use super::{Cursor, Writer};

/// A BGP ROUTE-REFRESH message (type 5, RFC 2918).
///
/// Requests the peer to re-advertise all routes for the given address family
/// without tearing down the session. Requires both sides to have negotiated
/// the Route Refresh capability during OPEN.
///
/// This is the primary tool for applying an updated import policy to an
/// existing session: send a ROUTE-REFRESH for each affected AFI/SAFI, then
/// re-process the incoming routes against the new policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    pub afi_safi: AfiSafi,
}

impl RouteRefreshMessage {
    pub(super) fn decode(cur: &mut Cursor<'_>) -> Result<Self, CodecError> {
        let afi = Afi::new(cur.read_u16()?);
        let _reserved = cur.read_u8()?;
        let safi = Safi::new(cur.read_u8()?);
        Ok(Self {
            afi_safi: AfiSafi::new(afi, safi),
        })
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        body.put_u16(self.afi_safi.afi.as_u16());
        body.put_u8(0); // reserved
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

    #[test]
    fn test_ipv4_unicast_roundtrip() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV4_UNICAST,
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_ipv6_unicast_roundtrip() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV6_UNICAST,
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_evpn_roundtrip() {
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::EVPN,
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_encoded_length() {
        // header(19) + AFI(2) + reserved(1) + SAFI(1) = 23 bytes.
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV4_UNICAST,
        };
        assert_eq!(msg.encode().len(), 23);
    }

    #[test]
    fn test_known_wire_bytes() {
        // IPv4 unicast: AFI=0x0001, reserved=0x00, SAFI=0x01
        let msg = RouteRefreshMessage {
            afi_safi: AfiSafi::IPV4_UNICAST,
        };
        let encoded = msg.encode();
        assert_eq!(&encoded[19..], &[0x00, 0x01, 0x00, 0x01]);
    }
}
