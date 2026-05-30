mod error;
mod header;
mod notification;
mod open;
mod route_refresh;
mod update;

pub use error::CodecError;
pub use header::MessageType;
pub use notification::{
    CeaseError, MsgHeaderError, NotificationError, NotificationMessage, OpenMsgError,
    UpdateMsgError,
};
pub use open::{Capability, GracefulRestartFamily, OpenMessage};
pub use route_refresh::RouteRefreshMessage;
pub use update::{MpReachNlri, MpUnreachNlri, PathAttribute, Prefix, UpdateMessage};

use header::{decode_header, encode_header, MessageType as MsgType};

// ── Shared codec primitives ───────────────────────────────────────────────────
//
// Cursor<'a> and Writer are private to this module tree. Child modules import
// them via `use super::{Cursor, Writer}`.

/// A cursor for reading typed fields from a byte slice.
///
/// Every read method advances the internal position. All methods return
/// `CodecError::Truncated` rather than panicking when the buffer is
/// exhausted, making the codec safe to use on untrusted input.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8, CodecError> {
        if self.remaining() < 1 {
            return Err(CodecError::Truncated { needed: 1, available: 0 });
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, CodecError> {
        if self.remaining() < 2 {
            return Err(CodecError::Truncated { needed: 2, available: self.remaining() });
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, CodecError> {
        if self.remaining() < 4 {
            return Err(CodecError::Truncated { needed: 4, available: self.remaining() });
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return Err(CodecError::Truncated { needed: n, available: self.remaining() });
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_ipv4addr(&mut self) -> Result<std::net::Ipv4Addr, CodecError> {
        let b = self.read_bytes(4)?;
        Ok(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    }

    /// Create a sub-cursor over the next `n` bytes, advancing `self` past them.
    ///
    /// Used for parsing fixed-length sub-structures (optional parameters,
    /// path attribute values) without risking reading beyond their boundaries.
    fn fork(&mut self, n: usize) -> Result<Cursor<'a>, CodecError> {
        let slice = self.read_bytes(n)?;
        Ok(Cursor::new(slice))
    }

    /// Return all remaining bytes and advance the cursor to the end.
    fn read_remaining(&mut self) -> &'a [u8] {
        let slice = &self.data[self.pos..];
        self.pos = self.data.len();
        slice
    }
}

/// A writer for building BGP message byte buffers.
struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn put_u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn put_slice(&mut self, s: &[u8]) {
        self.0.extend_from_slice(s);
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

// ── BgpMessage ───────────────────────────────────────────────────────────────

/// A decoded BGP message.
///
/// This is the central type of the message codec. `decode` parses any of the
/// five BGP message types from a complete byte slice (including the 19-byte
/// header). `encode` serialises back to wire format including the header.
#[derive(Debug, Clone, PartialEq)]
pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    /// KEEPALIVE has no body — it is just the 19-byte header.
    Keepalive,
    RouteRefresh(RouteRefreshMessage),
}

impl BgpMessage {
    /// Decode one complete BGP message from `buf`.
    ///
    /// `buf` must contain exactly one message: the 19-byte header followed by
    /// the body. Use the framing layer to split a TCP stream into individual
    /// messages before calling this.
    ///
    /// # Errors
    ///
    /// Returns `CodecError` if the marker is corrupt, the length is out of
    /// range, the type is unknown, or any field within the body is malformed.
    pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
        let mut cur = Cursor::new(buf);
        let (msg_type, total_len) = decode_header(&mut cur)?;

        if buf.len() != total_len as usize {
            return Err(CodecError::InvalidLength(total_len));
        }

        // cur is now positioned at the body (total_len - HEADER_LEN bytes remain).
        match msg_type {
            MsgType::Open => Ok(Self::Open(OpenMessage::decode(&mut cur)?)),
            MsgType::Update => Ok(Self::Update(UpdateMessage::decode(&mut cur)?)),
            MsgType::Notification => {
                Ok(Self::Notification(NotificationMessage::decode(&mut cur)?))
            }
            MsgType::Keepalive => {
                if cur.remaining() != 0 {
                    return Err(CodecError::InvalidLength(total_len));
                }
                Ok(Self::Keepalive)
            }
            MsgType::RouteRefresh => {
                Ok(Self::RouteRefresh(RouteRefreshMessage::decode(&mut cur)?))
            }
        }
    }

    /// Encode this message to wire format, including the 19-byte header.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Open(m) => m.encode(),
            Self::Update(m) => m.encode(),
            Self::Notification(m) => m.encode(),
            Self::Keepalive => {
                let mut w = Writer::new();
                encode_header(&mut w, MsgType::Keepalive, 0);
                w.finish()
            }
            Self::RouteRefresh(m) => m.encode(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pathvector_types::{AfiSafi, AsPath, Asn, Origin};

    use super::*;

    fn roundtrip(msg: &BgpMessage) -> BgpMessage {
        let encoded = msg.encode();
        BgpMessage::decode(&encoded).unwrap()
    }

    #[test]
    fn test_keepalive_roundtrip() {
        assert_eq!(roundtrip(&BgpMessage::Keepalive), BgpMessage::Keepalive);
    }

    #[test]
    fn test_keepalive_is_19_bytes() {
        assert_eq!(BgpMessage::Keepalive.encode().len(), 19);
    }

    #[test]
    fn test_open_roundtrip() {
        let msg = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65001,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![
                Capability::FourByteAsn(65001),
                Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
                Capability::RouteRefresh,
            ],
        });
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_update_roundtrip() {
        let nlri: pathvector_types::Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let msg = BgpMessage::Update(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            announced: vec![nlri],
        });
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_notification_roundtrip() {
        let msg = BgpMessage::Notification(NotificationMessage {
            error: NotificationError::HoldTimerExpired,
            data: vec![],
        });
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_route_refresh_roundtrip() {
        let msg = BgpMessage::RouteRefresh(RouteRefreshMessage {
            afi_safi: AfiSafi::IPV6_UNICAST,
        });
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_decode_rejects_wrong_length() {
        // A buffer that claims to be 19 bytes long but has 20 bytes.
        let mut keepalive = BgpMessage::Keepalive.encode();
        keepalive.push(0x00);
        assert!(matches!(
            BgpMessage::decode(&keepalive),
            Err(CodecError::InvalidLength(_))
        ));
    }

    #[test]
    fn test_decode_rejects_bad_marker() {
        let mut keepalive = BgpMessage::Keepalive.encode();
        keepalive[0] = 0x00;
        assert_eq!(BgpMessage::decode(&keepalive), Err(CodecError::InvalidMarker));
    }

}
