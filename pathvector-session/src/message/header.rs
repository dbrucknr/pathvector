use super::error::CodecError;
use super::{Cursor, Writer};

/// Every BGP message begins with this 16-byte sequence.
pub(super) const MARKER: [u8; 16] = [0xFF; 16];
/// The fixed size of the BGP message header in bytes.
pub(super) const HEADER_LEN: usize = 19;
/// Maximum total BGP message length (header + body) per RFC 4271.
pub const MAX_LEN: usize = 4096;
/// Maximum total BGP message length when Extended Message is negotiated (RFC 8654).
pub const MAX_LEN_EXTENDED: usize = 65535;

/// The five BGP message types defined in RFC 4271 and RFC 2918.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}

impl MessageType {
    pub(super) fn from_u8(v: u8) -> Result<Self, CodecError> {
        match v {
            1 => Ok(Self::Open),
            2 => Ok(Self::Update),
            3 => Ok(Self::Notification),
            4 => Ok(Self::Keepalive),
            5 => Ok(Self::RouteRefresh),
            other => Err(CodecError::UnknownMessageType(other)),
        }
    }

    pub(super) fn as_u8(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Update => 2,
            Self::Notification => 3,
            Self::Keepalive => 4,
            Self::RouteRefresh => 5,
        }
    }
}

/// Parse the 19-byte BGP header from `cur`.
///
/// `max_len` is the negotiated upper bound on total message size — use
/// [`MAX_LEN`] for the default RFC 4271 limit or [`MAX_LEN_EXTENDED`] when
/// RFC 8654 Extended Message is in effect.
///
/// On success returns `(message_type, total_length)` where `total_length`
/// includes the header itself. The cursor is advanced past the header.
pub(super) fn decode_header(
    cur: &mut Cursor<'_>,
    max_len: usize,
) -> Result<(MessageType, u16), CodecError> {
    let marker = cur.read_bytes(16)?;
    if marker != MARKER {
        return Err(CodecError::InvalidMarker);
    }
    let length = cur.read_u16()?;
    if (length as usize) < HEADER_LEN || (length as usize) > max_len {
        return Err(CodecError::InvalidLength(length));
    }
    let msg_type = MessageType::from_u8(cur.read_u8()?)?;
    Ok((msg_type, length))
}

/// Write the 19-byte BGP header into `w`.
///
/// `body_len` is the byte count of the message body (not including the
/// header). The total length written to the length field is
/// `HEADER_LEN + body_len`.
pub(super) fn encode_header(w: &mut Writer, msg_type: MessageType, body_len: usize) {
    w.put_slice(&MARKER);
    // body_len is bounded by MAX_LEN - HEADER_LEN = 4077 which fits in u16.
    #[allow(clippy::cast_possible_truncation)]
    w.put_u16((HEADER_LEN + body_len) as u16);
    w.put_u8(msg_type.as_u8());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header(msg_type: u8, total_len: u16) -> Vec<u8> {
        let mut v = vec![0xFF; 16];
        v.extend_from_slice(&total_len.to_be_bytes());
        v.push(msg_type);
        v
    }

    #[test]
    fn test_decode_header_keepalive() {
        let bytes = valid_header(4, 19);
        let mut cur = Cursor::new(&bytes);
        let (t, len) = decode_header(&mut cur, MAX_LEN).unwrap();
        assert_eq!(t, MessageType::Keepalive);
        assert_eq!(len, 19);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn test_decode_header_invalid_marker() {
        let mut bytes = valid_header(4, 19);
        bytes[0] = 0x00; // corrupt marker
        let mut cur = Cursor::new(&bytes);
        assert_eq!(
            decode_header(&mut cur, MAX_LEN),
            Err(CodecError::InvalidMarker)
        );
    }

    #[test]
    fn test_decode_header_length_too_small() {
        let bytes = valid_header(4, 18); // below minimum
        let mut cur = Cursor::new(&bytes);
        assert_eq!(
            decode_header(&mut cur, MAX_LEN),
            Err(CodecError::InvalidLength(18))
        );
    }

    #[test]
    fn test_decode_header_length_too_large() {
        let bytes = valid_header(4, 4097); // above RFC 4271 maximum
        let mut cur = Cursor::new(&bytes);
        assert_eq!(
            decode_header(&mut cur, MAX_LEN),
            Err(CodecError::InvalidLength(4097))
        );
    }

    #[test]
    fn test_decode_header_length_valid_in_extended_mode() {
        // 4097 is valid when RFC 8654 Extended Message is negotiated.
        let mut header = vec![0xFF; 16];
        header.extend_from_slice(&4097_u16.to_be_bytes());
        header.push(4); // Keepalive type
        let mut cur = Cursor::new(&header);
        assert!(decode_header(&mut cur, MAX_LEN_EXTENDED).is_ok());
    }

    #[test]
    fn test_decode_header_unknown_type() {
        let bytes = valid_header(99, 19);
        let mut cur = Cursor::new(&bytes);
        assert_eq!(
            decode_header(&mut cur, MAX_LEN),
            Err(CodecError::UnknownMessageType(99))
        );
    }

    #[test]
    fn test_encode_decode_header_roundtrip() {
        let mut w = Writer::new();
        encode_header(&mut w, MessageType::Open, 10);
        let encoded = w.finish();
        assert_eq!(encoded.len(), HEADER_LEN);
        let mut cur = Cursor::new(&encoded);
        let (t, len) = decode_header(&mut cur, MAX_LEN).unwrap();
        assert_eq!(t, MessageType::Open);
        assert_eq!(len as usize, HEADER_LEN + 10);
    }
}
