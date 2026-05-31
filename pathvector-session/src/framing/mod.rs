//! BGP framing layer.
//!
//! [`BgpCodec`] implements [`tokio_util::codec::Decoder`] and
//! [`tokio_util::codec::Encoder`], splitting a TCP byte stream into complete
//! BGP messages using the 2-byte length field in the BGP header.

use std::io;

use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::message::{BgpMessage, CodecError};

/// Total size of the BGP message header in bytes (marker + length + type).
const HEADER_LEN: usize = 19;
/// Offset of the 2-byte length field within the header.
const LEN_OFFSET: usize = 16;
/// Maximum total BGP message size (RFC 4271 §4.1).
const MAX_MSG_LEN: usize = 4096;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error returned by [`BgpCodec`].
#[derive(Debug)]
pub enum FramingError {
    /// Underlying I/O error from the transport.
    Io(io::Error),
    /// A complete frame arrived but failed BGP-level decoding.
    Codec(CodecError),
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Codec(e) => write!(f, "BGP codec: {e}"),
        }
    }
}

impl std::error::Error for FramingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Codec(e) => Some(e),
        }
    }
}

impl From<io::Error> for FramingError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CodecError> for FramingError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

// ── Codec ─────────────────────────────────────────────────────────────────────

/// BGP framing codec for use with [`tokio_util::codec::FramedRead`] /
/// [`tokio_util::codec::FramedWrite`].
///
/// The BGP header carries a 2-byte total-length field at offset 16. The codec
/// accumulates bytes until that many are available, then calls
/// [`BgpMessage::decode`] on the complete frame.
///
/// Wrap a [`tokio::net::TcpStream`] to get an async stream of decoded messages:
///
/// ```rust,ignore
/// use tokio_util::codec::FramedRead;
/// use pathvector_session::framing::BgpCodec;
///
/// let (reader, writer) = tcp_stream.into_split();
/// let mut framed = FramedRead::new(reader, BgpCodec);
/// while let Some(msg) = framed.next().await.transpose()? {
///     // msg: BgpMessage
/// }
/// ```
pub struct BgpCodec;

impl Decoder for BgpCodec {
    type Item = BgpMessage;
    type Error = FramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Wait until we have enough bytes to read the length field.
        if src.len() < HEADER_LEN {
            src.reserve(HEADER_LEN - src.len());
            return Ok(None);
        }

        let raw_len = u16::from_be_bytes([src[LEN_OFFSET], src[LEN_OFFSET + 1]]);
        let msg_len = usize::from(raw_len);

        // Validate before waiting for the rest of the body — a bad length
        // means the framing is broken and the connection must be closed.
        if !(HEADER_LEN..=MAX_MSG_LEN).contains(&msg_len) {
            return Err(FramingError::Codec(CodecError::InvalidLength(raw_len)));
        }

        if src.len() < msg_len {
            src.reserve(msg_len - src.len());
            return Ok(None);
        }

        let frame = src.split_to(msg_len);
        Ok(Some(BgpMessage::decode(&frame)?))
    }
}

impl Encoder<BgpMessage> for BgpCodec {
    type Error = FramingError;

    fn encode(&mut self, msg: BgpMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_slice(&msg.encode());
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod prop_tests;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    use super::*;
    use crate::message::{Capability, OpenMessage};

    fn keepalive_bytes() -> BytesMut {
        BytesMut::from(BgpMessage::Keepalive.encode().as_slice())
    }

    fn open_bytes() -> BytesMut {
        let msg = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65001,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![Capability::FourByteAsn(65001)],
        });
        BytesMut::from(msg.encode().as_slice())
    }

    // ── Decoder ───────────────────────────────────────────────────────────────

    #[test]
    fn test_partial_header_returns_none() {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::from(&[0xFF_u8; 10][..]);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
    }

    #[test]
    fn test_complete_header_but_incomplete_body_returns_none() {
        let mut codec = BgpCodec;
        // OPEN is longer than 19 bytes; truncate to exactly 19.
        let mut buf = open_bytes();
        let full_len = buf.len();
        assert!(full_len > HEADER_LEN);
        buf.truncate(full_len - 1); // one byte short of the full message
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
    }

    #[test]
    fn test_decode_keepalive() {
        let mut codec = BgpCodec;
        let mut buf = keepalive_bytes();
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg, BgpMessage::Keepalive);
        assert_eq!(buf.len(), 0, "buffer should be fully consumed");
    }

    #[test]
    fn test_decode_open() {
        let mut codec = BgpCodec;
        let mut buf = open_bytes();
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(msg, BgpMessage::Open(_)));
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decode_two_messages_in_one_buffer() {
        let mut codec = BgpCodec;
        let mut buf = keepalive_bytes();
        buf.extend_from_slice(&BgpMessage::Keepalive.encode());

        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(first, BgpMessage::Keepalive);
        assert_eq!(buf.len(), HEADER_LEN, "second message still in buffer");

        let second = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(second, BgpMessage::Keepalive);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decode_message_followed_by_partial() {
        let mut codec = BgpCodec;
        let mut buf = keepalive_bytes();
        buf.extend_from_slice(&[0xFF_u8; 5]); // partial of a second message

        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(first, BgpMessage::Keepalive);

        // Partial second frame should return None, not error.
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
    }

    #[test]
    fn test_decode_length_too_small_is_error() {
        let mut codec = BgpCodec;
        // Build a header with length=10 (below the 19-byte minimum).
        let mut buf = BytesMut::from([0xFF_u8; 16].as_slice());
        buf.extend_from_slice(&10_u16.to_be_bytes()); // length = 10
        buf.extend_from_slice(&[4_u8]); // type = Keepalive
        assert!(matches!(
            codec.decode(&mut buf),
            Err(FramingError::Codec(CodecError::InvalidLength(10)))
        ));
    }

    #[test]
    fn test_decode_length_too_large_is_error() {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::from([0xFF_u8; 16].as_slice());
        buf.extend_from_slice(&4097_u16.to_be_bytes()); // length = 4097
        buf.extend_from_slice(&[4_u8]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(FramingError::Codec(CodecError::InvalidLength(4097)))
        ));
    }

    #[test]
    fn test_decode_corrupt_marker_is_error() {
        let mut codec = BgpCodec;
        let mut bytes = BgpMessage::Keepalive.encode();
        bytes[0] = 0x00; // corrupt the first marker byte
        let mut buf = BytesMut::from(bytes.as_slice());
        assert!(matches!(
            codec.decode(&mut buf),
            Err(FramingError::Codec(CodecError::InvalidMarker))
        ));
    }

    // ── Encoder ───────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_keepalive_produces_19_bytes() {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::new();
        codec.encode(BgpMessage::Keepalive, &mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_LEN);
    }

    #[test]
    fn test_encode_sets_all_ff_marker() {
        let mut codec = BgpCodec;
        let mut buf = BytesMut::new();
        codec.encode(BgpMessage::Keepalive, &mut buf).unwrap();
        assert!(buf[..16].iter().all(|&b| b == 0xFF));
    }

    // ── FramingError trait impls ──────────────────────────────────────────────

    #[test]
    fn test_framing_error_io_display() {
        let e = FramingError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"));
        assert!(e.to_string().starts_with("I/O:"));
    }

    #[test]
    fn test_framing_error_codec_display() {
        let e = FramingError::Codec(CodecError::InvalidMarker);
        assert_eq!(e.to_string(), "BGP codec: BGP marker is not all 0xFF");
    }

    #[test]
    fn test_framing_error_io_source() {
        use std::error::Error;
        let e = FramingError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "test"));
        assert!(e.source().is_some());
    }

    #[test]
    fn test_framing_error_codec_source() {
        use std::error::Error;
        let e = FramingError::Codec(CodecError::InvalidMarker);
        assert!(e.source().is_some());
    }

    #[test]
    fn test_framing_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let framing_err = FramingError::from(io_err);
        assert!(matches!(framing_err, FramingError::Io(_)));
    }

    #[test]
    fn test_framing_error_from_codec_error() {
        let codec_err = CodecError::InvalidMarker;
        let framing_err = FramingError::from(codec_err);
        assert!(matches!(framing_err, FramingError::Codec(_)));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut codec = BgpCodec;
        let original = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65001,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![Capability::RouteRefresh],
        });

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, original);
    }
}
