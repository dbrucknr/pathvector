use super::error::CodecError;
use super::header::{MessageType, encode_header};
use super::{Cursor, Writer};

/// A BGP NOTIFICATION message (type 3).
///
/// Sent when a BGP speaker detects an error. After sending a NOTIFICATION,
/// the TCP connection is closed immediately. The `data` field carries optional
/// diagnostic bytes — for example, the malformed attribute that caused the
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub error: NotificationError,
    /// Optional diagnostic payload (e.g. the offending attribute bytes).
    pub data: Vec<u8>,
}

impl NotificationMessage {
    pub(super) fn decode(cur: &mut Cursor<'_>) -> Result<Self, CodecError> {
        let code = cur.read_u8()?;
        let subcode = cur.read_u8()?;
        let data = cur.read_remaining().to_vec();
        Ok(Self {
            error: NotificationError::from_codes(code, subcode),
            data,
        })
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        let (code, subcode) = self.error.as_codes();
        body.put_u8(code);
        body.put_u8(subcode);
        body.put_slice(&self.data);
        let body = body.finish();

        let mut w = Writer::new();
        encode_header(&mut w, MessageType::Notification, body.len());
        w.put_slice(&body);
        w.finish()
    }
}

/// The typed error carried in a NOTIFICATION message.
///
/// Maps the two-byte (code, subcode) wire representation to a structured Rust
/// enum. Codes and subcodes not listed in the RFCs are preserved in the
/// `Unknown` variant so that diagnostic data is never silently discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationError {
    /// Error code 1 — problems with the message header.
    MessageHeader(MsgHeaderError),
    /// Error code 2 — problems with an OPEN message.
    OpenMessage(OpenMsgError),
    /// Error code 3 — problems with an UPDATE message.
    UpdateMessage(UpdateMsgError),
    /// Error code 4 — no KEEPALIVE or UPDATE received within the hold time.
    HoldTimerExpired,
    /// Error code 5 subcode 0 — FSM error, unspecified.
    FsmError,
    /// Error code 5 subcode 1 — unexpected message received in `OpenSent`
    /// state (RFC 4271 §6.5).
    FsmErrorOpenSent,
    /// Error code 5 subcode 2 — unexpected message received in `OpenConfirm`
    /// state (RFC 4271 §6.5).
    FsmErrorOpenConfirm,
    /// Error code 5 subcode 3 — unexpected message received in `Established`
    /// state (RFC 4271 §6.5).
    FsmErrorEstablished,
    /// Error code 6 — operator-initiated or policy-driven session teardown
    /// (RFC 4486).
    Cease(CeaseError),
    /// Any (code, subcode) pair not recognised above.
    Unknown { code: u8, subcode: u8 },
}

impl NotificationError {
    fn from_codes(code: u8, subcode: u8) -> Self {
        match code {
            1 => Self::MessageHeader(MsgHeaderError::from_u8(subcode)),
            2 => Self::OpenMessage(OpenMsgError::from_u8(subcode)),
            3 => Self::UpdateMessage(UpdateMsgError::from_u8(subcode)),
            4 => Self::HoldTimerExpired,
            5 => match subcode {
                1 => Self::FsmErrorOpenSent,
                2 => Self::FsmErrorOpenConfirm,
                3 => Self::FsmErrorEstablished,
                _ => Self::FsmError,
            },
            6 => Self::Cease(CeaseError::from_u8(subcode)),
            _ => Self::Unknown { code, subcode },
        }
    }

    fn as_codes(&self) -> (u8, u8) {
        match self {
            Self::MessageHeader(s) => (1, s.as_u8()),
            Self::OpenMessage(s) => (2, s.as_u8()),
            Self::UpdateMessage(s) => (3, s.as_u8()),
            Self::HoldTimerExpired => (4, 0),
            Self::FsmError => (5, 0),
            Self::FsmErrorOpenSent => (5, 1),
            Self::FsmErrorOpenConfirm => (5, 2),
            Self::FsmErrorEstablished => (5, 3),
            Self::Cease(s) => (6, s.as_u8()),
            Self::Unknown { code, subcode } => (*code, *subcode),
        }
    }
}

/// Subcodes for Message Header Error (code 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgHeaderError {
    ConnectionNotSynchronized,
    BadMessageLength,
    BadMessageType,
    Unknown(u8),
}

impl MsgHeaderError {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ConnectionNotSynchronized,
            2 => Self::BadMessageLength,
            3 => Self::BadMessageType,
            _ => Self::Unknown(v),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::ConnectionNotSynchronized => 1,
            Self::BadMessageLength => 2,
            Self::BadMessageType => 3,
            Self::Unknown(v) => v,
        }
    }
}

/// Subcodes for OPEN Message Error (code 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMsgError {
    UnsupportedVersionNumber,
    BadPeerAs,
    BadBgpIdentifier,
    UnsupportedOptionalParameter,
    UnacceptableHoldTime,
    UnsupportedCapability,
    Unknown(u8),
}

impl OpenMsgError {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::UnsupportedVersionNumber,
            2 => Self::BadPeerAs,
            3 => Self::BadBgpIdentifier,
            4 => Self::UnsupportedOptionalParameter,
            6 => Self::UnacceptableHoldTime,
            7 => Self::UnsupportedCapability,
            _ => Self::Unknown(v),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::UnsupportedVersionNumber => 1,
            Self::BadPeerAs => 2,
            Self::BadBgpIdentifier => 3,
            Self::UnsupportedOptionalParameter => 4,
            Self::UnacceptableHoldTime => 6,
            Self::UnsupportedCapability => 7,
            Self::Unknown(v) => v,
        }
    }
}

/// Subcodes for UPDATE Message Error (code 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMsgError {
    MalformedAttributeList,
    UnrecognizedWellKnownAttribute,
    MissingWellKnownAttribute,
    AttributeFlagsError,
    AttributeLengthError,
    InvalidOriginAttribute,
    InvalidNextHopAttribute,
    OptionalAttributeError,
    InvalidNetworkField,
    MalformedAsPath,
    Unknown(u8),
}

impl UpdateMsgError {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::MalformedAttributeList,
            2 => Self::UnrecognizedWellKnownAttribute,
            3 => Self::MissingWellKnownAttribute,
            4 => Self::AttributeFlagsError,
            5 => Self::AttributeLengthError,
            6 => Self::InvalidOriginAttribute,
            8 => Self::InvalidNextHopAttribute,
            9 => Self::OptionalAttributeError,
            10 => Self::InvalidNetworkField,
            11 => Self::MalformedAsPath,
            _ => Self::Unknown(v),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::MalformedAttributeList => 1,
            Self::UnrecognizedWellKnownAttribute => 2,
            Self::MissingWellKnownAttribute => 3,
            Self::AttributeFlagsError => 4,
            Self::AttributeLengthError => 5,
            Self::InvalidOriginAttribute => 6,
            Self::InvalidNextHopAttribute => 8,
            Self::OptionalAttributeError => 9,
            Self::InvalidNetworkField => 10,
            Self::MalformedAsPath => 11,
            Self::Unknown(v) => v,
        }
    }
}

/// Subcodes for Cease NOTIFICATION (code 6, RFC 4486).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeaseError {
    MaximumNumberOfPrefixesReached,
    AdministrativeShutdown,
    PeerDeconfigured,
    AdministrativeReset,
    ConnectionRejected,
    OtherConfigurationChange,
    ConnectionCollisionResolution,
    OutOfResources,
    HardReset,
    BfdDown,
    Unknown(u8),
}

impl CeaseError {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::MaximumNumberOfPrefixesReached,
            2 => Self::AdministrativeShutdown,
            3 => Self::PeerDeconfigured,
            4 => Self::AdministrativeReset,
            5 => Self::ConnectionRejected,
            6 => Self::OtherConfigurationChange,
            7 => Self::ConnectionCollisionResolution,
            8 => Self::OutOfResources,
            9 => Self::HardReset,
            10 => Self::BfdDown,
            _ => Self::Unknown(v),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::MaximumNumberOfPrefixesReached => 1,
            Self::AdministrativeShutdown => 2,
            Self::PeerDeconfigured => 3,
            Self::AdministrativeReset => 4,
            Self::ConnectionRejected => 5,
            Self::OtherConfigurationChange => 6,
            Self::ConnectionCollisionResolution => 7,
            Self::OutOfResources => 8,
            Self::HardReset => 9,
            Self::BfdDown => 10,
            Self::Unknown(v) => v,
        }
    }
}

/// Encode a UTF-8 reason string into a CEASE NOTIFICATION `data` field per RFC 9003 §2.
///
/// Wire format: one length byte followed by the UTF-8 string bytes.
/// The string is silently truncated to 128 bytes if longer.
#[must_use]
pub fn encode_shutdown_message(msg: &str) -> Vec<u8> {
    let bytes = msg.as_bytes();
    let len = bytes.len().min(128);
    let mut out = Vec::with_capacity(1 + len);
    #[allow(clippy::cast_possible_truncation)]
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
    out
}

/// Decode a RFC 9003 shutdown reason from the `data` field of a CEASE NOTIFICATION.
///
/// Returns `None` if the data is empty, the length byte is out of range, or the
/// bytes are not valid UTF-8.
#[must_use]
pub fn decode_shutdown_message(data: &[u8]) -> Option<String> {
    let (&len, rest) = data.split_first()?;
    let end = (len as usize).min(rest.len());
    String::from_utf8(rest[..end].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: &NotificationMessage) -> NotificationMessage {
        let encoded = msg.encode();
        // Strip the 19-byte header before passing to decode.
        let mut cur = Cursor::new(&encoded[19..]);
        NotificationMessage::decode(&mut cur).unwrap()
    }

    #[test]
    fn test_hold_timer_expired_roundtrip() {
        let msg = NotificationMessage {
            error: NotificationError::HoldTimerExpired,
            data: vec![],
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_cease_admin_shutdown_roundtrip() {
        let msg = NotificationMessage {
            error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
            data: b"going down for maintenance".to_vec(),
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_update_error_roundtrip() {
        let msg = NotificationMessage {
            error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAsPath),
            data: vec![0xDE, 0xAD],
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_unknown_code_preserved() {
        let msg = NotificationMessage {
            error: NotificationError::Unknown {
                code: 42,
                subcode: 7,
            },
            data: vec![],
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_encoded_length() {
        // NOTIFICATION header(19) + code(1) + subcode(1) + no data = 21 bytes.
        let msg = NotificationMessage {
            error: NotificationError::HoldTimerExpired,
            data: vec![],
        };
        assert_eq!(msg.encode().len(), 21);
    }

    #[test]
    fn test_header_marker_is_correct() {
        let msg = NotificationMessage {
            error: NotificationError::FsmError,
            data: vec![],
        };
        let encoded = msg.encode();
        assert!(encoded[..16].iter().all(|&b| b == 0xFF));
    }

    // ── MessageHeader subcodes ────────────────────────────────────────────────

    #[test]
    fn test_msg_header_error_roundtrips() {
        let cases = [
            NotificationError::MessageHeader(MsgHeaderError::ConnectionNotSynchronized),
            NotificationError::MessageHeader(MsgHeaderError::BadMessageLength),
            NotificationError::MessageHeader(MsgHeaderError::BadMessageType),
            NotificationError::MessageHeader(MsgHeaderError::Unknown(9)),
        ];
        for error in cases {
            let msg = NotificationMessage {
                error,
                data: vec![],
            };
            assert_eq!(roundtrip(&msg), msg);
        }
    }

    // ── OpenMessage subcodes ──────────────────────────────────────────────────

    #[test]
    fn test_open_msg_error_roundtrips() {
        let cases = [
            NotificationError::OpenMessage(OpenMsgError::UnsupportedVersionNumber),
            NotificationError::OpenMessage(OpenMsgError::BadPeerAs),
            NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier),
            NotificationError::OpenMessage(OpenMsgError::UnsupportedOptionalParameter),
            NotificationError::OpenMessage(OpenMsgError::UnacceptableHoldTime),
            NotificationError::OpenMessage(OpenMsgError::UnsupportedCapability),
            NotificationError::OpenMessage(OpenMsgError::Unknown(9)),
        ];
        for error in cases {
            let msg = NotificationMessage {
                error,
                data: vec![],
            };
            assert_eq!(roundtrip(&msg), msg);
        }
    }

    // ── FsmError ──────────────────────────────────────────────────────────────

    #[test]
    fn test_fsm_error_roundtrip() {
        let msg = NotificationMessage {
            error: NotificationError::FsmError,
            data: vec![],
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn test_fsm_error_subcodes_roundtrip() {
        let cases = [
            NotificationError::FsmError,
            NotificationError::FsmErrorOpenSent,
            NotificationError::FsmErrorOpenConfirm,
            NotificationError::FsmErrorEstablished,
        ];
        for error in cases {
            let msg = NotificationMessage {
                error,
                data: vec![],
            };
            assert_eq!(roundtrip(&msg), msg);
        }
    }

    // ── UpdateMessage subcodes ────────────────────────────────────────────────

    #[test]
    fn test_update_msg_error_all_variants_roundtrip() {
        let cases = [
            NotificationError::UpdateMessage(UpdateMsgError::MalformedAttributeList),
            NotificationError::UpdateMessage(UpdateMsgError::UnrecognizedWellKnownAttribute),
            NotificationError::UpdateMessage(UpdateMsgError::MissingWellKnownAttribute),
            NotificationError::UpdateMessage(UpdateMsgError::AttributeFlagsError),
            NotificationError::UpdateMessage(UpdateMsgError::AttributeLengthError),
            NotificationError::UpdateMessage(UpdateMsgError::InvalidOriginAttribute),
            NotificationError::UpdateMessage(UpdateMsgError::InvalidNextHopAttribute),
            NotificationError::UpdateMessage(UpdateMsgError::OptionalAttributeError),
            NotificationError::UpdateMessage(UpdateMsgError::InvalidNetworkField),
            NotificationError::UpdateMessage(UpdateMsgError::MalformedAsPath),
            NotificationError::UpdateMessage(UpdateMsgError::Unknown(99)),
        ];
        for error in cases {
            let msg = NotificationMessage {
                error,
                data: vec![],
            };
            assert_eq!(roundtrip(&msg), msg);
        }
    }

    // ── Cease subcodes ────────────────────────────────────────────────────────

    #[test]
    fn test_cease_all_variants_roundtrip() {
        let cases = [
            NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached),
            NotificationError::Cease(CeaseError::AdministrativeShutdown),
            NotificationError::Cease(CeaseError::PeerDeconfigured),
            NotificationError::Cease(CeaseError::AdministrativeReset),
            NotificationError::Cease(CeaseError::ConnectionRejected),
            NotificationError::Cease(CeaseError::OtherConfigurationChange),
            NotificationError::Cease(CeaseError::ConnectionCollisionResolution),
            NotificationError::Cease(CeaseError::OutOfResources),
            NotificationError::Cease(CeaseError::HardReset),
            NotificationError::Cease(CeaseError::BfdDown),
            NotificationError::Cease(CeaseError::Unknown(42)),
        ];
        for error in cases {
            let msg = NotificationMessage {
                error,
                data: vec![],
            };
            assert_eq!(roundtrip(&msg), msg);
        }
    }

    // ── RFC 9003 shutdown message helpers ─────────────────────────────────────

    #[test]
    fn test_rfc9003_encode_decode_roundtrip() {
        let reason = "going down for maintenance";
        let data = encode_shutdown_message(reason);
        assert_eq!(data[0] as usize, reason.len());
        assert_eq!(decode_shutdown_message(&data).unwrap(), reason);
    }

    #[test]
    fn test_rfc9003_message_truncated_to_128_bytes() {
        let long_msg = "x".repeat(200);
        let data = encode_shutdown_message(&long_msg);
        assert_eq!(data[0], 128);
        assert_eq!(data.len(), 129);
        let decoded = decode_shutdown_message(&data).unwrap();
        assert_eq!(decoded.len(), 128);
    }

    #[test]
    fn test_rfc9003_empty_data_returns_none() {
        assert!(decode_shutdown_message(&[]).is_none());
    }

    #[test]
    fn test_rfc9003_length_byte_exceeds_remaining_data() {
        // length byte says 10 bytes but only 3 follow — should clamp gracefully
        let data = vec![10u8, b'h', b'i', b'!'];
        let decoded = decode_shutdown_message(&data).unwrap();
        assert_eq!(decoded, "hi!");
    }

    #[test]
    fn test_rfc9003_shutdown_notification_roundtrips() {
        let reason = "planned maintenance";
        let msg = NotificationMessage {
            error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
            data: encode_shutdown_message(reason),
        };
        let decoded = roundtrip(&msg);
        assert_eq!(decoded, msg);
        assert_eq!(decode_shutdown_message(&decoded.data).unwrap(), reason);
    }

    #[test]
    fn test_rfc9003_admin_reset_roundtrips() {
        let reason = "config reload";
        let msg = NotificationMessage {
            error: NotificationError::Cease(CeaseError::AdministrativeReset),
            data: encode_shutdown_message(reason),
        };
        let decoded = roundtrip(&msg);
        assert_eq!(decode_shutdown_message(&decoded.data).unwrap(), reason);
    }
}
