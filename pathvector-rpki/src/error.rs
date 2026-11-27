use std::time::Duration;

use crate::pdu::RtrVersion;

/// Errors produced by the RTR PDU codec.
///
/// The client answers a received PDU that fails to decode with an RFC 8210 §12
/// Error Report and drops the session — except an Error Report, which is never
/// answered (§5.11). Once a protocol version is agreed, a PDU at any other
/// version gets code 8 whatever else is wrong with it (§7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduError {
    /// The byte slice is shorter than required to read the next field.
    Truncated { needed: usize, available: usize },
    /// The PDU type byte does not match any known RTR PDU type. Error Report
    /// code 5 ("Unsupported PDU Type").
    UnknownPduType(u8),
    /// The protocol version byte is neither 0 (RFC 6810) nor 1 (RFC 8210).
    /// Error Report code 4 ("Unsupported Protocol Version") during version
    /// negotiation, 8 after it; a Serial Notify is ignored during it (§7).
    UnknownVersion(u8),
    /// The PDU's declared length field does not match the expected length
    /// for its type (and, for v0/v1-variable PDUs like End of Data, version).
    /// Error Report code 0 ("Corrupt Data").
    InvalidLength { pdu_type: u8, len: u32 },
    /// An Error Report PDU's text field is not valid UTF-8.
    Utf8(std::str::Utf8Error),
    /// A Prefix PDU's lengths are outside what RFC 8210 §§5.1, 5.6 and 5.7
    /// permit (RFC 6810 §5 for version 0). Error Report code 0 ("Corrupt
    /// Data").
    InvalidPrefix(VrpError),
}

impl std::fmt::Display for PduError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(f, "truncated: need {needed} bytes, have {available}")
            }
            Self::UnknownPduType(t) => write!(f, "unknown RTR PDU type: {t}"),
            Self::UnknownVersion(v) => {
                write!(f, "unknown RTR protocol version: {v} (expected 0 or 1)")
            }
            Self::InvalidLength { pdu_type, len } => {
                write!(f, "invalid PDU length {len} for PDU type {pdu_type}")
            }
            Self::Utf8(e) => write!(f, "invalid UTF-8 in Error Report text: {e}"),
            Self::InvalidPrefix(e) => write!(f, "invalid Prefix PDU: {e}"),
        }
    }
}

impl std::error::Error for PduError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Utf8(e) => Some(e),
            Self::InvalidPrefix(e) => Some(e),
            _ => None,
        }
    }
}

/// Why a `(prefix length, max length)` pair cannot form a VRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrpError {
    /// Prefix Length is longer than the address family's addresses.
    PrefixLengthExceedsFamily { prefix_len: u8, family_bits: u8 },
    /// Max Length is longer than the address family's addresses.
    MaxLengthExceedsFamily { max_len: u8, family_bits: u8 },
    /// RFC 8210 §5.1: Max Length "MUST NOT be less than the Prefix Length
    /// element".
    MaxLengthBelowPrefixLength { prefix_len: u8, max_len: u8 },
}

impl std::fmt::Display for VrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrefixLengthExceedsFamily {
                prefix_len,
                family_bits,
            } => write!(
                f,
                "Prefix Length {prefix_len} exceeds the {family_bits}-bit address family"
            ),
            Self::MaxLengthExceedsFamily {
                max_len,
                family_bits,
            } => write!(
                f,
                "Max Length {max_len} exceeds the {family_bits}-bit address family"
            ),
            Self::MaxLengthBelowPrefixLength {
                prefix_len,
                max_len,
            } => write!(
                f,
                "Max Length {max_len} is less than Prefix Length {prefix_len}"
            ),
        }
    }
}

impl std::error::Error for VrpError {}

/// An [`RtrConfig`](crate::RtrConfig) timer is outside what RFC 8210 §6
/// permits a cache to advertise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtrConfigError {
    /// `field` is outside `min..=max`.
    OutOfRange {
        field: &'static str,
        value: Duration,
        min: Duration,
        max: Duration,
    },
    /// RFC 8210 §6: "Caches MUST set Expire Interval to a value larger than
    /// either Refresh Interval or Retry Interval." The configured defaults
    /// (used for the first sync and for every v0 session) should honour the
    /// same relationship.
    ExpireNotAfterPollIntervals {
        expire: Duration,
        refresh: Duration,
        retry: Duration,
    },
}

impl std::fmt::Display for RtrConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange {
                field,
                value,
                min,
                max,
            } => write!(
                f,
                "RTR {field} of {}s is outside the RFC 8210 §6 range {}s..={}s",
                value.as_secs(),
                min.as_secs(),
                max.as_secs()
            ),
            Self::ExpireNotAfterPollIntervals {
                expire,
                refresh,
                retry,
            } => write!(
                f,
                "RTR expire_interval ({}s) must be larger than both refresh_interval ({}s) \
                 and retry_interval ({}s) (RFC 8210 §6)",
                expire.as_secs(),
                refresh.as_secs(),
                retry.as_secs()
            ),
        }
    }
}

impl std::error::Error for RtrConfigError {}

/// Errors produced by an RTR client session.
#[derive(Debug)]
pub enum RtrError {
    /// A TCP-level I/O error (connect, read, write).
    Io(std::io::Error),
    /// A malformed PDU was received.
    Pdu(PduError),
    /// A PDU of an unexpected type arrived at this point in the session
    /// lifecycle (e.g. a Prefix PDU before a Cache Response).
    UnexpectedPdu { expected: &'static str, got: String },
    /// The server sent an Error Report PDU.
    ErrorReported { code: u16, text: String },
    /// A PDU's Session ID does not match the session the router is in (the
    /// remembered session for a Serial Query's Cache Response or a Serial
    /// Notify; the Cache Response's session for End of Data).
    SessionIdMismatch { expected: u16, got: u16 },
    /// A PDU arrived at a Protocol Version other than the one negotiated for
    /// this session (RFC 8210 §7: the version "is stable for the life of the
    /// session"; the party that sees a different one MUST drop the session).
    UnexpectedVersion {
        expected: RtrVersion,
        got: RtrVersion,
    },
    /// A cache answered a Serial Query that resumed a session of one protocol
    /// version at a lower one. RFC 8210 §5.1: sessions of different versions
    /// are separate sessions, so the incremental response cannot be applied;
    /// the client reconnects and performs a full resynchronisation at the
    /// lower version.
    VersionChanged {
        resumed: RtrVersion,
        answered: RtrVersion,
    },
    /// The TCP connection closed unexpectedly.
    Closed,
}

impl std::fmt::Display for RtrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "RTR session I/O error: {e}"),
            Self::Pdu(e) => write!(f, "RTR PDU error: {e}"),
            Self::UnexpectedPdu { expected, got } => {
                write!(f, "expected {expected} PDU, got {got}")
            }
            Self::ErrorReported { code, text } => {
                write!(f, "RTR server reported error {code}: {text}")
            }
            Self::SessionIdMismatch { expected, got } => {
                write!(f, "RTR session ID mismatch: expected {expected}, got {got}")
            }
            Self::UnexpectedVersion { expected, got } => write!(
                f,
                "RTR protocol version {got:?} PDU in a {expected:?} session"
            ),
            Self::VersionChanged { resumed, answered } => write!(
                f,
                "RTR cache answered a {resumed:?} session resume at {answered:?}; \
                 resynchronising from scratch at {answered:?}"
            ),
            Self::Closed => write!(f, "RTR connection closed"),
        }
    }
}

impl std::error::Error for RtrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Pdu(e) => Some(e),
            _ => None,
        }
    }
}

impl From<PduError> for RtrError {
    fn from(e: PduError) -> Self {
        Self::Pdu(e)
    }
}

impl From<std::io::Error> for RtrError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdu_error_display_truncated() {
        let e = PduError::Truncated {
            needed: 8,
            available: 3,
        };
        assert_eq!(e.to_string(), "truncated: need 8 bytes, have 3");
    }

    #[test]
    fn pdu_error_display_unknown_pdu_type() {
        assert_eq!(
            PduError::UnknownPduType(42).to_string(),
            "unknown RTR PDU type: 42"
        );
    }

    #[test]
    fn pdu_error_display_unknown_version() {
        assert_eq!(
            PduError::UnknownVersion(9).to_string(),
            "unknown RTR protocol version: 9 (expected 0 or 1)"
        );
    }

    #[test]
    fn pdu_error_display_invalid_length() {
        assert_eq!(
            PduError::InvalidLength {
                pdu_type: 4,
                len: 5
            }
            .to_string(),
            "invalid PDU length 5 for PDU type 4"
        );
    }

    #[test]
    fn pdu_error_is_std_error() {
        let e: &dyn std::error::Error = &PduError::UnknownPduType(1);
        assert!(e.source().is_none());
    }

    #[test]
    fn rtr_error_display_unexpected_pdu() {
        let e = RtrError::UnexpectedPdu {
            expected: "Cache Response",
            got: "Error Report".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "expected Cache Response PDU, got Error Report"
        );
    }

    #[test]
    fn rtr_error_display_error_reported() {
        let e = RtrError::ErrorReported {
            code: 4,
            text: "unsupported protocol version".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "RTR server reported error 4: unsupported protocol version"
        );
    }

    #[test]
    fn rtr_error_display_session_id_mismatch() {
        let e = RtrError::SessionIdMismatch {
            expected: 1,
            got: 2,
        };
        assert_eq!(e.to_string(), "RTR session ID mismatch: expected 1, got 2");
    }

    #[test]
    fn rtr_error_display_closed() {
        assert_eq!(RtrError::Closed.to_string(), "RTR connection closed");
    }

    #[test]
    fn rtr_error_from_pdu_error() {
        let e: RtrError = PduError::UnknownVersion(9).into();
        assert!(matches!(e, RtrError::Pdu(_)));
    }

    #[test]
    fn rtr_error_source_chains_to_pdu_error() {
        let e = RtrError::Pdu(PduError::UnknownVersion(9));
        let src: &dyn std::error::Error = &e;
        assert!(src.source().is_some());
    }
}
