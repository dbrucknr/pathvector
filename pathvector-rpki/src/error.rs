/// Errors produced by the RTR PDU codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduError {
    /// The byte slice is shorter than required to read the next field.
    Truncated { needed: usize, available: usize },
    /// The PDU type byte does not match any known RTR PDU type.
    UnknownPduType(u8),
    /// The protocol version byte is neither 0 (RFC 6810) nor 1 (RFC 8210).
    UnknownVersion(u8),
    /// The PDU's declared length field does not match the expected length
    /// for its type (and, for v0/v1-variable PDUs like End of Data, version).
    InvalidLength { pdu_type: u8, len: u32 },
    /// An Error Report PDU's text field is not valid UTF-8.
    Utf8(std::str::Utf8Error),
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
        }
    }
}

impl std::error::Error for PduError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Utf8(e) => Some(e),
            _ => None,
        }
    }
}

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
    /// The session ID in an End of Data PDU does not match the one
    /// established by the preceding Cache Response.
    SessionIdMismatch { expected: u16, got: u16 },
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
