/// Errors produced by the BGP message codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The byte slice is shorter than required to read the next field.
    Truncated { needed: usize, available: usize },
    /// The 16-byte marker is not all `0xFF`.
    InvalidMarker,
    /// The length field in the header is outside the valid range for this
    /// message type (`19..=4096`).
    InvalidLength(u16),
    /// The type byte is not 1–5.
    UnknownMessageType(u8),
    /// The OPEN version field is not 4.
    UnsupportedVersion(u8),
    /// An `AS_PATH` segment type code is not 1–4.
    UnknownAsPathSegmentType(u8),
    /// The `ORIGIN` attribute value is not 0, 1, or 2.
    InvalidOrigin(u8),
    /// A capability TLV body is too short for the declared code.
    InvalidCapability { code: u8 },
    /// A path attribute body does not match the expected format.
    InvalidAttribute { type_code: u8, detail: &'static str },
    /// A prefix length is invalid for its address family
    /// (> 32 for IPv4, > 128 for IPv6).
    InvalidNlri { prefix_len: u8 },
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { needed, available } =>
                write!(f, "truncated: need {needed} bytes, have {available}"),
            Self::InvalidMarker =>
                write!(f, "BGP marker is not all 0xFF"),
            Self::InvalidLength(len) =>
                write!(f, "invalid message length: {len}"),
            Self::UnknownMessageType(t) =>
                write!(f, "unknown message type: {t}"),
            Self::UnsupportedVersion(v) =>
                write!(f, "unsupported BGP version: {v} (expected 4)"),
            Self::UnknownAsPathSegmentType(t) =>
                write!(f, "unknown AS_PATH segment type: {t}"),
            Self::InvalidOrigin(v) =>
                write!(f, "invalid ORIGIN value: {v} (expected 0–2)"),
            Self::InvalidCapability { code } =>
                write!(f, "malformed capability TLV for code {code}"),
            Self::InvalidAttribute { type_code, detail } =>
                write!(f, "invalid path attribute {type_code}: {detail}"),
            Self::InvalidNlri { prefix_len } =>
                write!(f, "NLRI prefix length {prefix_len} is out of range"),
        }
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_truncated() {
        let e = CodecError::Truncated { needed: 4, available: 1 };
        assert_eq!(e.to_string(), "truncated: need 4 bytes, have 1");
    }

    #[test]
    fn test_error_display_invalid_marker() {
        assert_eq!(CodecError::InvalidMarker.to_string(), "BGP marker is not all 0xFF");
    }

    #[test]
    fn test_error_is_std_error() {
        // Verify the trait impl compiles and the source chain is empty.
        let e: &dyn std::error::Error = &CodecError::InvalidMarker;
        assert!(e.source().is_none());
    }

    #[test]
    fn test_error_display_invalid_length() {
        assert_eq!(CodecError::InvalidLength(100).to_string(), "invalid message length: 100");
    }

    #[test]
    fn test_error_display_unknown_message_type() {
        assert_eq!(CodecError::UnknownMessageType(9).to_string(), "unknown message type: 9");
    }

    #[test]
    fn test_error_display_unsupported_version() {
        assert_eq!(
            CodecError::UnsupportedVersion(3).to_string(),
            "unsupported BGP version: 3 (expected 4)"
        );
    }

    #[test]
    fn test_error_display_unknown_as_path_segment_type() {
        assert_eq!(
            CodecError::UnknownAsPathSegmentType(5).to_string(),
            "unknown AS_PATH segment type: 5"
        );
    }

    #[test]
    fn test_error_display_invalid_origin() {
        assert_eq!(
            CodecError::InvalidOrigin(9).to_string(),
            "invalid ORIGIN value: 9 (expected 0\u{2013}2)"
        );
    }

    #[test]
    fn test_error_display_invalid_capability() {
        assert_eq!(
            CodecError::InvalidCapability { code: 64 }.to_string(),
            "malformed capability TLV for code 64"
        );
    }

    #[test]
    fn test_error_display_invalid_attribute() {
        let e = CodecError::InvalidAttribute { type_code: 3, detail: "NEXT_HOP must be 4 bytes" };
        assert_eq!(e.to_string(), "invalid path attribute 3: NEXT_HOP must be 4 bytes");
    }

    #[test]
    fn test_error_display_invalid_nlri() {
        assert_eq!(
            CodecError::InvalidNlri { prefix_len: 33 }.to_string(),
            "NLRI prefix length 33 is out of range"
        );
    }
}
