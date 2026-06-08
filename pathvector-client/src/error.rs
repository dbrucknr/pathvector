//! Error types for `pathvector-client`.

/// Error returned by [`PathvectorClient::connect`].
///
/// [`PathvectorClient::connect`]: crate::PathvectorClient::connect
#[derive(Debug)]
pub enum ConnectError {
    /// The endpoint URI could not be parsed.
    InvalidEndpoint(String),
    /// The transport-level connection failed.
    Transport(tonic::transport::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEndpoint(s) => write!(f, "invalid endpoint URI: {s}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEndpoint(_) => None,
            Self::Transport(e) => Some(e),
        }
    }
}

impl From<tonic::transport::Error> for ConnectError {
    fn from(e: tonic::transport::Error) -> Self {
        Self::Transport(e)
    }
}

/// Error returned by individual RPC calls on [`PathvectorClient`].
///
/// [`PathvectorClient`]: crate::PathvectorClient
#[derive(Debug)]
pub enum ClientError {
    /// The gRPC call returned a non-OK status.
    Rpc(tonic::Status),
    /// The server returned data that could not be converted into domain types.
    Convert(ConvertError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(s) => write!(f, "gRPC error {}: {}", s.code(), s.message()),
            Self::Convert(e) => write!(f, "convert error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(s) => Some(s),
            Self::Convert(e) => Some(e),
        }
    }
}

impl From<tonic::Status> for ClientError {
    fn from(s: tonic::Status) -> Self {
        Self::Rpc(s)
    }
}

impl From<ConvertError> for ClientError {
    fn from(e: ConvertError) -> Self {
        Self::Convert(e)
    }
}

/// Error produced while converting a proto message into a domain type.
#[derive(Debug)]
pub enum ConvertError {
    /// A string field that should be an IP address could not be parsed.
    InvalidAddress(String),
    /// An enum discriminant was outside the set of known values.
    UnknownEnumValue(&'static str, i32),
    /// An extended community byte slice was not exactly 8 bytes.
    BadExtendedCommunityLen(usize),
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAddress(s) => write!(f, "invalid IP address: {s:?}"),
            Self::UnknownEnumValue(ty, v) => write!(f, "unknown {ty} discriminant: {v}"),
            Self::BadExtendedCommunityLen(n) => {
                write!(f, "extended community must be 8 bytes, got {n}")
            }
        }
    }
}

impl std::error::Error for ConvertError {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    // ── ConvertError ──────────────────────────────────────────────────────────

    #[test]
    fn convert_error_display_invalid_address() {
        let e = ConvertError::InvalidAddress("not-an-ip".into());
        assert_eq!(e.to_string(), r#"invalid IP address: "not-an-ip""#);
    }

    #[test]
    fn convert_error_display_unknown_enum() {
        let e = ConvertError::UnknownEnumValue("Origin", 99);
        assert_eq!(e.to_string(), "unknown Origin discriminant: 99");
    }

    #[test]
    fn convert_error_display_bad_ext_community() {
        let e = ConvertError::BadExtendedCommunityLen(7);
        assert_eq!(e.to_string(), "extended community must be 8 bytes, got 7");
    }

    /// `ConvertError` has no chained source.
    #[test]
    fn convert_error_source_is_none() {
        assert!(ConvertError::InvalidAddress("x".into()).source().is_none());
        assert!(ConvertError::UnknownEnumValue("T", 0).source().is_none());
        assert!(ConvertError::BadExtendedCommunityLen(0).source().is_none());
    }

    // ── ConnectError ──────────────────────────────────────────────────────────

    #[test]
    fn connect_error_display_invalid_endpoint() {
        let e = ConnectError::InvalidEndpoint("not-a-uri".into());
        assert_eq!(e.to_string(), "invalid endpoint URI: not-a-uri");
    }

    /// `InvalidEndpoint` has no chained source.
    #[test]
    fn connect_error_source_invalid_endpoint_is_none() {
        let e = ConnectError::InvalidEndpoint("x".into());
        assert!(e.source().is_none());
    }

    // ── ClientError ───────────────────────────────────────────────────────────

    #[test]
    fn client_error_display_rpc() {
        let status = tonic::Status::not_found("peer not found");
        let e = ClientError::Rpc(status);
        let s = e.to_string();
        // The gRPC code renders as its human-readable description; the message
        // must also appear verbatim.
        assert!(s.starts_with("gRPC error "), "unexpected prefix: {s}");
        assert!(s.contains("peer not found"), "message missing: {s}");
    }

    #[test]
    fn client_error_display_convert() {
        let ce = ConvertError::InvalidAddress("bad".into());
        let e = ClientError::Convert(ce);
        assert!(e.to_string().contains("convert error"));
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn client_error_source_rpc() {
        let status = tonic::Status::internal("boom");
        let e = ClientError::Rpc(status);
        assert!(e.source().is_some());
    }

    #[test]
    fn client_error_source_convert() {
        let e = ClientError::Convert(ConvertError::BadExtendedCommunityLen(3));
        assert!(e.source().is_some());
    }

    // ── From impls ────────────────────────────────────────────────────────────

    #[test]
    fn from_tonic_status_into_client_error() {
        let status = tonic::Status::unavailable("down");
        let e: ClientError = status.into();
        assert!(matches!(e, ClientError::Rpc(_)));
    }

    #[test]
    fn from_convert_error_into_client_error() {
        let ce = ConvertError::UnknownEnumValue("PeerType", 42);
        let e: ClientError = ce.into();
        assert!(matches!(e, ClientError::Convert(_)));
    }
}
