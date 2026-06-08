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
