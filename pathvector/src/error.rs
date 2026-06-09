//! Error types for the `pathvector` CLI.
//!
//! All errors that can occur during a CLI invocation are represented here so
//! that `main` can convert any failure into a single user-friendly message and
//! a non-zero exit code.

use std::fmt;

use pathvector_client::error::{ClientError, ConnectError};

/// Top-level error type returned from every CLI command.
#[derive(Debug)]
pub enum CliError {
    /// The gRPC channel could not be created (bad endpoint URI).
    Connect(ConnectError),
    /// An RPC call failed or the server returned malformed data.
    Client(ClientError),
    /// Terminal setup/teardown failed (dashboard only).
    Terminal(std::io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "cannot connect to daemon: {e}"),
            Self::Client(e) => write!(f, "{e}"),
            Self::Terminal(e) => write!(f, "terminal error: {e}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) => Some(e),
            Self::Client(e) => Some(e),
            Self::Terminal(e) => Some(e),
        }
    }
}

impl From<ConnectError> for CliError {
    fn from(e: ConnectError) -> Self {
        Self::Connect(e)
    }
}

impl From<ClientError> for CliError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Terminal(e)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn connect_error_display() {
        let e = CliError::Connect(ConnectError::InvalidEndpoint("bad uri".into()));
        assert!(e.to_string().contains("cannot connect to daemon"));
        assert!(e.to_string().contains("bad uri"));
        assert!(e.source().is_some());
    }

    #[test]
    fn terminal_error_display() {
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let e = CliError::Terminal(io);
        assert!(e.to_string().contains("terminal error"));
        assert!(e.source().is_some());
    }
}
