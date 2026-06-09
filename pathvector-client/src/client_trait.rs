//! The [`DaemonClient`] abstraction trait.
//!
//! Importing this trait and implementing it on a test double lets you unit-test
//! any code that talks to `pathvectord` without a running daemon.
//!
//! # Example
//!
//! ```rust
//! use std::{future::Future, net::IpAddr};
//! use pathvector_client::{DaemonClient, error::ClientError, types::{PeerState, Route}};
//!
//! struct NullClient;
//!
//! impl DaemonClient for NullClient {
//!     fn list_peers(&mut self) -> impl Future<Output = Result<Vec<PeerState>, ClientError>> + Send {
//!         async { Ok(vec![]) }
//!     }
//!     fn get_peer(&mut self, _: IpAddr) -> impl Future<Output = Result<PeerState, ClientError>> + Send {
//!         async { Err(ClientError::Rpc(tonic::Status::not_found("no peers"))) }
//!     }
//!     fn list_routes(&mut self, _: Option<IpAddr>) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send {
//!         async { Ok(vec![]) }
//!     }
//!     fn get_best_route(&mut self, _: &str) -> impl Future<Output = Result<Option<Route>, ClientError>> + Send {
//!         async { Ok(None) }
//!     }
//!     fn list_candidates(&mut self, _: &str) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send {
//!         async { Ok(vec![]) }
//!     }
//!     fn set_import_default(&mut self, _: &str, _: bool) -> impl Future<Output = Result<(), ClientError>> + Send {
//!         async { Ok(()) }
//!     }
//!     fn set_export_default(&mut self, _: &str, _: bool) -> impl Future<Output = Result<(), ClientError>> + Send {
//!         async { Ok(()) }
//!     }
//! }
//! ```

use std::{future::Future, net::IpAddr};

use crate::{
    PathvectorClient,
    error::ClientError,
    types::{PeerState, Route},
};

/// Abstracts the seven gRPC calls used to manage a running `pathvectord` daemon.
///
/// [`PathvectorClient`] implements this trait.  Implement it on your own type
/// to write unit tests that exercise command or business logic without a live
/// daemon.  Because the bound is a plain generic (no `dyn`), the compiler
/// monomorphises a separate call path for each concrete type — zero runtime
/// overhead.
///
/// All returned futures are `Send` so implementors can be used in multi-threaded
/// Tokio runtimes.  Single-threaded implementations (e.g. `#[cfg(test)]` mocks)
/// satisfy this automatically when they produce futures that do not hold
/// non-`Send` state across `.await` points.
pub trait DaemonClient {
    /// List all configured BGP peers and their current session state.
    fn list_peers(&mut self) -> impl Future<Output = Result<Vec<PeerState>, ClientError>> + Send;

    /// Return the operational state of a single peer by IP address.
    fn get_peer(
        &mut self,
        address: IpAddr,
    ) -> impl Future<Output = Result<PeerState, ClientError>> + Send;

    /// Return all best routes, optionally filtered to routes won by `peer`.
    fn list_routes(
        &mut self,
        peer: Option<IpAddr>,
    ) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send;

    /// Return the best route for a CIDR prefix, or `None` if absent.
    fn get_best_route(
        &mut self,
        prefix: &str,
    ) -> impl Future<Output = Result<Option<Route>, ClientError>> + Send;

    /// Return all candidate routes for a CIDR prefix across all peers.
    fn list_candidates(
        &mut self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send;

    /// Change the import-policy default for a peer at runtime (soft reconfiguration).
    ///
    /// Pass `accept = true` to admit all routes from this peer by default;
    /// `false` to revert to RFC 8212 reject-by-default.
    fn set_import_default(
        &mut self,
        peer: &str,
        accept: bool,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Change the export-policy default for a peer at runtime (soft reconfiguration).
    ///
    /// Pass `accept = true` to advertise all best routes to this peer by default;
    /// `false` to stop advertising.
    fn set_export_default(
        &mut self,
        peer: &str,
        accept: bool,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;
}

// ── Blanket implementation for the real client ────────────────────────────────

impl DaemonClient for PathvectorClient {
    fn list_peers(&mut self) -> impl Future<Output = Result<Vec<PeerState>, ClientError>> + Send {
        PathvectorClient::list_peers(self)
    }

    fn get_peer(
        &mut self,
        address: IpAddr,
    ) -> impl Future<Output = Result<PeerState, ClientError>> + Send {
        PathvectorClient::get_peer(self, address)
    }

    fn list_routes(
        &mut self,
        peer: Option<IpAddr>,
    ) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send {
        PathvectorClient::list_routes(self, peer)
    }

    fn get_best_route(
        &mut self,
        prefix: &str,
    ) -> impl Future<Output = Result<Option<Route>, ClientError>> + Send {
        PathvectorClient::get_best_route(self, prefix)
    }

    fn list_candidates(
        &mut self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send {
        PathvectorClient::list_candidates(self, prefix)
    }

    fn set_import_default(
        &mut self,
        peer: &str,
        accept: bool,
    ) -> impl Future<Output = Result<(), ClientError>> + Send {
        PathvectorClient::set_import_default(self, peer, accept)
    }

    fn set_export_default(
        &mut self,
        peer: &str,
        accept: bool,
    ) -> impl Future<Output = Result<(), ClientError>> + Send {
        PathvectorClient::set_export_default(self, peer, accept)
    }
}
