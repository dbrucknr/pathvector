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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    // Minimal mock that returns fixed values for every method.
    struct StubClient;

    impl DaemonClient for StubClient {
        async fn list_peers(&mut self) -> Result<Vec<PeerState>, ClientError> {
            Ok(vec![])
        }

        async fn get_peer(&mut self, _address: IpAddr) -> Result<PeerState, ClientError> {
            Err(ClientError::Rpc(tonic::Status::not_found("no peer")))
        }

        async fn list_routes(
            &mut self,
            _peer: Option<IpAddr>,
        ) -> Result<Vec<Route>, ClientError> {
            Ok(vec![])
        }

        async fn get_best_route(&mut self, _prefix: &str) -> Result<Option<Route>, ClientError> {
            Ok(None)
        }

        async fn list_candidates(&mut self, _prefix: &str) -> Result<Vec<Route>, ClientError> {
            Ok(vec![])
        }

        async fn set_import_default(
            &mut self,
            _peer: &str,
            _accept: bool,
        ) -> Result<(), ClientError> {
            Ok(())
        }

        async fn set_export_default(
            &mut self,
            _peer: &str,
            _accept: bool,
        ) -> Result<(), ClientError> {
            Ok(())
        }
    }

    /// Each method of `StubClient` returns the correct value as documented.
    #[tokio::test]
    async fn stub_client_returns_correct_values() {
        let mut c = StubClient;

        assert_eq!(c.list_peers().await.unwrap(), vec![]);
        assert_eq!(c.list_routes(None).await.unwrap(), vec![]);
        assert_eq!(
            c.list_routes(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))))
                .await
                .unwrap(),
            vec![]
        );
        assert_eq!(c.get_best_route("10.0.0.0/8").await.unwrap(), None);
        assert_eq!(c.list_candidates("10.0.0.0/8").await.unwrap(), vec![]);
        assert!(c.set_import_default("10.0.0.1", true).await.is_ok());
        assert!(c.set_export_default("10.0.0.1", false).await.is_ok());

        let err = c
            .get_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::Rpc(_)));
    }

    /// A function generic over [`DaemonClient`] compiles and dispatches correctly.
    ///
    /// Validates that the trait bound and `impl Future + Send` constraints are
    /// usable from call sites that don't know the concrete type.
    #[tokio::test]
    async fn trait_works_as_generic_bound() {
        async fn count_peers<C: DaemonClient>(client: &mut C) -> usize {
            client.list_peers().await.unwrap_or_default().len()
        }

        let mut c = StubClient;
        assert_eq!(count_peers(&mut c).await, 0);
    }

    /// The blanket `impl DaemonClient for PathvectorClient` forwards each method
    /// to the concrete implementation.  `connect_lazy` does not open a socket, so
    /// constructing the client succeeds even without a daemon.  Every call fails
    /// with `ClientError::Rpc` (connection refused), proving the forwarding path
    /// is exercised.
    #[tokio::test]
    async fn blanket_impl_forwards_all_methods() {
        // Port 1 is reserved and will always refuse connections.
        let mut c = crate::PathvectorClient::connect("http://127.0.0.1:1").unwrap();

        assert!(matches!(c.list_peers().await, Err(ClientError::Rpc(_))));
        assert!(matches!(
            c.get_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(c.list_routes(None).await, Err(ClientError::Rpc(_))));
        assert!(matches!(
            c.get_best_route("10.0.0.0/8").await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(
            c.list_candidates("10.0.0.0/8").await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(
            c.set_import_default("10.0.0.1", true).await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(
            c.set_export_default("10.0.0.1", false).await,
            Err(ClientError::Rpc(_))
        ));
    }
}
