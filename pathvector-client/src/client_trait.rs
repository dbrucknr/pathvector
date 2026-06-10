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
    proto::{
        GetBestRouteRequest, GetPeerRequest, ListCandidatesRequest, ListPeersRequest,
        ListRoutesRequest, PolicyAction, SetExportDefaultRequest, SetImportDefaultRequest,
    },
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

// ── Implementation for the real client ───────────────────────────────────────

impl DaemonClient for PathvectorClient {
    /// Return the operational state of every configured BGP peer.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] on gRPC failure, or
    /// [`ClientError::Convert`] if the server returns malformed data.
    async fn list_peers(&mut self) -> Result<Vec<PeerState>, ClientError> {
        let resp = self
            .peers
            .list_peers(ListPeersRequest {})
            .await?
            .into_inner();

        resp.peers
            .into_iter()
            .map(|p| PeerState::try_from(p).map_err(ClientError::from))
            .collect()
    }

    /// Return the operational state of a single peer identified by its address.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with status `NOT_FOUND` if the address is
    /// not a configured peer, `INVALID_ARGUMENT` if it is not a valid IP
    /// address, or [`ClientError::Convert`] if the server returns malformed
    /// data.
    async fn get_peer(&mut self, address: IpAddr) -> Result<PeerState, ClientError> {
        let resp = self
            .peers
            .get_peer(GetPeerRequest {
                address: address.to_string(),
            })
            .await?
            .into_inner();

        PeerState::try_from(resp).map_err(ClientError::from)
    }

    /// Return every best route in the Loc-RIB, optionally filtered by peer.
    ///
    /// When `peer` is [`Some`], only routes whose best-path winner is that peer
    /// address are returned.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] on gRPC failure, or
    /// [`ClientError::Convert`] if the server returns malformed data.
    async fn list_routes(&mut self, peer: Option<IpAddr>) -> Result<Vec<Route>, ClientError> {
        let resp = self
            .rib
            .list_routes(ListRoutesRequest {
                peer_address: peer.map_or_else(String::new, |a| a.to_string()),
            })
            .await?
            .into_inner();

        resp.routes
            .into_iter()
            .map(|r| Route::try_from(r).map_err(ClientError::from))
            .collect()
    }

    /// Return the best route for a single prefix, or [`None`] if no route
    /// exists.
    ///
    /// `prefix` must be valid CIDR notation, e.g. `"10.0.0.0/8"`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with status `INVALID_ARGUMENT` if
    /// `prefix` is not valid CIDR, or [`ClientError::Convert`] if the server
    /// returns malformed data.
    async fn get_best_route(&mut self, prefix: &str) -> Result<Option<Route>, ClientError> {
        let resp = self
            .rib
            .get_best_route(GetBestRouteRequest {
                prefix: prefix.into(),
            })
            .await?
            .into_inner();

        if resp.found {
            let route = resp
                .route
                .ok_or_else(|| tonic::Status::internal("found=true but route field was absent"))?;
            Route::try_from(route).map(Some).map_err(ClientError::from)
        } else {
            Ok(None)
        }
    }

    /// Return all candidate routes (from every peer) for a single prefix.
    ///
    /// Candidates are routes that passed import policy and are tracked in the
    /// Loc-RIB candidate map.  Use [`get_best_route`] to identify which
    /// candidate won best-path selection.
    ///
    /// [`get_best_route`]: Self::get_best_route
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with status `INVALID_ARGUMENT` if
    /// `prefix` is not valid CIDR, or [`ClientError::Convert`] if the server
    /// returns malformed data.
    async fn list_candidates(&mut self, prefix: &str) -> Result<Vec<Route>, ClientError> {
        let resp = self
            .rib
            .list_candidates(ListCandidatesRequest {
                prefix: prefix.into(),
            })
            .await?
            .into_inner();

        resp.routes
            .into_iter()
            .map(|r| Route::try_from(r).map_err(ClientError::from))
            .collect()
    }

    /// Replace the import-policy default for `peer` and immediately
    /// re-evaluate the peer's Adj-RIB-In against the new policy.  Routes that
    /// change accepted/rejected status are reflected in the Loc-RIB, and the
    /// resulting best-path changes are propagated to all established peers.
    ///
    /// `accept` — `true` to set the default to **Accept**, `false` for **Reject**.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with status `INVALID_ARGUMENT` if `peer`
    /// is not a valid IPv4 address, `NOT_FOUND` if it is not a configured peer.
    async fn set_import_default(&mut self, peer: &str, accept: bool) -> Result<(), ClientError> {
        let action = if accept {
            PolicyAction::Accept as i32
        } else {
            PolicyAction::Reject as i32
        };
        self.policy
            .set_import_default(SetImportDefaultRequest {
                peer_address: peer.into(),
                action,
            })
            .await?;
        Ok(())
    }

    /// Replace the export-policy default for `peer` and immediately
    /// re-evaluate the Loc-RIB for that peer against the new policy.  The peer
    /// receives UPDATEs for newly accepted prefixes and WITHDRAWs for newly
    /// rejected ones.  Has no effect on the wire if the peer is not currently
    /// established.
    ///
    /// `accept` — `true` to set the default to **Accept**, `false` for **Reject**.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with status `INVALID_ARGUMENT` if `peer`
    /// is not a valid IPv4 address, `NOT_FOUND` if it is not a configured peer.
    async fn set_export_default(&mut self, peer: &str, accept: bool) -> Result<(), ClientError> {
        let action = if accept {
            PolicyAction::Accept as i32
        } else {
            PolicyAction::Reject as i32
        };
        self.policy
            .set_export_default(SetExportDefaultRequest {
                peer_address: peer.into(),
                action,
            })
            .await?;
        Ok(())
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

    /// `impl DaemonClient for PathvectorClient` contains the real gRPC logic.
    /// `connect_lazy` does not open a socket, so constructing the client succeeds
    /// even without a daemon running.  Every call fails with `ClientError::Rpc`
    /// (connection refused), exercising each method body in the trait impl.
    #[tokio::test]
    async fn daemon_client_impl_exercises_each_method() {
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
