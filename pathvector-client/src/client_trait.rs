//! The [`DaemonClient`] abstraction trait.
//!
//! Importing this trait and implementing it on a test double lets you unit-test
//! any code that talks to `pathvectord` without a running daemon.
//!
//! # Example
//!
//! ```rust
//! use std::{future::Future, net::IpAddr};
//! use pathvector_client::{DaemonClient, error::ClientError, types::{OriginateRouteParams, PeerState, Route}};
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
//!     fn list_all_routes(&mut self, _: Option<IpAddr>) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send {
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
//!     fn originate_route(&mut self, _: OriginateRouteParams) -> impl Future<Output = Result<(), ClientError>> + Send {
//!         async { Ok(()) }
//!     }
//!     fn originate_routes(&mut self, _: Vec<OriginateRouteParams>) -> impl Future<Output = Result<u32, ClientError>> + Send {
//!         async { Ok(0) }
//!     }
//!     fn withdraw_originated_route(&mut self, _: &str) -> impl Future<Output = Result<(), ClientError>> + Send {
//!         async { Ok(()) }
//!     }
//!     fn withdraw_originated_routes(&mut self, _: Vec<String>) -> impl Future<Output = Result<u32, ClientError>> + Send {
//!         async { Ok(0) }
//!     }
//!     fn list_originated_routes(&mut self) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send {
//!         async { Ok(vec![]) }
//!     }
//!     fn watch_routes(&mut self, _: Option<&str>) -> impl Future<Output = Result<pathvector_client::BoxStream<pathvector_client::types::RouteEvent>, ClientError>> + Send {
//!         async { Ok(Box::pin(futures::stream::empty()) as pathvector_client::BoxStream<_>) }
//!     }
//!     fn watch_peers(&mut self) -> impl Future<Output = Result<pathvector_client::BoxStream<pathvector_client::types::PeerEvent>, ClientError>> + Send {
//!         async { Ok(Box::pin(futures::stream::empty()) as pathvector_client::BoxStream<_>) }
//!     }
//!     fn add_peer(&mut self, _: pathvector_client::types::AddPeerParams) -> impl Future<Output = Result<(), ClientError>> + Send {
//!         async { Ok(()) }
//!     }
//!     fn remove_peer(&mut self, _: IpAddr) -> impl Future<Output = Result<(), ClientError>> + Send {
//!         async { Ok(()) }
//!     }
//!     fn soft_reset(&mut self, _: IpAddr, _: &str) -> impl Future<Output = Result<(), ClientError>> + Send {
//!         async { Ok(()) }
//!     }
//! }
//! ```

use std::{future::Future, net::IpAddr};

use tokio_stream::StreamExt as _;

use crate::{
    BoxStream, PathvectorClient,
    error::ClientError,
    proto::{
        AddPeerRequest, GetBestRouteRequest, GetPeerRequest, ListCandidatesRequest,
        ListOriginatedRoutesRequest, ListPeersRequest, ListRoutesRequest, OriginateRouteRequest,
        OriginateRoutesRequest, PolicyAction, RemovePeerRequest, SetExportDefaultRequest,
        SetImportDefaultRequest, SoftResetRequest, WatchPeersRequest, WatchRoutesRequest,
        WithdrawOriginatedRouteRequest, WithdrawOriginatedRoutesRequest,
    },
    types::{AddPeerParams, OriginateRouteParams, PeerEvent, PeerState, Route, RouteEvent},
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
    ///
    /// May fail with [`ClientError::Rpc`] / `RESOURCE_EXHAUSTED` when the
    /// table exceeds ~26k routes (gRPC 4 MB limit).  Use [`list_all_routes`]
    /// for large tables.
    ///
    /// [`list_all_routes`]: DaemonClient::list_all_routes
    fn list_routes(
        &mut self,
        peer: Option<IpAddr>,
    ) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send;

    /// Return all best routes using automatic pagination.
    ///
    /// Issues multiple `ListRoutes` RPCs with a fixed page size so the
    /// response never exceeds the gRPC message-size limit.  Safe for any
    /// table size.
    fn list_all_routes(
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

    /// Inject a single locally originated route into the daemon's Loc-RIB.
    fn originate_route(
        &mut self,
        params: OriginateRouteParams,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Batch-inject routes into the daemon's Loc-RIB.  Returns the number of
    /// routes accepted.
    fn originate_routes(
        &mut self,
        routes: Vec<OriginateRouteParams>,
    ) -> impl Future<Output = Result<u32, ClientError>> + Send;

    /// Withdraw a single locally originated route.  No-op if not previously
    /// originated.
    fn withdraw_originated_route(
        &mut self,
        prefix: &str,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Batch-withdraw locally originated routes.  Returns the number of
    /// prefixes withdrawn.
    fn withdraw_originated_routes(
        &mut self,
        prefixes: Vec<String>,
    ) -> impl Future<Output = Result<u32, ClientError>> + Send;

    /// Return all currently originated routes.
    fn list_originated_routes(
        &mut self,
    ) -> impl Future<Output = Result<Vec<Route>, ClientError>> + Send;

    /// Subscribe to live Loc-RIB changes.
    ///
    /// The returned stream first delivers the current best routes as
    /// [`RouteEventType::Current`] events, then a single
    /// [`RouteEventType::EndInitial`] sentinel, then live
    /// [`RouteEventType::Announced`] / [`RouteEventType::Withdrawn`] deltas.
    ///
    /// Pass `peer` to filter the initial snapshot to routes from a specific peer.
    ///
    /// [`RouteEventType::Current`]: crate::types::RouteEventType::Current
    /// [`RouteEventType::EndInitial`]: crate::types::RouteEventType::EndInitial
    /// [`RouteEventType::Announced`]: crate::types::RouteEventType::Announced
    /// [`RouteEventType::Withdrawn`]: crate::types::RouteEventType::Withdrawn
    fn watch_routes(
        &mut self,
        peer: Option<&str>,
    ) -> impl Future<Output = Result<BoxStream<RouteEvent>, ClientError>> + Send;

    /// Subscribe to live peer session changes.
    ///
    /// The returned stream first delivers the current state of every configured
    /// peer as [`PeerEventType::Current`] events, then a single
    /// [`PeerEventType::EndInitial`] sentinel, then live
    /// [`PeerEventType::Changed`] events as sessions transition.
    ///
    /// [`PeerEventType::Current`]: crate::types::PeerEventType::Current
    /// [`PeerEventType::EndInitial`]: crate::types::PeerEventType::EndInitial
    /// [`PeerEventType::Changed`]: crate::types::PeerEventType::Changed
    fn watch_peers(
        &mut self,
    ) -> impl Future<Output = Result<BoxStream<PeerEvent>, ClientError>> + Send;

    /// Add a new BGP peer at runtime without restarting the daemon.
    ///
    /// Idempotent — calling this for an already-configured address returns `Ok(())`
    /// without modifying the existing session.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with `INVALID_ARGUMENT` for a malformed
    /// address, `remote_as = 0`, or `remote_as = 23456 (AS_TRANS)`.
    fn add_peer(
        &mut self,
        params: AddPeerParams,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Remove a BGP peer at runtime.
    ///
    /// Sends a Cease NOTIFICATION to the peer, withdraws all routes received
    /// from it, and removes it from the daemon's configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with `INVALID_ARGUMENT` for a malformed
    /// address, or `NOT_FOUND` if the address is not a configured peer.
    fn remove_peer(
        &mut self,
        address: IpAddr,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Send a ROUTE-REFRESH to the peer for the given address family (RFC 2918).
    ///
    /// `afi_safi` is `"ipv4"` or `"ipv6"`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with `NOT_FOUND` if the peer is not
    /// configured, `FAILED_PRECONDITION` if the session is not Established or
    /// if the peer did not negotiate the Route Refresh capability.
    fn soft_reset(
        &mut self,
        address: IpAddr,
        afi_safi: &str,
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
                page_size: 0,
                page_token: String::new(),
            })
            .await?
            .into_inner();

        resp.routes
            .into_iter()
            .map(|r| Route::try_from(r).map_err(ClientError::from))
            .collect()
    }

    /// Return all best routes using automatic pagination, optionally filtered
    /// to routes won by `peer`.
    ///
    /// Unlike [`list_routes`], this method works for any table size — it
    /// issues multiple `ListRoutes` RPCs with `page_size = 5000` and
    /// accumulates the results.  Use this instead of `list_routes` when the
    /// table may exceed ~26k routes (the gRPC 4 MB response limit).
    ///
    /// [`list_routes`]: DaemonClient::list_routes
    async fn list_all_routes(&mut self, peer: Option<IpAddr>) -> Result<Vec<Route>, ClientError> {
        const PAGE_SIZE: u32 = 5_000;
        let peer_address = peer.map_or_else(String::new, |a| a.to_string());

        let mut all: Vec<Route> = Vec::new();
        let mut page_token = String::new();

        loop {
            let resp = self
                .rib
                .list_routes(ListRoutesRequest {
                    peer_address: peer_address.clone(),
                    page_size: PAGE_SIZE,
                    page_token: page_token.clone(),
                })
                .await?
                .into_inner();

            let page: Vec<Route> = resp
                .routes
                .into_iter()
                .map(|r| Route::try_from(r).map_err(ClientError::from))
                .collect::<Result<_, _>>()?;

            all.extend(page);

            if resp.next_page_token.is_empty() {
                break;
            }
            page_token = resp.next_page_token;
        }

        Ok(all)
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

    async fn originate_route(&mut self, params: OriginateRouteParams) -> Result<(), ClientError> {
        self.origination
            .originate_route(OriginateRouteRequest::from(params))
            .await?;
        Ok(())
    }

    async fn originate_routes(
        &mut self,
        routes: Vec<OriginateRouteParams>,
    ) -> Result<u32, ClientError> {
        let resp = self
            .origination
            .originate_routes(OriginateRoutesRequest {
                routes: routes
                    .into_iter()
                    .map(OriginateRouteRequest::from)
                    .collect(),
            })
            .await?
            .into_inner();
        Ok(resp.count)
    }

    async fn withdraw_originated_route(&mut self, prefix: &str) -> Result<(), ClientError> {
        self.origination
            .withdraw_originated_route(WithdrawOriginatedRouteRequest {
                prefix: prefix.into(),
            })
            .await?;
        Ok(())
    }

    async fn withdraw_originated_routes(
        &mut self,
        prefixes: Vec<String>,
    ) -> Result<u32, ClientError> {
        let resp = self
            .origination
            .withdraw_originated_routes(WithdrawOriginatedRoutesRequest { prefixes })
            .await?
            .into_inner();
        Ok(resp.count)
    }

    async fn list_originated_routes(&mut self) -> Result<Vec<Route>, ClientError> {
        let resp = self
            .origination
            .list_originated_routes(ListOriginatedRoutesRequest {})
            .await?
            .into_inner();
        resp.routes
            .into_iter()
            .map(|r| Route::try_from(r).map_err(ClientError::from))
            .collect()
    }

    async fn watch_routes(
        &mut self,
        peer: Option<&str>,
    ) -> Result<BoxStream<RouteEvent>, ClientError> {
        let stream = self
            .rib
            .watch_routes(WatchRoutesRequest {
                peer_address: peer.unwrap_or("").to_owned(),
            })
            .await?
            .into_inner();

        Ok(Box::pin(stream.map(|msg| {
            let event = msg?;
            RouteEvent::try_from(event).map_err(ClientError::from)
        })))
    }

    async fn watch_peers(&mut self) -> Result<BoxStream<PeerEvent>, ClientError> {
        let stream = self
            .peers
            .watch_peers(WatchPeersRequest {})
            .await?
            .into_inner();

        Ok(Box::pin(stream.map(|msg| {
            let event = msg?;
            PeerEvent::try_from(event).map_err(ClientError::from)
        })))
    }

    async fn add_peer(&mut self, params: AddPeerParams) -> Result<(), ClientError> {
        let import_action =
            params
                .import_default
                .map_or(PolicyAction::Unspecified as i32, |accept| {
                    if accept {
                        PolicyAction::Accept as i32
                    } else {
                        PolicyAction::Reject as i32
                    }
                });
        let export_action =
            params
                .export_default
                .map_or(PolicyAction::Unspecified as i32, |accept| {
                    if accept {
                        PolicyAction::Accept as i32
                    } else {
                        PolicyAction::Reject as i32
                    }
                });
        self.peers
            .add_peer(AddPeerRequest {
                address: params.address.to_string(),
                remote_as: params.remote_as,
                port: u32::from(params.port.unwrap_or(0)),
                import_default: import_action,
                export_default: export_action,
                md5_password: params.md5_password.unwrap_or_default(),
            })
            .await?;
        Ok(())
    }

    async fn remove_peer(&mut self, address: IpAddr) -> Result<(), ClientError> {
        self.peers
            .remove_peer(RemovePeerRequest {
                address: address.to_string(),
            })
            .await?;
        Ok(())
    }

    async fn soft_reset(&mut self, address: IpAddr, afi_safi: &str) -> Result<(), ClientError> {
        self.peers
            .soft_reset(SoftResetRequest {
                address: address.to_string(),
                afi_safi: afi_safi.to_string(),
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

        async fn list_routes(&mut self, _peer: Option<IpAddr>) -> Result<Vec<Route>, ClientError> {
            Ok(vec![])
        }

        async fn list_all_routes(
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

        async fn originate_route(&mut self, _: OriginateRouteParams) -> Result<(), ClientError> {
            Ok(())
        }

        async fn originate_routes(
            &mut self,
            routes: Vec<OriginateRouteParams>,
        ) -> Result<u32, ClientError> {
            Ok(u32::try_from(routes.len()).unwrap_or(u32::MAX))
        }

        async fn withdraw_originated_route(&mut self, _: &str) -> Result<(), ClientError> {
            Ok(())
        }

        async fn withdraw_originated_routes(
            &mut self,
            prefixes: Vec<String>,
        ) -> Result<u32, ClientError> {
            Ok(u32::try_from(prefixes.len()).unwrap_or(u32::MAX))
        }

        async fn list_originated_routes(&mut self) -> Result<Vec<Route>, ClientError> {
            Ok(vec![])
        }

        async fn watch_routes(
            &mut self,
            _peer: Option<&str>,
        ) -> Result<BoxStream<RouteEvent>, ClientError> {
            Ok(Box::pin(futures::stream::empty()))
        }

        async fn watch_peers(&mut self) -> Result<BoxStream<PeerEvent>, ClientError> {
            Ok(Box::pin(futures::stream::empty()))
        }

        async fn add_peer(&mut self, _: AddPeerParams) -> Result<(), ClientError> {
            Ok(())
        }

        async fn remove_peer(&mut self, _: IpAddr) -> Result<(), ClientError> {
            Ok(())
        }

        async fn soft_reset(&mut self, _: IpAddr, _: &str) -> Result<(), ClientError> {
            Ok(())
        }
    }

    use crate::types::{Origin, OriginateRouteParams};

    fn make_params() -> OriginateRouteParams {
        OriginateRouteParams {
            prefix: "1.2.3.4/32".into(),
            next_hop: "10.0.0.1".into(),
            origin: Origin::Igp,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
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
        assert!(c.originate_route(make_params()).await.is_ok());
        assert_eq!(
            c.originate_routes(vec![make_params(), make_params()])
                .await
                .unwrap(),
            2
        );
        assert!(c.withdraw_originated_route("1.2.3.4/32").await.is_ok());
        assert_eq!(
            c.withdraw_originated_routes(vec!["1.2.3.4/32".into(), "5.6.7.8/32".into()])
                .await
                .unwrap(),
            2
        );
        assert_eq!(c.list_originated_routes().await.unwrap(), vec![]);

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
        assert!(matches!(
            c.list_routes(None).await,
            Err(ClientError::Rpc(_))
        ));
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
        assert!(matches!(
            c.originate_route(make_params()).await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(
            c.originate_routes(vec![make_params()]).await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(
            c.withdraw_originated_route("1.2.3.4/32").await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(
            c.withdraw_originated_routes(vec!["1.2.3.4/32".into()])
                .await,
            Err(ClientError::Rpc(_))
        ));
        assert!(matches!(
            c.list_originated_routes().await,
            Err(ClientError::Rpc(_))
        ));
    }
}
