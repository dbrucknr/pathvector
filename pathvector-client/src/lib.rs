//! gRPC client library for the `pathvector` BGP daemon management API.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use pathvector_client::PathvectorClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = PathvectorClient::connect("http://127.0.0.1:50051")?;
//!     for peer in client.list_peers().await? {
//!         println!("{} — {:?}", peer.address, peer.session_state);
//!     }
//!     Ok(())
//! }
//! ```

mod convert;
pub mod error;
mod proto;
pub mod types;

use std::net::IpAddr;

use tonic::transport::Channel;

use error::{ClientError, ConnectError};
use proto::{
    GetBestRouteRequest, GetPeerRequest, ListCandidatesRequest, ListPeersRequest,
    ListRoutesRequest, PolicyAction, SetExportDefaultRequest, SetImportDefaultRequest,
    peer_service_client::PeerServiceClient, policy_service_client::PolicyServiceClient,
    rib_service_client::RibServiceClient,
};
use types::{PeerState, Route};

/// A connected client to a running `pathvectord` daemon.
///
/// Construct one via [`PathvectorClient::connect`], then call the async methods
/// to query peers and RIB state.  The client is cheap to clone — it shares the
/// underlying gRPC channel.
#[derive(Clone)]
pub struct PathvectorClient {
    peers: PeerServiceClient<Channel>,
    rib: RibServiceClient<Channel>,
    policy: PolicyServiceClient<Channel>,
}

impl PathvectorClient {
    /// Connect to a `pathvectord` daemon.
    ///
    /// `addr` should be a URI such as `"http://127.0.0.1:50051"`.  The
    /// underlying TCP connection is lazy — it is not established until the
    /// first RPC is made.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::InvalidEndpoint`] if the endpoint URI cannot be
    /// parsed.
    pub fn connect(addr: impl Into<String>) -> Result<Self, ConnectError> {
        let addr = addr.into();
        let channel = Channel::from_shared(addr)
            .map_err(|e| ConnectError::InvalidEndpoint(e.to_string()))?
            .connect_lazy();

        Ok(Self {
            peers: PeerServiceClient::new(channel.clone()),
            rib: RibServiceClient::new(channel.clone()),
            policy: PolicyServiceClient::new(channel),
        })
    }

    // ── PeerService ───────────────────────────────────────────────────────────

    /// Return the operational state of every configured BGP peer.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] on gRPC failure, or
    /// [`ClientError::Convert`] if the server returns malformed data.
    pub async fn list_peers(&mut self) -> Result<Vec<PeerState>, ClientError> {
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
    pub async fn get_peer(&mut self, address: IpAddr) -> Result<PeerState, ClientError> {
        let resp = self
            .peers
            .get_peer(GetPeerRequest {
                address: address.to_string(),
            })
            .await?
            .into_inner();

        PeerState::try_from(resp).map_err(ClientError::from)
    }

    // ── RibService ────────────────────────────────────────────────────────────

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
    pub async fn get_best_route(
        &mut self,
        prefix: impl Into<String>,
    ) -> Result<Option<Route>, ClientError> {
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

    /// Return every best route in the Loc-RIB, optionally filtered by peer.
    ///
    /// When `peer_filter` is [`Some`], only routes whose best-path winner is
    /// that peer address are returned.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] on gRPC failure, or
    /// [`ClientError::Convert`] if the server returns malformed data.
    pub async fn list_routes(
        &mut self,
        peer_filter: Option<IpAddr>,
    ) -> Result<Vec<Route>, ClientError> {
        let resp = self
            .rib
            .list_routes(ListRoutesRequest {
                peer_address: peer_filter.map_or_else(String::new, |a| a.to_string()),
            })
            .await?
            .into_inner();

        resp.routes
            .into_iter()
            .map(|r| Route::try_from(r).map_err(ClientError::from))
            .collect()
    }

    // ── PolicyService ─────────────────────────────────────────────────────────

    /// Replace the import-policy default for `peer_address` and immediately
    /// re-evaluate the peer's Adj-RIB-In against the new policy.  Routes that
    /// change accepted/rejected status are reflected in the Loc-RIB, and the
    /// resulting best-path changes are propagated to all established peers.
    ///
    /// `accept` — `true` to set the default to **Accept**, `false` for **Reject**.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with status `INVALID_ARGUMENT` if
    /// `peer_address` is not a valid IPv4 address, `NOT_FOUND` if it is not a
    /// configured peer.
    pub async fn set_import_default(
        &mut self,
        peer_address: impl Into<String>,
        accept: bool,
    ) -> Result<(), ClientError> {
        let action = if accept {
            PolicyAction::Accept as i32
        } else {
            PolicyAction::Reject as i32
        };
        self.policy
            .set_import_default(SetImportDefaultRequest {
                peer_address: peer_address.into(),
                action,
            })
            .await?;
        Ok(())
    }

    /// Replace the export-policy default for `peer_address` and immediately
    /// re-evaluate the Loc-RIB for that peer against the new policy.  The peer
    /// receives UPDATEs for newly accepted prefixes and WITHDRAWs for newly
    /// rejected ones.  Has no effect on the wire if the peer is not currently
    /// established.
    ///
    /// `accept` — `true` to set the default to **Accept**, `false` for **Reject**.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with status `INVALID_ARGUMENT` if
    /// `peer_address` is not a valid IPv4 address, `NOT_FOUND` if it is not a
    /// configured peer.
    pub async fn set_export_default(
        &mut self,
        peer_address: impl Into<String>,
        accept: bool,
    ) -> Result<(), ClientError> {
        let action = if accept {
            PolicyAction::Accept as i32
        } else {
            PolicyAction::Reject as i32
        };
        self.policy
            .set_export_default(SetExportDefaultRequest {
                peer_address: peer_address.into(),
                action,
            })
            .await?;
        Ok(())
    }

    // ── RibService (continued) ────────────────────────────────────────────────

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
    pub async fn list_candidates(
        &mut self,
        prefix: impl Into<String>,
    ) -> Result<Vec<Route>, ClientError> {
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
}
