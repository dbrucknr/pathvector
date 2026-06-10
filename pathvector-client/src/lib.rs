//! gRPC client library for the `pathvector` BGP daemon management API.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use pathvector_client::{DaemonClient, PathvectorClient};
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

mod client_trait;
mod convert;
pub mod error;
mod proto;
pub mod types;

pub use client_trait::DaemonClient;

use futures::Stream;
use tokio_stream::StreamExt as _;
use tonic::transport::Channel;

use error::{ClientError, ConnectError};
use proto::{
    origination_service_client::OriginationServiceClient,
    peer_service_client::PeerServiceClient,
    policy_service_client::PolicyServiceClient,
    rib_service_client::RibServiceClient,
};
use types::{OriginateRouteParams, PeerEvent, RouteEvent};

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
    origination: OriginationServiceClient<Channel>,
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
            policy: PolicyServiceClient::new(channel.clone()),
            origination: OriginationServiceClient::new(channel),
        })
    }

    /// Inject a single locally originated route into the daemon's Loc-RIB.
    ///
    /// Idempotent: re-originating the same prefix replaces the previous route.
    /// Export policy still applies per peer.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with `INVALID_ARGUMENT` if the prefix or
    /// next_hop in `params` is malformed.
    pub async fn originate_route(&mut self, params: OriginateRouteParams) -> Result<(), ClientError> {
        self.origination
            .originate_route(proto::OriginateRouteRequest::from(params))
            .await?;
        Ok(())
    }

    /// Batch-inject routes into the daemon's Loc-RIB.
    ///
    /// All routes are inserted before any outbound advertisement is computed,
    /// so a single propagation pass is performed regardless of batch size.
    /// Returns the number of routes accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with `INVALID_ARGUMENT` if any entry has
    /// a malformed prefix or next_hop.
    pub async fn originate_routes(
        &mut self,
        routes: Vec<OriginateRouteParams>,
    ) -> Result<u32, ClientError> {
        let resp = self
            .origination
            .originate_routes(proto::OriginateRoutesRequest {
                routes: routes.into_iter().map(proto::OriginateRouteRequest::from).collect(),
            })
            .await?
            .into_inner();
        Ok(resp.count)
    }

    /// Withdraw a single locally originated route.
    ///
    /// No-op if the prefix was not previously originated.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with `INVALID_ARGUMENT` if `prefix` is not
    /// valid CIDR notation.
    pub async fn withdraw_originated_route(&mut self, prefix: &str) -> Result<(), ClientError> {
        self.origination
            .withdraw_originated_route(proto::WithdrawOriginatedRouteRequest {
                prefix: prefix.into(),
            })
            .await?;
        Ok(())
    }

    /// Batch-withdraw locally originated routes.
    ///
    /// Returns the number of prefixes withdrawn.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] with `INVALID_ARGUMENT` if any prefix is
    /// not valid CIDR notation.
    pub async fn withdraw_originated_routes(
        &mut self,
        prefixes: Vec<String>,
    ) -> Result<u32, ClientError> {
        let resp = self
            .origination
            .withdraw_originated_routes(proto::WithdrawOriginatedRoutesRequest { prefixes })
            .await?
            .into_inner();
        Ok(resp.count)
    }

    /// Return all currently originated routes.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] on gRPC failure, or [`ClientError::Convert`]
    /// if the server returns malformed data.
    pub async fn list_originated_routes(
        &mut self,
    ) -> Result<Vec<types::Route>, ClientError> {
        let resp = self
            .origination
            .list_originated_routes(proto::ListOriginatedRoutesRequest {})
            .await?
            .into_inner();
        resp.routes
            .into_iter()
            .map(|r| types::Route::try_from(r).map_err(ClientError::from))
            .collect()
    }

    /// Subscribe to live Loc-RIB changes.
    ///
    /// Returns a stream that first delivers the current best routes as
    /// [`RouteEventType::Current`] events, then a single
    /// [`RouteEventType::EndInitial`] sentinel, then live
    /// [`RouteEventType::Announced`] / [`RouteEventType::Withdrawn`] deltas.
    ///
    /// Pass `peer` to filter the initial snapshot to routes from a specific
    /// peer; pass `Some("local")` for locally originated routes.  Live deltas
    /// are always delivered regardless of the filter.
    ///
    /// If the daemon's broadcast channel overflows (slow consumer), the stream
    /// will end with [`ClientError::Rpc`] — reconnect to get a fresh snapshot.
    ///
    /// [`RouteEventType::Current`]: types::RouteEventType::Current
    /// [`RouteEventType::EndInitial`]: types::RouteEventType::EndInitial
    /// [`RouteEventType::Announced`]: types::RouteEventType::Announced
    /// [`RouteEventType::Withdrawn`]: types::RouteEventType::Withdrawn
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] if the initial gRPC call fails.  Individual
    /// stream items return [`ClientError::Rpc`] on stream failure or
    /// [`ClientError::Convert`] if the daemon sends malformed event data.
    pub async fn watch_routes(
        &mut self,
        peer: Option<&str>,
    ) -> Result<impl Stream<Item = Result<RouteEvent, ClientError>>, ClientError> {
        let stream = self
            .rib
            .watch_routes(proto::WatchRoutesRequest {
                peer_address: peer.unwrap_or("").to_owned(),
            })
            .await?
            .into_inner();

        Ok(stream.map(|msg| {
            let event = msg?;
            RouteEvent::try_from(event).map_err(ClientError::from)
        }))
    }

    /// Subscribe to live peer session changes.
    ///
    /// Returns a stream that first delivers the current state of every
    /// configured peer as [`PeerEventType::Current`] events, then a single
    /// [`PeerEventType::EndInitial`] sentinel, then live
    /// [`PeerEventType::Changed`] events as sessions transition.
    ///
    /// [`PeerEventType::Current`]: types::PeerEventType::Current
    /// [`PeerEventType::EndInitial`]: types::PeerEventType::EndInitial
    /// [`PeerEventType::Changed`]: types::PeerEventType::Changed
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rpc`] if the initial gRPC call fails.  Individual
    /// stream items return [`ClientError::Rpc`] on stream failure or
    /// [`ClientError::Convert`] if the daemon sends malformed event data.
    pub async fn watch_peers(
        &mut self,
    ) -> Result<impl Stream<Item = Result<PeerEvent, ClientError>>, ClientError> {
        let stream = self
            .peers
            .watch_peers(proto::WatchPeersRequest {})
            .await?
            .into_inner();

        Ok(stream.map(|msg| {
            let event = msg?;
            PeerEvent::try_from(event).map_err(ClientError::from)
        }))
    }
}
