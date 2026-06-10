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

use tonic::transport::Channel;

use error::ConnectError;
use proto::{
    peer_service_client::PeerServiceClient, policy_service_client::PolicyServiceClient,
    rib_service_client::RibServiceClient,
};

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

}
