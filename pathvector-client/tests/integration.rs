//! Integration tests for [`PathvectorClient`].
//!
//! Each test spins up a minimal in-process gRPC server (using the generated
//! server stubs from the same proto file), connects the client to it, and
//! verifies that the public API methods return the expected domain types.

use std::{net::SocketAddr, time::Duration};

use pathvector_client::{
    DaemonClient, PathvectorClient,
    error::{ClientError, ConnectError},
    types::{Origin, PeerType, SessionState},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

// ── Re-include the generated proto types ─────────────────────────────────────
// The `proto` module is private inside the crate; integration tests include it
// independently.  `OUT_DIR` is set by Cargo and refers to the same generated
// file that the main crate uses.

mod proto {
    #![allow(clippy::all, unused_qualifications)]
    tonic::include_proto!("pathvector.v1");
}

use proto::{
    ListPeersResponse, ListRoutesResponse, PeerState as ProtoPeerState, Route as ProtoRoute,
    RouteResponse,
    peer_service_server::{PeerService, PeerServiceServer},
    rib_service_server::{RibService, RibServiceServer},
};

// ── Proto fixture builders ────────────────────────────────────────────────────

fn proto_peer() -> ProtoPeerState {
    ProtoPeerState {
        address: "192.0.2.1".into(),
        remote_as: 65001,
        local_as: 65000,
        session_state: 2, // Established
        peer_type: 1,     // External
        hold_time: 90,
        uptime_seconds: 3_600,
        prefixes_received: 10,
        prefixes_accepted: 8,
        prefixes_advertised: 5,
    }
}

fn proto_route(prefix: &str) -> ProtoRoute {
    ProtoRoute {
        prefix: prefix.into(),
        peer_address: "192.0.2.1".into(),
        peer_type: 1, // External
        next_hop: "10.0.0.1".into(),
        as_path: vec![],
        origin: 0, // Igp
        local_pref: None,
        med: None,
        communities: vec![],
        large_communities: vec![],
        extended_communities: vec![],
        atomic_aggregate: false,
        aggregator: None,
    }
}

// ── Mock server implementations ───────────────────────────────────────────────

struct MockPeer;
struct MockRib;

#[tonic::async_trait]
impl PeerService for MockPeer {
    async fn list_peers(
        &self,
        _req: Request<proto::ListPeersRequest>,
    ) -> Result<Response<ListPeersResponse>, Status> {
        Ok(Response::new(ListPeersResponse {
            peers: vec![proto_peer()],
        }))
    }

    async fn get_peer(
        &self,
        req: Request<proto::GetPeerRequest>,
    ) -> Result<Response<ProtoPeerState>, Status> {
        let addr = req.into_inner().address;
        match addr.as_str() {
            "192.0.2.1" => Ok(Response::new(proto_peer())),
            _ => Err(Status::not_found(format!("peer {addr} not found"))),
        }
    }
}

#[tonic::async_trait]
impl RibService for MockRib {
    async fn get_best_route(
        &self,
        req: Request<proto::GetBestRouteRequest>,
    ) -> Result<Response<RouteResponse>, Status> {
        match req.into_inner().prefix.as_str() {
            "10.0.0.0/8" => Ok(Response::new(RouteResponse {
                found: true,
                route: Some(proto_route("10.0.0.0/8")),
            })),
            // Simulate a misbehaving server: found=true but route absent.
            "buggy/0" => Ok(Response::new(RouteResponse {
                found: true,
                route: None,
            })),
            _ => Ok(Response::new(RouteResponse {
                found: false,
                route: None,
            })),
        }
    }

    async fn list_routes(
        &self,
        _req: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        Ok(Response::new(ListRoutesResponse {
            routes: vec![proto_route("10.0.0.0/8"), proto_route("192.168.0.0/16")],
        }))
    }

    async fn list_candidates(
        &self,
        _req: Request<proto::ListCandidatesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        Ok(Response::new(ListRoutesResponse {
            routes: vec![proto_route("10.0.0.0/8")],
        }))
    }
}

// ── Server fixture ────────────────────────────────────────────────────────────

/// Bind to an OS-assigned port, spawn the mock server, and return the address.
async fn start_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(PeerServiceServer::new(MockPeer))
            .add_service(RibServiceServer::new(MockRib))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    // Allow the Tokio task to be scheduled before the first RPC.
    tokio::time::sleep(Duration::from_millis(10)).await;
    addr
}

fn client_for(addr: SocketAddr) -> PathvectorClient {
    PathvectorClient::connect(format!("http://{addr}")).expect("connect")
}

// ── connect() ─────────────────────────────────────────────────────────────────

#[test]
fn connect_invalid_uri_returns_error() {
    let result = PathvectorClient::connect("not a uri at all ://!!");
    assert!(result.is_err());
    let err = result.err().expect("Err");
    assert!(matches!(err, ConnectError::InvalidEndpoint(_)));
    assert!(!err.to_string().is_empty());
}

#[tokio::test]
async fn connect_valid_uri_succeeds() {
    // No server needed — connect_lazy() defers the TCP handshake, but the
    // Channel internally registers with the tokio reactor on construction.
    let result = PathvectorClient::connect("http://127.0.0.1:50051");
    assert!(result.is_ok());
}

// ── list_peers() ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_peers_returns_all_peers() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    let peers = client.list_peers().await.expect("list_peers");

    assert_eq!(peers.len(), 1);
    let p = &peers[0];
    assert_eq!(p.address.to_string(), "192.0.2.1");
    assert_eq!(p.remote_as, 65001);
    assert_eq!(p.local_as, 65000);
    assert_eq!(p.session_state, SessionState::Established);
    assert_eq!(p.peer_type, Some(PeerType::External));
    assert_eq!(p.hold_time, 90);
    assert_eq!(p.uptime_seconds, 3_600);
    assert_eq!(p.prefixes_received, 10);
    assert_eq!(p.prefixes_accepted, 8);
    assert_eq!(p.prefixes_advertised, 5);
}

#[tokio::test]
async fn list_peers_rpc_error_propagates() {
    // Point at a port with no server — the lazy channel will fail on first use.
    let mut client = PathvectorClient::connect("http://127.0.0.1:1").expect("connect");
    let err = client.list_peers().await.unwrap_err();
    assert!(
        matches!(err, ClientError::Rpc(_)),
        "expected Rpc error, got {err}"
    );
}

// ── get_peer() ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_peer_known_address_returns_peer() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    let p = client
        .get_peer("192.0.2.1".parse().unwrap())
        .await
        .expect("get_peer");

    assert_eq!(p.address.to_string(), "192.0.2.1");
    assert_eq!(p.session_state, SessionState::Established);
}

#[tokio::test]
async fn get_peer_unknown_address_returns_not_found() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    let err = client
        .get_peer("10.0.0.1".parse().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(&err, ClientError::Rpc(s) if s.code() == tonic::Code::NotFound),
        "expected NOT_FOUND, got {err}"
    );
}

// ── get_best_route() ──────────────────────────────────────────────────────────

#[tokio::test]
async fn get_best_route_known_prefix_returns_some() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    let route = client
        .get_best_route("10.0.0.0/8")
        .await
        .expect("get_best_route")
        .expect("route present");

    assert_eq!(route.prefix, "10.0.0.0/8");
    assert_eq!(route.peer_type, PeerType::External);
    assert_eq!(route.origin, Origin::Igp);
    assert_eq!(
        route.next_hop.map(|a| a.to_string()).as_deref(),
        Some("10.0.0.1")
    );
}

#[tokio::test]
async fn get_best_route_unknown_prefix_returns_none() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    let result = client
        .get_best_route("172.16.0.0/12")
        .await
        .expect("get_best_route");

    assert!(result.is_none());
}

#[tokio::test]
async fn get_best_route_found_true_but_null_route_is_error() {
    // The mock returns found=true with route=None for "buggy/0".
    // The client must reject this as a server-side protocol violation.
    let addr = start_server().await;
    let mut client = client_for(addr);

    let err = client.get_best_route("buggy/0").await.unwrap_err();
    assert!(
        matches!(&err, ClientError::Rpc(s) if s.code() == tonic::Code::Internal),
        "expected Internal error for found=true+route=None, got {err}"
    );
}

// ── list_routes() ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_routes_no_filter_returns_all() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    let routes = client.list_routes(None).await.expect("list_routes");

    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].prefix, "10.0.0.0/8");
    assert_eq!(routes[1].prefix, "192.168.0.0/16");
}

#[tokio::test]
async fn list_routes_with_peer_filter() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    // Mock ignores the filter; just confirm the parameter is accepted and
    // converted correctly (peer_address serialised to the request).
    let routes = client
        .list_routes(Some("192.0.2.1".parse().unwrap()))
        .await
        .expect("list_routes with filter");

    assert!(!routes.is_empty());
}

// ── list_candidates() ─────────────────────────────────────────────────────────

#[tokio::test]
async fn list_candidates_returns_candidates() {
    let addr = start_server().await;
    let mut client = client_for(addr);

    let candidates = client
        .list_candidates("10.0.0.0/8")
        .await
        .expect("list_candidates");

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].prefix, "10.0.0.0/8");
    assert_eq!(candidates[0].peer_address.to_string(), "192.0.2.1");
}
