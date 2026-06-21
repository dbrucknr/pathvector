//! Integration tests for [`PathvectorClient`].
//!
//! Each test spins up a minimal in-process gRPC server (using the generated
//! server stubs from the same proto file), connects the client to it, and
//! verifies that the public API methods return the expected domain types.

use std::{net::SocketAddr, time::Duration};

use futures::StreamExt as _;

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
    ListOriginatedRoutesResponse, ListPeersResponse, ListRoutesResponse, OriginateRouteResponse,
    OriginateRoutesResponse, PeerEvent, PeerState as ProtoPeerState, Route as ProtoRoute,
    RouteEvent, RouteResponse, SetExportDefaultResponse, SetImportDefaultResponse,
    WithdrawOriginatedRouteResponse, WithdrawOriginatedRoutesResponse,
    origination_service_server::{OriginationService, OriginationServiceServer},
    peer_service_server::{PeerService, PeerServiceServer},
    policy_service_server::{PolicyService, PolicyServiceServer},
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
        eor_ipv4_received: false,
        eor_ipv6_received: false,
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

    type WatchPeersStream =
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<PeerEvent, Status>> + Send>>;

    async fn watch_peers(
        &self,
        _req: Request<proto::WatchPeersRequest>,
    ) -> Result<Response<Self::WatchPeersStream>, Status> {
        let stream = futures::stream::empty();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn add_peer(
        &self,
        _req: Request<proto::AddPeerRequest>,
    ) -> Result<Response<proto::AddPeerResponse>, Status> {
        Ok(Response::new(proto::AddPeerResponse {}))
    }

    async fn remove_peer(
        &self,
        _req: Request<proto::RemovePeerRequest>,
    ) -> Result<Response<proto::RemovePeerResponse>, Status> {
        Err(Status::not_found("peer not found"))
    }

    async fn soft_reset(
        &self,
        _req: Request<proto::SoftResetRequest>,
    ) -> Result<Response<proto::SoftResetResponse>, Status> {
        Ok(Response::new(proto::SoftResetResponse {}))
    }
}

struct MockPeerWithEvents;

#[tonic::async_trait]
impl PeerService for MockPeerWithEvents {
    async fn list_peers(
        &self,
        _req: Request<proto::ListPeersRequest>,
    ) -> Result<Response<ListPeersResponse>, Status> {
        Ok(Response::new(ListPeersResponse { peers: vec![] }))
    }

    async fn get_peer(
        &self,
        _req: Request<proto::GetPeerRequest>,
    ) -> Result<Response<proto::PeerState>, Status> {
        Err(Status::not_found("no peers"))
    }

    type WatchPeersStream =
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<PeerEvent, Status>> + Send>>;

    async fn watch_peers(
        &self,
        _req: Request<proto::WatchPeersRequest>,
    ) -> Result<Response<Self::WatchPeersStream>, Status> {
        let event = PeerEvent {
            r#type: proto::PeerEventType::EndInitial as i32,
            peer: None,
        };
        let stream = futures::stream::once(async move { Ok(event) });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn add_peer(
        &self,
        _req: Request<proto::AddPeerRequest>,
    ) -> Result<Response<proto::AddPeerResponse>, Status> {
        Ok(Response::new(proto::AddPeerResponse {}))
    }

    async fn remove_peer(
        &self,
        _req: Request<proto::RemovePeerRequest>,
    ) -> Result<Response<proto::RemovePeerResponse>, Status> {
        Err(Status::not_found("peer not found"))
    }

    async fn soft_reset(
        &self,
        _req: Request<proto::SoftResetRequest>,
    ) -> Result<Response<proto::SoftResetResponse>, Status> {
        Ok(Response::new(proto::SoftResetResponse {}))
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
            next_page_token: String::new(),
        }))
    }

    async fn list_candidates(
        &self,
        _req: Request<proto::ListCandidatesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        Ok(Response::new(ListRoutesResponse {
            routes: vec![proto_route("10.0.0.0/8")],
            next_page_token: String::new(),
        }))
    }

    type WatchRoutesStream =
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<RouteEvent, Status>> + Send>>;

    async fn watch_routes(
        &self,
        _req: Request<proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        let stream = futures::stream::empty();
        Ok(Response::new(Box::pin(stream)))
    }
}

struct MockRibWithEvents;

#[tonic::async_trait]
impl RibService for MockRibWithEvents {
    async fn get_best_route(
        &self,
        _req: Request<proto::GetBestRouteRequest>,
    ) -> Result<Response<RouteResponse>, Status> {
        Ok(Response::new(RouteResponse {
            found: false,
            route: None,
        }))
    }

    async fn list_routes(
        &self,
        _req: Request<proto::ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        Ok(Response::new(ListRoutesResponse {
            routes: vec![],
            next_page_token: String::new(),
        }))
    }

    async fn list_candidates(
        &self,
        _req: Request<proto::ListCandidatesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        Ok(Response::new(ListRoutesResponse {
            routes: vec![],
            next_page_token: String::new(),
        }))
    }

    type WatchRoutesStream =
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<RouteEvent, Status>> + Send>>;

    async fn watch_routes(
        &self,
        _req: Request<proto::WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        let event = RouteEvent {
            r#type: proto::RouteEventType::EndInitial as i32,
            route: None,
            withdrawn_prefix: None,
        };
        let stream = futures::stream::once(async move { Ok(event) });
        Ok(Response::new(Box::pin(stream)))
    }
}

struct MockPolicy;

#[tonic::async_trait]
impl PolicyService for MockPolicy {
    async fn set_import_default(
        &self,
        _req: Request<proto::SetImportDefaultRequest>,
    ) -> Result<Response<SetImportDefaultResponse>, Status> {
        Ok(Response::new(SetImportDefaultResponse {}))
    }

    async fn set_export_default(
        &self,
        _req: Request<proto::SetExportDefaultRequest>,
    ) -> Result<Response<SetExportDefaultResponse>, Status> {
        Ok(Response::new(SetExportDefaultResponse {}))
    }
}

struct MockOrigination;

#[tonic::async_trait]
impl OriginationService for MockOrigination {
    async fn originate_route(
        &self,
        _req: Request<proto::OriginateRouteRequest>,
    ) -> Result<Response<OriginateRouteResponse>, Status> {
        Ok(Response::new(OriginateRouteResponse {}))
    }

    async fn originate_routes(
        &self,
        req: Request<proto::OriginateRoutesRequest>,
    ) -> Result<Response<OriginateRoutesResponse>, Status> {
        let count = u32::try_from(req.into_inner().routes.len()).unwrap_or(u32::MAX);
        Ok(Response::new(OriginateRoutesResponse { count }))
    }

    async fn withdraw_originated_route(
        &self,
        _req: Request<proto::WithdrawOriginatedRouteRequest>,
    ) -> Result<Response<WithdrawOriginatedRouteResponse>, Status> {
        Ok(Response::new(WithdrawOriginatedRouteResponse {}))
    }

    async fn withdraw_originated_routes(
        &self,
        req: Request<proto::WithdrawOriginatedRoutesRequest>,
    ) -> Result<Response<WithdrawOriginatedRoutesResponse>, Status> {
        let count = u32::try_from(req.into_inner().prefixes.len()).unwrap_or(u32::MAX);
        Ok(Response::new(WithdrawOriginatedRoutesResponse { count }))
    }

    async fn list_originated_routes(
        &self,
        _req: Request<proto::ListOriginatedRoutesRequest>,
    ) -> Result<Response<ListOriginatedRoutesResponse>, Status> {
        Ok(Response::new(ListOriginatedRoutesResponse {
            routes: vec![],
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
            .add_service(PolicyServiceServer::new(MockPolicy))
            .add_service(OriginationServiceServer::new(MockOrigination))
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
    assert_eq!(
        candidates[0].peer_address.map(|a| a.to_string()),
        Some("192.0.2.1".to_owned())
    );
}

// ── set_import_default() / set_export_default() ───────────────────────────────

#[tokio::test]
async fn set_import_default_accept_succeeds() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    client
        .set_import_default("192.0.2.1", true)
        .await
        .expect("set_import_default accept");
}

#[tokio::test]
async fn set_import_default_reject_succeeds() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    client
        .set_import_default("192.0.2.1", false)
        .await
        .expect("set_import_default reject");
}

#[tokio::test]
async fn set_export_default_accept_succeeds() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    client
        .set_export_default("192.0.2.1", true)
        .await
        .expect("set_export_default accept");
}

#[tokio::test]
async fn set_export_default_reject_succeeds() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    client
        .set_export_default("192.0.2.1", false)
        .await
        .expect("set_export_default reject");
}

// ── origination — inherent methods (covers lib.rs) ────────────────────────────

fn make_params(prefix: &str) -> pathvector_client::types::OriginateRouteParams {
    pathvector_client::types::OriginateRouteParams {
        prefix: prefix.to_owned(),
        next_hop: "10.0.0.1".to_owned(),
        origin: pathvector_client::types::Origin::Igp,
        communities: vec![],
        large_communities: vec![],
        extended_communities: vec![],
        local_pref: None,
        med: None,
    }
}

#[tokio::test]
async fn originate_route_inherent_succeeds() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    client
        .originate_route(make_params("192.0.2.0/24"))
        .await
        .expect("originate_route");
}

#[tokio::test]
async fn originate_routes_inherent_returns_count() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    let count = client
        .originate_routes(vec![
            make_params("192.0.2.0/24"),
            make_params("198.51.100.0/24"),
        ])
        .await
        .expect("originate_routes");
    assert_eq!(count, 2);
}

#[tokio::test]
async fn withdraw_originated_route_inherent_succeeds() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    client
        .withdraw_originated_route("192.0.2.0/24")
        .await
        .expect("withdraw_originated_route");
}

#[tokio::test]
async fn withdraw_originated_routes_inherent_returns_count() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    let count = client
        .withdraw_originated_routes(vec![
            "192.0.2.0/24".to_owned(),
            "198.51.100.0/24".to_owned(),
        ])
        .await
        .expect("withdraw_originated_routes");
    assert_eq!(count, 2);
}

#[tokio::test]
async fn list_originated_routes_inherent_returns_empty() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    let routes = client
        .list_originated_routes()
        .await
        .expect("list_originated_routes");
    assert!(routes.is_empty());
}

// ── origination — via DaemonClient trait (covers client_trait.rs) ────────────

/// Call origination methods through a generic DaemonClient bound so the
/// trait impl in client_trait.rs is exercised rather than the inherent methods.
async fn originate_via_trait<C: DaemonClient>(client: &mut C) {
    client
        .originate_route(make_params("10.0.0.0/8"))
        .await
        .expect("trait originate_route");
    let count = client
        .originate_routes(vec![make_params("10.1.0.0/16"), make_params("10.2.0.0/16")])
        .await
        .expect("trait originate_routes");
    assert_eq!(count, 2);
    client
        .withdraw_originated_route("10.0.0.0/8")
        .await
        .expect("trait withdraw_originated_route");
    let wcount = client
        .withdraw_originated_routes(vec!["10.1.0.0/16".to_owned()])
        .await
        .expect("trait withdraw_originated_routes");
    assert_eq!(wcount, 1);
    let routes = client
        .list_originated_routes()
        .await
        .expect("trait list_originated_routes");
    assert!(routes.is_empty());
}

#[tokio::test]
async fn origination_methods_via_trait_dispatch() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    originate_via_trait(&mut client).await;
}

// ── watch_routes() / watch_peers() ───────────────────────────────────────────

#[tokio::test]
async fn watch_routes_empty_stream_terminates() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    // The mock returns an empty stream; collecting it should yield no items.
    let stream = client.watch_routes(None).await.expect("watch_routes call");
    let items: Vec<_> = stream.collect().await;
    assert!(items.is_empty());
}

#[tokio::test]
async fn watch_routes_with_peer_filter_terminates() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    let stream = client
        .watch_routes(Some("192.0.2.1"))
        .await
        .expect("watch_routes with peer filter");
    let items: Vec<_> = stream.collect().await;
    assert!(items.is_empty());
}

#[tokio::test]
async fn watch_routes_with_local_filter_terminates() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    let stream = client
        .watch_routes(Some("local"))
        .await
        .expect("watch_routes with local filter");
    let items: Vec<_> = stream.collect().await;
    assert!(items.is_empty());
}

#[tokio::test]
async fn watch_peers_empty_stream_terminates() {
    let addr = start_server().await;
    let mut client = client_for(addr);
    let stream = client.watch_peers().await.expect("watch_peers call");
    let items: Vec<_> = stream.collect().await;
    assert!(items.is_empty());
}

/// Starts a server whose watch mocks emit one real event each, ensuring the
/// `.map()` conversion closures in `watch_routes` and `watch_peers` execute.
async fn start_server_with_events() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(PeerServiceServer::new(MockPeerWithEvents))
            .add_service(RibServiceServer::new(MockRibWithEvents))
            .add_service(PolicyServiceServer::new(MockPolicy))
            .add_service(OriginationServiceServer::new(MockOrigination))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    addr
}

#[tokio::test]
async fn watch_routes_conversion_closure_executes() {
    let addr = start_server_with_events().await;
    let mut client = client_for(addr);
    let stream = client.watch_routes(None).await.expect("watch_routes call");
    let items: Vec<_> = stream.collect().await;
    // One EndInitial event from the mock — conversion closure ran.
    assert_eq!(items.len(), 1);
    assert!(items[0].is_ok());
}

#[tokio::test]
async fn watch_peers_conversion_closure_executes() {
    let addr = start_server_with_events().await;
    let mut client = client_for(addr);
    let stream = client.watch_peers().await.expect("watch_peers call");
    let items: Vec<_> = stream.collect().await;
    // One EndInitial event from the mock — conversion closure ran.
    assert_eq!(items.len(), 1);
    assert!(items[0].is_ok());
}
