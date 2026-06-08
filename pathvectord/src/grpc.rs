//! gRPC management API server.
//!
//! Exposes two services over a single `tonic` server:
//!
//! - [`PeerService`] — per-peer session state (addresses, AS numbers, uptime,
//!   prefix counts).
//! - [`RibService`] — Loc-RIB queries: best route for a prefix, all best
//!   routes, and all candidate routes for a prefix.
//!
//! Both services hold an `Arc<RwLock<DaemonState>>` and acquire a **read**
//! lock for every request, so they never block the BGP event loop.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pathvector_rib::PeerId;
use pathvector_types::{AsPathSegment, LocalPref, Med, NextHop, Origin, PeerType};

use crate::DaemonState;

// ── Generated protobuf/gRPC code ─────────────────────────────────────────────
//
// The proto types live in a separate `proto.rs` source file so that a
// file-level `#![allow(clippy::all)]` can suppress lints on prost-generated
// code without affecting the rest of this module.  Inner attributes cannot
// appear inside an `include!` expansion in an inline `mod { }` block.

use crate::proto;

use proto::{
    Aggregator, AsSegment, GetBestRouteRequest, GetPeerRequest, LargeCommunity,
    ListCandidatesRequest, ListPeersRequest, ListPeersResponse, ListRoutesRequest,
    ListRoutesResponse, PeerState, Route, RouteResponse,
    peer_service_server::{PeerService, PeerServiceServer},
    rib_service_server::{RibService, RibServiceServer},
};

// ── Type-conversion helpers ───────────────────────────────────────────────────

fn proto_origin(o: Origin) -> i32 {
    match o {
        Origin::Igp => proto::Origin::Igp as i32,
        Origin::Egp => proto::Origin::Egp as i32,
        Origin::Incomplete => proto::Origin::Incomplete as i32,
    }
}

fn proto_peer_type(pt: PeerType) -> i32 {
    match pt {
        PeerType::External => proto::PeerType::External as i32,
        PeerType::Internal => proto::PeerType::Internal as i32,
    }
}

fn proto_as_segment(seg: &AsPathSegment) -> AsSegment {
    let (seg_type, asns): (i32, Vec<u32>) = match seg {
        AsPathSegment::Sequence(asns) => (
            proto::as_segment::Type::Sequence as i32,
            asns.iter().map(|a| a.as_u32()).collect(),
        ),
        AsPathSegment::Set(asns) => (
            proto::as_segment::Type::Set as i32,
            asns.iter().map(|a| a.as_u32()).collect(),
        ),
        AsPathSegment::ConfedSequence(asns) => (
            proto::as_segment::Type::ConfedSequence as i32,
            asns.iter().map(|a| a.as_u32()).collect(),
        ),
        AsPathSegment::ConfedSet(asns) => (
            proto::as_segment::Type::ConfedSet as i32,
            asns.iter().map(|a| a.as_u32()).collect(),
        ),
    };
    AsSegment {
        r#type: seg_type,
        asns,
    }
}

/// Convert an internal `Route<Ipv4Addr>` to its proto representation.
///
/// `peer_id` is the peer from which the route was received; it is stored
/// separately from the route itself in the RIB structures.
fn route_to_proto(
    peer_id: PeerId,
    nlri: pathvector_types::Nlri<Ipv4Addr>,
    route: &pathvector_rib::Route<Ipv4Addr>,
) -> Route {
    let peer_address = peer_id.ip().to_string();

    let next_hop = match route.next_hop {
        Some(NextHop::V4(ip)) => ip.to_string(),
        Some(NextHop::V6(ip)) => ip.to_string(),
        Some(NextHop::V6WithLinkLocal { global, .. }) => global.to_string(),
        None => String::new(),
    };

    let as_path: Vec<AsSegment> = route
        .as_path
        .segments()
        .iter()
        .map(proto_as_segment)
        .collect();

    let communities: Vec<u32> = route.communities.iter().map(|c| c.as_u32()).collect();

    let large_communities: Vec<LargeCommunity> = route
        .large_communities
        .iter()
        .map(|lc| LargeCommunity {
            global_admin: lc.global_administrator,
            local_data1: lc.local_data_1,
            local_data2: lc.local_data_2,
        })
        .collect();

    let extended_communities: Vec<Vec<u8>> = route
        .extended_communities
        .iter()
        .map(|ec| ec.as_bytes().to_vec())
        .collect();

    let aggregator = route.aggregator.map(|agg| Aggregator {
        asn: agg.asn.as_u32(),
        address: agg.ip.to_string(),
    });

    Route {
        prefix: nlri.to_string(),
        peer_address,
        peer_type: proto_peer_type(route.peer_type),
        next_hop,
        as_path,
        origin: proto_origin(route.origin),
        local_pref: route.local_pref.map(LocalPref::as_u32),
        med: route.med.map(Med::as_u32),
        communities,
        large_communities,
        extended_communities,
        atomic_aggregate: route.atomic_aggregate,
        aggregator,
    }
}

// ── PeerService ───────────────────────────────────────────────────────────────

struct PeerServiceImpl {
    state: Arc<tokio::sync::RwLock<DaemonState>>,
}

/// Build a `PeerState` proto message from daemon state for `addr`.
///
/// Returns `None` if `addr` is not in `peer_remote_as` (i.e. not configured).
fn build_peer_state(s: &DaemonState, addr: Ipv4Addr) -> Option<PeerState> {
    let remote_as = *s.peer_remote_as.get(&addr)?;
    let peer_id = PeerId::from(addr);

    let (session_state, peer_type, hold_time, uptime_seconds) =
        if let Some(&pt) = s.peer_types.get(&addr) {
            let uptime = s
                .established_at
                .get(&addr)
                .map_or(0, |t| t.elapsed().as_secs());
            let ht = s.hold_times.get(&addr).copied().unwrap_or(0);
            (
                proto::SessionState::Established as i32,
                proto_peer_type(pt),
                u32::from(ht),
                uptime,
            )
        } else {
            (
                proto::SessionState::Idle as i32,
                proto::PeerType::Unspecified as i32,
                0u32,
                0u64,
            )
        };

    let prefixes_received = s
        .adj_ribs_in
        .get(&addr)
        .map_or(0, |ari| u32::try_from(ari.len()).unwrap_or(u32::MAX));

    // Count best-path wins: routes in the Loc-RIB whose winner is this peer.
    let prefixes_accepted = s
        .loc_rib
        .best_routes()
        .filter(|(nlri, _)| s.loc_rib.best_peer(nlri) == Some(peer_id))
        .count();
    let prefixes_accepted = u32::try_from(prefixes_accepted).unwrap_or(u32::MAX);

    let prefixes_advertised = s
        .adj_ribs_out
        .get(&addr)
        .map_or(0, |aro| u32::try_from(aro.len()).unwrap_or(u32::MAX));

    Some(PeerState {
        address: addr.to_string(),
        remote_as,
        local_as: s.local_as,
        session_state,
        peer_type,
        hold_time,
        uptime_seconds,
        prefixes_received,
        prefixes_accepted,
        prefixes_advertised,
    })
}

#[tonic::async_trait]
impl PeerService for PeerServiceImpl {
    async fn list_peers(
        &self,
        _request: Request<ListPeersRequest>,
    ) -> Result<Response<ListPeersResponse>, Status> {
        let s = self.state.read().await;
        let mut peers: Vec<PeerState> = s
            .peer_remote_as
            .keys()
            .copied()
            .filter_map(|addr| build_peer_state(&s, addr))
            .collect();
        // Stable ordering by address for predictable CLI output.
        peers.sort_by_key(|p| p.address.clone());
        Ok(Response::new(ListPeersResponse { peers }))
    }

    async fn get_peer(
        &self,
        request: Request<GetPeerRequest>,
    ) -> Result<Response<PeerState>, Status> {
        let addr: Ipv4Addr = request
            .into_inner()
            .address
            .parse()
            .map_err(|_| Status::invalid_argument("address must be a valid IPv4 address"))?;

        let s = self.state.read().await;
        build_peer_state(&s, addr)
            .map(Response::new)
            .ok_or_else(|| Status::not_found(format!("peer {addr} is not configured")))
    }
}

// ── RibService ────────────────────────────────────────────────────────────────

struct RibServiceImpl {
    state: Arc<tokio::sync::RwLock<DaemonState>>,
}

fn parse_nlri(s: &str) -> Result<pathvector_types::Nlri<Ipv4Addr>, Status> {
    s.parse()
        .map_err(|_| Status::invalid_argument(format!("'{s}' is not valid CIDR notation")))
}

#[tonic::async_trait]
impl RibService for RibServiceImpl {
    async fn get_best_route(
        &self,
        request: Request<GetBestRouteRequest>,
    ) -> Result<Response<RouteResponse>, Status> {
        let prefix = request.into_inner().prefix;
        let nlri = parse_nlri(&prefix)?;

        let s = self.state.read().await;
        let resp = match s.loc_rib.best(&nlri) {
            Some(route) => {
                let peer_id = s
                    .loc_rib
                    .best_peer(&nlri)
                    .unwrap_or_else(|| PeerId::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
                RouteResponse {
                    found: true,
                    route: Some(route_to_proto(peer_id, nlri, route)),
                }
            }
            None => RouteResponse {
                found: false,
                route: None,
            },
        };
        Ok(Response::new(resp))
    }

    async fn list_routes(
        &self,
        request: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let peer_filter_str = request.into_inner().peer_address;

        // Parse the optional peer filter; error early on a bad address.
        let peer_filter: Option<PeerId> = if peer_filter_str.is_empty() {
            None
        } else {
            let addr: Ipv4Addr = peer_filter_str.parse().map_err(|_| {
                Status::invalid_argument("peer_address must be a valid IPv4 address")
            })?;
            Some(PeerId::from(addr))
        };

        let s = self.state.read().await;
        let routes: Vec<Route> = s
            .loc_rib
            .best_routes()
            .filter_map(|(nlri, route)| {
                let peer_id = s.loc_rib.best_peer(&nlri)?;
                if peer_filter.is_none_or(|f| f == peer_id) {
                    Some(route_to_proto(peer_id, nlri, route))
                } else {
                    None
                }
            })
            .collect();

        Ok(Response::new(ListRoutesResponse { routes }))
    }

    async fn list_candidates(
        &self,
        request: Request<ListCandidatesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let prefix = request.into_inner().prefix;
        let nlri = parse_nlri(&prefix)?;

        let s = self.state.read().await;
        let routes: Vec<Route> = s
            .loc_rib
            .candidates(&nlri)
            .map(|map| {
                map.iter()
                    .map(|(peer_id, route)| route_to_proto(*peer_id, nlri, route))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Response::new(ListRoutesResponse { routes }))
    }
}

// ── Server entrypoint ─────────────────────────────────────────────────────────

/// Start the gRPC management server on `0.0.0.0:<port>`.
///
/// Called once from `run()` as a background Tokio task.  Logs an error and
/// returns (rather than panicking) if the server fails to bind or encounters a
/// fatal transport error.
pub(crate) async fn serve(state: Arc<tokio::sync::RwLock<DaemonState>>, port: u16) {
    let addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .expect("grpc bind address is always valid");

    tracing::info!(%addr, "gRPC management API listening");

    let peer_svc = PeerServiceServer::new(PeerServiceImpl {
        state: Arc::clone(&state),
    });
    let rib_svc = RibServiceServer::new(RibServiceImpl { state });
    let reflection_svc = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("file descriptor set is valid");

    if let Err(e) = tonic::transport::Server::builder()
        .add_service(peer_svc)
        .add_service(rib_svc)
        .add_service(reflection_svc)
        .serve(addr)
        .await
    {
        tracing::error!(error = %e, "gRPC server terminated with error");
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pathvector_rib::{PeerId, RouteBuilder};
    use pathvector_types::{AsPath, Asn, Community, LargeCommunity as TypesLargeCommunity, Origin};

    use super::{build_peer_state, proto, route_to_proto};
    use crate::{
        DaemonState,
        config::{self, ExportDefault, ImportDefault},
    };
    use std::collections::HashMap;
    use tokio::sync::mpsc;

    fn make_state(local_as: u32, peers: &[(Ipv4Addr, u32)]) -> DaemonState {
        let mut senders = HashMap::new();
        for &(ip, _) in peers {
            let (tx, _rx) = mpsc::channel(64);
            senders.insert(ip, tx);
        }
        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(ImportDefault::Accept),
                export_default: Some(ExportDefault::Accept),
            })
            .collect();
        DaemonState::new(local_as, Ipv4Addr::new(10, 0, 0, 1), &peer_configs, senders)
    }

    fn nlri(s: &str) -> pathvector_types::Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn peer(ip: &str) -> PeerId {
        PeerId::from(ip.parse::<Ipv4Addr>().unwrap())
    }

    // ── build_peer_state ──────────────────────────────────────────────────────

    #[test]
    fn test_build_peer_state_unknown_address_returns_none() {
        let s = make_state(65001, &[]);
        assert!(build_peer_state(&s, "10.0.0.99".parse().unwrap()).is_none());
    }

    #[test]
    fn test_build_peer_state_idle_peer() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let s = make_state(65001, &[(addr, 65002)]);
        let ps = build_peer_state(&s, addr).unwrap();

        assert_eq!(ps.address, "10.0.0.2");
        assert_eq!(ps.remote_as, 65002);
        assert_eq!(ps.local_as, 65001);
        assert_eq!(ps.session_state, proto::SessionState::Idle as i32);
        assert_eq!(ps.peer_type, proto::PeerType::Unspecified as i32);
        assert_eq!(ps.hold_time, 0);
        assert_eq!(ps.uptime_seconds, 0);
        assert_eq!(ps.prefixes_received, 0);
        assert_eq!(ps.prefixes_accepted, 0);
        assert_eq!(ps.prefixes_advertised, 0);
    }

    #[test]
    fn test_build_peer_state_established_peer() {
        use pathvector_types::PeerType;

        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let mut s = make_state(65001, &[(addr, 65002)]);
        s.on_established(addr, PeerType::External, 65002, 90);

        let ps = build_peer_state(&s, addr).unwrap();
        assert_eq!(ps.session_state, proto::SessionState::Established as i32);
        assert_eq!(ps.peer_type, proto::PeerType::External as i32);
        assert_eq!(ps.hold_time, 90);
        // uptime may be 0 or 1 depending on timing — just check it's present
        assert!(ps.uptime_seconds < 5);
    }

    #[test]
    fn test_build_peer_state_prefix_counts() {
        use pathvector_types::PeerType;

        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let mut s = make_state(65001, &[(addr, 65002)]);
        s.on_established(addr, PeerType::External, 65002, 90);

        // Insert a route so the counts are non-zero.
        let n = nlri("10.0.0.0/8");
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::from_sequence(vec![Asn::new(65002)]))
            .peer_type(PeerType::External)
            .build();
        s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
        s.loc_rib.insert(peer("10.0.0.2"), route);

        let ps = build_peer_state(&s, addr).unwrap();
        assert_eq!(ps.prefixes_received, 1);
        assert_eq!(ps.prefixes_accepted, 1);
    }

    // ── route_to_proto ────────────────────────────────────────────────────────

    #[test]
    fn test_route_to_proto_basic_fields() {
        use pathvector_types::{NextHop, PeerType};
        use std::net::Ipv4Addr;

        let n = nlri("192.168.0.0/24");
        let route = RouteBuilder::new(
            n,
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .peer_type(PeerType::External)
        .build();

        let r = route_to_proto(peer("10.0.0.2"), n, &route);
        assert_eq!(r.prefix, "192.168.0.0/24");
        assert_eq!(r.peer_address, "10.0.0.2");
        assert_eq!(r.next_hop, "10.0.0.1");
        assert_eq!(r.as_path.len(), 1); // one Sequence segment
        assert_eq!(r.as_path[0].asns, vec![65002, 65001]);
        assert_eq!(r.origin, proto::Origin::Igp as i32);
        assert!(!r.atomic_aggregate);
        assert!(r.aggregator.is_none());
    }

    #[test]
    fn test_route_to_proto_optional_attributes() {
        use pathvector_types::{LocalPref, Med, PeerType};

        let n = nlri("10.0.0.0/8");
        let route = RouteBuilder::new(n, Origin::Incomplete, AsPath::new())
            .local_pref(LocalPref::new(200))
            .med(Med::new(100))
            .community(Community::from_parts(65000, 1))
            .peer_type(PeerType::Internal)
            .build();

        let r = route_to_proto(peer("10.0.0.3"), n, &route);
        assert_eq!(r.local_pref, Some(200));
        assert_eq!(r.med, Some(100));
        assert_eq!(
            r.communities,
            vec![Community::from_parts(65000, 1).as_u32()]
        );
        assert_eq!(r.peer_type, proto::PeerType::Internal as i32);
    }

    #[test]
    fn test_route_to_proto_large_community() {
        let n = nlri("10.0.0.0/8");
        let lc = TypesLargeCommunity::new(65000, 1, 2);
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .large_community(lc)
            .build();

        let r = route_to_proto(peer("10.0.0.2"), n, &route);
        assert_eq!(r.large_communities.len(), 1);
        assert_eq!(r.large_communities[0].global_admin, 65000);
        assert_eq!(r.large_communities[0].local_data1, 1);
        assert_eq!(r.large_communities[0].local_data2, 2);
    }
}
