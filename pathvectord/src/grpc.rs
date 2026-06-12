//! gRPC management API server.
//!
//! Exposes three services over a single `tonic` server:
//!
//! - [`PeerService`] — per-peer session state (addresses, AS numbers, uptime,
//!   prefix counts).
//! - [`RibService`] — Loc-RIB queries: best route for a prefix, all best
//!   routes, and all candidate routes for a prefix.
//! - [`PolicyService`] — runtime policy management: replace the import or
//!   export default action for a peer and immediately propagate the change.
//!
//! `PeerService` and `RibService` hold an `Arc<RwLock<DaemonState>>` and
//! acquire a **read** lock for every request.  `PolicyService` requires a
//! **write** lock because it mutates import/export policy maps and re-evaluates
//! RIB state.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pathvector_policy::DefaultAction;
use pathvector_rib::PeerId;
use pathvector_types::{AsPathSegment, LocalPref, Med, NextHop, Origin, PeerType};

use crate::{DaemonState, RibSnapshot};

// ── Generated protobuf/gRPC code ─────────────────────────────────────────────
//
// The proto types live in a separate `proto.rs` source file so that a
// file-level `#![allow(clippy::all)]` can suppress lints on prost-generated
// code without affecting the rest of this module.  Inner attributes cannot
// appear inside an `include!` expansion in an inline `mod { }` block.

use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

use crate::proto;

use proto::{
    Aggregator, AsSegment, GetBestRouteRequest, GetPeerRequest, LargeCommunity,
    ListCandidatesRequest, ListOriginatedRoutesRequest, ListOriginatedRoutesResponse,
    ListPeersRequest, ListPeersResponse, ListRoutesRequest, ListRoutesResponse,
    OriginateRouteRequest, OriginateRouteResponse, OriginateRoutesRequest, OriginateRoutesResponse,
    PeerEvent, PeerEventType, PeerState, PolicyAction, Route, RouteEvent, RouteEventType,
    RouteResponse, SetExportDefaultRequest, SetExportDefaultResponse, SetImportDefaultRequest,
    SetImportDefaultResponse, WatchPeersRequest, WatchRoutesRequest,
    WithdrawOriginatedRouteRequest, WithdrawOriginatedRouteResponse,
    WithdrawOriginatedRoutesRequest, WithdrawOriginatedRoutesResponse,
    origination_service_server::{OriginationService, OriginationServiceServer},
    peer_service_server::{PeerService, PeerServiceServer},
    policy_service_server::{PolicyService, PolicyServiceServer},
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
        PeerType::Local => proto::PeerType::Unspecified as i32,
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
pub(crate) fn route_to_proto(
    peer_id: PeerId,
    nlri: pathvector_types::Nlri<Ipv4Addr>,
    route: &pathvector_rib::Route<Ipv4Addr>,
) -> Route {
    let peer_address = if route.peer_type == PeerType::Local {
        "local".to_string()
    } else {
        peer_id.ip().to_string()
    };

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

fn route_v6_to_proto(
    peer_id: PeerId,
    nlri: pathvector_types::Nlri<std::net::Ipv6Addr>,
    route: &pathvector_rib::Route<std::net::Ipv6Addr>,
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
fn build_peer_state(snap: &RibSnapshot, addr: Ipv4Addr) -> Option<PeerState> {
    let remote_as = *snap.peer_remote_as.get(&addr)?;
    let peer_id = PeerId::from(addr);

    let (session_state, peer_type, hold_time, uptime_seconds) =
        if let Some(&pt) = snap.peer_types.get(&addr) {
            let uptime = snap
                .established_at
                .get(&addr)
                .map_or(0, |t| t.elapsed().as_secs());
            let ht = snap.hold_times.get(&addr).copied().unwrap_or(0);
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

    let prefixes_received = snap
        .prefixes_received
        .get(&addr)
        .copied()
        .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX));

    // Count best-path wins: routes in the Loc-RIB whose winner is this peer.
    let prefixes_accepted = snap
        .loc_rib
        .best_routes()
        .filter(|(nlri, _)| snap.loc_rib.best_peer(nlri) == Some(peer_id))
        .count();
    let prefixes_accepted = u32::try_from(prefixes_accepted).unwrap_or(u32::MAX);

    let prefixes_advertised = snap
        .prefixes_advertised
        .get(&addr)
        .copied()
        .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX));

    Some(PeerState {
        address: addr.to_string(),
        remote_as,
        local_as: snap.local_as,
        session_state,
        peer_type,
        hold_time,
        uptime_seconds,
        prefixes_received,
        prefixes_accepted,
        prefixes_advertised,
    })
}

type PeerEventStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<PeerEvent, Status>> + Send>>;
type RouteEventStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<RouteEvent, Status>> + Send>>;

#[tonic::async_trait]
impl PeerService for PeerServiceImpl {
    type WatchPeersStream = PeerEventStream;

    async fn list_peers(
        &self,
        _request: Request<ListPeersRequest>,
    ) -> Result<Response<ListPeersResponse>, Status> {
        let snap = self.state.read().await.snapshot();
        let mut peers: Vec<PeerState> = snap
            .peer_remote_as
            .keys()
            .copied()
            .filter_map(|addr| build_peer_state(&snap, addr))
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

        let snap = self.state.read().await.snapshot();
        build_peer_state(&snap, addr)
            .map(Response::new)
            .ok_or_else(|| Status::not_found(format!("peer {addr} is not configured")))
    }

    async fn watch_peers(
        &self,
        _request: Request<WatchPeersRequest>,
    ) -> Result<Response<Self::WatchPeersStream>, Status> {
        // Subscribe BEFORE snapshot to avoid a race between snapshot and first delta.
        let rx = self.state.read().await.peer_tx.subscribe();

        // Snapshot: clone Arc once, release lock, iterate without holding it.
        let snap = self.state.read().await.snapshot();
        let mut events: Vec<PeerEvent> = snap
            .peer_remote_as
            .keys()
            .copied()
            .filter_map(|addr| build_peer_state(&snap, addr))
            .map(|ps| PeerEvent {
                r#type: PeerEventType::Current as i32,
                peer: Some(ps),
            })
            .collect();
        events.sort_by_key(|e| e.peer.as_ref().map_or(String::new(), |p| p.address.clone()));
        events.push(PeerEvent {
            r#type: PeerEventType::EndInitial as i32,
            peer: None,
        });
        let snapshot = events;

        let stream = async_stream::stream! {
            for event in snapshot {
                yield Ok(event);
            }
            // Forward live deltas; reconnect on lag.
            let mut live = BroadcastStream::new(rx);
            while let Some(item) = live.next().await {
                match item {
                    Ok(event) => yield Ok(event),
                    Err(_lagged) => {
                        yield Err(Status::data_loss(
                            "watch stream fell behind; reconnect to receive a fresh snapshot",
                        ));
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
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
    type WatchRoutesStream = RouteEventStream;

    async fn get_best_route(
        &self,
        request: Request<GetBestRouteRequest>,
    ) -> Result<Response<RouteResponse>, Status> {
        let prefix = request.into_inner().prefix;
        let nlri = parse_nlri(&prefix)?;

        let snap = self.state.read().await.snapshot();
        let resp = match snap.loc_rib.best(&nlri) {
            Some(route) => {
                let peer_id = snap
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

        // Clone the Arc, release the lock, iterate without holding it.
        let snap = self.state.read().await.snapshot();
        let v4_routes = snap.loc_rib.best_routes().filter_map(|(nlri, route)| {
            let peer_id = snap.loc_rib.best_peer(&nlri)?;
            if peer_filter.is_none_or(|f| f == peer_id) {
                Some(route_to_proto(peer_id, nlri, route))
            } else {
                None
            }
        });
        let v6_routes = snap.loc_rib_v6.best_routes().filter_map(|(nlri, route)| {
            let peer_id = snap.loc_rib_v6.best_peer(&nlri)?;
            if peer_filter.is_none_or(|f| f == peer_id) {
                Some(route_v6_to_proto(peer_id, nlri, route))
            } else {
                None
            }
        });
        let routes: Vec<Route> = v4_routes.chain(v6_routes).collect();

        Ok(Response::new(ListRoutesResponse { routes }))
    }

    async fn watch_routes(
        &self,
        request: Request<WatchRoutesRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        let peer_filter_str = request.into_inner().peer_address;

        // Resolve optional peer filter; "local" maps to LOCAL_ORIGIN_PEER.
        let peer_filter: Option<PeerId> = if peer_filter_str.is_empty() {
            None
        } else if peer_filter_str == "local" {
            Some(PeerId::from(crate::LOCAL_ORIGIN_PEER))
        } else {
            let addr: Ipv4Addr = peer_filter_str.parse().map_err(|_| {
                Status::invalid_argument("peer_address must be a valid IPv4 address or \"local\"")
            })?;
            Some(PeerId::from(addr))
        };

        // Subscribe BEFORE snapshot to avoid gap between snapshot and first delta.
        let rx = self.state.read().await.route_tx.subscribe();

        // Clone the Arc, release the lock, build snapshot without holding it.
        let snap = self.state.read().await.snapshot();
        let v4_events = snap.loc_rib.best_routes().filter_map(|(nlri, route)| {
            let peer_id = snap.loc_rib.best_peer(&nlri)?;
            if peer_filter.is_none_or(|f| f == peer_id) {
                Some(RouteEvent {
                    r#type: RouteEventType::Current as i32,
                    route: Some(route_to_proto(peer_id, nlri, route)),
                    withdrawn_prefix: None,
                })
            } else {
                None
            }
        });
        let v6_events = snap.loc_rib_v6.best_routes().filter_map(|(nlri, route)| {
            let peer_id = snap.loc_rib_v6.best_peer(&nlri)?;
            if peer_filter.is_none_or(|f| f == peer_id) {
                Some(RouteEvent {
                    r#type: RouteEventType::Current as i32,
                    route: Some(route_v6_to_proto(peer_id, nlri, route)),
                    withdrawn_prefix: None,
                })
            } else {
                None
            }
        });
        let mut events: Vec<RouteEvent> = v4_events.chain(v6_events).collect();
        events.push(RouteEvent {
            r#type: RouteEventType::EndInitial as i32,
            route: None,
            withdrawn_prefix: None,
        });
        let snapshot = events;

        let stream = async_stream::stream! {
            for event in snapshot {
                yield Ok(event);
            }
            let mut live = BroadcastStream::new(rx);
            while let Some(item) = live.next().await {
                match item {
                    Ok(event) => yield Ok(event),
                    Err(_lagged) => {
                        yield Err(Status::data_loss(
                            "watch stream fell behind; reconnect to receive a fresh snapshot",
                        ));
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_candidates(
        &self,
        request: Request<ListCandidatesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let prefix = request.into_inner().prefix;
        let nlri = parse_nlri(&prefix)?;

        let snap = self.state.read().await.snapshot();
        let routes: Vec<Route> = snap
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

// ── PolicyService ─────────────────────────────────────────────────────────────

struct PolicyServiceImpl {
    state: Arc<tokio::sync::RwLock<DaemonState>>,
}

/// Parse a dotted-decimal IPv4 address from a gRPC request field, returning a
/// gRPC `INVALID_ARGUMENT` status on failure.
fn parse_peer_address(raw: &str) -> Result<Ipv4Addr, Status> {
    raw.parse::<Ipv4Addr>()
        .map_err(|_| Status::invalid_argument(format!("'{raw}' is not a valid IPv4 address")))
}

/// Map a `PolicyAction` proto enum to a [`DefaultAction`], returning
/// `INVALID_ARGUMENT` for the unspecified/unknown variant.
fn parse_policy_action(action: i32) -> Result<DefaultAction, Status> {
    match PolicyAction::try_from(action) {
        Ok(PolicyAction::Accept) => Ok(DefaultAction::Accept),
        Ok(PolicyAction::Reject) => Ok(DefaultAction::Reject),
        _ => Err(Status::invalid_argument(
            "action must be POLICY_ACTION_ACCEPT or POLICY_ACTION_REJECT",
        )),
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    async fn set_import_default(
        &self,
        request: Request<SetImportDefaultRequest>,
    ) -> Result<Response<SetImportDefaultResponse>, Status> {
        let req = request.into_inner();
        let peer_ip = parse_peer_address(&req.peer_address)?;
        let action = parse_policy_action(req.action)?;

        let mut s = self.state.write().await;
        if !s.import_policies.contains_key(&peer_ip) {
            return Err(Status::not_found(format!(
                "peer {peer_ip} is not configured"
            )));
        }

        tracing::info!(
            peer = %peer_ip,
            ?action,
            "SetImportDefault: replacing import policy and reapplying to Adj-RIB-In"
        );
        s.set_import_default(peer_ip, action);
        Ok(Response::new(SetImportDefaultResponse {}))
    }

    async fn set_export_default(
        &self,
        request: Request<SetExportDefaultRequest>,
    ) -> Result<Response<SetExportDefaultResponse>, Status> {
        let req = request.into_inner();
        let peer_ip = parse_peer_address(&req.peer_address)?;
        let action = parse_policy_action(req.action)?;

        let mut s = self.state.write().await;
        if !s.export_policies.contains_key(&peer_ip) {
            return Err(Status::not_found(format!(
                "peer {peer_ip} is not configured"
            )));
        }

        tracing::info!(
            peer = %peer_ip,
            ?action,
            "SetExportDefault: replacing export policy and re-evaluating Loc-RIB for peer"
        );
        s.set_export_default(peer_ip, action);
        Ok(Response::new(SetExportDefaultResponse {}))
    }
}

// ── OriginationService ────────────────────────────────────────────────────────

struct OriginationServiceImpl {
    state: Arc<tokio::sync::RwLock<DaemonState>>,
}

/// Parse an `OriginateRouteRequest` into a `Route<Ipv4Addr>`.
fn parse_originate_request(
    req: OriginateRouteRequest,
) -> Result<pathvector_rib::Route<Ipv4Addr>, Status> {
    use pathvector_rib::RouteBuilder;
    use pathvector_types::{
        Community, ExtendedCommunity, LargeCommunity as TypesLargeCommunity, Nlri, Origin, PeerType,
    };

    let nlri: Nlri<Ipv4Addr> = req.prefix.parse().map_err(|_| {
        Status::invalid_argument(format!("'{}' is not valid CIDR notation", req.prefix))
    })?;

    let next_hop_ip: Ipv4Addr = req.next_hop.parse().map_err(|_| {
        Status::invalid_argument(format!("'{}' is not a valid IPv4 next-hop", req.next_hop))
    })?;

    let origin = match proto::Origin::try_from(req.origin) {
        Ok(proto::Origin::Igp) => Origin::Igp,
        Ok(proto::Origin::Egp) => Origin::Egp,
        _ => Origin::Incomplete,
    };

    let communities: Vec<Community> = req.communities.into_iter().map(Community::from).collect();

    let large_communities: Vec<TypesLargeCommunity> = req
        .large_communities
        .into_iter()
        .map(|lc| TypesLargeCommunity {
            global_administrator: lc.global_admin,
            local_data_1: lc.local_data1,
            local_data_2: lc.local_data2,
        })
        .collect();

    let extended_communities: Vec<ExtendedCommunity> = req
        .extended_communities
        .into_iter()
        .map(|bytes| {
            let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                Status::invalid_argument("each extended_community must be exactly 8 bytes")
            })?;
            Ok::<ExtendedCommunity, Status>(ExtendedCommunity::from_bytes(arr))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut builder = RouteBuilder::new(nlri, origin, pathvector_types::AsPath::new())
        .next_hop(pathvector_types::NextHop::V4(next_hop_ip))
        .peer_type(PeerType::Local);

    for c in communities {
        builder = builder.community(c);
    }
    for lc in large_communities {
        builder = builder.large_community(lc);
    }
    for ec in extended_communities {
        builder = builder.extended_community(ec);
    }
    if let Some(lp) = req.local_pref {
        builder = builder.local_pref(pathvector_types::LocalPref::new(lp));
    }
    if let Some(med) = req.med {
        builder = builder.med(pathvector_types::Med::new(med));
    }

    Ok(builder.build())
}

#[tonic::async_trait]
impl OriginationService for OriginationServiceImpl {
    async fn originate_route(
        &self,
        request: Request<OriginateRouteRequest>,
    ) -> Result<Response<OriginateRouteResponse>, Status> {
        let route = parse_originate_request(request.into_inner())?;
        tracing::info!(prefix = %route.nlri, "OriginateRoute");
        self.state.write().await.originate_route(route);
        Ok(Response::new(OriginateRouteResponse {}))
    }

    async fn originate_routes(
        &self,
        request: Request<OriginateRoutesRequest>,
    ) -> Result<Response<OriginateRoutesResponse>, Status> {
        let routes_req = request.into_inner().routes;
        let count = u32::try_from(routes_req.len()).unwrap_or(u32::MAX);
        let routes: Vec<pathvector_rib::Route<Ipv4Addr>> = routes_req
            .into_iter()
            .map(parse_originate_request)
            .collect::<Result<_, _>>()?;
        tracing::info!(count, "OriginateRoutes (batch)");
        self.state.write().await.originate_routes(routes);
        Ok(Response::new(OriginateRoutesResponse { count }))
    }

    async fn withdraw_originated_route(
        &self,
        request: Request<WithdrawOriginatedRouteRequest>,
    ) -> Result<Response<WithdrawOriginatedRouteResponse>, Status> {
        let prefix = request.into_inner().prefix;
        let nlri: pathvector_types::Nlri<Ipv4Addr> = parse_nlri(&prefix)?;
        tracing::info!(%prefix, "WithdrawOriginatedRoute");
        self.state.write().await.withdraw_originated_route(nlri);
        Ok(Response::new(WithdrawOriginatedRouteResponse {}))
    }

    async fn withdraw_originated_routes(
        &self,
        request: Request<WithdrawOriginatedRoutesRequest>,
    ) -> Result<Response<WithdrawOriginatedRoutesResponse>, Status> {
        let prefixes = request.into_inner().prefixes;
        let count = u32::try_from(prefixes.len()).unwrap_or(u32::MAX);
        let nlris: Vec<pathvector_types::Nlri<Ipv4Addr>> = prefixes
            .iter()
            .map(|p| parse_nlri(p))
            .collect::<Result<_, _>>()?;
        tracing::info!(count, "WithdrawOriginatedRoutes (batch)");
        self.state.write().await.withdraw_originated_routes(&nlris);
        Ok(Response::new(WithdrawOriginatedRoutesResponse { count }))
    }

    async fn list_originated_routes(
        &self,
        _request: Request<ListOriginatedRoutesRequest>,
    ) -> Result<Response<ListOriginatedRoutesResponse>, Status> {
        let snap = self.state.read().await.snapshot();
        let local_peer = PeerId::from(crate::LOCAL_ORIGIN_PEER);
        let routes: Vec<Route> = snap
            .originated_routes
            .iter()
            .map(|(&nlri, route)| route_to_proto(local_peer, nlri, route))
            .collect();
        Ok(Response::new(ListOriginatedRoutesResponse { routes }))
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
    let rib_svc = RibServiceServer::new(RibServiceImpl {
        state: Arc::clone(&state),
    });
    let policy_svc = PolicyServiceServer::new(PolicyServiceImpl {
        state: Arc::clone(&state),
    });
    let origination_svc = OriginationServiceServer::new(OriginationServiceImpl {
        state: Arc::clone(&state),
    });
    let reflection_svc = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("file descriptor set is valid");

    if let Err(e) = tonic::transport::Server::builder()
        .add_service(peer_svc)
        .add_service(rib_svc)
        .add_service(policy_svc)
        .add_service(origination_svc)
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
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use pathvector_rib::{PeerId, RouteBuilder};
    use pathvector_types::{
        AsPath, AsPathSegment, Asn, Community, LargeCommunity as TypesLargeCommunity, NextHop,
        Origin, PeerType,
    };
    use tokio::sync::{RwLock, mpsc};
    use tonic::Request;

    use super::{
        OriginationServiceImpl, PeerServiceImpl, PolicyServiceImpl, RibServiceImpl,
        build_peer_state, parse_nlri, parse_originate_request, parse_peer_address,
        parse_policy_action, proto, proto_as_segment, proto_origin, route_to_proto,
    };
    use tokio_stream::StreamExt as _;

    use crate::{
        DaemonState,
        config::{self, ExportDefault, ImportDefault},
    };
    use proto::{
        GetBestRouteRequest, GetPeerRequest, ListCandidatesRequest, ListOriginatedRoutesRequest,
        ListPeersRequest, ListRoutesRequest, OriginateRouteRequest, OriginateRoutesRequest,
        SetExportDefaultRequest, SetImportDefaultRequest, WatchPeersRequest, WatchRoutesRequest,
        WithdrawOriginatedRouteRequest, WithdrawOriginatedRoutesRequest,
        origination_service_server::OriginationService, peer_service_server::PeerService,
        policy_service_server::PolicyService, rib_service_server::RibService,
    };

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
        DaemonState::new(
            local_as,
            Ipv4Addr::new(10, 0, 0, 1),
            &peer_configs,
            senders,
            vec![],
        )
    }

    fn nlri(s: &str) -> pathvector_types::Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn peer(ip: &str) -> PeerId {
        PeerId::from(ip.parse::<Ipv4Addr>().unwrap())
    }

    fn arc_state(local_as: u32, peers: &[(Ipv4Addr, u32)]) -> Arc<RwLock<DaemonState>> {
        Arc::new(RwLock::new(make_state(local_as, peers)))
    }

    fn route_igp(
        n: pathvector_types::Nlri<Ipv4Addr>,
        pt: PeerType,
    ) -> pathvector_rib::Route<Ipv4Addr> {
        RouteBuilder::new(n, Origin::Igp, AsPath::from_sequence(vec![Asn::new(65002)]))
            .next_hop(NextHop::V4("10.0.0.1".parse().unwrap()))
            .peer_type(pt)
            .build()
    }

    // ── build_peer_state ──────────────────────────────────────────────────────

    #[test]
    fn test_build_peer_state_unknown_address_returns_none() {
        let s = make_state(65001, &[]);
        assert!(build_peer_state(&s.rib, "10.0.0.99".parse().unwrap()).is_none());
    }

    #[test]
    fn test_build_peer_state_idle_peer() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let s = make_state(65001, &[(addr, 65002)]);
        let ps = build_peer_state(&s.rib, addr).unwrap();

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
        s.on_established(addr, PeerType::External, 65002, 90, &[]);

        let ps = build_peer_state(&s.rib, addr).unwrap();
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
        s.on_established(addr, PeerType::External, 65002, 90, &[]);

        // Insert a route so the counts are non-zero.
        let n = nlri("10.0.0.0/8");
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::from_sequence(vec![Asn::new(65002)]))
            .peer_type(PeerType::External)
            .build();
        s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
        s.rib_mut().loc_rib.insert(peer("10.0.0.2"), route);
        s.sync_received(addr);

        let ps = build_peer_state(&s.rib, addr).unwrap();
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

    // ── proto_origin ──────────────────────────────────────────────────────────

    #[test]
    fn test_proto_origin_egp() {
        assert_eq!(proto_origin(Origin::Egp), proto::Origin::Egp as i32);
    }

    #[test]
    fn test_proto_origin_incomplete() {
        assert_eq!(
            proto_origin(Origin::Incomplete),
            proto::Origin::Incomplete as i32
        );
    }

    // ── proto_as_segment — confederation variants ─────────────────────────────

    #[test]
    fn test_proto_as_segment_set() {
        let asns = vec![Asn::new(65100), Asn::new(65101)];
        let seg = proto_as_segment(&AsPathSegment::Set(asns));
        assert_eq!(seg.r#type, proto::as_segment::Type::Set as i32);
        assert_eq!(seg.asns, vec![65100, 65101]);
    }

    #[test]
    fn test_proto_as_segment_confed_sequence() {
        let asns = vec![Asn::new(65100)];
        let seg = proto_as_segment(&AsPathSegment::ConfedSequence(asns));
        assert_eq!(seg.r#type, proto::as_segment::Type::ConfedSequence as i32);
        assert_eq!(seg.asns, vec![65100]);
    }

    #[test]
    fn test_proto_as_segment_confed_set() {
        let asns = vec![Asn::new(65200), Asn::new(65201)];
        let seg = proto_as_segment(&AsPathSegment::ConfedSet(asns));
        assert_eq!(seg.r#type, proto::as_segment::Type::ConfedSet as i32);
        assert_eq!(seg.asns, vec![65200, 65201]);
    }

    // ── parse_nlri ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_nlri_valid_cidrs() {
        assert!(parse_nlri("10.0.0.0/8").is_ok());
        assert!(parse_nlri("192.168.1.0/24").is_ok());
        assert!(parse_nlri("0.0.0.0/0").is_ok());
    }

    #[test]
    fn test_parse_nlri_invalid_returns_invalid_argument() {
        let err = parse_nlri("not-a-cidr").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err2 = parse_nlri("10.0.0.0/99").unwrap_err();
        assert_eq!(err2.code(), tonic::Code::InvalidArgument);
    }

    // ── PeerService::list_peers ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_peers_empty_state() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl { state };
        let resp = svc
            .list_peers(Request::new(ListPeersRequest {}))
            .await
            .unwrap();
        assert!(resp.into_inner().peers.is_empty());
    }

    #[tokio::test]
    async fn test_list_peers_returns_all_configured_peers_sorted() {
        let a1: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let a2: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let state = arc_state(65001, &[(a1, 65002), (a2, 65003)]);
        let svc = PeerServiceImpl { state };
        let resp = svc
            .list_peers(Request::new(ListPeersRequest {}))
            .await
            .unwrap();
        let peers = resp.into_inner().peers;

        assert_eq!(peers.len(), 2);
        // Sorted by address string.
        assert_eq!(peers[0].address, "10.0.0.2");
        assert_eq!(peers[0].remote_as, 65002);
        assert_eq!(peers[1].address, "10.0.0.3");
        assert_eq!(peers[1].remote_as, 65003);
    }

    #[tokio::test]
    async fn test_list_peers_established_peer_shows_established_state() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        state
            .write()
            .await
            .on_established(addr, PeerType::External, 65002, 90, &[]);

        let svc = PeerServiceImpl { state };
        let resp = svc
            .list_peers(Request::new(ListPeersRequest {}))
            .await
            .unwrap();
        let peers = resp.into_inner().peers;

        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].session_state,
            proto::SessionState::Established as i32
        );
    }

    // ── PeerService::get_peer ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_peer_idle() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PeerServiceImpl { state };

        let resp = svc
            .get_peer(Request::new(GetPeerRequest {
                address: "10.0.0.2".into(),
            }))
            .await
            .unwrap();
        let ps = resp.into_inner();
        assert_eq!(ps.address, "10.0.0.2");
        assert_eq!(ps.remote_as, 65002);
        assert_eq!(ps.session_state, proto::SessionState::Idle as i32);
    }

    #[tokio::test]
    async fn test_get_peer_not_found_returns_not_found_status() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl { state };

        let err = svc
            .get_peer(Request::new(GetPeerRequest {
                address: "10.0.0.99".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_get_peer_invalid_address_returns_invalid_argument() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl { state };

        let err = svc
            .get_peer(Request::new(GetPeerRequest {
                address: "not-an-ip".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── RibService::get_best_route ────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_best_route_not_found() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };

        let resp = svc
            .get_best_route(Request::new(GetBestRouteRequest {
                prefix: "10.0.0.0/8".into(),
            }))
            .await
            .unwrap();
        let rr = resp.into_inner();
        assert!(!rr.found);
        assert!(rr.route.is_none());
    }

    #[tokio::test]
    async fn test_get_best_route_found() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        {
            let mut s = state.write().await;
            s.on_established(addr, PeerType::External, 65002, 90, &[]);
            let n = nlri("10.0.0.0/8");
            let route = route_igp(n, PeerType::External);
            s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
            s.rib_mut().loc_rib.insert(peer("10.0.0.2"), route);
        }

        let svc = RibServiceImpl { state };
        let resp = svc
            .get_best_route(Request::new(GetBestRouteRequest {
                prefix: "10.0.0.0/8".into(),
            }))
            .await
            .unwrap();
        let rr = resp.into_inner();
        assert!(rr.found);
        let r = rr.route.unwrap();
        assert_eq!(r.prefix, "10.0.0.0/8");
        assert_eq!(r.peer_address, "10.0.0.2");
    }

    #[tokio::test]
    async fn test_get_best_route_invalid_cidr_returns_invalid_argument() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };

        let err = svc
            .get_best_route(Request::new(GetBestRouteRequest {
                prefix: "bad/prefix".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── RibService::list_routes ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_routes_empty_rib() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };

        let resp = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
            }))
            .await
            .unwrap();
        assert!(resp.into_inner().routes.is_empty());
    }

    #[tokio::test]
    async fn test_list_routes_all_routes_no_filter() {
        let a1: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let a2: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let state = arc_state(65001, &[(a1, 65002), (a2, 65003)]);
        {
            let mut s = state.write().await;
            s.on_established(a1, PeerType::External, 65002, 90, &[]);
            s.on_established(a2, PeerType::External, 65003, 90, &[]);

            let n1 = nlri("10.0.0.0/8");
            let r1 = route_igp(n1, PeerType::External);
            s.adj_ribs_in.get_mut(&a1).unwrap().insert(r1.clone());
            s.rib_mut().loc_rib.insert(peer("10.0.0.2"), r1);

            let n2 = nlri("192.168.0.0/24");
            let r2 = route_igp(n2, PeerType::External);
            s.adj_ribs_in.get_mut(&a2).unwrap().insert(r2.clone());
            s.rib_mut().loc_rib.insert(peer("10.0.0.3"), r2);
        }

        let svc = RibServiceImpl { state };
        let resp = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
            }))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().routes.len(), 2);
    }

    #[tokio::test]
    async fn test_list_routes_with_peer_filter() {
        let a1: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let a2: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let state = arc_state(65001, &[(a1, 65002), (a2, 65003)]);
        {
            let mut s = state.write().await;
            s.on_established(a1, PeerType::External, 65002, 90, &[]);
            s.on_established(a2, PeerType::External, 65003, 90, &[]);

            let n1 = nlri("10.0.0.0/8");
            let r1 = route_igp(n1, PeerType::External);
            s.adj_ribs_in.get_mut(&a1).unwrap().insert(r1.clone());
            s.rib_mut().loc_rib.insert(peer("10.0.0.2"), r1);

            let n2 = nlri("192.168.0.0/24");
            let r2 = route_igp(n2, PeerType::External);
            s.adj_ribs_in.get_mut(&a2).unwrap().insert(r2.clone());
            s.rib_mut().loc_rib.insert(peer("10.0.0.3"), r2);
        }

        let svc = RibServiceImpl { state };
        let resp = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: "10.0.0.2".into(),
            }))
            .await
            .unwrap();
        let routes = resp.into_inner().routes;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].peer_address, "10.0.0.2");
    }

    #[tokio::test]
    async fn test_list_routes_bad_peer_filter_returns_invalid_argument() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };

        let err = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: "not-an-ip".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── RibService::list_candidates ───────────────────────────────────────────

    #[tokio::test]
    async fn test_list_candidates_empty_returns_empty() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };

        let resp = svc
            .list_candidates(Request::new(ListCandidatesRequest {
                prefix: "10.0.0.0/8".into(),
            }))
            .await
            .unwrap();
        assert!(resp.into_inner().routes.is_empty());
    }

    #[tokio::test]
    async fn test_list_candidates_found() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        {
            let mut s = state.write().await;
            s.on_established(addr, PeerType::External, 65002, 90, &[]);
            let n = nlri("10.0.0.0/8");
            let route = route_igp(n, PeerType::External);
            s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
            s.rib_mut().loc_rib.insert(peer("10.0.0.2"), route);
        }

        let svc = RibServiceImpl { state };
        let resp = svc
            .list_candidates(Request::new(ListCandidatesRequest {
                prefix: "10.0.0.0/8".into(),
            }))
            .await
            .unwrap();
        let routes = resp.into_inner().routes;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "10.0.0.0/8");
        assert_eq!(routes[0].peer_address, "10.0.0.2");
    }

    #[tokio::test]
    async fn test_list_candidates_invalid_cidr_returns_invalid_argument() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };

        let err = svc
            .list_candidates(Request::new(ListCandidatesRequest {
                prefix: "bad".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── route_to_proto — aggregator ──────────────────────────────────────────

    #[test]
    fn test_route_to_proto_aggregator() {
        use pathvector_types::{Aggregator, Asn, PeerType};

        let n = nlri("10.0.0.0/8");
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .aggregator(Aggregator {
                asn: Asn::new(65000),
                ip: "192.0.2.1".parse().unwrap(),
            })
            .peer_type(PeerType::External)
            .build();

        let r = route_to_proto(peer("10.0.0.2"), n, &route);
        let agg = r.aggregator.expect("aggregator must be present");
        assert_eq!(agg.asn, 65000);
        assert_eq!(agg.address, "192.0.2.1");
    }

    // ── route_to_proto — V6 next-hop branches ────────────────────────────────

    #[test]
    fn test_route_to_proto_v6_nexthop() {
        use pathvector_types::{NextHop, PeerType};
        use std::net::Ipv6Addr;

        let n = nlri("10.0.0.0/8");
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6(v6))
            .peer_type(PeerType::External)
            .build();

        let r = route_to_proto(peer("10.0.0.2"), n, &route);
        assert_eq!(r.next_hop, "2001:db8::1");
    }

    #[test]
    fn test_route_to_proto_v6_with_link_local_nexthop() {
        use pathvector_types::{NextHop, PeerType};
        use std::net::Ipv6Addr;

        let n = nlri("10.0.0.0/8");
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6WithLinkLocal { global, link_local })
            .peer_type(PeerType::External)
            .build();

        // V6WithLinkLocal renders as the global address.
        let r = route_to_proto(peer("10.0.0.2"), n, &route);
        assert_eq!(r.next_hop, "2001:db8::1");
    }

    // ── parse_peer_address ────────────────────────────────────────────────────

    #[test]
    fn test_parse_peer_address_valid() {
        let ip = parse_peer_address("10.0.0.1").unwrap();
        assert_eq!(ip, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_parse_peer_address_invalid_returns_invalid_argument() {
        let err = parse_peer_address("not-an-ip").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not-an-ip"));
    }

    // ── parse_policy_action ───────────────────────────────────────────────────

    #[test]
    fn test_parse_policy_action_accept() {
        use pathvector_policy::DefaultAction;
        let action = parse_policy_action(proto::PolicyAction::Accept as i32).unwrap();
        assert!(matches!(action, DefaultAction::Accept));
    }

    #[test]
    fn test_parse_policy_action_reject() {
        use pathvector_policy::DefaultAction;
        let action = parse_policy_action(proto::PolicyAction::Reject as i32).unwrap();
        assert!(matches!(action, DefaultAction::Reject));
    }

    #[test]
    fn test_parse_policy_action_unspecified_returns_invalid_argument() {
        // PolicyAction::Unspecified (value 0) must be rejected.
        let err = parse_policy_action(proto::PolicyAction::Unspecified as i32).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── PolicyService::set_import_default ─────────────────────────────────────

    #[tokio::test]
    async fn test_set_import_default_accept_success() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PolicyServiceImpl { state };

        svc.set_import_default(Request::new(SetImportDefaultRequest {
            peer_address: "10.0.0.2".into(),
            action: proto::PolicyAction::Accept as i32,
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_set_import_default_reject_success() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PolicyServiceImpl { state };

        svc.set_import_default(Request::new(SetImportDefaultRequest {
            peer_address: "10.0.0.2".into(),
            action: proto::PolicyAction::Reject as i32,
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_set_import_default_invalid_address_returns_invalid_argument() {
        let state = arc_state(65001, &[]);
        let svc = PolicyServiceImpl { state };

        let err = svc
            .set_import_default(Request::new(SetImportDefaultRequest {
                peer_address: "not-an-ip".into(),
                action: proto::PolicyAction::Accept as i32,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_set_import_default_unknown_peer_returns_not_found() {
        let state = arc_state(65001, &[]);
        let svc = PolicyServiceImpl { state };

        let err = svc
            .set_import_default(Request::new(SetImportDefaultRequest {
                peer_address: "10.0.0.99".into(),
                action: proto::PolicyAction::Accept as i32,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_set_import_default_invalid_action_returns_invalid_argument() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PolicyServiceImpl { state };

        let err = svc
            .set_import_default(Request::new(SetImportDefaultRequest {
                peer_address: "10.0.0.2".into(),
                action: proto::PolicyAction::Unspecified as i32,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── PolicyService::set_export_default ─────────────────────────────────────

    #[tokio::test]
    async fn test_set_export_default_accept_success() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PolicyServiceImpl { state };

        svc.set_export_default(Request::new(SetExportDefaultRequest {
            peer_address: "10.0.0.2".into(),
            action: proto::PolicyAction::Accept as i32,
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_set_export_default_reject_success() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PolicyServiceImpl { state };

        svc.set_export_default(Request::new(SetExportDefaultRequest {
            peer_address: "10.0.0.2".into(),
            action: proto::PolicyAction::Reject as i32,
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_set_export_default_invalid_address_returns_invalid_argument() {
        let state = arc_state(65001, &[]);
        let svc = PolicyServiceImpl { state };

        let err = svc
            .set_export_default(Request::new(SetExportDefaultRequest {
                peer_address: "bad-addr".into(),
                action: proto::PolicyAction::Accept as i32,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_set_export_default_unknown_peer_returns_not_found() {
        let state = arc_state(65001, &[]);
        let svc = PolicyServiceImpl { state };

        let err = svc
            .set_export_default(Request::new(SetExportDefaultRequest {
                peer_address: "10.0.0.99".into(),
                action: proto::PolicyAction::Reject as i32,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_set_export_default_invalid_action_returns_invalid_argument() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PolicyServiceImpl { state };

        let err = svc
            .set_export_default(Request::new(SetExportDefaultRequest {
                peer_address: "10.0.0.2".into(),
                action: proto::PolicyAction::Unspecified as i32,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── parse_originate_request ───────────────────────────────────────────────

    fn minimal_originate_req() -> OriginateRouteRequest {
        OriginateRouteRequest {
            prefix: "192.0.2.0/24".to_owned(),
            next_hop: "10.0.0.1".to_owned(),
            origin: proto::Origin::Igp as i32,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        }
    }

    #[test]
    fn test_parse_originate_request_valid() {
        let route = parse_originate_request(minimal_originate_req()).unwrap();
        assert_eq!(route.nlri.to_string(), "192.0.2.0/24");
    }

    #[test]
    fn test_parse_originate_request_invalid_prefix() {
        let mut req = minimal_originate_req();
        req.prefix = "not-cidr".to_owned();
        let err = parse_originate_request(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_parse_originate_request_invalid_next_hop() {
        let mut req = minimal_originate_req();
        req.next_hop = "not-an-ip".to_owned();
        let err = parse_originate_request(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_parse_originate_request_invalid_ext_community_length() {
        let mut req = minimal_originate_req();
        req.extended_communities = vec![vec![0x00; 7]]; // wrong length
        let err = parse_originate_request(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_parse_originate_request_with_communities() {
        let mut req = minimal_originate_req();
        req.communities = vec![(65000_u32 << 16) | 0x29A];
        req.large_communities = vec![proto::LargeCommunity {
            global_admin: 65000,
            local_data1: 1,
            local_data2: 2,
        }];
        req.extended_communities = vec![vec![0u8; 8]];
        let route = parse_originate_request(req).unwrap();
        assert!(!route.communities.is_empty());
        assert!(!route.large_communities.is_empty());
        assert!(!route.extended_communities.is_empty());
    }

    #[test]
    fn test_parse_originate_request_with_local_pref_and_med() {
        let mut req = minimal_originate_req();
        req.local_pref = Some(200);
        req.med = Some(50);
        let route = parse_originate_request(req).unwrap();
        assert!(route.local_pref.is_some());
        assert!(route.med.is_some());
    }

    #[test]
    fn test_parse_originate_request_egp_origin() {
        let mut req = minimal_originate_req();
        req.origin = proto::Origin::Egp as i32;
        let route = parse_originate_request(req).unwrap();
        assert_eq!(route.origin, pathvector_types::Origin::Egp);
    }

    #[test]
    fn test_parse_originate_request_incomplete_origin() {
        let mut req = minimal_originate_req();
        req.origin = proto::Origin::Incomplete as i32;
        let route = parse_originate_request(req).unwrap();
        assert_eq!(route.origin, pathvector_types::Origin::Incomplete);
    }

    // ── OriginationService handlers ───────────────────────────────────────────

    #[tokio::test]
    async fn test_originate_route_inserts_into_loc_rib() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl {
            state: Arc::clone(&state),
        };

        svc.originate_route(Request::new(minimal_originate_req()))
            .await
            .expect("originate_route");

        let s = state.read().await;
        let nlri: pathvector_types::Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        assert!(s.rib.originated_routes.contains_key(&nlri));
    }

    #[tokio::test]
    async fn test_originate_route_event_carries_route_payload() {
        let state = arc_state(65001, &[]);
        // Subscribe before originating so we catch the event.
        let mut rx = state.read().await.route_tx.subscribe();
        let svc = OriginationServiceImpl {
            state: Arc::clone(&state),
        };

        svc.originate_route(Request::new(minimal_originate_req()))
            .await
            .expect("originate_route");

        let event = tokio::time::timeout(tokio::time::Duration::from_millis(100), async {
            rx.recv().await
        })
        .await
        .expect("timed out waiting for RouteEvent")
        .expect("channel closed");

        assert_eq!(event.r#type, proto::RouteEventType::Announced as i32);
        let route = event
            .route
            .expect("Announced event must carry route payload");
        assert_eq!(route.prefix, "192.0.2.0/24");
        assert_eq!(route.peer_address, "local"); // LOCAL_ORIGIN_PEER sentinel
        assert_eq!(route.next_hop, "10.0.0.1");
    }

    #[tokio::test]
    async fn test_originate_route_invalid_prefix_returns_error() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl { state };
        let mut req = minimal_originate_req();
        req.prefix = "bad".to_owned();
        let err = svc.originate_route(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_originate_routes_batch_inserts_all() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl {
            state: Arc::clone(&state),
        };

        let resp = svc
            .originate_routes(Request::new(OriginateRoutesRequest {
                routes: vec![
                    OriginateRouteRequest {
                        prefix: "192.0.2.0/24".to_owned(),
                        ..minimal_originate_req()
                    },
                    OriginateRouteRequest {
                        prefix: "198.51.100.0/24".to_owned(),
                        ..minimal_originate_req()
                    },
                ],
            }))
            .await
            .expect("originate_routes")
            .into_inner();

        assert_eq!(resp.count, 2);
        let s = state.read().await;
        assert_eq!(s.rib.originated_routes.len(), 2);
    }

    #[tokio::test]
    async fn test_originate_routes_batch_invalid_returns_error() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl { state };
        let err = svc
            .originate_routes(Request::new(OriginateRoutesRequest {
                routes: vec![OriginateRouteRequest {
                    prefix: "bad".to_owned(),
                    ..minimal_originate_req()
                }],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_withdraw_originated_route_removes_from_loc_rib() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl {
            state: Arc::clone(&state),
        };

        svc.originate_route(Request::new(minimal_originate_req()))
            .await
            .unwrap();
        svc.withdraw_originated_route(Request::new(WithdrawOriginatedRouteRequest {
            prefix: "192.0.2.0/24".to_owned(),
        }))
        .await
        .expect("withdraw_originated_route");

        let s = state.read().await;
        let nlri: pathvector_types::Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        assert!(!s.rib.originated_routes.contains_key(&nlri));
    }

    #[tokio::test]
    async fn test_withdraw_originated_route_invalid_prefix_returns_error() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl { state };
        let err = svc
            .withdraw_originated_route(Request::new(WithdrawOriginatedRouteRequest {
                prefix: "bad".to_owned(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_withdraw_originated_routes_batch() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl {
            state: Arc::clone(&state),
        };

        svc.originate_routes(Request::new(OriginateRoutesRequest {
            routes: vec![
                OriginateRouteRequest {
                    prefix: "192.0.2.0/24".to_owned(),
                    ..minimal_originate_req()
                },
                OriginateRouteRequest {
                    prefix: "198.51.100.0/24".to_owned(),
                    ..minimal_originate_req()
                },
            ],
        }))
        .await
        .unwrap();

        let resp = svc
            .withdraw_originated_routes(Request::new(WithdrawOriginatedRoutesRequest {
                prefixes: vec!["192.0.2.0/24".to_owned(), "198.51.100.0/24".to_owned()],
            }))
            .await
            .expect("withdraw_originated_routes")
            .into_inner();

        assert_eq!(resp.count, 2);
        assert!(state.read().await.rib.originated_routes.is_empty());
    }

    #[tokio::test]
    async fn test_withdraw_originated_routes_invalid_prefix_returns_error() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl { state };
        let err = svc
            .withdraw_originated_routes(Request::new(WithdrawOriginatedRoutesRequest {
                prefixes: vec!["bad".to_owned()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_list_originated_routes_empty() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl { state };
        let resp = svc
            .list_originated_routes(Request::new(ListOriginatedRoutesRequest {}))
            .await
            .expect("list_originated_routes")
            .into_inner();
        assert!(resp.routes.is_empty());
    }

    #[tokio::test]
    async fn test_list_originated_routes_after_originate() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl { state };

        svc.originate_route(Request::new(minimal_originate_req()))
            .await
            .unwrap();

        let resp = svc
            .list_originated_routes(Request::new(ListOriginatedRoutesRequest {}))
            .await
            .expect("list_originated_routes")
            .into_inner();

        assert_eq!(resp.routes.len(), 1);
        assert_eq!(resp.routes[0].prefix, "192.0.2.0/24");
        assert_eq!(resp.routes[0].peer_address, "local");
    }

    // ── WatchPeers / WatchRoutes streaming handlers ───────────────────────────

    #[tokio::test]
    async fn test_watch_peers_empty_state_yields_end_initial() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl { state };
        let resp = svc
            .watch_peers(Request::new(WatchPeersRequest {}))
            .await
            .expect("watch_peers");
        // Drop svc so the broadcast sender closes, which terminates the stream.
        drop(svc);
        let mut stream = resp.into_inner();
        // No peers configured → only EndInitial event
        let ev = stream.next().await.unwrap().unwrap();
        assert_eq!(ev.r#type, proto::PeerEventType::EndInitial as i32);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_watch_peers_with_peer_yields_current_then_end_initial() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PeerServiceImpl { state };
        let resp = svc
            .watch_peers(Request::new(WatchPeersRequest {}))
            .await
            .expect("watch_peers");
        drop(svc);
        let mut stream = resp.into_inner();

        let current = stream.next().await.unwrap().unwrap();
        assert_eq!(current.r#type, proto::PeerEventType::Current as i32);

        let end = stream.next().await.unwrap().unwrap();
        assert_eq!(end.r#type, proto::PeerEventType::EndInitial as i32);

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_watch_routes_empty_state_yields_end_initial() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };
        let resp = svc
            .watch_routes(Request::new(WatchRoutesRequest {
                peer_address: String::new(),
            }))
            .await
            .expect("watch_routes");
        drop(svc);
        let mut stream = resp.into_inner();
        // No routes → only EndInitial
        let ev = stream.next().await.unwrap().unwrap();
        assert_eq!(ev.r#type, proto::RouteEventType::EndInitial as i32);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_watch_routes_invalid_peer_address_returns_error() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };
        let result = svc
            .watch_routes(Request::new(WatchRoutesRequest {
                peer_address: "not-an-ip".to_owned(),
            }))
            .await;
        match result {
            Err(status) => assert_eq!(status.code(), tonic::Code::InvalidArgument),
            Ok(_) => panic!("expected InvalidArgument error"),
        }
    }

    #[tokio::test]
    async fn test_watch_routes_local_filter_yields_end_initial() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };
        let resp = svc
            .watch_routes(Request::new(WatchRoutesRequest {
                peer_address: "local".to_owned(),
            }))
            .await
            .expect("watch_routes local");
        drop(svc);
        let mut stream = resp.into_inner();
        let ev = stream.next().await.unwrap().unwrap();
        assert_eq!(ev.r#type, proto::RouteEventType::EndInitial as i32);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_watch_routes_with_routes_yields_current_events() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let mut s = make_state(65001, &[(addr, 65002)]);
        s.on_established(addr, pathvector_types::PeerType::External, 65002, 90, &[]);
        let n = nlri("192.0.2.0/24");
        s.rib_mut().loc_rib.insert(
            peer(addr.to_string().as_str()),
            route_igp(n, PeerType::External),
        );
        let state = Arc::new(RwLock::new(s));

        let svc = RibServiceImpl { state };
        let resp = svc
            .watch_routes(Request::new(WatchRoutesRequest {
                peer_address: String::new(),
            }))
            .await
            .expect("watch_routes with routes");
        drop(svc);
        let mut stream = resp.into_inner();

        let current = stream.next().await.unwrap().unwrap();
        assert_eq!(current.r#type, proto::RouteEventType::Current as i32);
        assert!(current.route.is_some());

        let end = stream.next().await.unwrap().unwrap();
        assert_eq!(end.r#type, proto::RouteEventType::EndInitial as i32);
        assert!(stream.next().await.is_none());
    }
}
