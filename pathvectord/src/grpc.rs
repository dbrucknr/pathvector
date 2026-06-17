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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pathvector_policy::DefaultAction;
use pathvector_rib::PeerId;
use pathvector_types::{AsPathSegment, LocalPref, Med, NextHop, Origin, PeerType};

use tokio::sync::mpsc;

use crate::{DaemonState, RibSnapshot, daemon::DaemonCommand};

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
    AddPeerRequest, AddPeerResponse, Aggregator, AsSegment, GetBestRouteRequest, GetPeerRequest,
    LargeCommunity, ListCandidatesRequest, ListOriginatedRoutesRequest,
    ListOriginatedRoutesResponse, ListPeersRequest, ListPeersResponse, ListRoutesRequest,
    ListRoutesResponse, OriginateRouteRequest, OriginateRouteResponse, OriginateRoutesRequest,
    OriginateRoutesResponse, PeerEvent, PeerEventType, PeerState, PolicyAction, RemovePeerRequest,
    RemovePeerResponse, Route, RouteEvent, RouteEventType, RouteResponse, SetExportDefaultRequest,
    SetExportDefaultResponse, SetImportDefaultRequest, SetImportDefaultResponse, WatchPeersRequest,
    WatchRoutesRequest, WithdrawOriginatedRouteRequest, WithdrawOriginatedRouteResponse,
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

    let rare = route.rare_or_default();
    let communities: Vec<u32> = rare.communities.iter().map(|c| c.as_u32()).collect();
    let large_communities: Vec<LargeCommunity> = rare
        .large_communities
        .iter()
        .map(|lc| LargeCommunity {
            global_admin: lc.global_administrator,
            local_data1: lc.local_data_1,
            local_data2: lc.local_data_2,
        })
        .collect();
    let extended_communities: Vec<Vec<u8>> = rare
        .extended_communities
        .iter()
        .map(|ec| ec.as_bytes().to_vec())
        .collect();
    let aggregator = rare.aggregator.map(|agg| Aggregator {
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
        atomic_aggregate: rare.atomic_aggregate,
        aggregator,
    }
}

pub(crate) fn route_v6_to_proto(
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

    let rare = route.rare_or_default();
    let communities: Vec<u32> = rare.communities.iter().map(|c| c.as_u32()).collect();
    let large_communities: Vec<LargeCommunity> = rare
        .large_communities
        .iter()
        .map(|lc| LargeCommunity {
            global_admin: lc.global_administrator,
            local_data1: lc.local_data_1,
            local_data2: lc.local_data_2,
        })
        .collect();
    let extended_communities: Vec<Vec<u8>> = rare
        .extended_communities
        .iter()
        .map(|ec| ec.as_bytes().to_vec())
        .collect();
    let aggregator = rare.aggregator.map(|agg| Aggregator {
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
        atomic_aggregate: rare.atomic_aggregate,
        aggregator,
    }
}

// ── PeerService ───────────────────────────────────────────────────────────────

struct PeerServiceImpl {
    state: Arc<tokio::sync::RwLock<DaemonState>>,
    /// Channel to the command processor for AddPeer / RemovePeer at runtime.
    cmd_tx: mpsc::Sender<DaemonCommand>,
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

fn proto_policy_to_config_import(action: i32) -> Option<crate::config::ImportDefault> {
    match PolicyAction::try_from(action).unwrap_or(PolicyAction::Unspecified) {
        PolicyAction::Accept => Some(crate::config::ImportDefault::Accept),
        PolicyAction::Reject => Some(crate::config::ImportDefault::Reject),
        PolicyAction::Unspecified => None,
    }
}

fn proto_policy_to_config_export(action: i32) -> Option<crate::config::ExportDefault> {
    match PolicyAction::try_from(action).unwrap_or(PolicyAction::Unspecified) {
        PolicyAction::Accept => Some(crate::config::ExportDefault::Accept),
        PolicyAction::Reject => Some(crate::config::ExportDefault::Reject),
        PolicyAction::Unspecified => None,
    }
}

/// RFC 7607 §2: AS 0 and AS 23456 (AS_TRANS) are invalid in `remote_as`.
fn validate_remote_as(remote_as: u32) -> Result<(), Status> {
    match remote_as {
        0 => Err(Status::invalid_argument("remote_as must not be 0")),
        23456 => Err(Status::invalid_argument(
            "remote_as must not be 23456 (AS_TRANS is reserved, RFC 6793)",
        )),
        _ => Ok(()),
    }
}

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

        // Hold a Weak so that dropping the last strong Arc (i.e. daemon
        // shutdown) closes peer_tx and naturally terminates the stream, while
        // still allowing snapshot reads for state-change signals.
        let state_weak = Arc::downgrade(&self.state);
        let stream = async_stream::stream! {
            for event in snapshot {
                yield Ok(event);
            }
            // Forward live deltas; reconnect on lag.
            let mut live = BroadcastStream::new(rx);
            while let Some(item) = live.next().await {
                match item {
                    Ok(PeerEvent { peer: None, .. }) => {
                        // on_terminated / on_established broadcast a signal
                        // without the peer payload. Upgrade to read the current
                        // snapshot and emit one Changed event per configured
                        // peer so every subscriber gets a consistent view.
                        let Some(state) = state_weak.upgrade() else { break };
                        let snap = state.read().await.snapshot();
                        let mut changed: Vec<PeerEvent> = snap
                            .peer_remote_as
                            .keys()
                            .copied()
                            .filter_map(|addr| build_peer_state(&snap, addr))
                            .map(|ps| PeerEvent {
                                r#type: PeerEventType::Changed as i32,
                                peer: Some(ps),
                            })
                            .collect();
                        changed.sort_by_key(|e| {
                            e.peer.as_ref().map_or(String::new(), |p| p.address.clone())
                        });
                        for e in changed {
                            yield Ok(e);
                        }
                    }
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

    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerResponse>, Status> {
        let req = request.into_inner();

        let addr: std::net::Ipv4Addr = req
            .address
            .parse()
            .map_err(|_| Status::invalid_argument("address must be a valid IPv4 address"))?;

        validate_remote_as(req.remote_as)?;

        let port: u16 = if req.port == 0 {
            179
        } else {
            u16::try_from(req.port)
                .map_err(|_| Status::invalid_argument("port must be in range 1–65535"))?
        };

        let import_default = proto_policy_to_config_import(req.import_default);
        let export_default = proto_policy_to_config_export(req.export_default);
        let md5_password = if req.md5_password.is_empty() {
            None
        } else {
            Some(req.md5_password)
        };

        let peer = crate::config::PeerConfig {
            address: addr,
            port,
            remote_as: req.remote_as,
            import_default,
            export_default,
            import_default_v6: None,
            md5_password,
            is_rr_client: false,
        };

        self.cmd_tx
            .send(DaemonCommand::AddPeer(peer))
            .await
            .map_err(|_| Status::internal("daemon command channel closed"))?;

        Ok(Response::new(AddPeerResponse {}))
    }

    async fn remove_peer(
        &self,
        request: Request<RemovePeerRequest>,
    ) -> Result<Response<RemovePeerResponse>, Status> {
        let addr: std::net::Ipv4Addr = request
            .into_inner()
            .address
            .parse()
            .map_err(|_| Status::invalid_argument("address must be a valid IPv4 address"))?;

        // Verify the peer exists before sending the command so the caller gets a
        // NOT_FOUND immediately rather than silently doing nothing.
        let snap = self.state.read().await.snapshot();
        if !snap.peer_remote_as.contains_key(&addr) {
            return Err(Status::not_found(format!("peer {addr} is not configured")));
        }
        drop(snap);

        self.cmd_tx
            .send(DaemonCommand::RemovePeer(addr))
            .await
            .map_err(|_| Status::internal("daemon command channel closed"))?;

        Ok(Response::new(RemovePeerResponse {}))
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

fn parse_nlri_v6(s: &str) -> Result<pathvector_types::Nlri<Ipv6Addr>, Status> {
    s.parse()
        .map_err(|_| Status::invalid_argument(format!("'{s}' is not valid IPv6 CIDR notation")))
}

#[tonic::async_trait]
impl RibService for RibServiceImpl {
    type WatchRoutesStream = RouteEventStream;

    async fn get_best_route(
        &self,
        request: Request<GetBestRouteRequest>,
    ) -> Result<Response<RouteResponse>, Status> {
        let prefix = request.into_inner().prefix;
        let snap = self.state.read().await.snapshot();

        // Try IPv4 first; if parsing fails, try IPv6.
        if let Ok(nlri) = prefix.parse::<pathvector_types::Nlri<Ipv4Addr>>() {
            let resp = match snap.loc_rib.best(&nlri) {
                Some(route) => {
                    let peer_id = snap.loc_rib.best_peer(&nlri).unwrap_or_else(|| {
                        PeerId::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                    });
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
            return Ok(Response::new(resp));
        }

        if let Ok(nlri) = prefix.parse::<pathvector_types::Nlri<Ipv6Addr>>() {
            let resp = match snap.loc_rib_v6.best(&nlri) {
                Some(route) => {
                    let peer_id = snap.loc_rib_v6.best_peer(&nlri).unwrap_or_else(|| {
                        PeerId::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                    });
                    RouteResponse {
                        found: true,
                        route: Some(route_v6_to_proto(peer_id, nlri, route)),
                    }
                }
                None => RouteResponse {
                    found: false,
                    route: None,
                },
            };
            return Ok(Response::new(resp));
        }

        Err(Status::invalid_argument(format!(
            "'{prefix}' is not valid CIDR notation"
        )))
    }

    async fn list_routes(
        &self,
        request: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let req = request.into_inner();
        let peer_filter_str = req.peer_address;
        let page_size = req.page_size as usize;
        let page_token = req.page_token;

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

        // Collect and sort so the cursor (last prefix CIDR) gives a stable ordering
        // across pages.  The sort is O(n log n) but list_routes is a management
        // operation, not a hot path.
        let mut all: Vec<Route> = v4_routes.chain(v6_routes).collect();
        if page_size > 0 {
            all.sort_unstable_by(|a, b| a.prefix.cmp(&b.prefix));
        }

        let (routes, next_page_token) = if page_size == 0 {
            // No pagination requested — return everything (original behaviour).
            (all, String::new())
        } else {
            // Skip entries up to and including the cursor prefix.
            let start = if page_token.is_empty() {
                0
            } else {
                all.iter()
                    .position(|r| r.prefix == page_token)
                    .map_or(0, |i| i + 1)
            };
            let page: Vec<Route> = all.iter().skip(start).take(page_size).cloned().collect();
            let next_token = if start + page_size < all.len() {
                page.last().map(|r| r.prefix.clone()).unwrap_or_default()
            } else {
                String::new()
            };
            (page, next_token)
        };

        Ok(Response::new(ListRoutesResponse {
            routes,
            next_page_token,
        }))
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

        Ok(Response::new(ListRoutesResponse {
            routes,
            next_page_token: String::new(),
        }))
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

    if next_hop_ip.is_unspecified() {
        return Err(Status::invalid_argument("next_hop must not be 0.0.0.0"));
    }

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

/// Parse an `OriginateRouteRequest` whose prefix is IPv6 into a `Route<Ipv6Addr>`.
fn parse_originate_request_v6(
    req: OriginateRouteRequest,
) -> Result<pathvector_rib::Route<Ipv6Addr>, Status> {
    use pathvector_rib::RouteBuilder;
    use pathvector_types::{
        Community, ExtendedCommunity, LargeCommunity as TypesLargeCommunity, Nlri, Origin, PeerType,
    };

    let nlri: Nlri<Ipv6Addr> = req.prefix.parse().map_err(|_| {
        Status::invalid_argument(format!("'{}' is not valid CIDR notation", req.prefix))
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

    let mut builder =
        RouteBuilder::new(nlri, origin, pathvector_types::AsPath::new()).peer_type(PeerType::Local);
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

/// Returns true if `prefix` parses as an IPv6 CIDR (contains ':').
fn is_ipv6_prefix(prefix: &str) -> bool {
    prefix.contains(':')
}

#[tonic::async_trait]
impl OriginationService for OriginationServiceImpl {
    async fn originate_route(
        &self,
        request: Request<OriginateRouteRequest>,
    ) -> Result<Response<OriginateRouteResponse>, Status> {
        let req = request.into_inner();
        if is_ipv6_prefix(&req.prefix) {
            let route = parse_originate_request_v6(req)?;
            tracing::info!(prefix = %route.nlri, "OriginateRoute (IPv6)");
            self.state.write().await.originate_route_v6(route);
        } else {
            let route = parse_originate_request(req)?;
            tracing::info!(prefix = %route.nlri, "OriginateRoute");
            self.state.write().await.originate_route(route);
        }
        Ok(Response::new(OriginateRouteResponse {}))
    }

    async fn originate_routes(
        &self,
        request: Request<OriginateRoutesRequest>,
    ) -> Result<Response<OriginateRoutesResponse>, Status> {
        let routes_req = request.into_inner().routes;
        let count = u32::try_from(routes_req.len()).unwrap_or(u32::MAX);
        // Split into v4 and v6 batches; process each with its own originate call.
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for req in routes_req {
            if is_ipv6_prefix(&req.prefix) {
                v6.push(parse_originate_request_v6(req)?);
            } else {
                v4.push(parse_originate_request(req)?);
            }
        }
        tracing::info!(count, "OriginateRoutes (batch)");
        let mut state = self.state.write().await;
        if !v4.is_empty() {
            state.originate_routes(v4);
        }
        if !v6.is_empty() {
            state.originate_routes_v6(v6);
        }
        Ok(Response::new(OriginateRoutesResponse { count }))
    }

    async fn withdraw_originated_route(
        &self,
        request: Request<WithdrawOriginatedRouteRequest>,
    ) -> Result<Response<WithdrawOriginatedRouteResponse>, Status> {
        let prefix = request.into_inner().prefix;
        tracing::info!(%prefix, "WithdrawOriginatedRoute");
        let mut state = self.state.write().await;
        if is_ipv6_prefix(&prefix) {
            let nlri = parse_nlri_v6(&prefix)?;
            state.withdraw_originated_route_v6(nlri);
        } else {
            let nlri: pathvector_types::Nlri<Ipv4Addr> = parse_nlri(&prefix)?;
            state.withdraw_originated_route(nlri);
        }
        Ok(Response::new(WithdrawOriginatedRouteResponse {}))
    }

    async fn withdraw_originated_routes(
        &self,
        request: Request<WithdrawOriginatedRoutesRequest>,
    ) -> Result<Response<WithdrawOriginatedRoutesResponse>, Status> {
        let prefixes = request.into_inner().prefixes;
        let count = u32::try_from(prefixes.len()).unwrap_or(u32::MAX);
        tracing::info!(count, "WithdrawOriginatedRoutes (batch)");
        let mut v4: Vec<pathvector_types::Nlri<Ipv4Addr>> = Vec::new();
        let mut v6: Vec<pathvector_types::Nlri<Ipv6Addr>> = Vec::new();
        for p in &prefixes {
            if is_ipv6_prefix(p) {
                v6.push(parse_nlri_v6(p)?);
            } else {
                v4.push(parse_nlri(p)?);
            }
        }
        let mut state = self.state.write().await;
        if !v4.is_empty() {
            state.withdraw_originated_routes(&v4);
        }
        if !v6.is_empty() {
            state.withdraw_originated_routes_v6(&v6);
        }
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
            .filter_map(|&nlri| {
                let route = snap.loc_rib.best(&nlri)?;
                Some(route_to_proto(local_peer, nlri, route))
            })
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
pub(crate) async fn serve(
    state: Arc<tokio::sync::RwLock<DaemonState>>,
    port: u16,
    cmd_tx: mpsc::Sender<DaemonCommand>,
) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!(%addr, "gRPC management API listening");

    let peer_svc = PeerServiceServer::new(PeerServiceImpl {
        state: Arc::clone(&state),
        cmd_tx,
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
    let reflection_svc = match tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()
    {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!(error = %e, "failed to build gRPC reflection service");
            return;
        }
    };

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
    use std::net::{Ipv4Addr, Ipv6Addr};
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
        route_v6_to_proto,
    };
    use tokio_stream::StreamExt as _;

    /// Returns a no-op DaemonCommand sender for tests that do not exercise
    /// AddPeer / RemovePeer.  The receiver is immediately dropped so any
    /// attempted sends are silently discarded.
    fn noop_cmd_tx() -> mpsc::Sender<crate::daemon::DaemonCommand> {
        let (tx, _rx) = mpsc::channel(1);
        tx
    }

    use crate::{
        DaemonState,
        config::{self, ExportDefault, ImportDefault},
        daemon::DaemonCommand,
    };
    use proto::{
        AddPeerRequest, AddPeerResponse, GetBestRouteRequest, GetPeerRequest,
        ListCandidatesRequest, ListOriginatedRoutesRequest, ListPeersRequest, ListRoutesRequest,
        OriginateRouteRequest, OriginateRoutesRequest, RemovePeerRequest, SetExportDefaultRequest,
        SetImportDefaultRequest, WatchPeersRequest, WatchRoutesRequest,
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
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            })
            .collect();
        DaemonState::new(
            local_as,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
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
        s.on_established(addr, PeerType::External, 65002, 90, &[], None);

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
        s.on_established(addr, PeerType::External, 65002, 90, &[], None);

        // Insert a route so the counts are non-zero.
        let n = nlri("10.0.0.0/8");
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::from_sequence(vec![Asn::new(65002)]))
            .peer_type(PeerType::External)
            .build();
        s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
        s.rib_insert_v4(peer("10.0.0.2"), route);
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

    // ── parse_nlri / parse_nlri_v6 ───────────────────────────────────────────

    #[test]
    fn test_parse_nlri_v6_invalid_returns_invalid_argument() {
        let err = super::parse_nlri_v6("not-a-cidr").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err2 = super::parse_nlri_v6("2001:db8::/999").unwrap_err();
        assert_eq!(err2.code(), tonic::Code::InvalidArgument);
    }

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
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
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
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
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
            .on_established(addr, PeerType::External, 65002, 90, &[], None);

        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
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
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };

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
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };

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
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };

        let err = svc
            .get_peer(Request::new(GetPeerRequest {
                address: "not-an-ip".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── PeerService::add_peer / remove_peer ──────────────────────────────────

    #[tokio::test]
    async fn test_add_peer_invalid_address() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
        let err = svc
            .add_peer(Request::new(AddPeerRequest {
                address: "not-an-ip".into(),
                remote_as: 65002,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_add_peer_rejects_as_zero() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
        let err = svc
            .add_peer(Request::new(AddPeerRequest {
                address: "10.0.0.2".into(),
                remote_as: 0,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("remote_as must not be 0"));
    }

    #[tokio::test]
    async fn test_add_peer_rejects_as_trans() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
        let err = svc
            .add_peer(Request::new(AddPeerRequest {
                address: "10.0.0.2".into(),
                remote_as: 23456,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("23456"));
    }

    #[tokio::test]
    async fn test_add_peer_sends_command_on_valid_request() {
        let state = arc_state(65001, &[]);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(4);
        let svc = PeerServiceImpl { state, cmd_tx };
        let resp = svc
            .add_peer(Request::new(AddPeerRequest {
                address: "10.0.0.2".into(),
                remote_as: 65002,
                port: 0,
                ..Default::default()
            }))
            .await
            .expect("add_peer must succeed for valid args");
        assert_eq!(resp.into_inner(), AddPeerResponse {});

        let cmd = cmd_rx.try_recv().expect("command must have been sent");
        let DaemonCommand::AddPeer(cfg) = cmd else {
            panic!("expected AddPeer command")
        };
        assert_eq!(
            cfg.address,
            "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(cfg.remote_as, 65002);
        assert_eq!(cfg.port, 179, "port 0 must default to 179");
    }

    #[tokio::test]
    async fn test_remove_peer_invalid_address() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
        let err = svc
            .remove_peer(Request::new(RemovePeerRequest {
                address: "bad".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_remove_peer_not_found() {
        let state = arc_state(65001, &[]);
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
        let err = svc
            .remove_peer(Request::new(RemovePeerRequest {
                address: "10.0.0.2".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_remove_peer_sends_command_when_peer_exists() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(4);
        let svc = PeerServiceImpl { state, cmd_tx };
        svc.remove_peer(Request::new(RemovePeerRequest {
            address: "10.0.0.2".into(),
        }))
        .await
        .expect("remove_peer must succeed for a configured peer");

        let cmd = cmd_rx.try_recv().expect("command must have been sent");
        let DaemonCommand::RemovePeer(ip) = cmd else {
            panic!("expected RemovePeer command")
        };
        assert_eq!(ip, addr);
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
            s.on_established(addr, PeerType::External, 65002, 90, &[], None);
            let n = nlri("10.0.0.0/8");
            let route = route_igp(n, PeerType::External);
            s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
            s.rib_insert_v4(peer("10.0.0.2"), route);
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
                page_size: 0,
                page_token: String::new(),
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
            s.on_established(a1, PeerType::External, 65002, 90, &[], None);
            s.on_established(a2, PeerType::External, 65003, 90, &[], None);

            let n1 = nlri("10.0.0.0/8");
            let r1 = route_igp(n1, PeerType::External);
            s.adj_ribs_in.get_mut(&a1).unwrap().insert(r1.clone());
            s.rib_insert_v4(peer("10.0.0.2"), r1);

            let n2 = nlri("192.168.0.0/24");
            let r2 = route_igp(n2, PeerType::External);
            s.adj_ribs_in.get_mut(&a2).unwrap().insert(r2.clone());
            s.rib_insert_v4(peer("10.0.0.3"), r2);
        }

        let svc = RibServiceImpl { state };
        let resp = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
                page_size: 0,
                page_token: String::new(),
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
            s.on_established(a1, PeerType::External, 65002, 90, &[], None);
            s.on_established(a2, PeerType::External, 65003, 90, &[], None);

            let n1 = nlri("10.0.0.0/8");
            let r1 = route_igp(n1, PeerType::External);
            s.adj_ribs_in.get_mut(&a1).unwrap().insert(r1.clone());
            s.rib_insert_v4(peer("10.0.0.2"), r1);

            let n2 = nlri("192.168.0.0/24");
            let r2 = route_igp(n2, PeerType::External);
            s.adj_ribs_in.get_mut(&a2).unwrap().insert(r2.clone());
            s.rib_insert_v4(peer("10.0.0.3"), r2);
        }

        let svc = RibServiceImpl { state };
        let resp = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: "10.0.0.2".into(),
                page_size: 0,
                page_token: String::new(),
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
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── RibService::list_routes (pagination) ─────────────────────────────────

    /// Build a RIB with three routes on two peers for pagination tests.
    async fn three_route_state() -> Arc<tokio::sync::RwLock<DaemonState>> {
        let a1: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let a2: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let state = arc_state(65001, &[(a1, 65002), (a2, 65003)]);
        let mut s = state.write().await;
        s.on_established(a1, PeerType::External, 65002, 90, &[], None);
        s.on_established(a2, PeerType::External, 65003, 90, &[], None);
        for (prefix, addr) in [
            ("10.0.0.0/8", a1),
            ("172.16.0.0/12", a2),
            ("192.168.0.0/24", a1),
        ] {
            let n = nlri(prefix);
            let r = route_igp(n, PeerType::External);
            s.adj_ribs_in.get_mut(&addr).unwrap().insert(r.clone());
            s.rib_insert_v4(peer(&addr.to_string()), r);
        }
        drop(s);
        state
    }

    #[tokio::test]
    async fn test_list_routes_pagination_first_page() {
        let svc = RibServiceImpl {
            state: three_route_state().await,
        };
        let resp = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
                page_size: 2,
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.routes.len(), 2, "first page should have 2 routes");
        assert!(
            !resp.next_page_token.is_empty(),
            "should have a next page token"
        );
        // sorted by prefix string; first two alphabetically
        assert_eq!(resp.routes[0].prefix, "10.0.0.0/8");
        assert_eq!(resp.routes[1].prefix, "172.16.0.0/12");
    }

    #[tokio::test]
    async fn test_list_routes_pagination_second_page_is_last() {
        let svc = RibServiceImpl {
            state: three_route_state().await,
        };
        // Get the cursor from the first page.
        let first = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
                page_size: 2,
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let cursor = first.next_page_token.clone();

        let svc2 = RibServiceImpl {
            state: three_route_state().await,
        };
        let resp = svc2
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
                page_size: 2,
                page_token: cursor,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.routes.len(), 1, "second page should have 1 route");
        assert!(resp.next_page_token.is_empty(), "no more pages");
        assert_eq!(resp.routes[0].prefix, "192.168.0.0/24");
    }

    #[tokio::test]
    async fn test_list_routes_pagination_page_size_zero_returns_all() {
        let svc = RibServiceImpl {
            state: three_route_state().await,
        };
        let resp = svc
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.routes.len(), 3, "page_size=0 should return all routes");
        assert!(
            resp.next_page_token.is_empty(),
            "no pagination token when all returned"
        );
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
            s.on_established(addr, PeerType::External, 65002, 90, &[], None);
            let n = nlri("10.0.0.0/8");
            let route = route_igp(n, PeerType::External);
            s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
            s.rib_insert_v4(peer("10.0.0.2"), route);
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

    // ── PolicyService with established peer + routes (exchange scenario) ────────
    //
    // All previous policy tests use empty state (no established peers, no routes)
    // so propagate_to_all_peers is never exercised.  These tests mirror the
    // scripts/exchange.sh phase 3 scenario exactly.

    #[tokio::test]
    async fn test_set_import_default_reject_with_established_peer_and_routes() {
        use pathvector_session::message::{PathAttribute, UpdateMessage};
        use pathvector_types::{AsPath, Asn, Nlri};

        let peer_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let state = arc_state(65002, &[(peer_ip, 65001)]);

        // Simulate BGP session reaching Established (GoBGP peer).
        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65001, 90, &[], None);
        }

        // Simulate GoBGP sending 3 routes (like exchange script phase 1).
        let routes: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
        for prefix in routes {
            let nlri: Nlri<Ipv4Addr> = prefix.parse().unwrap();
            let mut s = state.write().await;
            s.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(pathvector_types::Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                        PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                    ],
                    announced: vec![nlri],
                },
            );
        }

        // Verify routes are in loc_rib before the policy change.
        {
            let s = state.read().await;
            assert_eq!(s.rib.loc_rib.len(), 3, "3 GoBGP routes must be in loc_rib");
        }

        // Phase 3: flip to reject-import — mirrors `pv policy set-import 127.0.0.1 reject`.
        let svc = PolicyServiceImpl {
            state: Arc::clone(&state),
        };
        svc.set_import_default(Request::new(SetImportDefaultRequest {
            peer_address: "127.0.0.1".into(),
            action: proto::PolicyAction::Reject as i32,
        }))
        .await
        .expect("set_import_default reject must succeed with populated rib");

        // All 3 routes should now be gone from loc_rib.
        {
            let s = state.read().await;
            assert_eq!(
                s.rib.loc_rib.len(),
                0,
                "loc_rib must be empty after reject-import policy"
            );
        }

        // Restore: flip back to accept-import.
        svc.set_import_default(Request::new(SetImportDefaultRequest {
            peer_address: "127.0.0.1".into(),
            action: proto::PolicyAction::Accept as i32,
        }))
        .await
        .expect("set_import_default accept must succeed");
    }

    #[tokio::test]
    async fn test_set_export_default_reject_with_established_peer_and_routes() {
        use pathvector_session::message::{PathAttribute, UpdateMessage};
        use pathvector_types::{AsPath, Asn, Nlri};

        let peer_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let state = arc_state(65002, &[(peer_ip, 65001)]);

        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65001, 90, &[], None);
        }

        // Inject a route into loc_rib via origination (simulates phase 2).
        {
            let mut s = state.write().await;
            s.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(pathvector_types::Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                        PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                    ],
                    announced: vec!["10.0.0.0/8".parse::<Nlri<Ipv4Addr>>().unwrap()],
                },
            );
        }

        let svc = PolicyServiceImpl {
            state: Arc::clone(&state),
        };
        svc.set_export_default(Request::new(SetExportDefaultRequest {
            peer_address: "127.0.0.1".into(),
            action: proto::PolicyAction::Reject as i32,
        }))
        .await
        .expect("set_export_default reject must succeed with populated rib");
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
        let rare = route.rare_or_default();
        assert!(!rare.communities.is_empty());
        assert!(!rare.large_communities.is_empty());
        assert!(!rare.extended_communities.is_empty());
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

    // ── parse_originate_request_v6 ────────────────────────────────────────────

    fn minimal_originate_req_v6() -> OriginateRouteRequest {
        OriginateRouteRequest {
            prefix: "2001:db8::/32".to_owned(),
            next_hop: "::".to_owned(),
            origin: proto::Origin::Igp as i32,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        }
    }

    #[test]
    fn test_parse_originate_request_v6_valid() {
        use super::parse_originate_request_v6;
        let route = parse_originate_request_v6(minimal_originate_req_v6()).unwrap();
        assert_eq!(route.nlri.to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_parse_originate_request_v6_invalid_prefix() {
        use super::parse_originate_request_v6;
        let mut req = minimal_originate_req_v6();
        req.prefix = "not-cidr".to_owned();
        let err = parse_originate_request_v6(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_parse_originate_request_v6_with_communities() {
        use super::parse_originate_request_v6;
        let mut req = minimal_originate_req_v6();
        req.communities = vec![(65000_u32 << 16) | 1];
        req.large_communities = vec![proto::LargeCommunity {
            global_admin: 65000,
            local_data1: 1,
            local_data2: 2,
        }];
        req.extended_communities = vec![vec![0u8; 8]];
        let route = parse_originate_request_v6(req).unwrap();
        let rare = route.rare_or_default();
        assert!(!rare.communities.is_empty());
        assert!(!rare.large_communities.is_empty());
        assert!(!rare.extended_communities.is_empty());
    }

    #[test]
    fn test_parse_originate_request_v6_with_local_pref_and_med() {
        use super::parse_originate_request_v6;
        let mut req = minimal_originate_req_v6();
        req.local_pref = Some(100);
        req.med = Some(50);
        let route = parse_originate_request_v6(req).unwrap();
        assert!(route.local_pref.is_some());
        assert!(route.med.is_some());
    }

    #[test]
    fn test_parse_originate_request_v6_invalid_ext_community_length() {
        use super::parse_originate_request_v6;
        let mut req = minimal_originate_req_v6();
        req.extended_communities = vec![vec![0x00; 5]];
        let err = parse_originate_request_v6(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_parse_originate_request_v6_egp_origin() {
        use super::parse_originate_request_v6;
        let mut req = minimal_originate_req_v6();
        req.origin = proto::Origin::Egp as i32;
        let route = parse_originate_request_v6(req).unwrap();
        assert_eq!(route.origin, pathvector_types::Origin::Egp);
    }

    #[test]
    fn test_parse_originate_request_v6_incomplete_origin() {
        use super::parse_originate_request_v6;
        let mut req = minimal_originate_req_v6();
        req.origin = proto::Origin::Incomplete as i32;
        let route = parse_originate_request_v6(req).unwrap();
        assert_eq!(route.origin, pathvector_types::Origin::Incomplete);
    }

    // ── list_routes: peer-filter mismatch (v6 None branch) ───────────────────

    #[tokio::test]
    async fn test_list_routes_v6_peer_filter_excludes_unmatched_peer() {
        // Insert a v6 route from peer 10.0.0.2, but filter on 10.0.0.3.
        // The v6 filter_map must take the None branch (line 518 in original).
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        {
            let mut s = state.write().await;
            s.on_established(addr, PeerType::External, 65002, 90, &[], None);
            let n = nlri6("2001:db8::/32");
            s.rib_insert_v6(PeerId::from(addr), route_v6_igp(n, PeerType::External));
        }
        let svc = RibServiceImpl { state };
        let resp = svc
            .list_routes(Request::new(proto::ListRoutesRequest {
                peer_address: "10.0.0.3".into(),
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap();
        assert!(
            resp.into_inner().routes.is_empty(),
            "mismatched peer filter must exclude v6 routes"
        );
    }

    // ── watch_routes: peer-filter mismatch (None branches) ───────────────────

    #[tokio::test]
    async fn test_watch_routes_peer_filter_excludes_unmatched_v4_and_v6() {
        // Insert routes from peer 10.0.0.2 (v4 + v6), filter on 10.0.0.3.
        // Both filter_map None branches (v4 line 558, v6 line 570) must be taken.
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let mut s = make_state(65001, &[(addr, 65002)]);
        s.on_established(addr, PeerType::External, 65002, 90, &[], None);
        let n4 = nlri("192.0.2.0/24");
        s.rib_insert_v4(peer("10.0.0.2"), route_igp(n4, PeerType::External));
        let n6 = nlri6("2001:db8::/32");
        s.rib_insert_v6(PeerId::from(addr), route_v6_igp(n6, PeerType::External));
        let state = Arc::new(RwLock::new(s));

        let svc = RibServiceImpl { state };
        let resp = svc
            .watch_routes(Request::new(WatchRoutesRequest {
                peer_address: "10.0.0.3".into(),
            }))
            .await
            .unwrap();
        drop(svc);
        let mut stream = resp.into_inner();

        // Only the EndInitial marker must arrive — no Current events for any route.
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(
            first.r#type,
            proto::RouteEventType::EndInitial as i32,
            "mismatched peer filter must suppress all current events"
        );
    }

    // ── route_v6_to_proto ─────────────────────────────────────────────────────

    fn nlri6(s: &str) -> pathvector_types::Nlri<std::net::Ipv6Addr> {
        s.parse().unwrap()
    }

    fn peer6(ip: &str) -> PeerId {
        PeerId::from(ip.parse::<Ipv4Addr>().unwrap())
    }

    fn route_v6_igp(
        n: pathvector_types::Nlri<std::net::Ipv6Addr>,
        pt: PeerType,
    ) -> pathvector_rib::Route<std::net::Ipv6Addr> {
        use pathvector_types::NextHop;
        RouteBuilder::new(n, Origin::Igp, AsPath::from_sequence(vec![Asn::new(65002)]))
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .peer_type(pt)
            .build()
    }

    #[test]
    fn test_route_v6_to_proto_basic_fields() {
        let n = nlri6("2001:db8::/32");
        let route = route_v6_igp(n, PeerType::External);
        let r = route_v6_to_proto(peer6("10.0.0.2"), n, &route);
        assert_eq!(r.prefix, "2001:db8::/32");
        assert_eq!(r.peer_address, "10.0.0.2");
        assert_eq!(r.next_hop, "2001:db8::1");
        assert_eq!(r.origin, proto_origin(pathvector_types::Origin::Igp));
    }

    #[test]
    fn test_route_v6_to_proto_v4_next_hop() {
        use pathvector_types::NextHop;
        let n = nlri6("2001:db8::/32");
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .peer_type(PeerType::External)
            .build();
        let r = route_v6_to_proto(peer6("10.0.0.2"), n, &route);
        assert_eq!(r.next_hop, "10.0.0.1");
    }

    #[test]
    fn test_route_v6_to_proto_v6_with_link_local_next_hop() {
        use pathvector_types::NextHop;
        let n = nlri6("2001:db8::/32");
        let global: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6WithLinkLocal { global, link_local })
            .peer_type(PeerType::External)
            .build();
        let r = route_v6_to_proto(peer6("10.0.0.2"), n, &route);
        assert_eq!(r.next_hop, "2001:db8::1");
    }

    #[test]
    fn test_route_v6_to_proto_with_aggregator() {
        use pathvector_types::{Aggregator, Asn};
        let n = nlri6("2001:db8::/32");
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(10, 0, 0, 1)))
            .peer_type(PeerType::External)
            .build();
        let r = route_v6_to_proto(peer6("10.0.0.2"), n, &route);
        let agg = r.aggregator.expect("aggregator must be set");
        assert_eq!(agg.asn, 65001);
        assert_eq!(agg.address, "10.0.0.1");
    }

    #[test]
    fn test_route_v6_to_proto_with_communities() {
        use pathvector_types::{Community, ExtendedCommunity, LargeCommunity as TypesLC};
        let n = nlri6("2001:db8::/32");
        let route = RouteBuilder::new(n, Origin::Igp, AsPath::new())
            .community(Community::from(0x0001_0001u32))
            .large_community(TypesLC {
                global_administrator: 1,
                local_data_1: 2,
                local_data_2: 3,
            })
            .extended_community(ExtendedCommunity::from_bytes([0u8; 8]))
            .peer_type(PeerType::External)
            .build();
        let r = route_v6_to_proto(peer6("10.0.0.2"), n, &route);
        assert_eq!(r.communities.len(), 1);
        assert_eq!(r.large_communities.len(), 1);
        assert_eq!(r.extended_communities.len(), 1);
    }

    // ── RibService::get_best_route (IPv6) ─────────────────────────────────────

    #[tokio::test]
    async fn test_get_best_route_v6_found() {
        let state = arc_state(65001, &[]);
        {
            let mut s = state.write().await;
            let n = nlri6("2001:db8::/32");
            s.rib_insert_v6(
                PeerId::from(Ipv4Addr::new(10, 0, 0, 2)),
                route_v6_igp(n, PeerType::External),
            );
        }
        let svc = RibServiceImpl { state };
        let resp = svc
            .get_best_route(Request::new(GetBestRouteRequest {
                prefix: "2001:db8::/32".into(),
            }))
            .await
            .unwrap();
        let rr = resp.into_inner();
        assert!(rr.found);
        let r = rr.route.unwrap();
        assert_eq!(r.prefix, "2001:db8::/32");
    }

    #[tokio::test]
    async fn test_get_best_route_v6_not_found() {
        let state = arc_state(65001, &[]);
        let svc = RibServiceImpl { state };
        let resp = svc
            .get_best_route(Request::new(GetBestRouteRequest {
                prefix: "2001:db8::/32".into(),
            }))
            .await
            .unwrap();
        let rr = resp.into_inner();
        assert!(!rr.found);
    }

    // ── RibService::list_routes (IPv6) ────────────────────────────────────────

    #[tokio::test]
    async fn test_list_routes_includes_v6_routes() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        {
            let mut s = state.write().await;
            s.on_established(addr, PeerType::External, 65002, 90, &[], None);
            let n = nlri6("2001:db8::/32");
            s.rib_insert_v6(PeerId::from(addr), route_v6_igp(n, PeerType::External));
        }
        let svc = RibServiceImpl { state };
        let resp = svc
            .list_routes(Request::new(proto::ListRoutesRequest {
                peer_address: String::new(),
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap();
        let routes = resp.into_inner().routes;
        assert!(
            routes.iter().any(|r| r.prefix == "2001:db8::/32"),
            "IPv6 route must appear in list_routes"
        );
    }

    // ── RibService::watch_routes (IPv6) ───────────────────────────────────────

    #[tokio::test]
    async fn test_watch_routes_includes_v6_current_events() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        {
            let mut s = state.write().await;
            s.on_established(addr, PeerType::External, 65002, 90, &[], None);
            let n = nlri6("2001:db8::/32");
            s.rib_insert_v6(PeerId::from(addr), route_v6_igp(n, PeerType::External));
        }
        let svc = RibServiceImpl { state };
        let resp = svc
            .watch_routes(Request::new(WatchRoutesRequest {
                peer_address: String::new(),
            }))
            .await
            .unwrap();
        drop(svc);
        let mut stream = resp.into_inner();

        let current = stream.next().await.unwrap().unwrap();
        assert_eq!(current.r#type, proto::RouteEventType::Current as i32);
        let r = current.route.unwrap();
        assert_eq!(r.prefix, "2001:db8::/32");
    }

    // ── OriginationService: IPv6 dispatch ─────────────────────────────────────

    #[tokio::test]
    async fn test_originate_route_v6_inserts_into_loc_rib_v6() {
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl {
            state: Arc::clone(&state),
        };

        svc.originate_route(Request::new(minimal_originate_req_v6()))
            .await
            .expect("originate_route v6");

        let s = state.read().await;
        let n: pathvector_types::Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        assert!(
            s.rib.loc_rib_v6.best(&n).is_some(),
            "v6 route must be in loc_rib_v6"
        );
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
        assert!(s.rib.originated_routes.contains(&nlri));
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
        assert!(!s.rib.originated_routes.contains(&nlri));
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
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
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
        let svc = PeerServiceImpl {
            state,
            cmd_tx: noop_cmd_tx(),
        };
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
    async fn test_watch_peers_peer_none_broadcast_emits_changed_with_state() {
        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);
        let svc = PeerServiceImpl {
            state: Arc::clone(&state),
            cmd_tx: noop_cmd_tx(),
        };
        let resp = svc
            .watch_peers(Request::new(WatchPeersRequest {}))
            .await
            .expect("watch_peers");
        let mut stream = resp.into_inner();

        // Drain the snapshot (Current + EndInitial).
        while let Some(Ok(ev)) = stream.next().await {
            if ev.r#type == proto::PeerEventType::EndInitial as i32 {
                break;
            }
        }

        // Simulate on_terminated / on_established broadcasting peer: None.
        let _ = state.read().await.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None,
        });

        // The stream should enrich the signal and emit one Changed event with
        // the current peer state (Idle, since peer_types has no entry).
        let ev = stream.next().await.unwrap().unwrap();
        assert_eq!(ev.r#type, proto::PeerEventType::Changed as i32);
        let ps = ev
            .peer
            .expect("peer payload must be present after enrichment");
        assert_eq!(ps.address, "10.0.0.2");
        assert_eq!(ps.remote_as, 65002);
        assert_eq!(ps.session_state, proto::SessionState::Idle as i32);

        // Close the sender so the stream terminates.
        drop(state);
        drop(svc);
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
        s.on_established(
            addr,
            pathvector_types::PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        let n = nlri("192.0.2.0/24");
        s.rib_insert_v4(
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

    // ── Event emission: on_route_update ───────────────────────────────────────

    /// on_route_update must emit an Announced RouteEvent for each accepted
    /// prefix so the dashboard's watch_routes stream reflects peer-received
    /// routes without requiring a full reconnect/snapshot.
    #[tokio::test]
    async fn test_on_route_update_emits_announced_route_events() {
        use pathvector_session::message::{PathAttribute, UpdateMessage};
        use pathvector_types::{AsPath, Asn};

        let peer_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let state = arc_state(65002, &[(peer_ip, 65001)]);

        let mut route_rx = state.read().await.route_tx.subscribe();

        let mut s = state.write().await;
        s.on_established(peer_ip, PeerType::External, 65001, 90, &[], None);

        let announced = vec![nlri("10.0.0.0/8"), nlri("172.16.0.0/12")];
        s.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(pathvector_types::Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                    PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                ],
                announced: announced.clone(),
            },
        );
        drop(s);

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for _ in 0..announced.len() {
            let ev = route_rx
                .try_recv()
                .expect("RouteEvent must be emitted for each announced prefix");
            assert_eq!(
                ev.r#type,
                proto::RouteEventType::Announced as i32,
                "event type must be Announced"
            );
            let route = ev.route.expect("Announced event must carry route payload");
            seen.insert(route.prefix);
        }
        assert!(seen.contains("10.0.0.0/8"), "10/8 RouteEvent missing");
        assert!(
            seen.contains("172.16.0.0/12"),
            "172.16/12 RouteEvent missing"
        );
    }

    /// on_route_update must emit a Withdrawn RouteEvent when a peer withdraws
    /// a prefix that was previously accepted into the Loc-RIB.
    #[tokio::test]
    async fn test_on_route_update_emits_withdrawn_route_event() {
        use pathvector_session::message::{PathAttribute, UpdateMessage};
        use pathvector_types::{AsPath, Asn};

        let peer_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let state = arc_state(65002, &[(peer_ip, 65001)]);

        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65001, 90, &[], None);
            s.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(pathvector_types::Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                        PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                    ],
                    announced: vec![nlri("10.0.0.0/8")],
                },
            );
        } // write lock released before subscribe

        // Subscribe after the announce so the channel only sees the withdraw.
        // No tasks are running between the drop above and here, so no events
        // can be lost.
        let mut route_rx = state.read().await.route_tx.subscribe();

        {
            let mut s = state.write().await;
            s.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![nlri("10.0.0.0/8")],
                    attributes: vec![],
                    announced: vec![],
                },
            );
        }

        let ev = route_rx
            .try_recv()
            .expect("Withdrawn RouteEvent must be emitted");
        assert_eq!(ev.r#type, proto::RouteEventType::Withdrawn as i32);
        assert_eq!(
            ev.withdrawn_prefix.as_deref(),
            Some("10.0.0.0/8"),
            "withdrawn_prefix must name the removed NLRI"
        );
    }

    /// on_route_update must emit a PeerEvent::Changed after processing so the
    /// dashboard's RCV counter (and ADV from propagation) refreshes without
    /// waiting for a session reconnect.
    #[tokio::test]
    async fn test_on_route_update_emits_peer_changed_event() {
        use pathvector_session::message::{PathAttribute, UpdateMessage};
        use pathvector_types::{AsPath, Asn};

        let peer_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let state = arc_state(65002, &[(peer_ip, 65001)]);

        let mut peer_rx = state.read().await.peer_tx.subscribe();

        let mut s = state.write().await;
        s.on_established(peer_ip, PeerType::External, 65001, 90, &[], None);

        // Drain the PeerEvent fired by on_established.
        drop(s);
        while peer_rx.try_recv().is_ok() {}
        let mut s = state.write().await;

        s.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(pathvector_types::Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                    PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        drop(s);

        // At least one PeerEvent::Changed must arrive so the RCV counter
        // refreshes on the dashboard.
        let ev = peer_rx
            .try_recv()
            .expect("PeerEvent::Changed must be emitted after on_route_update");
        assert_eq!(ev.r#type, proto::PeerEventType::Changed as i32);
    }

    /// set_import_default must emit RouteEvents for all affected NLRIs so the
    /// dashboard reflects policy-driven adds and removes without a reconnect.
    #[tokio::test]
    async fn test_set_import_default_emits_route_events() {
        use pathvector_session::message::{PathAttribute, UpdateMessage};
        use pathvector_types::{AsPath, Asn};

        let peer_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let state = arc_state(65002, &[(peer_ip, 65001)]);

        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65001, 90, &[], None);
            s.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(pathvector_types::Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                        PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                    ],
                    announced: vec![nlri("192.168.0.0/16")],
                },
            );
        }

        // Subscribe after the initial announce so we only see the policy events.
        let mut route_rx = state.read().await.route_tx.subscribe();

        let svc = PolicyServiceImpl {
            state: Arc::clone(&state),
        };

        // Flip to reject — 192.168/16 should be withdrawn from the dashboard.
        svc.set_import_default(Request::new(SetImportDefaultRequest {
            peer_address: peer_ip.to_string(),
            action: proto::PolicyAction::Reject as i32,
        }))
        .await
        .expect("set_import_default reject");

        let ev = route_rx
            .try_recv()
            .expect("Withdrawn RouteEvent must be emitted on reject-import");
        assert_eq!(ev.r#type, proto::RouteEventType::Withdrawn as i32);
        assert_eq!(ev.withdrawn_prefix.as_deref(), Some("192.168.0.0/16"));

        // Flip back to accept — 192.168/16 should reappear on the dashboard.
        svc.set_import_default(Request::new(SetImportDefaultRequest {
            peer_address: peer_ip.to_string(),
            action: proto::PolicyAction::Accept as i32,
        }))
        .await
        .expect("set_import_default accept");

        let ev = route_rx
            .try_recv()
            .expect("Announced RouteEvent must be emitted on accept-import");
        assert_eq!(ev.r#type, proto::RouteEventType::Announced as i32);
        let route = ev.route.expect("Announced event must carry route payload");
        assert_eq!(route.prefix, "192.168.0.0/16");
    }

    // ── In-process integration test: real tonic server + PathvectorClient ─────
    //
    // Starts a real tonic gRPC server on a random port and calls it via
    // PathvectorClient over an actual H2C connection to catch routing or
    // transport-level bugs that direct handler-call tests cannot detect.

    async fn start_grpc_server_for_integration(
        state: Arc<tokio::sync::RwLock<DaemonState>>,
    ) -> std::net::SocketAddr {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let policy_svc =
            proto::policy_service_server::PolicyServiceServer::new(PolicyServiceImpl {
                state: Arc::clone(&state),
            });
        let peer_svc = proto::peer_service_server::PeerServiceServer::new(PeerServiceImpl {
            state: Arc::clone(&state),
            cmd_tx: noop_cmd_tx(),
        });
        let origination_svc = proto::origination_service_server::OriginationServiceServer::new(
            OriginationServiceImpl {
                state: Arc::clone(&state),
            },
        );

        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(peer_svc)
                .add_service(policy_svc)
                .add_service(origination_svc)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        addr
    }

    /// on_terminated must emit Withdrawn RouteEvents for every NLRI whose best
    /// path was removed when the peer disconnected. Without this the dashboard
    /// shows stale routes after a session drops.
    #[tokio::test]
    async fn test_on_terminated_emits_withdrawn_route_events() {
        use pathvector_session::message::{PathAttribute, UpdateMessage};
        use pathvector_types::{AsPath, Asn};

        let peer_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let state = arc_state(65002, &[(peer_ip, 65001)]);

        // Establish and announce two routes, then drop the lock so subscribe
        // works without hitting the RwLock deadlock.
        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65001, 90, &[], None);
            s.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(pathvector_types::Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                        PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                    ],
                    announced: vec![nlri("10.0.0.0/8"), nlri("172.16.0.0/12")],
                },
            );
        }

        // Subscribe after the announce; the channel only sees the withdraw events.
        let mut route_rx = state.read().await.route_tx.subscribe();

        {
            let mut s = state.write().await;
            s.on_terminated(peer_ip);
        }

        let mut withdrawn: std::collections::HashSet<String> = std::collections::HashSet::new();
        while let Ok(ev) = route_rx.try_recv() {
            if ev.r#type == proto::RouteEventType::Withdrawn as i32
                && let Some(pfx) = ev.withdrawn_prefix
            {
                withdrawn.insert(pfx);
            }
        }
        assert!(
            withdrawn.contains("10.0.0.0/8"),
            "Withdrawn RouteEvent for 10/8 must be emitted on peer termination"
        );
        assert!(
            withdrawn.contains("172.16.0.0/12"),
            "Withdrawn RouteEvent for 172.16/12 must be emitted on peer termination"
        );
    }

    #[tokio::test]
    async fn test_policy_service_over_real_h2c_connection() {
        use pathvector_client::{DaemonClient, PathvectorClient};

        let peer_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let state = arc_state(65001, &[(peer_ip, 65002)]);
        let addr = start_grpc_server_for_integration(Arc::clone(&state)).await;

        let mut client = PathvectorClient::connect(format!("http://{addr}")).expect("connect");

        client
            .set_import_default(&peer_ip.to_string(), false)
            .await
            .expect("set_import_default reject via H2C failed");

        client
            .set_import_default(&peer_ip.to_string(), true)
            .await
            .expect("set_import_default accept via H2C failed");
    }

    // ── parse_originate_request — input validation ────────────────────────────

    #[test]
    fn test_parse_originate_request_rejects_unspecified_next_hop() {
        let req = OriginateRouteRequest {
            prefix: "10.0.0.0/8".into(),
            next_hop: "0.0.0.0".into(),
            origin: 0,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        };
        let err = super::parse_originate_request(req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── OriginationService::originate_route — upsert semantics ───────────────

    #[tokio::test]
    async fn test_originate_route_upsert_replaces_previous_route() {
        // RFC: "Idempotent: re-originating the same prefix replaces the previous route."
        // Verify that the second origination wins, including updated attributes.
        let state = arc_state(65001, &[]);
        let svc = OriginationServiceImpl {
            state: Arc::clone(&state),
        };

        // First origination: no community.
        svc.originate_route(Request::new(OriginateRouteRequest {
            prefix: "10.0.0.0/8".into(),
            next_hop: "10.0.0.1".into(),
            origin: 0,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        }))
        .await
        .unwrap();

        // Second origination: same prefix, adds a community.
        svc.originate_route(Request::new(OriginateRouteRequest {
            prefix: "10.0.0.0/8".into(),
            next_hop: "10.0.0.2".into(),
            origin: 0,
            communities: vec![Community::from_parts(65000, 100).as_u32()],
            large_communities: vec![],
            extended_communities: vec![],
            local_pref: None,
            med: None,
        }))
        .await
        .unwrap();

        // Only one route should be in the Loc-RIB, and it must be the second one.
        let svc_rib = super::RibServiceImpl {
            state: Arc::clone(&state),
        };
        let resp = svc_rib
            .list_routes(Request::new(ListRoutesRequest {
                peer_address: String::new(),
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.routes.len(), 1, "upsert must not duplicate the prefix");
        let route = &resp.routes[0];
        assert_eq!(route.next_hop, "10.0.0.2", "second origination must win");
        assert_eq!(
            route.communities,
            vec![Community::from_parts(65000, 100).as_u32()],
            "updated attributes must be present"
        );
    }

    // ── RibService::list_routes — pagination ──────────────────────────────────

    #[tokio::test]
    async fn test_list_routes_pagination_returns_all_routes_across_pages() {
        use pathvector_types::PeerType;

        let addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let state = arc_state(65001, &[(addr, 65002)]);

        // Insert 10 routes across distinct /24 prefixes.
        {
            let mut s = state.write().await;
            s.on_established(addr, PeerType::External, 65002, 90, &[], None);
            for i in 0..10u8 {
                let prefix: pathvector_types::Nlri<Ipv4Addr> =
                    format!("10.0.{i}.0/24").parse().unwrap();
                let route = RouteBuilder::new(
                    prefix,
                    Origin::Igp,
                    pathvector_types::AsPath::from_sequence(vec![Asn::new(65002)]),
                )
                .next_hop(pathvector_types::NextHop::V4("10.0.0.2".parse().unwrap()))
                .peer_type(PeerType::External)
                .build();
                s.adj_ribs_in.get_mut(&addr).unwrap().insert(route.clone());
                s.rib_insert_v4(peer("10.0.0.2"), route);
            }
        }

        let svc = RibServiceImpl { state };

        // Fetch 3 pages of 4, then a final page of 2.
        let mut all_prefixes = Vec::new();
        let mut token = String::new();
        loop {
            let resp = svc
                .list_routes(Request::new(ListRoutesRequest {
                    peer_address: String::new(),
                    page_size: 4,
                    page_token: token.clone(),
                }))
                .await
                .unwrap()
                .into_inner();
            for r in &resp.routes {
                all_prefixes.push(r.prefix.clone());
            }
            token = resp.next_page_token;
            if token.is_empty() {
                break;
            }
        }

        assert_eq!(
            all_prefixes.len(),
            10,
            "all 10 routes must be returned across pages"
        );
        // Each prefix must appear exactly once.
        all_prefixes.sort();
        all_prefixes.dedup();
        assert_eq!(all_prefixes.len(), 10, "no duplicates across pages");
    }
}
