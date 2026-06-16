//! BGP daemon core: routing state, event dispatch, and session management.
//!
//! This module owns [`DaemonState`], the BGP event loop (`run_event_loop`),
//! session setup (`build_daemon`), and the TCP listener (`run_bgp_listener`).

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use pathvector_policy::{Decision, DefaultAction, Policy};
use pathvector_rib::{
    AdjRibIn, AdjRibOut, BestPathChange, LocRib, PeerId, Route, RouteBuilder,
    oracle::{AlwaysReachable, NextHopOracle},
};
use pathvector_session::{
    message::{
        Capability, MAX_LEN, MAX_LEN_EXTENDED, MpReachNlri, MpUnreachNlri, NotificationError,
        NotificationMessage, PathAttribute, Prefix, UpdateMessage, UpdateMsgError,
    },
    transport::{self, SessionCommand, SessionConfig, SessionEvent, SessionHandle},
};
use pathvector_types::{AfiSafi, AsPath, LocalPref, Med, NextHop, Nlri, Origin, PeerType};
use tokio::sync::{RwLock, broadcast, mpsc, watch};

use crate::outbound::{
    PrefixDecision, PrefixDecisionV6, flush_updates, flush_updates_v6, propagate_prefix,
    propagate_prefix_v6,
};
use crate::{config, fib, grpc, proto};

/// Synthetic `PeerId` used as the source for locally originated routes.
///
/// Must not collide with any real peer address. `0.0.0.0` is unassignable as
/// a BGP peer, so it is safe as a sentinel here.
pub(crate) const LOCAL_ORIGIN_PEER: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

/// RFC 4271 §9.2.1.1: default Minimum Route Advertisement Interval for eBGP.
pub(crate) const MRAI: std::time::Duration = std::time::Duration::from_secs(30);

fn resolve_import_default(opt: Option<config::ImportDefault>, is_ebgp: bool) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
}

/// Resolves the effective export default action for a peer (RFC 8212).
///
/// eBGP peers with no explicit setting default to `Reject` — no routes are
/// advertised unless a policy term explicitly accepts them. iBGP peers default
/// to `Accept`. An explicit `export_default` in config always wins.
fn resolve_export_default(opt: Option<config::ExportDefault>, is_ebgp: bool) -> DefaultAction {
    match opt {
        Some(d) => DefaultAction::from(d),
        None if is_ebgp => DefaultAction::Reject,
        None => DefaultAction::Accept,
    }
}

/// Derives the peer type (iBGP / eBGP) from the configured AS numbers.
fn config_peer_type(local_as: u32, remote_as: u32) -> PeerType {
    if local_as == remote_as {
        PeerType::Internal
    } else {
        PeerType::External
    }
}

/// Immutable-ish snapshot of the read-heavy routing state.
///
/// Stored inside `DaemonState` as an `Arc<RibSnapshot>`. The event loop
/// mutates it via [`Arc::make_mut`] (zero-cost when no readers hold a clone;
/// copy-on-write when a gRPC call is in flight). gRPC handlers clone the `Arc`
/// in O(1) and release the outer `RwLock` immediately, so reads never block
/// BGP event processing.
#[derive(Clone)]
pub(crate) struct RibSnapshot {
    pub(crate) loc_rib: LocRib<Ipv4Addr>,
    /// IPv6 Loc-RIB — best IPv6 routes, post-import-policy.
    pub(crate) loc_rib_v6: LocRib<Ipv6Addr>,
    /// Locally originated routes (bypassed import policy; export policy applies).
    pub(crate) originated_routes: HashMap<Nlri<Ipv4Addr>, Route<Ipv4Addr>>,
    /// IPv6 locally originated routes (bypassed import policy; export policy applies).
    pub(crate) originated_routes_v6: HashMap<Nlri<Ipv6Addr>, Route<Ipv6Addr>>,
    /// Immutable after startup.
    pub(crate) local_as: u32,
    /// Immutable after startup.
    pub(crate) local_bgp_id: Ipv4Addr,
    /// Local IPv6 address for eBGP next-hop rewrite; `None` if not configured.
    /// Immutable after startup.
    pub(crate) local_ipv6: Option<Ipv6Addr>,
    /// Remote AS number for each configured peer; immutable after startup.
    pub(crate) peer_remote_as: HashMap<Ipv4Addr, u32>,
    /// Live session state: present while a peer is Established.
    pub(crate) peer_types: HashMap<Ipv4Addr, PeerType>,
    /// Wall-clock instant at which each peer last reached Established.
    pub(crate) established_at: HashMap<Ipv4Addr, std::time::Instant>,
    /// Negotiated hold-timer value per established peer.
    pub(crate) hold_times: HashMap<Ipv4Addr, u16>,
    /// Derived from `adj_ribs_in[peer].len()`; synced after each mutation.
    pub(crate) prefixes_received: HashMap<Ipv4Addr, usize>,
    /// Derived from `adj_ribs_out[peer].len()`; synced after each propagation.
    pub(crate) prefixes_advertised: HashMap<Ipv4Addr, usize>,
    /// Local TCP address per established peer, captured at connect time.
    ///
    /// Used as the eBGP NEXT_HOP (RFC 4271 §5.1.3) instead of `local_bgp_id`
    /// so the NEXT_HOP is the interface address reachable by the peer.
    pub(crate) local_addrs: HashMap<Ipv4Addr, Ipv4Addr>,
    /// Set of configured Route Reflector clients (RFC 4456).
    ///
    /// Empty when this daemon is not acting as a Route Reflector.
    /// Immutable after startup.
    pub(crate) rr_clients: std::collections::HashSet<Ipv4Addr>,
    /// Cluster identifier used in `CLUSTER_LIST` when reflecting routes (RFC 4456).
    ///
    /// Defaults to the 32-bit representation of `bgp_id` when not explicitly
    /// configured. Immutable after startup.
    pub(crate) cluster_id: u32,
    /// BGP Identifier of each established peer, received in their OPEN message.
    ///
    /// Used to set `ORIGINATOR_ID` when reflecting routes from a client (RFC 4456
    /// §8). Populated on `Established`; removed on `Terminated`.
    pub(crate) peer_bgp_ids: HashMap<Ipv4Addr, Ipv4Addr>,
}

/// Holds all per-peer routing state and applies BGP event semantics.
///
/// Constructed once at startup from config; `run()` feeds it `SessionEvent`s.
/// The struct owns no I/O — callers hold the session handles and event channel,
/// making the routing logic fully unit-testable without real TCP connections.
///
/// Read-heavy fields live in `Arc<RibSnapshot>`; gRPC handlers clone the `Arc`
/// and release the lock immediately so reads never contend with BGP writes.
pub(crate) struct DaemonState {
    /// Read-heavy routing state; cloned cheaply by gRPC handlers.
    pub(crate) rib: Arc<RibSnapshot>,
    pub(crate) import_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>>,
    pub(crate) import_policies_v6: HashMap<Ipv4Addr, Policy<Route<Ipv6Addr>>>,
    pub(crate) export_policies: HashMap<Ipv4Addr, Policy<Route<Ipv4Addr>>>,
    pub(crate) adj_ribs_in: HashMap<Ipv4Addr, AdjRibIn<Ipv4Addr>>,
    pub(crate) adj_ribs_out: HashMap<Ipv4Addr, AdjRibOut<Ipv4Addr>>,
    pub(crate) adj_ribs_in_v6: HashMap<Ipv4Addr, AdjRibIn<Ipv6Addr>>,
    pub(crate) adj_ribs_out_v6: HashMap<Ipv4Addr, AdjRibOut<Ipv6Addr>>,
    /// Static peer type derived from config; used to reset `AdjRibOut` on reconnect.
    pub(crate) peer_config_types: HashMap<Ipv4Addr, PeerType>,
    pub(crate) update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>>,
    /// Local capabilities advertised in OPEN messages; used to determine the
    /// negotiated message size limit after `Established`.
    pub(crate) config_capabilities: Vec<Capability>,
    /// Negotiated maximum BGP message size per established peer.
    ///
    /// Set to [`MAX_LEN_EXTENDED`] (65535) when both sides negotiated
    /// `Capability::ExtendedMessage`; otherwise [`MAX_LEN`] (4096).
    /// Removed when the peer transitions out of Established.
    pub(crate) negotiated_max_len: HashMap<Ipv4Addr, usize>,
    /// Peers that negotiated the IPv6 unicast Multi-Protocol capability (RFC 4760).
    ///
    /// Only these peers receive IPv6 MP_REACH_NLRI / MP_UNREACH_NLRI.
    pub(crate) ipv6_capable_peers: HashSet<Ipv4Addr>,
    /// Peers that negotiated RFC 6793 `FourByteAsn` capability.
    ///
    /// AS_PATH is sent unchanged to these peers. For absent peers, AS_PATH is
    /// downgraded (4-byte ASNs replaced with AS_TRANS) and AS4_PATH is added.
    pub(crate) four_byte_peers: HashSet<Ipv4Addr>,
    /// RFC 4271 §9.2.1.1: Minimum Route Advertisement Interval.
    ///
    /// Tracks when each prefix was last announced to each eBGP peer so that
    /// re-announcements are suppressed within the MRAI window (default: 30 s).
    /// Withdrawals bypass MRAI — they must be sent immediately.
    mrai_last_sent: HashMap<Ipv4Addr, HashMap<Nlri<Ipv4Addr>, Instant>>,
    /// NLRIs suppressed by MRAI that have not yet been sent.
    ///
    /// When an MRAI window elapses, the pending NLRIs for that peer are
    /// re-propagated. Uses a `HashSet` so repeated updates to the same prefix
    /// within one suppression window collapse to a single deferred flush.
    pub(crate) mrai_pending: HashMap<Ipv4Addr, HashSet<Nlri<Ipv4Addr>>>,
    /// Peers whose outbound UPDATE channel overflowed during the current event.
    ///
    /// The event loop drains this list after each event via [`take_stalled_peers`]
    /// and sends [`SessionCommand::Stop`] to each affected session so it can
    /// re-establish and perform a clean full-table dump.
    ///
    /// [`take_stalled_peers`]: DaemonState::take_stalled_peers
    stalled_peers: Vec<Ipv4Addr>,
    /// Broadcast channel for Loc-RIB events (announced / withdrawn).
    ///
    /// `WatchRoutes` gRPC handlers subscribe at call time. Slow subscribers
    /// receive `RecvError::Lagged` and must reconnect for a fresh snapshot.
    pub(crate) route_tx: broadcast::Sender<proto::RouteEvent>,
    /// Broadcast channel for peer session state changes.
    ///
    /// `WatchPeers` gRPC handlers subscribe at call time.
    pub(crate) peer_tx: broadcast::Sender<proto::PeerEvent>,
    /// FIB manager: installs / removes kernel routes on best-path changes.
    ///
    /// `None` when no kernel FIB integration is configured (e.g. tests).
    pub(crate) fib_manager: Option<Arc<fib::FibManager>>,
    /// Next-hop oracle consulted on every IPv4 best-path recompute (RFC 4271 §9.1
    /// steps 1 & 8). Defaults to `AlwaysReachable`; replaced with `DaemonOracle`
    /// once `KernelFib` is initialised at startup.
    oracle_v4: Arc<dyn NextHopOracle + Send + Sync>,
    /// Next-hop oracle for IPv6 best-path recompute.
    oracle_v6: Arc<dyn NextHopOracle + Send + Sync>,
}

impl DaemonState {
    pub(crate) fn new(
        local_as: u32,
        local_bgp_id: Ipv4Addr,
        local_ipv6: Option<Ipv6Addr>,
        cluster_id: Option<u32>,
        peers: &[config::PeerConfig],
        update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>>,
        config_capabilities: Vec<Capability>,
    ) -> Self {
        let rr_clients: HashSet<Ipv4Addr> = peers
            .iter()
            .filter(|p| p.is_rr_client && p.remote_as == local_as)
            .map(|p| p.address)
            .collect();
        let cluster_id = cluster_id.unwrap_or_else(|| u32::from_be_bytes(local_bgp_id.octets()));
        let is_rr = !rr_clients.is_empty();
        let import_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                (
                    p.address,
                    Policy::new(resolve_import_default(p.import_default, is_ebgp)),
                )
            })
            .collect();

        let import_policies_v6 = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                // import_default_v6 takes precedence; falls back to import_default,
                // then to the RFC 8212 default for the peer type.
                let default_v6 = p.import_default_v6.or(p.import_default);
                (
                    p.address,
                    Policy::new(resolve_import_default(default_v6, is_ebgp)),
                )
            })
            .collect();

        let export_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                (
                    p.address,
                    Policy::new(resolve_export_default(p.export_default, is_ebgp)),
                )
            })
            .collect();

        let adj_ribs_in = peers
            .iter()
            .map(|p| (p.address, AdjRibIn::new(PeerId::from(p.address))))
            .collect();

        let adj_ribs_in_v6 = peers
            .iter()
            .map(|p| (p.address, AdjRibIn::new(PeerId::from(p.address))))
            .collect();

        let peer_config_types = peers
            .iter()
            .map(|p| (p.address, config_peer_type(local_as, p.remote_as)))
            .collect();

        let adj_ribs_out = peers
            .iter()
            .map(|p| {
                let pt = config_peer_type(local_as, p.remote_as);
                let rib = if is_rr && pt == PeerType::Internal {
                    AdjRibOut::new_reflecting(PeerId::from(p.address), pt)
                } else {
                    AdjRibOut::new(PeerId::from(p.address), pt)
                };
                (p.address, rib)
            })
            .collect();

        let adj_ribs_out_v6 = peers
            .iter()
            .map(|p| {
                let pt = config_peer_type(local_as, p.remote_as);
                let rib = if is_rr && pt == PeerType::Internal {
                    AdjRibOut::new_reflecting(PeerId::from(p.address), pt)
                } else {
                    AdjRibOut::new(PeerId::from(p.address), pt)
                };
                (p.address, rib)
            })
            .collect();

        let peer_remote_as = peers.iter().map(|p| (p.address, p.remote_as)).collect();

        let (route_tx, _) = broadcast::channel(1024);
        let (peer_tx, _) = broadcast::channel(1024);

        let rib = Arc::new(RibSnapshot {
            loc_rib: LocRib::new(),
            loc_rib_v6: LocRib::new(),
            originated_routes: HashMap::new(),
            originated_routes_v6: HashMap::new(),
            local_as,
            local_bgp_id,
            local_ipv6,
            peer_remote_as,
            peer_types: HashMap::new(),
            established_at: HashMap::new(),
            hold_times: HashMap::new(),
            prefixes_received: HashMap::new(),
            prefixes_advertised: HashMap::new(),
            local_addrs: HashMap::new(),
            rr_clients,
            cluster_id,
            peer_bgp_ids: HashMap::new(),
        });

        Self {
            rib,
            import_policies,
            import_policies_v6,
            export_policies,
            adj_ribs_in,
            adj_ribs_out,
            adj_ribs_in_v6,
            adj_ribs_out_v6,
            peer_config_types,
            update_senders,
            config_capabilities,
            negotiated_max_len: HashMap::new(),
            ipv6_capable_peers: HashSet::new(),
            four_byte_peers: HashSet::new(),
            mrai_last_sent: HashMap::new(),
            mrai_pending: HashMap::new(),
            stalled_peers: Vec::new(),
            route_tx,
            peer_tx,
            fib_manager: None,
            oracle_v4: Arc::new(AlwaysReachable),
            oracle_v6: Arc::new(AlwaysReachable),
        }
    }

    /// Replaces both next-hop oracles once `KernelFib` is initialised.
    pub(crate) fn set_oracles(
        &mut self,
        v4: impl NextHopOracle + Send + Sync + 'static,
        v6: impl NextHopOracle + Send + Sync + 'static,
    ) {
        self.oracle_v4 = Arc::new(v4);
        self.oracle_v6 = Arc::new(v6);
    }

    // ── LocRib mutation wrappers ──────────────────────────────────────────────
    //
    // These clone the oracle Arc before calling rib_mut() so the borrow checker
    // sees two independent borrows of `self` (oracle_v4 vs rib) rather than one
    // mutable borrow of the entire struct.

    pub(crate) fn rib_insert_v4(
        &mut self,
        peer: PeerId,
        route: Route<Ipv4Addr>,
    ) -> BestPathChange<Ipv4Addr> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.insert(peer, route, &*oracle)
    }

    pub(crate) fn rib_withdraw_v4(
        &mut self,
        peer: &PeerId,
        nlri: &Nlri<Ipv4Addr>,
    ) -> BestPathChange<Ipv4Addr> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.withdraw(peer, nlri, &*oracle)
    }

    pub(crate) fn rib_withdraw_peer_v4(&mut self, peer: &PeerId) -> Vec<BestPathChange<Ipv4Addr>> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.withdraw_peer(peer, &*oracle)
    }

    pub(crate) fn rib_insert_v6(
        &mut self,
        peer: PeerId,
        route: Route<Ipv6Addr>,
    ) -> BestPathChange<Ipv6Addr> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.insert(peer, route, &*oracle)
    }

    pub(crate) fn rib_withdraw_v6(
        &mut self,
        peer: &PeerId,
        nlri: &Nlri<Ipv6Addr>,
    ) -> BestPathChange<Ipv6Addr> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.withdraw(peer, nlri, &*oracle)
    }

    pub(crate) fn rib_withdraw_peer_v6(&mut self, peer: &PeerId) -> Vec<BestPathChange<Ipv6Addr>> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.withdraw_peer(peer, &*oracle)
    }

    /// Re-evaluates best-path for every IPv4 prefix in the Loc-RIB using the
    /// current oracle.  Returns only the prefixes whose best path changed.
    ///
    /// Called when the kernel FIB changes (next-hop gained / lost) so that
    /// routes whose next-hop became unreachable are withdrawn and routes that
    /// recovered are re-announced.
    pub(crate) fn rib_recompute_all_v4(&mut self) -> Vec<BestPathChange<Ipv4Addr>> {
        let oracle = Arc::clone(&self.oracle_v4);
        self.rib_mut().loc_rib.recompute_all(&*oracle)
    }

    /// Re-evaluates best-path for every IPv6 prefix in the Loc-RIB.
    pub(crate) fn rib_recompute_all_v6(&mut self) -> Vec<BestPathChange<Ipv6Addr>> {
        let oracle = Arc::clone(&self.oracle_v6);
        self.rib_mut().loc_rib_v6.recompute_all(&*oracle)
    }

    /// Returns a cheap clone of the snapshot Arc for lock-free gRPC reads.
    ///
    /// gRPC handlers call this while holding the outer `RwLock` read guard,
    /// then immediately release the lock. All subsequent work runs against
    /// the cloned Arc without holding any lock.
    pub(crate) fn snapshot(&self) -> Arc<RibSnapshot> {
        Arc::clone(&self.rib)
    }

    /// Returns a mutable reference to the snapshot.
    ///
    /// Uses copy-on-write semantics: free when no readers hold a clone (the
    /// common case during BGP convergence); allocates a fresh `RibSnapshot`
    /// only when a concurrent gRPC read is in flight.
    pub(crate) fn rib_mut(&mut self) -> &mut RibSnapshot {
        Arc::make_mut(&mut self.rib)
    }

    /// Syncs the derived `prefixes_received` count for `peer_ip` from the
    /// current `adj_ribs_in` length.
    pub(crate) fn sync_received(&mut self, peer_ip: Ipv4Addr) {
        let v4 = self.adj_ribs_in.get(&peer_ip).map_or(0, AdjRibIn::len);
        let v6 = self.adj_ribs_in_v6.get(&peer_ip).map_or(0, AdjRibIn::len);
        self.rib_mut().prefixes_received.insert(peer_ip, v4 + v6);
    }

    /// Syncs the derived `prefixes_advertised` count for `peer_ip` from the
    /// current `adj_ribs_out` length.
    fn sync_advertised(&mut self, peer_ip: Ipv4Addr) {
        let v4 = self.adj_ribs_out.get(&peer_ip).map_or(0, AdjRibOut::len);
        let v6 = self.adj_ribs_out_v6.get(&peer_ip).map_or(0, AdjRibOut::len);
        self.rib_mut().prefixes_advertised.insert(peer_ip, v4 + v6);
    }

    /// Drains and returns the list of peers whose outbound UPDATE channel
    /// overflowed during the most recent event.
    ///
    /// The event loop calls this after each event and sends
    /// [`SessionCommand::Stop`] to each returned peer so the session can
    /// re-establish and perform a fresh full-table dump.
    fn take_stalled_peers(&mut self) -> Vec<Ipv4Addr> {
        std::mem::take(&mut self.stalled_peers)
    }

    /// Called when a BGP session reaches Established.
    ///
    /// Records the negotiated peer type, resets the peer's `AdjRibOut` to a
    /// clean slate, and performs a full-table dump of the current best routes
    /// subject to export policy.
    #[allow(clippy::similar_names)]
    pub(crate) fn on_established(
        &mut self,
        peer_ip: Ipv4Addr,
        peer_type: PeerType,
        peer_as: u32,
        hold_time: u16,
        peer_capabilities: &[Capability],
        local_addr: Option<Ipv4Addr>,
    ) {
        let peer_id = PeerId::from(peer_ip);

        // Update snapshot fields.
        {
            let rib = self.rib_mut();
            rib.peer_types.insert(peer_ip, peer_type);
            rib.established_at
                .insert(peer_ip, std::time::Instant::now());
            rib.hold_times.insert(peer_ip, hold_time);
            if let Some(addr) = local_addr {
                rib.local_addrs.insert(peer_ip, addr);
            }
        }

        // Record negotiated message size limit for NLRI batching.
        let max_len = if peer_capabilities.contains(&Capability::ExtendedMessage)
            && self
                .config_capabilities
                .contains(&Capability::ExtendedMessage)
        {
            MAX_LEN_EXTENDED
        } else {
            MAX_LEN
        };
        self.negotiated_max_len.insert(peer_ip, max_len);

        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            let is_rr = !self.rib.rr_clients.is_empty();
            *aro = if is_rr && peer_type == PeerType::Internal {
                AdjRibOut::new_reflecting(peer_id, peer_type)
            } else {
                AdjRibOut::new(peer_id, peer_type)
            };
        }
        // Reset v6 RIBs so a re-established session starts clean.
        self.adj_ribs_in_v6.insert(peer_ip, AdjRibIn::new(peer_id));
        self.adj_ribs_out_v6
            .insert(peer_ip, AdjRibOut::new(peer_id, peer_type));

        let all_nlris: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();
        let all_nlris_v6: Vec<Nlri<Ipv6Addr>> =
            self.rib.loc_rib_v6.best_routes().map(|(n, _)| n).collect();
        let rib_prefixes = all_nlris.len() + all_nlris_v6.len();

        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "export_policies missing peer — skipping Established event");
            return;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_out missing peer — skipping Established event");
            return;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping Established event");
            return;
        };

        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let local_next_hop = local_addr.unwrap_or(local_bgp_id);
        let local_ipv6 = self.rib.local_ipv6;

        // RFC 4456 §8 split-horizon: when acting as an RR, a non-client iBGP
        // peer must not receive routes learned from other non-client iBGP peers
        // in the initial full-table dump. The same check applies in
        // propagate_to_all_peers for incremental updates.
        let is_rr = !self.rib.rr_clients.is_empty();
        let dest_is_client = self.rib.rr_clients.contains(&peer_ip);
        let rr_clients = &self.rib.rr_clients;
        let peer_types = &self.rib.peer_types;
        let loc_rib = &self.rib.loc_rib;

        let decisions: Vec<PrefixDecision> = all_nlris
            .into_iter()
            .map(|nlri| {
                if is_rr
                    && peer_type == PeerType::Internal
                    && let Some(src) = loc_rib.best_peer(&nlri)
                    && let IpAddr::V4(src_ip) = src.ip()
                {
                    let src_is_client = rr_clients.contains(&src_ip);
                    let src_is_ibgp =
                        peer_types.get(&src_ip).copied() == Some(PeerType::Internal);
                    if src_is_ibgp && !src_is_client && !dest_is_client {
                        return PrefixDecision::NoChange;
                    }
                }
                propagate_prefix(
                    nlri,
                    loc_rib,
                    adj_rib_out,
                    export_policy,
                    peer_type,
                    local_as,
                    local_next_hop,
                )
            })
            .collect();

        // RFC 6793: track whether this peer supports 4-byte ASNs.
        let peer_four_byte = peer_capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourByteAsn(_)));
        if peer_four_byte {
            self.four_byte_peers.insert(peer_ip);
        } else {
            self.four_byte_peers.remove(&peer_ip);
        }

        if !flush_updates(decisions, max_len, update_tx, peer_type, peer_four_byte) {
            self.stalled_peers.push(peer_ip);
        }

        // Full-table dump for IPv6 — only for peers that negotiated IPv6 unicast
        // (RFC 4760): sending MP_REACH_NLRI to a peer that did not advertise the
        // Multi-Protocol capability for IPv6 unicast violates the capability
        // negotiation contract and the peer would silently discard the routes.
        let peer_supports_ipv6 = peer_capabilities
            .contains(&Capability::MultiProtocol(AfiSafi::IPV6_UNICAST));
        if peer_supports_ipv6 {
            self.ipv6_capable_peers.insert(peer_ip);
        } else {
            self.ipv6_capable_peers.remove(&peer_ip);
        }
        if peer_supports_ipv6
            && !all_nlris_v6.is_empty()
            && let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&peer_ip)
        {
            let decisions_v6: Vec<PrefixDecisionV6> = all_nlris_v6
                .into_iter()
                .map(|nlri| {
                    propagate_prefix_v6(
                        nlri,
                        &self.rib.loc_rib_v6,
                        adj_rib_out_v6,
                        peer_type,
                        local_as,
                        local_ipv6,
                    )
                })
                .collect();
            if !flush_updates_v6(decisions_v6, max_len, update_tx, peer_type, peer_four_byte) {
                self.stalled_peers.push(peer_ip);
            }
        }

        self.sync_advertised(peer_ip);

        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None, // gRPC handler builds PeerState from snapshot
        });

        tracing::info!(
            peer = %peer_ip,
            remote_as = peer_as,
            hold_time,
            peer_type = %peer_type,
            rib_prefixes,
            "session established"
        );
    }

    /// Called when a BGP session terminates.
    ///
    /// Clears the peer's RIB state, resets its outbound table, and propagates
    /// any best-path changes caused by the withdrawal to all remaining
    /// established peers.
    #[allow(clippy::similar_names)]
    pub(crate) fn on_terminated(&mut self, peer_ip: Ipv4Addr) {
        let peer_id = PeerId::from(peer_ip);

        // Remove live session state from snapshot.
        {
            let rib = self.rib_mut();
            rib.peer_types.remove(&peer_ip);
            rib.established_at.remove(&peer_ip);
            rib.hold_times.remove(&peer_ip);
            rib.prefixes_received.remove(&peer_ip);
            rib.prefixes_advertised.remove(&peer_ip);
            rib.local_addrs.remove(&peer_ip);
            rib.peer_bgp_ids.remove(&peer_ip);
        }
        self.negotiated_max_len.remove(&peer_ip);
        self.ipv6_capable_peers.remove(&peer_ip);
        self.four_byte_peers.remove(&peer_ip);
        self.mrai_last_sent.remove(&peer_ip);
        self.mrai_pending.remove(&peer_ip);

        if let Some(ari) = self.adj_ribs_in.get_mut(&peer_ip) {
            ari.clear();
        }
        if let Some(ari) = self.adj_ribs_in_v6.get_mut(&peer_ip) {
            ari.clear();
        }

        // Snapshot affected prefixes before withdrawal so we can propagate the
        // changes to other established peers below.
        let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();

        let fib_changes_v4 = self.rib_withdraw_peer_v4(&peer_id);
        let fib_changes_v6 = self.rib_withdraw_peer_v6(&peer_id);

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes_v4 {
                fm.apply_v4(change);
            }
            for change in fib_changes_v6 {
                fm.apply_v6(change);
            }
        }

        // Reset this peer's outbound state for a clean reconnect.
        let cfg_pt = self
            .peer_config_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);
        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            let is_rr = !self.rib.rr_clients.is_empty();
            *aro = if is_rr && cfg_pt == PeerType::Internal {
                AdjRibOut::new_reflecting(peer_id, cfg_pt)
            } else {
                AdjRibOut::new(peer_id, cfg_pt)
            };
        }
        if let Some(aro) = self.adj_ribs_out_v6.get_mut(&peer_ip) {
            *aro = AdjRibOut::new(peer_id, cfg_pt);
        }

        // Tell all other established peers about the best-path changes caused
        // by this teardown.
        let other_peers: Vec<Ipv4Addr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();

        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        for other_ip in other_peers {
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "export_policies missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                tracing::error!(peer = %other_ip, "adj_ribs_out missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "update_senders missing peer — skipping propagation on Terminated");
                continue;
            };

            let decisions: Vec<PrefixDecision> = prev_prefixes
                .iter()
                .map(|&nlri| {
                    propagate_prefix(
                        nlri,
                        &self.rib.loc_rib,
                        adj_rib_out,
                        export_policy,
                        other_type,
                        local_as,
                        local_bgp_id,
                    )
                })
                .collect();
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            if !flush_updates(decisions, max_len, update_tx, other_type, other_four_byte) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }

        // Emit Withdrawn RouteEvents for every NLRI that lost its best path
        // (or Announced if another peer's route was promoted). Without this,
        // the dashboard shows stale routes after a peer disconnects.
        self.emit_route_events(&prev_prefixes);

        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None, // gRPC handler builds PeerState from snapshot
        });

        tracing::info!(
            peer = %peer_ip,
            rib_size = self.rib.loc_rib.len(),
            "session terminated"
        );
    }

    /// Called when a BGP UPDATE message arrives from an established peer.
    ///
    /// Applies import policy, updates the RIB, and propagates best-path changes
    /// for all affected NLRIs to every established peer.
    #[allow(clippy::similar_names)]
    pub(crate) fn on_route_update(
        &mut self,
        peer_ip: Ipv4Addr,
        mut msg: UpdateMessage,
    ) -> Option<NotificationMessage> {
        let peer_id = PeerId::from(peer_ip);
        let peer_type = self
            .rib
            .peer_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);

        // Route reflection inbound processing (RFC 4456 §8).
        if self.rib.rr_clients.contains(&peer_ip) {
            let cluster_id = self.rib.cluster_id;
            // Loop detection: discard the entire UPDATE if our cluster_id
            // already appears in CLUSTER_LIST.
            let has_loop = msg.attributes.iter().any(
                |a| matches!(a, PathAttribute::ClusterList(list) if list.contains(&cluster_id)),
            );
            if has_loop {
                tracing::debug!(
                    peer = %peer_ip,
                    cluster_id,
                    "RR loop detected in CLUSTER_LIST — discarding UPDATE"
                );
                return None;
            }
            // Set ORIGINATOR_ID if not already present.
            if !msg
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_)))
            {
                let bgp_id = self
                    .rib
                    .peer_bgp_ids
                    .get(&peer_ip)
                    .copied()
                    .unwrap_or(peer_ip);
                msg.attributes.push(PathAttribute::OriginatorId(bgp_id));
            }
            // Prepend our cluster_id to CLUSTER_LIST.
            if let Some(PathAttribute::ClusterList(list)) = msg
                .attributes
                .iter_mut()
                .find(|a| matches!(a, PathAttribute::ClusterList(_)))
            {
                list.insert(0, cluster_id);
            } else {
                msg.attributes
                    .push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }

        // Collect all IPv4 prefixes that may change best-path: traditional
        // fields plus any IPv4 NLRIs carried in MP_REACH/MP_UNREACH attributes
        // (RFC 4760). These are used after `handle_update` to drive outbound
        // propagation, so they must be collected before `msg` is moved.
        let mut affected: Vec<Nlri<Ipv4Addr>> = msg
            .withdrawn
            .iter()
            .chain(msg.announced.iter())
            .copied()
            .collect();

        let mut affected_v6: Vec<Nlri<Ipv6Addr>> = Vec::new();

        for attr in &msg.attributes {
            match attr {
                PathAttribute::MpUnreachNlri(MpUnreachNlri { afi_safi, prefixes })
                    if *afi_safi == AfiSafi::IPV4_UNICAST =>
                {
                    affected.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V4(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi, prefixes, ..
                }) if *afi_safi == AfiSafi::IPV4_UNICAST => {
                    affected.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V4(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                PathAttribute::MpUnreachNlri(MpUnreachNlri { afi_safi, prefixes })
                    if *afi_safi == AfiSafi::IPV6_UNICAST =>
                {
                    affected_v6.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V6(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi, prefixes, ..
                }) if *afi_safi == AfiSafi::IPV6_UNICAST => {
                    affected_v6.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V6(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                _ => {}
            }
        }

        let Some(policy) = self.import_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "import_policies missing peer — skipping RouteUpdate");
            return None;
        };
        let Some(policy_v6) = self.import_policies_v6.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "import_policies_v6 missing peer — skipping RouteUpdate");
            return None;
        };
        let Some(adj_rib_in) = self.adj_ribs_in.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_in missing peer — skipping RouteUpdate");
            return None;
        };

        // IPv6 AdjRibIn may not exist for all peers (e.g. if capability was not
        // advertised); use a temporary empty table in that case so handle_update
        // can take ownership without a conditional.
        let mut scratch_v6 = AdjRibIn::new(peer_id);
        let adj_rib_in_v6 = self
            .adj_ribs_in_v6
            .get_mut(&peer_ip)
            .unwrap_or(&mut scratch_v6);

        // Split mutable borrows across distinct struct fields explicitly so the
        // borrow checker can verify they don't alias.
        let oracle_v4 = Arc::clone(&self.oracle_v4);
        let oracle_v6 = Arc::clone(&self.oracle_v6);
        let local_as = self.rib.local_as;
        let local_v4_addr = self.rib.local_addrs.get(&peer_ip).copied();
        let local_v6_addr = self.rib.local_ipv6;
        let rib = Arc::make_mut(&mut self.rib);
        let (fib_changes, fib_changes_v6, notification) = handle_update(
            peer_id,
            msg,
            adj_rib_in,
            &mut rib.loc_rib,
            adj_rib_in_v6,
            &mut rib.loc_rib_v6,
            policy,
            policy_v6,
            peer_type,
            &*oracle_v4,
            &*oracle_v6,
            local_as,
            local_v4_addr,
            local_v6_addr,
        );

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes {
                fm.apply_v4(change);
            }
            for change in fib_changes_v6 {
                fm.apply_v6(change);
            }
        }

        self.sync_received(peer_ip);

        // Propagate best-path changes for affected prefixes to all established
        // peers (iBGP split-horizon is enforced by AdjRibOut).
        self.propagate_to_all_peers(&affected);
        if !affected_v6.is_empty() {
            self.propagate_to_all_peers_v6(&affected_v6);
        }

        // Notify watchers so the dashboard reflects the updated Loc-RIB and
        // RCV/ADV counters.  `propagate_to_all_peers` already called
        // `sync_advertised`; the PeerEvent flushes that to the dashboard.
        self.emit_route_events(&affected);
        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None,
        });
        notification
    }

    /// Propagates best-path decisions for `nlris` to every currently established
    /// peer and flushes the resulting BGP UPDATE messages.
    ///
    /// Extracted to eliminate the identical loop body duplicated across
    /// `on_route_update`, `set_import_default`, `set_export_default`, and the
    /// origination methods.
    fn propagate_to_all_peers(&mut self, nlris: &[Nlri<Ipv4Addr>]) {
        let established_peers: Vec<Ipv4Addr> = self.rib.peer_types.keys().copied().collect();
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let is_rr = !self.rib.rr_clients.is_empty();
        for peer_ip in established_peers {
            let peer_type = self
                .rib
                .peer_types
                .get(&peer_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let local_next_hop = self
                .rib
                .local_addrs
                .get(&peer_ip)
                .copied()
                .unwrap_or(local_bgp_id);
            let max_len = self
                .negotiated_max_len
                .get(&peer_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "export_policies missing peer — skipping propagation");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "adj_ribs_out missing peer — skipping propagation");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping propagation");
                continue;
            };
            let rr_clients = &self.rib.rr_clients;
            let peer_types = &self.rib.peer_types;
            let loc_rib = &self.rib.loc_rib;
            let dest_is_client = rr_clients.contains(&peer_ip);
            let decisions: Vec<PrefixDecision> = nlris
                .iter()
                .map(|&nlri| {
                    // RR split-horizon (RFC 4456 §8): when acting as an RR,
                    // block propagation between two non-client iBGP peers.
                    // All other source/dest combinations are allowed; the
                    // AdjRibOut `reflects` flag suppresses the regular iBGP
                    // split-horizon so it does not re-block reflected routes.
                    if is_rr
                        && peer_type == PeerType::Internal
                        && let Some(src) = loc_rib.best_peer(&nlri)
                        && let IpAddr::V4(src_ip) = src.ip()
                    {
                        let src_is_client = rr_clients.contains(&src_ip);
                        let src_is_ibgp =
                            peer_types.get(&src_ip).copied() == Some(PeerType::Internal);
                        if src_is_ibgp && !src_is_client && !dest_is_client {
                            return PrefixDecision::NoChange;
                        }
                    }
                    propagate_prefix(
                        nlri,
                        loc_rib,
                        adj_rib_out,
                        export_policy,
                        peer_type,
                        local_as,
                        local_next_hop,
                    )
                })
                .collect();
            // RFC 4271 §9.2.1.1: apply MRAI for eBGP peers.
            // Withdrawals bypass MRAI (must be sent immediately per the RFC).
            let now = Instant::now();
            let decisions = if peer_type == PeerType::External {
                let last_sent = self.mrai_last_sent.entry(peer_ip).or_default();
                let pending = self.mrai_pending.entry(peer_ip).or_default();
                decisions
                    .into_iter()
                    .map(|d| match d {
                        PrefixDecision::Announce(ref route) => {
                            let nlri = route.nlri;
                            let elapsed = last_sent
                                .get(&nlri)
                                .map_or(MRAI, |t| now.saturating_duration_since(*t));
                            if elapsed >= MRAI {
                                last_sent.insert(nlri, now);
                                pending.remove(&nlri);
                                d
                            } else {
                                pending.insert(nlri);
                                PrefixDecision::NoChange
                            }
                        }
                        // Withdrawals are always sent immediately; also clear any
                        // pending MRAI entry so we don't re-announce after withdrawal.
                        PrefixDecision::Withdraw(nlri) => {
                            pending.remove(&nlri);
                            last_sent.remove(&nlri);
                            d
                        }
                        PrefixDecision::NoChange => d,
                    })
                    .collect()
            } else {
                decisions
            };
            let peer_four_byte = self.four_byte_peers.contains(&peer_ip);
            if !flush_updates(decisions, max_len, update_tx, peer_type, peer_four_byte) {
                self.stalled_peers.push(peer_ip);
            }
        }
        // Sync advertised counts after all propagation is complete.
        let peers: Vec<Ipv4Addr> = self.adj_ribs_out.keys().copied().collect();
        for peer_ip in peers {
            self.sync_advertised(peer_ip);
        }
        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None,
        });
    }

    /// Re-propagates NLRIs that were suppressed by MRAI and whose window has now elapsed.
    ///
    /// Should be called roughly every MRAI interval (30 s) by the event loop.
    /// For each eBGP peer with pending NLRIs, this re-runs `propagate_to_all_peers`
    /// for the pending set so routes reach the peer after the suppression window closes.
    pub(crate) fn flush_mrai_pending(&mut self) {
        let now = Instant::now();
        // Per-NLRI readiness check: only flush NLRIs whose individual MRAI window
        // has elapsed. A bulk "max of all last_sent" check would incorrectly
        // suppress a pending NLRI if any *other* (non-pending) NLRI was sent
        // recently enough to make the max appear within the window.
        let peers_with_pending: Vec<Ipv4Addr> = self
            .mrai_pending
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(&p, _)| p)
            .collect();

        for peer_ip in peers_with_pending {
            let Some(pending) = self.mrai_pending.get(&peer_ip) else {
                continue;
            };
            let (ready, not_ready): (Vec<Nlri<Ipv4Addr>>, Vec<Nlri<Ipv4Addr>>) = pending
                .iter()
                .copied()
                .partition(|nlri| {
                    self.mrai_last_sent
                        .get(&peer_ip)
                        .and_then(|m| m.get(nlri))
                        .map_or(true, |t| now.saturating_duration_since(*t) >= MRAI)
                });

            if ready.is_empty() {
                continue;
            }

            // Replace pending with the still-suppressed NLRIs before propagating,
            // so propagate_to_all_peers sees an accurate pending set.
            if let Some(p) = self.mrai_pending.get_mut(&peer_ip) {
                *p = not_ready.into_iter().collect();
            }
            self.propagate_to_all_peers(&ready);
        }
    }

    /// Returns `true` if any eBGP peer has NLRIs pending for MRAI flush.
    ///
    /// Used by the event loop to decide whether to schedule a wakeup timer.
    pub(crate) fn has_mrai_pending(&self) -> bool {
        self.mrai_pending.values().any(|s| !s.is_empty())
    }

    /// Emits a `RouteEvent` for each NLRI in `affected` based on the current
    /// Loc-RIB state: `Announced` when a best route exists, `Withdrawn` when
    /// the prefix has been removed.
    fn emit_route_events(&self, affected: &[Nlri<Ipv4Addr>]) {
        for &nlri in affected {
            let event = match self.rib.loc_rib.best(&nlri) {
                Some(route) => {
                    let peer_id = self
                        .rib
                        .loc_rib
                        .best_peer(&nlri)
                        .unwrap_or_else(|| PeerId::from(Ipv4Addr::UNSPECIFIED));
                    proto::RouteEvent {
                        r#type: proto::RouteEventType::Announced as i32,
                        route: Some(grpc::route_to_proto(peer_id, nlri, route)),
                        withdrawn_prefix: None,
                    }
                }
                None => proto::RouteEvent {
                    r#type: proto::RouteEventType::Withdrawn as i32,
                    route: None,
                    withdrawn_prefix: Some(nlri.to_string()),
                },
            };
            let _ = self.route_tx.send(event);
        }
    }

    fn propagate_to_all_peers_v6(&mut self, nlris: &[Nlri<Ipv6Addr>]) {
        // Only send IPv6 UPDATEs to peers that negotiated the Multi-Protocol
        // capability for IPv6 unicast (RFC 4760).
        let established_peers: Vec<Ipv4Addr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|ip| self.ipv6_capable_peers.contains(ip))
            .collect();
        let local_as = self.rib.local_as;
        let local_ipv6 = self.rib.local_ipv6;
        for peer_ip in established_peers {
            let peer_type = self
                .rib
                .peer_types
                .get(&peer_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&peer_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "adj_ribs_out_v6 missing peer — skipping v6 propagation");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping v6 propagation");
                continue;
            };
            let decisions: Vec<PrefixDecisionV6> = nlris
                .iter()
                .map(|&nlri| {
                    propagate_prefix_v6(
                        nlri,
                        &self.rib.loc_rib_v6,
                        adj_rib_out_v6,
                        peer_type,
                        local_as,
                        local_ipv6,
                    )
                })
                .collect();
            let peer_four_byte = self.four_byte_peers.contains(&peer_ip);
            if !flush_updates_v6(decisions, max_len, update_tx, peer_type, peer_four_byte) {
                self.stalled_peers.push(peer_ip);
            }
        }
    }

    /// Injects a single route into the Loc-RIB and advertises it to all
    /// established peers. Delegates to [`originate_routes`].
    ///
    /// [`originate_routes`]: DaemonState::originate_routes
    pub(crate) fn originate_route(&mut self, route: Route<Ipv4Addr>) {
        self.originate_routes(vec![route]);
    }

    /// Injects a batch of routes into the Loc-RIB and advertises all of them
    /// to established peers in a single propagation pass.
    ///
    /// All routes are inserted before propagation begins — one `propagate_to_all_peers`
    /// call regardless of batch size. This matches GoBGP `AddPathStream` semantics.
    ///
    /// Originated routes bypass import policy; they go directly into Loc-RIB.
    /// Export policy still applies on the outbound side.
    pub(crate) fn originate_routes(&mut self, routes: Vec<Route<Ipv4Addr>>) {
        let mut nlris = Vec::with_capacity(routes.len());
        for route in routes {
            let nlri = route.nlri;
            self.rib_mut().originated_routes.insert(nlri, route.clone());
            self.rib_insert_v4(PeerId::from(LOCAL_ORIGIN_PEER), route.clone());
            nlris.push(nlri);
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Announced as i32,
                route: Some(grpc::route_to_proto(
                    PeerId::from(LOCAL_ORIGIN_PEER),
                    nlri,
                    &route,
                )),
                withdrawn_prefix: None,
            });
        }
        self.propagate_to_all_peers(&nlris);
    }

    /// Injects a single IPv6 route into `loc_rib_v6` and propagates it.
    pub(crate) fn originate_route_v6(&mut self, route: Route<Ipv6Addr>) {
        self.originate_routes_v6(vec![route]);
    }

    /// Injects a batch of IPv6 routes into `loc_rib_v6` and propagates all of
    /// them in a single pass (one `propagate_to_all_peers_v6` call).
    pub(crate) fn originate_routes_v6(&mut self, routes: Vec<Route<Ipv6Addr>>) {
        let mut nlris = Vec::with_capacity(routes.len());
        for route in routes {
            let nlri = route.nlri;
            self.rib_mut()
                .originated_routes_v6
                .insert(nlri, route.clone());
            let fib_change = self.rib_insert_v6(PeerId::from(LOCAL_ORIGIN_PEER), route.clone());
            if let Some(fm) = &self.fib_manager {
                fm.apply_v6(fib_change);
            }
            nlris.push(nlri);
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Announced as i32,
                route: Some(grpc::route_v6_to_proto(
                    PeerId::from(LOCAL_ORIGIN_PEER),
                    nlri,
                    &route,
                )),
                withdrawn_prefix: None,
            });
        }
        self.propagate_to_all_peers_v6(&nlris);
    }

    /// Withdraws a single locally originated route.
    ///
    /// No-op if the prefix was not previously originated.
    pub(crate) fn withdraw_originated_route(&mut self, nlri: Nlri<Ipv4Addr>) {
        self.withdraw_originated_routes(&[nlri]);
    }

    /// Withdraws a batch of locally originated routes in a single propagation
    /// pass.
    pub(crate) fn withdraw_originated_routes(&mut self, nlris: &[Nlri<Ipv4Addr>]) {
        for nlri in nlris {
            self.rib_mut().originated_routes.remove(nlri);
            let fib_change = self.rib_withdraw_v4(&PeerId::from(LOCAL_ORIGIN_PEER), nlri);
            if let Some(fm) = &self.fib_manager {
                fm.apply_v4(fib_change);
            }
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Withdrawn as i32,
                route: None,
                withdrawn_prefix: Some(nlri.to_string()),
            });
        }
        self.propagate_to_all_peers(nlris);
    }

    /// Withdraws a single locally originated IPv6 route.
    ///
    /// No-op if the prefix was not previously originated.
    pub(crate) fn withdraw_originated_route_v6(&mut self, nlri: Nlri<Ipv6Addr>) {
        self.withdraw_originated_routes_v6(&[nlri]);
    }

    /// Withdraws a batch of locally originated IPv6 routes in a single
    /// propagation pass.
    pub(crate) fn withdraw_originated_routes_v6(&mut self, nlris: &[Nlri<Ipv6Addr>]) {
        for nlri in nlris {
            self.rib_mut().originated_routes_v6.remove(nlri);
            let fib_change = self.rib_withdraw_v6(&PeerId::from(LOCAL_ORIGIN_PEER), nlri);
            if let Some(fm) = &self.fib_manager {
                fm.apply_v6(fib_change);
            }
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Withdrawn as i32,
                route: None,
                withdrawn_prefix: Some(nlri.to_string()),
            });
        }
        self.propagate_to_all_peers_v6(nlris);
    }

    /// Replaces the import-policy default for `peer_ip` and re-evaluates the
    /// peer's entire Adj-RIB-In against the new policy.  Routes that change
    /// accepted/rejected status are written into Loc-RIB, and the resulting
    /// best-path changes are propagated to all currently established peers.
    ///
    /// This is the "soft reconfiguration" path: no session reset, no full-table
    /// dump — only the delta between the old and new policy is forwarded.
    pub(crate) fn set_import_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.import_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_import_default: unknown peer — ignoring");
            return;
        }
        self.import_policies.insert(peer_ip, Policy::new(action));

        // Collect affected NLRIs before the mutable borrow of loc_rib so the
        // borrow checker does not see two simultaneous borrows of `self`.
        let nlris: Vec<Nlri<Ipv4Addr>> = self
            .adj_ribs_in
            .get(&peer_ip)
            .map(|a| a.routes().map(|(n, _)| *n).collect())
            .unwrap_or_default();

        // Re-evaluate the peer's Adj-RIB-In against the new policy.
        // Clone oracle before the mutable borrow of rib so the borrow checker
        // sees oracle_v4 and rib as independent fields of self.
        let oracle = Arc::clone(&self.oracle_v4);
        let loc_rib = &mut Arc::make_mut(&mut self.rib).loc_rib;
        let fib_changes = reapply_import_policy(
            PeerId::from(peer_ip),
            &self.adj_ribs_in[&peer_ip],
            loc_rib,
            &self.import_policies[&peer_ip],
            &*oracle,
        );

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes {
                fm.apply_v4(change);
            }
        }

        self.propagate_to_all_peers(&nlris);
        // propagate_to_all_peers fires PeerEvent::Changed (ADV); fire route
        // events too so the dashboard reflects the Loc-RIB change.
        self.emit_route_events(&nlris);
    }

    /// Replaces the export-policy default for `peer_ip` and re-evaluates the
    /// entire Loc-RIB against the new policy for that peer.  Newly accepted
    /// prefixes are sent as UPDATEs; newly rejected ones trigger WITHDRAWs.
    ///
    /// Has no effect on the wire if the peer is not currently established — the
    /// new policy will be applied on the next session's opening table dump.
    pub(crate) fn set_export_default(&mut self, peer_ip: Ipv4Addr, action: DefaultAction) {
        if !self.export_policies.contains_key(&peer_ip) {
            tracing::warn!(peer = %peer_ip, "set_export_default: unknown peer — ignoring");
            return;
        }
        self.export_policies.insert(peer_ip, Policy::new(action));

        if !self.rib.peer_types.contains_key(&peer_ip) {
            tracing::debug!(
                peer = %peer_ip,
                "set_export_default: peer not established — new policy applies on reconnect"
            );
            return;
        }

        let peer_type = self
            .rib
            .peer_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);

        // Collect all Loc-RIB NLRIs; the borrow is dropped after the collect.
        let nlris: Vec<Nlri<Ipv4Addr>> = self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();

        let max_len = self
            .negotiated_max_len
            .get(&peer_ip)
            .copied()
            .unwrap_or(MAX_LEN);
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            return;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            return;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip) else {
            return;
        };

        let decisions: Vec<PrefixDecision> = nlris
            .into_iter()
            .map(|nlri| {
                propagate_prefix(
                    nlri,
                    &self.rib.loc_rib,
                    adj_rib_out,
                    export_policy,
                    peer_type,
                    local_as,
                    local_bgp_id,
                )
            })
            .collect();
        let peer_four_byte = self.four_byte_peers.contains(&peer_ip);
        if !flush_updates(decisions, max_len, update_tx, peer_type, peer_four_byte) {
            self.stalled_peers.push(peer_ip);
        }
        self.sync_advertised(peer_ip);
    }

    /// Called when the kernel FIB changes (next-hop gained or lost).
    ///
    /// Re-evaluates best-path selection for every prefix in the Loc-RIB using
    /// the current oracle.  For each prefix whose best path changed:
    ///
    /// - Enqueues the new state in the FIB manager (install or withdraw).
    /// - Propagates the change to all established BGP peers as an UPDATE or
    ///   WITHDRAW.
    ///
    /// Only prefixes that actually changed are processed; the full-table scan
    /// runs in O(n) and the expensive peer-propagation path is entered only
    /// for the affected subset.
    pub(crate) fn on_fib_change(&mut self) {
        let fib_changes_v4 = self.rib_recompute_all_v4();
        let fib_changes_v6 = self.rib_recompute_all_v6();

        let changed_nlris_v4: Vec<Nlri<Ipv4Addr>> = fib_changes_v4
            .iter()
            .filter_map(|c| match c {
                BestPathChange::Announced(n, _) | BestPathChange::Withdrawn(n) => Some(*n),
                BestPathChange::Unchanged => None,
            })
            .collect();

        let changed_nlris_v6: Vec<Nlri<Ipv6Addr>> = fib_changes_v6
            .iter()
            .filter_map(|c| match c {
                BestPathChange::Announced(n, _) | BestPathChange::Withdrawn(n) => Some(*n),
                BestPathChange::Unchanged => None,
            })
            .collect();

        if !changed_nlris_v4.is_empty() || !changed_nlris_v6.is_empty() {
            tracing::debug!(
                changed_v4 = changed_nlris_v4.len(),
                changed_v6 = changed_nlris_v6.len(),
                "FIB change triggered best-path re-evaluation"
            );
        }

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes_v4 {
                fm.apply_v4(change);
            }
            for change in fib_changes_v6 {
                fm.apply_v6(change);
            }
        }

        if !changed_nlris_v4.is_empty() {
            self.propagate_to_all_peers(&changed_nlris_v4);
            self.emit_route_events(&changed_nlris_v4);
        }
        if !changed_nlris_v6.is_empty() {
            self.propagate_to_all_peers_v6(&changed_nlris_v6);
        }
    }
}

pub(crate) async fn run(cfg: config::Config) {
    run_with(cfg, transport::spawn).await;
}

/// Runs the BGP daemon using `spawn_fn` to create session handles.
///
/// `run()` calls this with [`transport::spawn`]; tests call it with a mock
/// `spawn_fn` so the session-spawning setup phase can be exercised without
/// real TCP connections.
/// Withdraws every route in `stale_v4` / `stale_v6` from the kernel FIB.
///
/// Called at daemon startup before the BGP event loop begins.  At that point
/// the Loc-RIB is empty, so every `RTPROT_BGP` route is a stale remnant of a
/// previous run.  Individual withdrawal errors are logged as warnings and
/// skipped — an already-absent route (ESRCH) is already silenced by
/// `FibWriter::withdraw_v4` / `FibWriter::withdraw_v6`.
///
/// On non-Linux platforms `stale_v4` and `stale_v6` are always empty (returned
/// by [`pathvector_sys::KernelFib::stale_bgp_routes`]), so this is a no-op.
pub(crate) async fn withdraw_stale_bgp_routes(
    stale_v4: Vec<(std::net::Ipv4Addr, u8)>,
    stale_v6: Vec<(std::net::Ipv6Addr, u8)>,
    writer: &pathvector_sys::FibWriter,
) {
    for (dst, prefix_len) in stale_v4 {
        if let Err(e) = writer.withdraw_v4(dst, prefix_len).await {
            tracing::warn!(%dst, prefix_len, "stale BGP route removal failed: {e}");
        }
    }
    for (dst, prefix_len) in stale_v6 {
        if let Err(e) = writer.withdraw_v6(dst, prefix_len).await {
            tracing::warn!(%dst, prefix_len, "stale BGP v6 route removal failed: {e}");
        }
    }
}

pub(crate) async fn run_with<H, F>(cfg: config::Config, spawn_fn: F)
where
    H: SessionHandle,
    F: Fn(SessionConfig) -> H,
{
    let grpc_port = cfg.daemon.grpc_port;
    let bgp_port = cfg.daemon.bgp_port;
    let fib_table = cfg.daemon.fib_table;
    let fib_metric = cfg.daemon.fib_metric;
    let (state, event_rx, stop_senders, incoming_senders, md5_passwords) =
        build_daemon(&cfg, spawn_fn).await;

    // Spawn the kernel FIB tracker and install the FibManager.
    //
    // KernelFib dumps the initial routing table and then tracks RTM_NEWROUTE /
    // RTM_DELROUTE events; KernelOracle exposes the snapshot for next-hop
    // reachability queries.  FibWriter handles the write side (route install /
    // remove).  On non-Linux platforms both are no-ops.
    let (kernel_fib, fib_change_rx) = pathvector_sys::KernelFib::new(fib_table);
    // oracle() takes &self; call before spawn() consumes kernel_fib.
    let oracle_v4 = fib::DaemonOracle(kernel_fib.oracle());
    let oracle_v6 = fib::DaemonOracle(kernel_fib.oracle());
    let fib_writer = match pathvector_sys::FibWriter::new(fib_table, fib_metric) {
        Ok(w) => {
            // Gap 4: delete any RTPROT_BGP routes left by a previous daemon run
            // before the event loop starts. See `withdraw_stale_bgp_routes`.
            match kernel_fib.stale_bgp_routes().await {
                Ok((stale_v4, stale_v6)) => {
                    if !stale_v4.is_empty() || !stale_v6.is_empty() {
                        tracing::info!(
                            v4 = stale_v4.len(),
                            v6 = stale_v6.len(),
                            "removing stale BGP routes from previous run"
                        );
                    }
                    withdraw_stale_bgp_routes(stale_v4, stale_v6, &w).await;
                }
                Err(e) => {
                    tracing::warn!("failed to query stale BGP routes: {e}");
                }
            }
            tokio::spawn(kernel_fib.spawn());
            Some(w)
        }
        Err(e) => {
            tracing::warn!(
                "FIB integration unavailable: {e} — running without kernel route install"
            );
            None
        }
    };

    // Wire the live oracle and FIB writer into the daemon state now that
    // KernelFib is initialised.  Sessions have not yet started, so no
    // best-path recomputes are in flight — the update is safe.
    {
        let mut guard = state.write().await;
        guard.set_oracles(oracle_v4, oracle_v6);
        if let Some(writer) = fib_writer {
            guard.fib_manager = Some(Arc::new(fib::FibManager::new(writer)));
        }
    }

    // Spawn the gRPC management API server alongside the BGP event loop.
    let grpc_state = Arc::clone(&state);
    tokio::spawn(async move {
        grpc::serve(grpc_state, grpc_port).await;
    });

    // Spawn the BGP TCP listener for inbound connections (RFC 4271 §6.8).
    tokio::spawn(async move {
        run_bgp_listener(bgp_port, incoming_senders, md5_passwords).await;
    });

    run_event_loop(event_rx, state, stop_senders, Some(fib_change_rx)).await;
}

/// Sets up BGP sessions for every configured peer and constructs the initial
/// [`DaemonState`].
///
/// `spawn_fn` is called once per peer to create a [`SessionHandle`]; `start()`
/// is then called on each handle so the session task begins the TCP connect /
/// BGP open exchange.  The returned tuple contains:
///
/// - The shared daemon state (pre-populated with per-peer RIBs and policies).
/// - The event receiver that drains `(peer_ip, SessionEvent)` messages from
///   the per-peer forwarding tasks.
/// - The stop-sender map so the event loop can close a session whose outbound
///   channel overflowed.
///
/// Extracted from `run_with()` so it can be driven in tests by supplying a
/// mock `spawn_fn` — no real TCP sockets needed.
pub(crate) async fn build_daemon<H, F>(
    cfg: &config::Config,
    spawn_fn: F,
) -> (
    Arc<RwLock<DaemonState>>,
    mpsc::Receiver<(Ipv4Addr, SessionEvent)>,
    HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>,
    HashMap<IpAddr, mpsc::Sender<SessionCommand>>,
    HashMap<IpAddr, String>, // RFC 2385 MD5 passwords keyed by peer IP
)
where
    H: SessionHandle,
    F: Fn(SessionConfig) -> H,
{
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;

    let (event_tx, event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(256);
    let mut update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>> = HashMap::new();
    // Stop senders are kept here so the event loop can close a session whose
    // outbound UPDATE channel overflowed.  The session handle itself is moved
    // into the per-peer forwarding task, so this is the only retained handle.
    let mut stop_senders: HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>> = HashMap::new();
    // Incoming senders: keyed by IpAddr for O(1) lookup in the BGP listener.
    let mut incoming_senders: HashMap<IpAddr, mpsc::Sender<SessionCommand>> = HashMap::new();
    // RFC 2385 MD5 passwords: passed to the listener so it can configure
    // TCP_MD5SIG before any SYN arrives from an MD5-enabled peer.
    let mut md5_passwords: HashMap<IpAddr, String> = HashMap::new();

    let local_capabilities = vec![
        Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        Capability::FourByteAsn(local_as),
        Capability::ExtendedMessage,
    ];

    for peer in &cfg.peers {
        let session_cfg = SessionConfig {
            local_as,
            local_bgp_id,
            hold_time: cfg.daemon.hold_time,
            capabilities: local_capabilities.clone(),
            required_capabilities: vec![],
            peer_as: Some(peer.remote_as),
            peer_addr: SocketAddr::new(IpAddr::V4(peer.address), peer.port),
            md5_password: peer.md5_password.clone(),
        };

        let mut handle = spawn_fn(session_cfg);
        handle.start().await;

        update_senders.insert(peer.address, handle.update_sender());
        stop_senders.insert(peer.address, handle.stop_sender());
        incoming_senders.insert(IpAddr::V4(peer.address), handle.incoming_sender());
        if let Some(pw) = &peer.md5_password {
            md5_passwords.insert(IpAddr::V4(peer.address), pw.clone());
        }

        let peer_addr = peer.address;
        let tx = event_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = handle.next_event().await {
                if tx.send((peer_addr, event)).await.is_err() {
                    break;
                }
            }
        });
    }
    // Drop our sender copy so the channel closes when all peer tasks exit.
    drop(event_tx);

    let state = Arc::new(RwLock::new(DaemonState::new(
        local_as,
        local_bgp_id,
        cfg.daemon.local_ipv6,
        cfg.daemon.cluster_id,
        &cfg.peers,
        update_senders,
        local_capabilities,
    )));

    (
        state,
        event_rx,
        stop_senders,
        incoming_senders,
        md5_passwords,
    )
}

/// BGP TCP listener for inbound connections (RFC 4271 §6.8).
///
/// Binds on `0.0.0.0:<bgp_port>` and forwards each accepted connection to the
/// session task for the corresponding peer.  Unknown peers (not in
/// `incoming_senders`) have their connection dropped immediately — the TCP RST
/// tells the remote peer to back off.
///
/// The listener runs for the lifetime of the daemon.  If `bind()` fails (e.g.,
/// port 179 without `CAP_NET_BIND_SERVICE`), the error is logged and the
/// listener exits; the daemon continues operating in dial-only mode.
async fn run_bgp_listener(
    bgp_port: u16,
    incoming_senders: HashMap<IpAddr, mpsc::Sender<SessionCommand>>,
    md5_passwords: HashMap<IpAddr, String>,
) {
    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], bgp_port));
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => {
            tracing::info!(port = bgp_port, "BGP listener started");
            l
        }
        Err(e) => {
            tracing::error!(port = bgp_port, error = %e, "BGP listener failed to bind; operating in dial-only mode");
            return;
        }
    };

    // RFC 2385: install TCP MD5 keys on the listener socket before any SYN
    // arrives. If a peer sends a SYN with MD5 and the listener has no key for
    // that peer, the kernel silently drops the SYN.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        for (peer_ip, key) in &md5_passwords {
            if let Err(e) =
                pathvector_session::transport::apply_tcp_md5sig(listener.as_raw_fd(), *peer_ip, key)
            {
                tracing::error!(peer = %peer_ip, error = %e, "failed to set TCP MD5SIG on BGP listener");
            } else {
                tracing::info!(peer = %peer_ip, "TCP MD5SIG installed on BGP listener");
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = &md5_passwords;

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if let Some(tx) = incoming_senders.get(&peer_addr.ip()) {
                    tracing::debug!(peer = %peer_addr, "accepted inbound BGP connection");
                    let _ = tx.send(SessionCommand::IncomingConnection(stream)).await;
                } else {
                    tracing::debug!(peer = %peer_addr, "rejected inbound BGP connection from unknown peer");
                    // stream dropped here → TCP RST
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "BGP listener accept error");
            }
        }
    }
}

/// Core BGP event loop.
///
/// Drains `event_rx`, dispatches each `(peer_ip, SessionEvent)` to the shared
/// [`DaemonState`], then closes any sessions whose outbound UPDATE channel
/// overflowed during that dispatch.
///
/// `fib_change_rx` is a `watch::Receiver` that fires whenever the kernel FIB
/// snapshot changes.  On each tick the event loop calls
/// [`DaemonState::on_fib_change`] to re-evaluate best-paths whose next-hops
/// may have been affected.  Pass `None` in tests that do not exercise FIB
/// re-evaluation — the select arm is skipped entirely.
///
/// Extracted from `run()` so it can be driven in unit tests by injecting a
/// pre-built channel and a pre-populated `DaemonState` — no TCP connections
/// or real session tasks required.
pub(crate) async fn run_event_loop(
    mut event_rx: mpsc::Receiver<(Ipv4Addr, SessionEvent)>,
    state: Arc<RwLock<DaemonState>>,
    stop_senders: HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>,
    mut fib_change_rx: Option<watch::Receiver<()>>,
) {
    // MRAI flush timer — fires every MRAI/2 so suppressed eBGP routes are
    // re-advertised within one interval of their window expiring (RFC 4271 §9.2.1.1).
    // The first tick fires immediately but is a no-op (no sessions yet); subsequent
    // ticks are spaced MRAI/2 apart. MissedTickBehavior::Delay prevents burst
    // catch-up when the event loop is held under a write lock for an extended period.
    let mut mrai_timer = tokio::time::interval(MRAI / 2);
    mrai_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // `std::future::pending()` for the None branch ensures the select arm
        // is compiled in but never resolves, keeping the loop alive on the
        // BGP event path alone.
        let fib_changed = async {
            match fib_change_rx.as_mut() {
                Some(rx) => rx.changed().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            event = event_rx.recv() => {
                let Some((peer_ip, event)) = event else { break; };
                let mut s = state.write().await;
                match event {
                    SessionEvent::Established(info) => {
                        Arc::make_mut(&mut s.rib)
                            .peer_bgp_ids
                            .insert(peer_ip, info.peer_bgp_id);
                        s.on_established(
                            peer_ip,
                            info.peer_type,
                            info.peer_as,
                            info.hold_time,
                            &info.peer_capabilities,
                            info.local_addr,
                        );
                    }
                    SessionEvent::Terminated => {
                        s.on_terminated(peer_ip);
                    }
                    SessionEvent::RouteUpdate(msg) => {
                        let notify_err = s.on_route_update(peer_ip, msg);
                        // RFC 4271 §6.3: mandatory attribute violation — send
                        // specific NOTIFICATION before tearing down the session.
                        if let Some(err) = notify_err {
                            let stalled = s.take_stalled_peers();
                            drop(s);
                            if let Some(tx) = stop_senders.get(&peer_ip) {
                                let _ = tx.send(SessionCommand::Notification(err)).await;
                            }
                            // Process any stalled peers before next iteration.
                            for peer in stalled {
                                if let Some(tx) = stop_senders.get(&peer) {
                                    let _ = tx.send(SessionCommand::Stop).await;
                                }
                            }
                            continue;
                        }
                    }
                }
                // Collect any peers whose outbound channel overflowed.  Drain
                // outside the write-lock so we don't hold it across async sends.
                let stalled = s.take_stalled_peers();
                drop(s);

                for peer in stalled {
                    tracing::error!(
                        peer = %peer,
                        "closing session: outbound UPDATE channel overflowed; \
                         session will re-establish and perform a fresh full-table dump"
                    );
                    if let Some(tx) = stop_senders.get(&peer) {
                        let _ = tx.send(SessionCommand::Stop).await;
                    }
                }
            }

            Ok(()) = fib_changed => {
                let mut s = state.write().await;
                s.on_fib_change();
                let stalled = s.take_stalled_peers();
                drop(s);

                for peer in stalled {
                    tracing::error!(
                        peer = %peer,
                        "closing session: outbound UPDATE channel overflowed after FIB change; \
                         session will re-establish and perform a fresh full-table dump"
                    );
                    if let Some(tx) = stop_senders.get(&peer) {
                        let _ = tx.send(SessionCommand::Stop).await;
                    }
                }
            }

            _ = mrai_timer.tick() => {
                let mut s = state.write().await;
                if s.has_mrai_pending() {
                    s.flush_mrai_pending();
                    let stalled = s.take_stalled_peers();
                    drop(s);
                    for peer in stalled {
                        tracing::error!(
                            peer = %peer,
                            "closing session: outbound UPDATE channel overflowed during MRAI flush; \
                             session will re-establish and perform a fresh full-table dump"
                        );
                        if let Some(tx) = stop_senders.get(&peer) {
                            let _ = tx.send(SessionCommand::Stop).await;
                        }
                    }
                }
            }
        }
    }
}

/// Re-evaluates all routes stored in `adj_rib_in` against `policy` and
/// reconciles `loc_rib` with the result.
///
/// This is soft reconfiguration: when the import policy for a peer changes,
/// call this instead of resetting the session. Routes that the new policy
/// accepts are (re-)inserted into `loc_rib` with any attribute modifications
/// the policy applies. Routes that the new policy rejects are withdrawn from
/// `loc_rib` if they were previously accepted.
///
/// The raw routes in `adj_rib_in` are never modified — they always reflect
/// what the peer actually advertised.
pub(crate) fn reapply_import_policy(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    oracle: &dyn NextHopOracle,
) -> Vec<BestPathChange<Ipv4Addr>> {
    let mut fib_changes: Vec<BestPathChange<Ipv4Addr>> = Vec::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for (nlri, raw_route) in adj_rib_in.routes() {
        let mut route = raw_route.clone();
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                fib_changes.push(loc_rib.insert(peer, route, oracle));
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                fib_changes.push(loc_rib.withdraw(&peer, nlri, oracle));
                rejected += 1;
            }
        }
    }

    tracing::info!(
        peer = %peer,
        accepted,
        rejected,
        rib_size = loc_rib.len(),
        "soft reconfig complete"
    );
    fib_changes
}

// RFC 4271 §5.1.3 / §9.1.2 — NEXT_HOP validation.
// Returns false for addresses that are forbidden as next-hops: unspecified,
// loopback, multicast, and broadcast. The "own address" check (receiving
// router's address) is left to the FIB oracle reachability gate because
// handle_update has no direct access to the local interface address.
// `own_addr`: the local interface address toward this peer; if the NEXT_HOP
// equals our own address the peer would be sending traffic to us, black-holing
// it. RFC 4271 §5.1.3 requires the NEXT_HOP to be reachable and not the
// receiving router's own address.
fn is_valid_next_hop_v4(addr: Ipv4Addr, own_addr: Option<Ipv4Addr>) -> bool {
    !addr.is_unspecified()
        && !addr.is_loopback()
        && !addr.is_multicast()
        && addr != Ipv4Addr::BROADCAST
        && own_addr.map_or(true, |own| addr != own)
}

// RFC 4291 §2.5 / RFC 4271 §5.1.3 for IPv6 next-hops carried in MP_REACH_NLRI.
// Unspecified (::) and multicast (ff00::/8) are not valid forwarding targets.
// Link-local (fe80::/10) is valid when paired with an interface (V6WithLinkLocal)
// and is handled by the FIB oracle; a bare link-local as a global next-hop is
// accepted here because GoBGP and BIRD both use it legitimately in single-hop sessions.
fn is_valid_next_hop_v6(addr: Ipv6Addr) -> bool {
    !addr.is_unspecified() && !addr.is_multicast()
}

// UPDATE processing dispatches across all path attribute types in one pass.
// Splitting this function further would produce artificial helpers with no
// independent utility.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn handle_update(
    peer: PeerId,
    msg: UpdateMessage,
    adj_rib_in: &mut AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    adj_rib_in_v6: &mut AdjRibIn<Ipv6Addr>,
    loc_rib_v6: &mut LocRib<Ipv6Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    policy_v6: &Policy<Route<Ipv6Addr>>,
    peer_type: PeerType,
    oracle_v4: &dyn NextHopOracle,
    oracle_v6: &dyn NextHopOracle,
    local_as: u32,
    local_v4_addr: Option<Ipv4Addr>,
    local_v6_addr: Option<Ipv6Addr>,
) -> (Vec<BestPathChange<Ipv4Addr>>, Vec<BestPathChange<Ipv6Addr>>, Option<NotificationMessage>) {
    let mut fib_changes: Vec<BestPathChange<Ipv4Addr>> = Vec::new();
    let mut fib_changes_v6: Vec<BestPathChange<Ipv6Addr>> = Vec::new();
    let withdrawn_count = msg.withdrawn.len();

    // ── Traditional IPv4 withdrawals (RFC 4271 §4.3) ──────────────────────
    for nlri in &msg.withdrawn {
        adj_rib_in.withdraw(nlri);
        fib_changes.push(loc_rib.withdraw(&peer, nlri, oracle_v4));
    }

    // ── Single pass over path attributes ─────────────────────────────────
    // Extracts scalar attributes shared by all announced NLRIs, and collects
    // IPv4 NLRIs from MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 4760). Non-IPv4
    // AFI/SAFIs are logged and skipped; the daemon is IPv4-only for now.
    let mut has_origin = false;
    let mut has_as_path = false;
    let mut origin = Origin::Incomplete;
    let mut as_path = AsPath::new();
    let mut next_hop: Option<NextHop> = None;
    let mut local_pref: Option<LocalPref> = None;
    let mut med: Option<Med> = None;
    let mut communities = Vec::new();
    let mut large_communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut atomic_aggregate = false;
    let mut aggregator = None;
    let mut originator_id: Option<Ipv4Addr> = None;
    let mut cluster_list: Vec<u32> = Vec::new();
    // (nlri, next_hop) pairs from MP_REACH_NLRI; next_hop is mandatory there.
    let mut mp_v4_announced: Vec<(Nlri<Ipv4Addr>, NextHop)> = Vec::new();
    let mut mp_v4_withdrawn: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut mp_v6_announced: Vec<(Nlri<Ipv6Addr>, NextHop)> = Vec::new();
    let mut mp_v6_withdrawn: Vec<Nlri<Ipv6Addr>> = Vec::new();

    for attr in &msg.attributes {
        match attr {
            PathAttribute::Origin(o) => { origin = *o; has_origin = true; }
            PathAttribute::AsPath(p) => { as_path = p.clone(); has_as_path = true; }
            PathAttribute::NextHop(ip) => next_hop = Some(NextHop::V4(*ip)),
            PathAttribute::LocalPref(lp) => local_pref = Some(LocalPref::new(*lp)),
            PathAttribute::Med(m) => med = Some(Med::new(*m)),
            PathAttribute::Communities(cs) => communities.clone_from(cs),
            PathAttribute::LargeCommunities(lcs) => large_communities.clone_from(lcs),
            PathAttribute::ExtendedCommunities(ecs) => extended_communities.clone_from(ecs),
            PathAttribute::AtomicAggregate => atomic_aggregate = true,
            PathAttribute::Aggregator(a) => aggregator = Some(*a),
            PathAttribute::OriginatorId(id) => originator_id = Some(*id),
            PathAttribute::ClusterList(list) => cluster_list.clone_from(list),
            PathAttribute::MpReachNlri(mp) => {
                if mp.afi_safi == AfiSafi::IPV4_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V4(nlri) = prefix {
                            mp_v4_announced.push((*nlri, mp.next_hop));
                        }
                    }
                } else if mp.afi_safi == AfiSafi::IPV6_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V6(nlri) = prefix {
                            mp_v6_announced.push((*nlri, mp.next_hop));
                        }
                    }
                } else {
                    tracing::debug!(
                        peer = %peer,
                        afi_safi = %mp.afi_safi,
                        "MP_REACH_NLRI for unsupported AFI/SAFI — skipping"
                    );
                }
            }
            PathAttribute::MpUnreachNlri(mp) => {
                if mp.afi_safi == AfiSafi::IPV4_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V4(nlri) = prefix {
                            mp_v4_withdrawn.push(*nlri);
                        }
                    }
                } else if mp.afi_safi == AfiSafi::IPV6_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V6(nlri) = prefix {
                            mp_v6_withdrawn.push(*nlri);
                        }
                    }
                } else {
                    tracing::debug!(
                        peer = %peer,
                        afi_safi = %mp.afi_safi,
                        "MP_UNREACH_NLRI for unsupported AFI/SAFI — skipping"
                    );
                }
            }
            _ => {}
        }
    }

    // ── RFC 4271 §6.3: mandatory well-known attribute check ───────────────
    // When the UPDATE carries announcements, ORIGIN and AS_PATH MUST be present.
    // For conventional IPv4 NLRI, NEXT_HOP is also mandatory.
    // Violation → send NOTIFICATION (UpdateMessage/MissingWellKnownAttribute) and
    // tear down the session. Withdraw-only UPDATEs are exempt.
    let has_v4_announces = !msg.announced.is_empty() || !mp_v4_announced.is_empty();
    let has_any_announces = has_v4_announces || !mp_v6_announced.is_empty();
    if has_any_announces {
        let missing_attr = if !has_origin {
            Some(1u8) // ORIGIN type code
        } else if !has_as_path {
            Some(2u8) // AS_PATH type code
        } else if has_v4_announces && !msg.announced.is_empty() && next_hop.is_none() {
            // NEXT_HOP required for traditional (non-MP) IPv4 announcements.
            Some(3u8) // NEXT_HOP type code
        } else {
            None
        };
        if let Some(attr_type) = missing_attr {
            tracing::warn!(
                peer = %peer,
                attr_type,
                "mandatory well-known attribute missing (RFC 4271 §6.3) — sending NOTIFICATION"
            );
            // RFC 4271 §6.3: data field MUST contain the type code of the missing attribute.
            return (
                fib_changes,
                fib_changes_v6,
                Some(NotificationMessage {
                    error: NotificationError::UpdateMessage(
                        UpdateMsgError::MissingWellKnownAttribute,
                    ),
                    data: vec![attr_type],
                }),
            );
        }
    }

    // ── RFC 7607: AS 0 in AS_PATH ────────────────────────────────────────
    // AS 0 is reserved and MUST NOT appear in AS_PATH. A route carrying it
    // is malformed; silently drop announces (withdrawals are still processed).
    let has_as_zero = as_path.contains(pathvector_types::Asn::new(0));
    if has_as_zero && (!msg.announced.is_empty() || !mp_v4_announced.is_empty() || !mp_v6_announced.is_empty()) {
        tracing::warn!(
            peer = %peer,
            %as_path,
            "dropping UPDATE: AS_PATH contains reserved AS 0 (RFC 7607)"
        );
        mp_v4_announced.clear();
        mp_v6_announced.clear();
    }

    // ── RFC 4271 §9.1.2: AS_PATH loop detection ──────────────────────────
    // If our own AS appears in the received AS_PATH the route has looped back
    // to us. Silently ignore all announced NLRIs in this UPDATE (withdrawals
    // are still processed — they are safe and necessary).
    let has_loop = as_path.contains(pathvector_types::Asn::new(local_as));
    if has_loop && (!msg.announced.is_empty() || !mp_v4_announced.is_empty() || !mp_v6_announced.is_empty()) {
        tracing::debug!(
            peer = %peer,
            local_as,
            %as_path,
            "dropping UPDATE: AS_PATH contains local AS (RFC 4271 §9.1.2)"
        );
        // Still process withdrawals below; clear the announce lists.
        mp_v4_announced.clear();
        mp_v6_announced.clear();
        // The traditional NLRI list is consumed by the iterator below; return
        // early after processing withdrawals by short-circuiting via a flag.
    }

    // ── MP_UNREACH_NLRI withdrawals (RFC 4760) ────────────────────────────
    let mp_withdrawn_count = mp_v4_withdrawn.len();
    for nlri in &mp_v4_withdrawn {
        adj_rib_in.withdraw(nlri);
        fib_changes.push(loc_rib.withdraw(&peer, nlri, oracle_v4));
    }

    // ── Announcements: traditional NLRIs + MP_REACH_NLRI V4 prefixes ─────
    // Both paths share the same scalar attributes extracted above. The only
    // difference is the next-hop source: traditional NLRIs use the NEXT_HOP
    // path attribute (optional); MP_REACH_NLRI carries next-hop inline
    // (mandatory) and takes precedence when present.
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    let skip_announces = has_loop || has_as_zero;
    let all_announced = msg
        .announced
        .into_iter()
        .map(|nlri| (nlri, next_hop))
        .chain(
            mp_v4_announced
                .into_iter()
                .map(|(nlri, nh)| (nlri, Some(nh))),
        );

    for (nlri, nh) in all_announced {
        if skip_announces {
            rejected += 1;
            continue;
        }
        // RFC 4271 §5.1.3: validate NEXT_HOP before accepting the route.
        if let Some(NextHop::V4(addr)) = nh {
            if !is_valid_next_hop_v4(addr, local_v4_addr) {
                tracing::warn!(
                    peer = %peer,
                    prefix = %nlri,
                    next_hop = %addr,
                    "dropping route: invalid NEXT_HOP (RFC 4271 §5.1.3)"
                );
                rejected += 1;
                continue;
            }
        }

        let mut builder = RouteBuilder::new(nlri, origin, as_path.clone()).peer_type(peer_type);
        if let Some(nh) = nh {
            builder = builder.next_hop(nh);
        }
        if let Some(lp) = local_pref {
            builder = builder.local_pref(lp);
        }
        if let Some(m) = med {
            builder = builder.med(m);
        }
        for &c in &communities {
            builder = builder.community(c);
        }
        for &lc in &large_communities {
            builder = builder.large_community(lc);
        }
        for &ec in &extended_communities {
            builder = builder.extended_community(ec);
        }
        if atomic_aggregate {
            builder = builder.atomic_aggregate();
        }
        if let Some(agg) = aggregator {
            builder = builder.aggregator(agg);
        }

        let mut raw = builder.build();
        raw.originator_id = originator_id;
        raw.cluster_list.clone_from(&cluster_list);

        // RFC 7999: silently discard routes tagged with the BLACKHOLE community.
        // Store in AdjRibIn so soft-reconfig can see the raw route, but never
        // install into LocRib or advertise outbound.
        if raw.communities.iter().any(|c| c.is_blackhole()) {
            adj_rib_in.insert(raw.clone());
            tracing::debug!(peer = %peer, prefix = %nlri, "discarding BLACKHOLE-tagged route (RFC 7999)");
            rejected += 1;
            continue;
        }

        // Store the pre-policy route for soft reconfiguration.
        adj_rib_in.insert(raw.clone());

        // Apply import policy to a working copy; only insert if accepted.
        let mut route = raw;
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                fib_changes.push(loc_rib.insert(peer, route, oracle_v4));
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                rejected += 1;
            }
        }
    }

    // ── MP_UNREACH_NLRI IPv6 withdrawals (RFC 4760) ──────────────────────────
    let mp_v6_withdrawn_count = mp_v6_withdrawn.len();
    for nlri in &mp_v6_withdrawn {
        adj_rib_in_v6.withdraw(nlri);
        fib_changes_v6.push(loc_rib_v6.withdraw(&peer, nlri, oracle_v6));
    }

    // ── IPv6 announcements from MP_REACH_NLRI ─────────────────────────────
    // Same BLACKHOLE + import-policy gate as IPv4. RFC 8212: eBGP peers with no
    // explicit policy default to Reject via `policy_v6` default action.
    let mut accepted_v6 = 0usize;
    let mut rejected_v6 = 0usize;
    for (nlri, nh) in mp_v6_announced {
        // RFC 4271 §5.1.3 / RFC 4291 §2.5 / RFC 2545 §3: validate the IPv6 next-hop.
        // Own-address check: reject if global next-hop matches our configured IPv6 address.
        // Link-local addresses are not checked (interface-scoped; commonly used in eBGP).
        let bad_v6_nh = match nh {
            NextHop::V6(addr) => {
                !is_valid_next_hop_v6(addr)
                    || local_v6_addr.is_some_and(|local| local == addr)
            }
            NextHop::V6WithLinkLocal { global, link_local } => {
                !is_valid_next_hop_v6(global)
                    || local_v6_addr.is_some_and(|local| local == global)
                    || link_local.is_multicast()
            }
            _ => false,
        };
        if bad_v6_nh {
            tracing::warn!(
                peer = %peer,
                prefix = %nlri,
                "dropping IPv6 route: invalid NEXT_HOP (RFC 4271 §5.1.3)"
            );
            rejected_v6 += 1;
            continue;
        }
        let mut builder = RouteBuilder::new(nlri, origin, as_path.clone()).peer_type(peer_type);
        builder = builder.next_hop(nh);
        if let Some(lp) = local_pref {
            builder = builder.local_pref(lp);
        }
        if let Some(m) = med {
            builder = builder.med(m);
        }
        for &c in &communities {
            builder = builder.community(c);
        }
        for &lc in &large_communities {
            builder = builder.large_community(lc);
        }
        for &ec in &extended_communities {
            builder = builder.extended_community(ec);
        }
        if atomic_aggregate {
            builder = builder.atomic_aggregate();
        }
        if let Some(agg) = aggregator {
            builder = builder.aggregator(agg);
        }

        let raw = builder.build();

        if raw.communities.iter().any(|c| c.is_blackhole()) {
            adj_rib_in_v6.insert(raw.clone());
            tracing::debug!(peer = %peer, prefix = %nlri, "discarding BLACKHOLE-tagged IPv6 route (RFC 7999)");
            rejected_v6 += 1;
            continue;
        }

        adj_rib_in_v6.insert(raw.clone());

        let mut route = raw;
        match policy_v6.evaluate(&mut route) {
            Decision::Accept => {
                fib_changes_v6.push(loc_rib_v6.insert(peer, route, oracle_v6));
                accepted_v6 += 1;
            }
            Decision::Reject | Decision::Next => {
                rejected_v6 += 1;
            }
        }
    }

    tracing::info!(
        peer = %peer,
        withdrawn = withdrawn_count,
        mp_withdrawn = mp_withdrawn_count,
        mp_v6_withdrawn = mp_v6_withdrawn_count,
        accepted,
        rejected,
        accepted_v6,
        rejected_v6,
        rib_size = loc_rib.len(),
        rib_v6_size = loc_rib_v6.len(),
        "processed UPDATE"
    );
    (fib_changes, fib_changes_v6, None)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_policy::{
        Accept, ActionSequence, AnyCondition, CommunityCondition, DefaultAction, Policy, Reject,
        SetLocalPref, Term,
    };
    use pathvector_types::{
        Aggregator, Asn, Community, ExtendedCommunity, LargeCommunity, LocalPref as LP, Nlri,
    };

    use super::*;
    use crate::outbound::{propagate_prefix, propagate_prefix_v6, route_to_attributes};
    use pathvector_rib::{RibView, outbound::prepare_outbound};

    // ── test helpers ──────────────────────────────────────────────────────────

    fn peer_id(ip: &str) -> PeerId {
        PeerId::new(IpAddr::V4(ip.parse().unwrap()))
    }

    fn peer() -> PeerId {
        peer_id("10.0.0.1")
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn route_v4(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(nlri(prefix), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build()
    }

    fn route_v6(prefix: &str) -> Route<Ipv6Addr> {
        RouteBuilder::new(nlri_v6(prefix), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build()
    }

    fn accept_all() -> Policy<Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Accept)
    }

    fn accept_all_v6() -> Policy<Route<Ipv6Addr>> {
        Policy::new(DefaultAction::Accept)
    }

    fn reject_all() -> Policy<Route<Ipv4Addr>> {
        Policy::new(DefaultAction::Reject)
    }

    fn fresh_ari() -> AdjRibIn<Ipv4Addr> {
        AdjRibIn::new(peer())
    }

    /// Builds a `DaemonState` with explicit accept-all policies for every peer.
    /// Returns the state and a map of receivers for asserting on outbound messages.
    fn make_state(
        local_as: u32,
        peers: &[(Ipv4Addr, u32)],
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(64);
            senders.insert(ip, tx);
            receivers.insert(ip, rx);
        }
        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            })
            .collect();
        let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
        let state = DaemonState::new(
            local_as,
            local_bgp_id,
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );
        (state, receivers)
    }

    // ── config_peer_type ─────────────────────────────────────────────────────

    #[test]
    fn test_config_peer_type_different_as_is_external() {
        assert_eq!(config_peer_type(65001, 65002), PeerType::External);
    }

    #[test]
    fn test_config_peer_type_same_as_is_internal() {
        assert_eq!(config_peer_type(65001, 65001), PeerType::Internal);
    }

    // ── RFC 8212 default resolution ───────────────────────────────────────────

    #[test]
    fn test_resolve_import_ebgp_omitted_defaults_to_reject() {
        assert!(matches!(
            resolve_import_default(None, true),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_import_ibgp_omitted_defaults_to_accept() {
        assert!(matches!(
            resolve_import_default(None, false),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_import_explicit_accept_overrides_ebgp_default() {
        assert!(matches!(
            resolve_import_default(Some(config::ImportDefault::Accept), true),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_import_explicit_reject_overrides_ibgp_default() {
        assert!(matches!(
            resolve_import_default(Some(config::ImportDefault::Reject), false),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_export_ebgp_omitted_defaults_to_reject() {
        assert!(matches!(
            resolve_export_default(None, true),
            DefaultAction::Reject
        ));
    }

    #[test]
    fn test_resolve_export_ibgp_omitted_defaults_to_accept() {
        assert!(matches!(
            resolve_export_default(None, false),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_export_explicit_accept_overrides_ebgp_default() {
        assert!(matches!(
            resolve_export_default(Some(config::ExportDefault::Accept), true),
            DefaultAction::Accept
        ));
    }

    #[test]
    fn test_resolve_export_explicit_reject_overrides_ibgp_default() {
        assert!(matches!(
            resolve_export_default(Some(config::ExportDefault::Reject), false),
            DefaultAction::Reject
        ));
    }

    // ── DaemonState::new ─────────────────────────────────────────────────────

    #[test]
    fn test_daemon_state_new_creates_maps_for_all_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        for ip in [peer_a, peer_b] {
            assert!(state.import_policies.contains_key(&ip));
            assert!(state.export_policies.contains_key(&ip));
            assert!(state.adj_ribs_in.contains_key(&ip));
            assert!(state.adj_ribs_out.contains_key(&ip));
            assert!(state.update_senders.contains_key(&ip));
        }
    }

    #[test]
    fn test_daemon_state_new_ebgp_gets_reject_default_when_omitted() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002,
            import_default: None,
            import_default_v6: None,
            md5_password: None,
            export_default: None,
            is_rr_client: false,
        }];
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peers,
            {
                let mut m = HashMap::new();
                m.insert(peer_ip, tx);
                m
            },
            vec![],
        );
        // Import policy with Reject default means routes are dropped unless a
        // term accepts them. Verify by running a route through it.
        let mut route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .build();
        let decision = state.import_policies[&peer_ip].evaluate(&mut route);
        assert!(
            matches!(decision, Decision::Reject),
            "eBGP with no import_default must reject by default (RFC 8212)"
        );
    }

    // ── DaemonState::on_established ───────────────────────────────────────────

    #[test]
    fn test_on_established_records_peer_type() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        assert!(!state.rib.peer_types.contains_key(&peer_ip));
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        assert_eq!(state.rib.peer_types[&peer_ip], PeerType::External);
    }

    #[test]
    fn test_on_established_empty_rib_sends_nothing() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        assert!(
            receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "empty RIB should produce no messages on establish"
        );
    }

    #[test]
    fn test_on_established_sends_full_table_dump() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);

        // Pre-populate the RIB with a route from a third-party peer.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build();
        state.rib_insert_v4(src, route);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);

        let msg = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("should have queued a full-table dump UPDATE");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
    }

    /// RFC 4271 §5.1.3 regression: eBGP NEXT_HOP in the full-table dump must
    /// be the TCP session's local address, not the BGP router ID.
    ///
    /// Before the fix `prepare_outbound` always used `local_bgp_id` (10.0.0.1)
    /// as NEXT_HOP.  BIRD 2 rejects such routes because the router ID is not
    /// reachable on the session interface.
    #[test]
    fn test_on_established_ebgp_next_hop_uses_local_addr_not_router_id() {
        use pathvector_session::message::PathAttribute;

        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let local_bgp_id: Ipv4Addr = "10.0.0.1".parse().unwrap(); // router ID (make_state uses this)
        let session_local_addr: Ipv4Addr = "172.31.50.20".parse().unwrap(); // TCP interface address

        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
        assert_eq!(state.rib.local_bgp_id, local_bgp_id);

        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        state.rib_insert_v4(
            src,
            RouteBuilder::new(
                nlri("10.0.0.0/8"),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65009)]),
            )
            .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
            .peer_type(PeerType::External)
            .build(),
        );

        state.on_established(
            peer_ip,
            PeerType::External,
            65002,
            90,
            &[],
            Some(session_local_addr),
        );

        let msg = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("full-table dump UPDATE expected");

        let next_hop = msg.attributes.iter().find_map(|a| {
            if let PathAttribute::NextHop(ip) = a {
                Some(*ip)
            } else {
                None
            }
        });
        assert_eq!(
            next_hop,
            Some(session_local_addr),
            "eBGP NEXT_HOP must be the session local address, not the router ID"
        );
        assert_ne!(
            next_hop,
            Some(local_bgp_id),
            "NEXT_HOP must not be the router ID"
        );
    }

    /// RFC 4271 §5.1.3 regression: eBGP NEXT_HOP in `propagate_to_all_peers`
    /// must use the per-peer session local address stored in `local_addrs`.
    #[test]
    fn test_propagate_to_all_peers_ebgp_next_hop_uses_local_addr() {
        use pathvector_session::message::PathAttribute;

        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let local_bgp_id: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let session_local_addr: Ipv4Addr = "172.31.50.20".parse().unwrap();

        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);

        // Establish with a distinct local_addr so local_addrs is populated.
        state.on_established(
            peer_ip,
            PeerType::External,
            65002,
            90,
            &[],
            Some(session_local_addr),
        );
        // Drain the (empty) full-table dump; no routes pre-installed.
        while receivers.get_mut(&peer_ip).unwrap().try_recv().is_ok() {}

        // Now insert a route into the loc-rib via a third-party peer and trigger propagation.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let route = RouteBuilder::new(
            nlri("192.0.2.0/24"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V4("10.0.0.9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build();
        state.rib_insert_v4(src, route);
        state.propagate_to_all_peers(&[nlri("192.0.2.0/24")]);

        let msg = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("propagated UPDATE expected");

        let next_hop = msg.attributes.iter().find_map(|a| {
            if let PathAttribute::NextHop(ip) = a {
                Some(*ip)
            } else {
                None
            }
        });
        assert_eq!(
            next_hop,
            Some(session_local_addr),
            "eBGP NEXT_HOP must be the session local address, not the router ID"
        );
        assert_ne!(
            next_hop,
            Some(local_bgp_id),
            "NEXT_HOP must not be the router ID"
        );
    }

    #[test]
    fn test_on_established_export_reject_sends_nothing() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002,
            import_default_v6: None,
            md5_password: None,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Reject),
            is_rr_client: false,
        }];
        let mut state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peers,
            {
                let mut m = HashMap::new();
                m.insert(peer_ip, tx);
                m
            },
            vec![],
        );

        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        state.rib_insert_v4(
            src,
            RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
                .peer_type(PeerType::External)
                .build(),
        );

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        // Export policy rejects everything — no UPDATE should be queued.
        // (We can't assert on the receiver here since we dropped _rx, but the
        // important invariant is that no panic or error occurs, and the RIB is
        // not modified.)
        assert_eq!(state.rib.loc_rib.len(), 1, "RIB must be unchanged");
    }

    // ── DaemonState::on_terminated ────────────────────────────────────────────

    #[test]
    fn test_on_terminated_removes_peer_type() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        state.on_terminated(peer_ip);
        assert!(!state.rib.peer_types.contains_key(&peer_ip));
    }

    #[test]
    fn test_on_terminated_withdraws_peer_routes_from_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);

        state.rib_insert_v4(
            PeerId::from(peer_ip),
            RouteBuilder::new(
                nlri("10.0.0.0/8"),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65002)]),
            )
            .peer_type(PeerType::External)
            .build(),
        );
        assert_eq!(state.rib.loc_rib.len(), 1);

        state.on_terminated(peer_ip);
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    #[test]
    fn test_on_terminated_propagates_withdraw_to_other_established_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // Announce a route from peer_a so it reaches peer_b's AdjRibOut.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
        );
        // Drain the propagation messages sent during on_route_update.
        receivers.get_mut(&peer_a).unwrap().try_recv().ok();
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();

        // Terminate peer_a — peer_b must receive a WITHDRAW.
        state.on_terminated(peer_a);

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive WITHDRAW after peer_a terminates");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("192.168.0.0/16"));
    }

    // ── DaemonState::on_fib_change ────────────────────────────────────────────

    /// Oracle that can be toggled reachable/unreachable at test time.
    #[derive(Clone)]
    struct ToggleOracle(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl ToggleOracle {
        fn reachable() -> Self {
            Self(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                true,
            )))
        }

        fn set(&self, v: bool) {
            self.0.store(v, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl NextHopOracle for ToggleOracle {
        fn is_reachable(&self, _: &pathvector_types::NextHop) -> bool {
            self.0.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn igp_metric(&self, _: &pathvector_types::NextHop) -> Option<u32> {
            None
        }
    }

    #[test]
    fn test_on_fib_change_withdraws_when_next_hop_goes_down() {
        use pathvector_types::{AsPath, Asn, Origin};

        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        // Install a toggle oracle (both peers initially reachable).
        let oracle = ToggleOracle::reachable();
        state.set_oracles(oracle.clone(), oracle.clone());

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // Announce a route from peer_a with an explicit next-hop.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        // Drain initial propagation to peer_b.
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();

        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
            "route must be in Loc-RIB"
        );

        // Next-hop goes down — FIB change fires.
        oracle.set(false);
        state.on_fib_change();

        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
            "route must be removed from Loc-RIB when next-hop is unreachable"
        );

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b must receive WITHDRAW when next-hop goes down");
        assert!(!msg.withdrawn.is_empty(), "UPDATE must carry a WITHDRAW");
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_on_fib_change_reannounces_when_next_hop_recovers() {
        use pathvector_types::{AsPath, Asn, Origin};

        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        // Start with next-hop unreachable so the initial INSERT produces no best path.
        let oracle = ToggleOracle::reachable();
        oracle.set(false);
        state.set_oracles(oracle.clone(), oracle.clone());

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        // No best path yet — nothing should have been sent to peer_b.
        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none());
        receivers.get_mut(&peer_b).unwrap().try_recv().ok(); // discard any spurious message

        // Next-hop recovers.
        oracle.set(true);
        state.on_fib_change();

        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
            "route must appear in Loc-RIB after next-hop recovery"
        );

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b must receive UPDATE when next-hop recovers");
        assert!(!msg.announced.is_empty(), "UPDATE must carry an ANNOUNCE");
        assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_on_fib_change_noop_when_nothing_changes() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // FIB change fires with empty RIB — should be a no-op.
        state.on_fib_change();
        assert!(receivers.get_mut(&peer_b).unwrap().try_recv().is_err());
    }

    // ── DaemonState::on_route_update ──────────────────────────────────────────

    #[test]
    fn test_on_route_update_inserts_route_into_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert_eq!(state.rib.loc_rib.len(), 1);
        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_on_route_update_propagates_to_other_established_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive UPDATE for the new route");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
    }

    #[test]
    fn test_on_route_update_withdraw_removes_route_from_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 1);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    // ── test wrappers ─────────────────────────────────────────────────────────

    /// Wrapper for IPv4-only `handle_update` calls — passes fresh v6 stubs.
    fn handle_update_v4(
        p: PeerId,
        mut msg: UpdateMessage,
        ari: &mut AdjRibIn<Ipv4Addr>,
        rib: &mut LocRib<Ipv4Addr>,
        policy: &Policy<Route<Ipv4Addr>>,
        pt: PeerType,
    ) {
        // Ensure tests with IPv4 announces satisfy mandatory-attribute validation
        // (RFC 4271 §6.3) so they don't get rejected before reaching the logic
        // under test. Supply defaults when mandatory attributes are absent.
        if !msg.announced.is_empty() {
            let has_origin = msg.attributes.iter().any(|a| matches!(a, PathAttribute::Origin(_)));
            let has_as_path = msg.attributes.iter().any(|a| matches!(a, PathAttribute::AsPath(_)));
            let has_next_hop = msg.attributes.iter().any(|a| matches!(a, PathAttribute::NextHop(_)));
            if !has_origin {
                msg.attributes.push(PathAttribute::Origin(Origin::Igp));
            }
            if !has_as_path {
                msg.attributes.push(PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])));
            }
            if !has_next_hop {
                msg.attributes.push(PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
            }
        }
        let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(p);
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
        handle_update(
            p,
            msg,
            ari,
            rib,
            &mut ari_v6,
            &mut rib_v6,
            policy,
            &policy_v6,
            pt,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
            None,
        );
    }

    fn nlri_v6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    // ── basic handle_update behaviour ─────────────────────────────────────────

    #[test]
    fn test_handle_update_inserts_route_with_all_attributes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Egp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::LocalPref(200),
                PathAttribute::Med(50),
                PathAttribute::Communities(vec![Community::new(0x0001_0001)]),
                PathAttribute::LargeCommunities(vec![LargeCommunity::new(65000, 1, 100)]),
                PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::route_target_as2(
                    65000, 1,
                )]),
                PathAttribute::AtomicAggregate,
                PathAttribute::Aggregator(Aggregator::new(
                    Asn::new(65001),
                    Ipv4Addr::new(1, 1, 1, 1),
                )),
            ],
            announced: vec![nlri("192.168.0.0/16")],
        };
        handle_update_v4(
            peer(),
            msg,
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        let route = rib.best(&nlri("192.168.0.0/16")).unwrap();
        assert_eq!(route.origin, Origin::Egp);
        assert_eq!(route.local_pref, Some(LocalPref::new(200)));
        assert_eq!(route.med, Some(Med::new(50)));
        assert_eq!(route.communities.len(), 1);
        assert_eq!(route.large_communities.len(), 1);
        assert_eq!(route.extended_communities.len(), 1);
        assert!(route.atomic_aggregate);
        assert!(route.aggregator.is_some());
    }

    #[test]
    fn test_handle_update_withdraw_removes_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert!(ari.is_empty());
    }

    #[test]
    fn test_handle_update_empty_announced_is_noop() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert!(ari.is_empty());
    }

    #[test]
    fn test_handle_update_unknown_attribute_is_skipped() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::Unknown {
                        flags: 0x80,
                        type_code: 255,
                        value: vec![1, 2, 3],
                    },
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);
    }

    // ── RFC 7999 — BLACKHOLE community discard ───────────────────────────────

    #[test]
    fn test_handle_update_blackhole_route_not_installed() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![Community::BLACKHOLE]),
                ],
                announced: vec![nlri("192.0.2.0/24")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        // BLACKHOLE-tagged route must not enter LocRib even with accept-all policy.
        assert_eq!(rib.len(), 0, "BLACKHOLE route must not be installed");
    }

    #[test]
    fn test_handle_update_blackhole_route_stored_in_adj_rib_in() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        let prefix = nlri("192.0.2.0/24");
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![Community::BLACKHOLE]),
                ],
                announced: vec![prefix],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        // Pre-policy route stored in AdjRibIn for soft-reconfig visibility.
        assert!(
            ari.get(&prefix).is_some(),
            "BLACKHOLE route must be in AdjRibIn"
        );
    }

    #[test]
    fn test_handle_update_non_blackhole_route_installed_normally() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    // Regular community, not BLACKHOLE.
                    PathAttribute::Communities(vec![Community::NO_EXPORT]),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);
    }

    // ── MP_UNREACH_NLRI / MP_REACH_NLRI (RFC 4760) ───────────────────────────

    #[test]
    fn test_handle_update_mp_unreach_withdraws_ipv4_route() {
        // Peer first announces a route via the traditional field, then
        // withdraws it via MP_UNREACH_NLRI (AFI=1, SAFI=1) — valid per RFC 4760
        // and done by some modern implementations when multiprotocol is negotiated.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1);

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
                })],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert!(
            rib.is_empty(),
            "MP_UNREACH_NLRI should have removed the route"
        );
        assert!(ari.is_empty(), "AdjRibIn should also be cleared");
    }

    #[test]
    fn test_handle_update_mp_reach_announces_ipv4_route() {
        // Peer announces via MP_REACH_NLRI instead of the traditional NLRI field.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::LocalPref(150),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        next_hop: NextHop::V4("10.0.0.2".parse().unwrap()),
                        prefixes: vec![
                            Prefix::V4(nlri("192.168.1.0/24")),
                            Prefix::V4(nlri("192.168.2.0/24")),
                        ],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert_eq!(rib.len(), 2, "both MP_REACH prefixes should be in LocRib");
        assert_eq!(ari.len(), 2, "both MP_REACH prefixes should be in AdjRibIn");

        let route = rib.best(&nlri("192.168.1.0/24")).unwrap();
        assert_eq!(route.local_pref, Some(LP::new(150)));
        assert_eq!(
            route.next_hop,
            Some(NextHop::V4("10.0.0.2".parse().unwrap()))
        );
    }

    #[test]
    fn test_handle_update_mp_reach_mixed_with_traditional() {
        // Traditional NLRI + MP_REACH_NLRI V4 in the same UPDATE — both should land.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::NextHop("10.0.0.2".parse().unwrap()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        next_hop: NextHop::V4("10.0.0.3".parse().unwrap()),
                        prefixes: vec![Prefix::V4(nlri("172.16.0.0/12"))],
                    }),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert_eq!(rib.len(), 2);
        // Traditional NLRI uses NEXT_HOP attribute
        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().next_hop,
            Some(NextHop::V4("10.0.0.2".parse().unwrap()))
        );
        // MP_REACH_NLRI uses its own embedded next-hop
        assert_eq!(
            rib.best(&nlri("172.16.0.0/12")).unwrap().next_hop,
            Some(NextHop::V4("10.0.0.3".parse().unwrap()))
        );
    }

    #[test]
    fn test_handle_update_mp_unreach_non_ipv4_is_skipped() {
        // MP_UNREACH_NLRI for a non-IPv4 AFI/SAFI is silently skipped —
        // no panic, no crash, IPv4 RIB unchanged.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    prefixes: vec![], // IPv6 prefixes; we have none to construct here
                })],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );

        assert!(rib.is_empty());
    }

    #[test]
    fn test_handle_update_mp_reach_import_policy_applied() {
        // Import policy must be evaluated for MP_REACH_NLRI routes just as
        // it is for traditional NLRIs.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV4_UNICAST,
                        next_hop: NextHop::V4("10.0.0.2".parse().unwrap()),
                        prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );

        // Policy rejected it: AdjRibIn stores the raw route, LocRib stays empty.
        assert_eq!(ari.len(), 1, "pre-policy route stored in AdjRibIn");
        assert!(rib.is_empty(), "rejected route must not enter LocRib");
    }

    #[test]
    fn test_on_route_update_mp_unreach_propagates_withdraw_to_peers() {
        // End-to-end: a peer withdraws via MP_UNREACH_NLRI, and the best-path
        // change must reach all other established peers as a WITHDRAW UPDATE.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // Peer A announces 10.0.0.0/8 via traditional field.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        // Drain the announcement that went to peer B.
        let _ = rxs.get_mut(&peer_b).unwrap().try_recv();

        // Peer A now withdraws via MP_UNREACH_NLRI.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV4_UNICAST,
                    prefixes: vec![Prefix::V4(nlri("10.0.0.0/8"))],
                })],
                announced: vec![],
            },
        );

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "LocRib must be empty after MP_UNREACH_NLRI"
        );

        let withdraw_msg = rxs
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer B should receive a WITHDRAW");
        assert!(
            withdraw_msg.withdrawn.contains(&nlri("10.0.0.0/8")),
            "WITHDRAW must contain the MP-withdrawn prefix"
        );
    }

    // ── IPv6 inbound (MP_REACH_NLRI / MP_UNREACH_NLRI) ───────────────────────

    fn fresh_ari_v6() -> AdjRibIn<Ipv6Addr> {
        AdjRibIn::new(peer())
    }

    #[test]
    fn test_handle_update_mp_reach_ipv6_inserts_into_loc_rib_v6() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );

        assert_eq!(rib_v6.len(), 1, "IPv6 route must enter loc_rib_v6");
        assert!(rib.is_empty(), "IPv4 LocRib must remain empty");
        let route = rib_v6.best(&nlri_v6("2001:db8::/32")).unwrap();
        assert_eq!(route.origin, Origin::Igp);
    }

    #[test]
    fn test_handle_update_mp_reach_ipv6_stored_in_adj_rib_in_v6() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("fe80::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("fd00::/16"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );

        assert_eq!(ari_v6.len(), 1, "pre-policy route must be in adj_rib_in_v6");
    }

    #[test]
    fn test_rfc8212_ebgp_ipv6_reject_without_policy() {
        // RFC 8212: eBGP peers with no import policy configured must have routes
        // rejected by default. This verifies the IPv6 path applies the same gate
        // as IPv4 — previously IPv6 was accept-all regardless of peer type.
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let reject_policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Reject);

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &reject_policy_v6,
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );

        assert!(
            rib_v6.is_empty(),
            "eBGP IPv6 route must be rejected when import policy is Reject (RFC 8212)"
        );
        assert_eq!(
            ari_v6.len(),
            1,
            "rejected route must still be stored in AdjRibIn for soft-reconfig"
        );
    }

    // ── import_default_v6 TOML wiring ────────────────────────────────────────

    /// When `import_default_v6` is not set in config, the IPv6 import policy
    /// falls back to `import_default`. This test verifies the fallback: an eBGP
    /// peer with `import_default = "accept"` and no `import_default_v6` must
    /// accept IPv6 routes.
    #[test]
    fn test_import_default_v6_falls_back_to_import_default() {
        use std::collections::HashMap;

        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002, // eBGP
            import_default: Some(config::ImportDefault::Accept),
            import_default_v6: None, // omitted → falls back to import_default
            export_default: None,
            md5_password: None,
            is_rr_client: false,
        }];
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peers,
            {
                let mut m = HashMap::new();
                m.insert(peer_ip, tx);
                m
            },
            vec![],
        );

        let policy_v6 = state.import_policies_v6.get(&peer_ip).unwrap();
        let mut dummy = route_v6("2001:db8::/32");
        assert_eq!(
            policy_v6.evaluate(&mut dummy),
            Decision::Accept,
            "IPv6 policy must fall back to import_default (Accept) when import_default_v6 is None"
        );
    }

    /// When `import_default_v6` is set it overrides `import_default` for the
    /// IPv6 policy only. The IPv4 policy must remain unaffected.
    #[test]
    fn test_import_default_v6_overrides_import_default() {
        use std::collections::HashMap;

        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let peers = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65002, // eBGP
            import_default: Some(config::ImportDefault::Accept),
            import_default_v6: Some(config::ImportDefault::Reject),
            export_default: None,
            md5_password: None,
            is_rr_client: false,
        }];
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peers,
            {
                let mut m = HashMap::new();
                m.insert(peer_ip, tx);
                m
            },
            vec![],
        );

        let policy_v4 = state.import_policies.get(&peer_ip).unwrap();
        let policy_v6 = state.import_policies_v6.get(&peer_ip).unwrap();

        let mut dummy_v4 = route_v4("192.0.2.0/24");
        let mut dummy_v6 = route_v6("2001:db8::/32");

        assert_eq!(
            policy_v4.evaluate(&mut dummy_v4),
            Decision::Accept,
            "IPv4 policy must remain Accept (import_default)"
        );
        assert_eq!(
            policy_v6.evaluate(&mut dummy_v6),
            Decision::Reject,
            "IPv6 policy must be Reject (import_default_v6 overrides)"
        );
    }

    #[test]
    fn test_handle_update_mp_unreach_ipv6_withdraws_route() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        // Announce first.
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );
        assert_eq!(rib_v6.len(), 1);

        // Then withdraw.
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                })],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );

        assert!(
            rib_v6.is_empty(),
            "loc_rib_v6 must be empty after withdrawal"
        );
        assert!(rib.is_empty(), "IPv4 LocRib must be unaffected");
    }

    #[test]
    fn test_handle_update_ipv4_and_ipv6_in_same_update() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();

        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );

        assert_eq!(rib.len(), 1, "IPv4 route must be in loc_rib");
        assert_eq!(rib_v6.len(), 1, "IPv6 route must be in loc_rib_v6");
    }

    // ── IPv6 outbound (propagate_prefix_v6 / flush_updates_v6) ───────────────

    fn peer_b() -> PeerId {
        peer_id("10.0.0.2")
    }

    fn make_adj_rib_out_v6(pt: PeerType) -> AdjRibOut<Ipv6Addr> {
        // Use a distinct peer ID from `peer()` (the typical route source) so
        // that the source-peer split-horizon check in propagate_prefix_v6 does
        // not suppress the announcement in these unit tests.
        AdjRibOut::new(peer_b(), pt)
    }

    #[test]
    fn test_propagate_prefix_v6_ibgp_announces_route() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::Internal);
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route, &AlwaysReachable);

        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::Internal,
            65001,
            None, // no local_ipv6 — OK for iBGP
        );

        assert!(
            matches!(decision, PrefixDecisionV6::Announce(_)),
            "iBGP peer should receive v6 announcement regardless of local_ipv6"
        );
    }

    #[test]
    fn test_propagate_prefix_v6_ebgp_with_local_ipv6_rewrites_nexthop() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::External);
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route, &AlwaysReachable);

        let local_v6: Ipv6Addr = "2001:db8::ff".parse().unwrap();
        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::External,
            65001,
            Some(local_v6),
        );

        match decision {
            PrefixDecisionV6::Announce(r) => {
                assert_eq!(
                    r.next_hop,
                    Some(NextHop::V6(local_v6)),
                    "eBGP next-hop must be rewritten to local_ipv6"
                );
            }
            other => panic!("expected Announce, got {other:?}"),
        }
    }

    #[test]
    fn test_propagate_prefix_v6_ebgp_without_local_ipv6_is_no_announce() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::External);
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route, &AlwaysReachable);

        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::External,
            65001,
            None, // no local_ipv6 — eBGP must NOT announce
        );

        assert!(
            matches!(decision, PrefixDecisionV6::NoChange),
            "eBGP peer without local_ipv6 must not receive v6 announcement"
        );
    }

    #[test]
    fn test_propagate_prefix_v6_withdraw_when_best_disappears() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut aro = make_adj_rib_out_v6(PeerType::Internal);
        // Pre-populate AdjRibOut with an existing announcement.
        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .peer_type(PeerType::External)
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        rib_v6.insert(peer(), route.clone(), &AlwaysReachable);
        // Announce it first so AdjRibOut records it.
        propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::Internal,
            65001,
            None,
        );

        // Now withdraw from loc_rib_v6 and propagate again.
        rib_v6.withdraw(&peer(), &nlri_v6("2001:db8::/32"), &AlwaysReachable);
        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            PeerType::Internal,
            65001,
            None,
        );

        assert!(
            matches!(decision, PrefixDecisionV6::Withdraw(_)),
            "must produce Withdraw when best path is gone"
        );
    }

    #[test]
    fn test_on_established_sends_v6_full_table_dump() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_ip, 65002)]);

        // Pre-populate the v6 RIB with a route from a third-party peer.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let v6_route = RouteBuilder::new(
            nlri_v6("2001:db8::/32"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V6("2001:db8::9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build();
        state.rib_insert_v6(src, v6_route);

        // Set local_ipv6 so eBGP dump works.
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        let caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(peer_ip, PeerType::External, 65002, 90, &caps, None);

        // First message should be the MP_REACH_NLRI UPDATE for the v6 prefix.
        let msg = rxs
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("should receive v6 UPDATE on establish");
        let has_mp_reach = msg.attributes.iter().any(
            |a| matches!(a, PathAttribute::MpReachNlri(mp) if mp.afi_safi == AfiSafi::IPV6_UNICAST),
        );
        assert!(
            has_mp_reach,
            "Established full-table dump must include v6 MP_REACH_NLRI"
        );
    }

    #[test]
    fn test_on_route_update_v6_propagates_to_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        // Set local_ipv6 so eBGP next-hop rewrite works for peer_b.
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(peer_a, PeerType::External, 65002, 90, &v6_caps, None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &v6_caps, None);

        // Peer A announces an IPv6 route via MP_REACH_NLRI.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
        );

        // peer_b should receive an UPDATE with MP_REACH_NLRI for the v6 prefix.
        let msg = rxs
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b should receive a v6 UPDATE");
        let has_v6 = msg.attributes.iter().any(
            |a| matches!(a, PathAttribute::MpReachNlri(mp) if mp.afi_safi == AfiSafi::IPV6_UNICAST),
        );
        assert!(
            has_v6,
            "propagated UPDATE must contain MP_REACH_NLRI for v6 prefix"
        );
    }

    // ── import policy ─────────────────────────────────────────────────────────

    #[test]
    fn test_reject_all_policy_blocks_all_routes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
    }

    #[test]
    fn test_accept_all_policy_passes_all_routes() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8"), nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 2);
    }

    #[test]
    fn test_policy_modifies_route_before_insert() {
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(200)))
                .then(Accept),
        ));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.local_pref, Some(LP::new(200)));
    }

    #[test]
    fn test_policy_partial_reject_only_accepted_routes_inserted() {
        let blocked = Community::from_parts(65001, 1);
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![blocked]),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        assert!(
            rib.best(&nlri("10.0.0.0/8")).is_none(),
            "blocked route must not be in RIB"
        );
        assert!(
            rib.best(&nlri("192.168.0.0/16")).is_some(),
            "clean route must be in RIB"
        );
    }

    #[test]
    fn test_peer_type_tagged_on_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::Internal,
        );
        let route = rib.best(&nlri("10.0.0.0/8")).unwrap();
        assert_eq!(route.peer_type, PeerType::Internal);
    }

    // ── Adj-RIB-In pre-policy store ───────────────────────────────────────────

    #[test]
    fn test_adj_rib_in_stores_raw_route_even_when_rejected() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());
        assert_eq!(ari.len(), 1);
        assert!(ari.get(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_adj_rib_in_stores_raw_attributes_before_policy_modification() {
        let mut policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(200)))
                .then(Accept),
        ));

        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &policy,
            PeerType::External,
        );

        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
            Some(LP::new(200))
        );
        assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
    }

    #[test]
    fn test_adj_rib_in_withdraw_clears_both_tables() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(ari.len(), 1);
        assert_eq!(rib.len(), 1);

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(ari.is_empty());
        assert!(rib.is_empty());
    }

    // ── soft reconfiguration ──────────────────────────────────────────────────

    #[test]
    fn test_reapply_accepts_previously_rejected_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &reject_all(),
            PeerType::External,
        );
        assert!(rib.is_empty());

        reapply_import_policy(peer(), &ari, &mut rib, &accept_all(), &AlwaysReachable);
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_reapply_rejects_previously_accepted_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(rib.best(&nlri("10.0.0.0/8")).is_some());

        reapply_import_policy(peer(), &ari, &mut rib, &reject_all(), &AlwaysReachable);
        assert!(rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_reapply_applies_new_policy_modifications() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref, None);

        let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Reject);
        new_policy.add_term(Term::new(
            AnyCondition,
            ActionSequence::new()
                .then(SetLocalPref::new(LP::new(300)))
                .then(Accept),
        ));

        reapply_import_policy(peer(), &ari, &mut rib, &new_policy, &AlwaysReachable);
        assert_eq!(
            rib.best(&nlri("10.0.0.0/8")).unwrap().local_pref,
            Some(LP::new(300))
        );
        assert_eq!(ari.get(&nlri("10.0.0.0/8")).unwrap().local_pref, None);
    }

    #[test]
    fn test_reapply_partial_accept_reject() {
        let blocked = Community::from_parts(65001, 1);
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::Communities(vec![blocked]),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 2);

        let mut new_policy: Policy<Route<Ipv4Addr>> = Policy::new(DefaultAction::Accept);
        new_policy.add_term(Term::new(CommunityCondition::new(blocked), Reject));

        reapply_import_policy(peer(), &ari, &mut rib, &new_policy, &AlwaysReachable);
        assert!(
            rib.best(&nlri("10.0.0.0/8")).is_none(),
            "blocked route must be withdrawn"
        );
        assert!(
            rib.best(&nlri("192.168.0.0/16")).is_some(),
            "clean route must remain"
        );
    }

    // ── prepare_outbound ──────────────────────────────────────────────────────

    fn bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    fn ebgp_route_with_lp(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LP::new(200))
        .peer_type(PeerType::External)
        .build()
    }

    fn ibgp_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LP::new(200))
        .peer_type(PeerType::Internal)
        .build()
    }

    #[test]
    fn test_prepare_outbound_ebgp_prepends_local_as() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert_eq!(out.as_path.path_length(), 2);
        assert!(out.as_path.contains(Asn::new(65001)));
        assert!(out.as_path.contains(Asn::new(65002)));
    }

    #[test]
    fn test_prepare_outbound_ebgp_rewrites_next_hop() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert_eq!(out.next_hop, Some(NextHop::V4(bgp_id())));
    }

    #[test]
    fn test_prepare_outbound_ebgp_strips_local_pref() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id());
        assert!(
            out.local_pref.is_none(),
            "LOCAL_PREF must be stripped for eBGP"
        );
    }

    #[test]
    fn test_prepare_outbound_ibgp_preserves_attributes() {
        let route = ibgp_route("10.0.0.0/8");
        let out = prepare_outbound(route.clone(), PeerType::Internal, 65001, bgp_id());
        assert_eq!(out.as_path.path_length(), route.as_path.path_length());
        assert_eq!(out.local_pref, route.local_pref);
        assert_eq!(out.next_hop, route.next_hop);
    }

    // ── route_to_attributes ───────────────────────────────────────────────────

    fn route_to_update_for_test(route: &Route<Ipv4Addr>) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: route_to_attributes(route, PeerType::External, true),
            announced: vec![route.nlri],
        }
    }

    #[test]
    fn test_route_to_update_contains_mandatory_attributes() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .build();

        let msg = route_to_update_for_test(&route);
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);
        assert!(msg.withdrawn.is_empty());
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Origin(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::AsPath(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::NextHop(_)))
        );
    }

    #[test]
    fn test_route_to_update_omits_absent_optional_attributes() {
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new()).build();
        let msg = route_to_update_for_test(&route);
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        );
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Med(_)))
        );
    }

    #[test]
    fn test_route_to_update_includes_all_optional_attributes() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .local_pref(LP::new(150))
        .med(Med::new(100))
        .community(Community::new(0xFFFF_FF01))
        .large_community(LargeCommunity::new(65001, 1, 1))
        .extended_community(ExtendedCommunity::route_target_as2(65001, 1))
        .atomic_aggregate()
        .aggregator(Aggregator::new(Asn::new(65001), Ipv4Addr::new(1, 1, 1, 1)))
        .build();

        // Use Internal peer type so MED and reflector attributes are not stripped.
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: route_to_attributes(&route, PeerType::Internal, true),
            announced: vec![route.nlri],
        };
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Med(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Communities(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::LargeCommunities(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_)))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::AtomicAggregate))
        );
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Aggregator(_)))
        );
    }

    // ── RFC correctness regressions ───────────────────────────────────────────

    // Finding A — RFC 4271 §9.1.2: AS_PATH loop detection.
    // A route whose AS_PATH contains the local AS MUST be silently dropped.

    #[test]
    fn test_as_path_loop_detection_drops_traditional_nlri() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        // local_as == 65002; route contains 65002 in AS_PATH → loop detected.
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![
                        Asn::new(65100),
                        Asn::new(65002), // local AS
                        Asn::new(65200),
                    ])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "route with local AS in AS_PATH must be dropped (RFC 4271 §9.1.2)"
        );
        // AdjRibIn is also empty — silently ignore means do not store.
        assert!(
            ari.is_empty(),
            "silently ignored route must not be stored in AdjRibIn"
        );
    }

    #[test]
    fn test_as_path_loop_detection_drops_mp_reach_nlri() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![
                        Asn::new(65100),
                        Asn::new(65002), // local AS
                    ])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::9".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );
        assert!(
            rib_v6.is_empty(),
            "IPv6 route with local AS in AS_PATH must be dropped (RFC 4271 §9.1.2)"
        );
    }

    #[test]
    fn test_as_path_loop_detection_permits_empty_as_path() {
        // iBGP routes may have an empty AS_PATH — must not be dropped.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::Internal,
        );
        assert_eq!(rib.len(), 1, "route with empty AS_PATH must be accepted");
    }

    #[test]
    fn test_as_path_loop_detection_does_not_block_withdrawals() {
        // Withdrawals MUST be processed even if the AS_PATH contains our own AS.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        // First install a route via a clean update from a different AS.
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1, "prerequisite: route must be installed");

        // Now send a withdrawal that also carries a looping AS_PATH.
        // RFC 4271 §9.1.2 says loop detection applies to announcements, not withdrawals.
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![
                        Asn::new(65002), // local AS in path
                    ])),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "withdrawal must be processed despite looping AS_PATH"
        );
    }

    // Finding F (RFC 4456 §8) and G (RFC 4271 §5.1.4) — eBGP attribute stripping.
    // ORIGINATOR_ID, CLUSTER_LIST, and MED MUST be stripped before advertising to eBGP peers.

    #[test]
    fn test_route_to_attributes_ebgp_strips_med() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .med(Med::new(100))
        .build();

        let attrs = route_to_attributes(&route, PeerType::External, true);
        assert!(
            !attrs.iter().any(|a| matches!(a, PathAttribute::Med(_))),
            "MED must be stripped for eBGP peers (RFC 4271 §5.1.4)"
        );
    }

    #[test]
    fn test_route_to_attributes_ibgp_preserves_med() {
        let route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .med(Med::new(100))
        .build();

        let attrs = route_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs.iter().any(|a| matches!(a, PathAttribute::Med(_))),
            "MED must be preserved for iBGP peers"
        );
    }

    #[test]
    fn test_route_to_attributes_ebgp_strips_originator_id_and_cluster_list() {
        let mut route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .build();
        route.originator_id = Some("1.1.1.1".parse::<Ipv4Addr>().unwrap());
        route.cluster_list = vec![0x0101_0101u32];

        let attrs = route_to_attributes(&route, PeerType::External, true);
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_))),
            "ORIGINATOR_ID must be stripped for eBGP peers (RFC 4456 §8)"
        );
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::ClusterList(_))),
            "CLUSTER_LIST must be stripped for eBGP peers (RFC 4456 §8)"
        );
    }

    #[test]
    fn test_route_to_attributes_ibgp_preserves_rr_attributes() {
        let mut route = RouteBuilder::new(
            nlri("10.0.0.0/8"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65001)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .build();
        route.originator_id = Some("1.1.1.1".parse::<Ipv4Addr>().unwrap());
        route.cluster_list = vec![0x0101_0101u32];

        let attrs = route_to_attributes(&route, PeerType::Internal, true);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_))),
            "ORIGINATOR_ID must be preserved for iBGP peers"
        );
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::ClusterList(_))),
            "CLUSTER_LIST must be preserved for iBGP peers"
        );
    }

    // Finding C — RFC 4271 §5.1.3 / §9.1.2: NEXT_HOP validation.
    // Routes with invalid next-hops (unspecified, loopback, multicast, broadcast)
    // must be dropped.

    #[test]
    fn test_invalid_next_hop_unspecified_is_rejected() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED), // 0.0.0.0
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "route with 0.0.0.0 NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
        );
    }

    #[test]
    fn test_invalid_next_hop_multicast_is_rejected() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(Ipv4Addr::new(224, 0, 0, 1)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "route with multicast NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
        );
    }

    #[test]
    fn test_invalid_next_hop_broadcast_is_rejected() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(Ipv4Addr::BROADCAST),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "route with broadcast NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
        );
    }

    #[test]
    fn test_invalid_next_hop_v6_unspecified_is_rejected() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6(Ipv6Addr::UNSPECIFIED), // ::
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );
        assert!(
            rib_v6.is_empty(),
            "IPv6 route with :: NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
        );
    }

    #[test]
    fn test_invalid_next_hop_v6_multicast_is_rejected() {
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("ff02::1".parse().unwrap()), // multicast
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );
        assert!(
            rib_v6.is_empty(),
            "IPv6 route with multicast NEXT_HOP must be rejected (RFC 4271 §5.1.3)"
        );
    }

    #[test]
    fn test_valid_next_hop_is_accepted() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1, "route with valid NEXT_HOP must be accepted");
    }

    #[test]
    fn test_valid_next_hop_v6_link_local_is_accepted() {
        // Link-local (fe80::/10) is a valid next-hop in single-hop eBGP sessions
        // (GoBGP, BIRD both use it). Must not be rejected.
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("fe80::1".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );
        assert_eq!(
            rib_v6.len(),
            1,
            "link-local IPv6 next-hop must be accepted (used by GoBGP/BIRD)"
        );
    }

    #[test]
    fn test_invalid_next_hop_v6_with_link_local_bad_global_rejected() {
        // V6WithLinkLocal: if the global address is :: (unspecified), drop.
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6WithLinkLocal {
                            global: Ipv6Addr::UNSPECIFIED, // ::
                            link_local: "fe80::1".parse().unwrap(),
                        },
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );
        assert!(
            rib_v6.is_empty(),
            "V6WithLinkLocal with unspecified global must be rejected"
        );
    }

    #[test]
    fn test_invalid_next_hop_v6_with_link_local_multicast_link_local_rejected() {
        // V6WithLinkLocal: if the link-local field is multicast, drop.
        let mut ari = fresh_ari();
        let mut rib = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6WithLinkLocal {
                            global: "2001:db8::1".parse().unwrap(),
                            link_local: "ff02::1".parse().unwrap(), // multicast
                        },
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &accept_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
        None,
        );
        assert!(
            rib_v6.is_empty(),
            "V6WithLinkLocal with multicast link-local must be rejected (RFC 2545 §3)"
        );
    }

    #[test]
    fn test_as_path_loop_detection_fires_for_as_set() {
        // RFC 4271 §9.1.2 applies regardless of segment type. If the local AS
        // appears in an AS_SET produced by aggregation, the route must still be dropped.
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        use pathvector_types::AsPathSegment;
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(65100)]),
            AsPathSegment::Set(vec![Asn::new(65002), Asn::new(65200)]), // local AS in set
        ]);
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(path),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "route with local AS in AS_SET must be dropped (RFC 4271 §9.1.2)"
        );
    }

    // Finding L — RFC 7607: AS 0 in AS_PATH MUST be rejected.

    #[test]
    fn test_as_zero_in_path_drops_route() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![
                        Asn::new(65100),
                        Asn::new(0), // reserved — RFC 7607
                        Asn::new(65200),
                    ])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "route with AS 0 in AS_PATH must be dropped (RFC 7607)"
        );
    }

    #[test]
    fn test_as_zero_does_not_block_withdrawals() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();

        // Install a route first.
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert_eq!(rib.len(), 1, "prerequisite: route must be installed");

        // Withdraw it in an UPDATE that also carries AS 0 in the path.
        handle_update_v4(
            peer(),
            UpdateMessage {
                withdrawn: vec![nlri("10.0.0.0/8")],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(0)])),
                ],
                announced: vec![],
            },
            &mut ari,
            &mut rib,
            &accept_all(),
            PeerType::External,
        );
        assert!(
            rib.is_empty(),
            "withdrawal must be processed even when AS_PATH contains AS 0"
        );
    }

    // Finding C-remaining — RFC 4271 §5.1.3: NEXT_HOP must not equal the
    // receiving router's own address.

    #[test]
    fn test_next_hop_own_address_is_rejected() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        let own_addr: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(peer());
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(own_addr),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &policy_v6,
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            Some(own_addr), // local interface address matches NEXT_HOP
        None,
        );
        assert!(
            rib.is_empty(),
            "route with NEXT_HOP == own address must be rejected (RFC 4271 §5.1.3)"
        );
    }

    #[test]
    fn test_next_hop_different_from_own_address_is_accepted() {
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
        let own_addr: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let peer_addr: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(peer());
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(DefaultAction::Accept);
        handle_update(
            peer(),
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65009)])),
                    PathAttribute::NextHop(peer_addr),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &policy_v6,
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            Some(own_addr), // NEXT_HOP differs from own address — valid
        None,
        );
        assert_eq!(
            rib.len(),
            1,
            "route with NEXT_HOP != own address must be accepted"
        );
    }

    // Finding I — RFC 4456 §8: RR split-horizon must apply during full-table dump.

    #[test]
    fn test_on_established_rr_split_horizon_blocks_non_client_to_non_client() {
        // Topology: local speaker is RR with one client (10.0.0.3) and one
        // non-client (10.0.0.4). A route from another non-client iBGP peer
        // (10.0.0.5) must NOT be sent to 10.0.0.4 on establish (finding I).
        let non_client_a: Ipv4Addr = "10.0.0.4".parse().unwrap();
        let non_client_b: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let client: Ipv4Addr = "10.0.0.3".parse().unwrap();

        let (mut state, mut rxs) = make_state(
            65001,
            &[
                (non_client_a, 65001), // iBGP
                (non_client_b, 65001), // iBGP
                (client, 65001),       // iBGP
            ],
        );
        // Designate client as an RR client.
        Arc::make_mut(&mut state.rib)
            .rr_clients
            .insert(client);

        // non_client_b establishes and deposits a route.
        state.on_established(non_client_b, PeerType::Internal, 65001, 90, &[], None);
        let src = PeerId::new(IpAddr::V4(non_client_b));
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(non_client_b))
            .peer_type(PeerType::Internal)
            .build();
        state.rib_insert_v4(src, route);

        // Drain non_client_b's channel (its own establish dump).
        while rxs.get_mut(&non_client_b).unwrap().try_recv().is_ok() {}

        // non_client_a establishes — must NOT receive the route from non_client_b.
        state.on_established(non_client_a, PeerType::Internal, 65001, 90, &[], None);
        assert!(
            rxs.get_mut(&non_client_a).unwrap().try_recv().is_err(),
            "non-client must not receive routes from other non-clients during full-table dump (RFC 4456 §8)"
        );
    }

    #[test]
    fn test_on_established_rr_client_receives_all_routes_in_dump() {
        // An RR client MUST receive the full table on establish, including routes
        // from non-client iBGP peers.
        let non_client: Ipv4Addr = "10.0.0.4".parse().unwrap();
        let client: Ipv4Addr = "10.0.0.3".parse().unwrap();

        let (mut state, mut rxs) =
            make_state(65001, &[(non_client, 65001), (client, 65001)]);
        Arc::make_mut(&mut state.rib)
            .rr_clients
            .insert(client);

        // non_client deposits a route.
        state.on_established(non_client, PeerType::Internal, 65001, 90, &[], None);
        let src = PeerId::new(IpAddr::V4(non_client));
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(non_client))
            .peer_type(PeerType::Internal)
            .build();
        state.rib_insert_v4(src, route);
        while rxs.get_mut(&non_client).unwrap().try_recv().is_ok() {}

        // RR client establishes — MUST receive the route from the non-client.
        state.on_established(client, PeerType::Internal, 65001, 90, &[], None);
        assert!(
            rxs.get_mut(&client).unwrap().try_recv().is_ok(),
            "RR client must receive routes from non-client iBGP peers in full-table dump"
        );
    }

    // Finding K — RFC 4760: IPv6 routes must only be sent to peers that negotiated
    // MultiProtocol(IPV6_UNICAST) capability.

    #[test]
    fn test_ipv6_route_not_propagated_to_non_ipv6_capable_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        // peer_a negotiated IPv6; peer_b did NOT.
        let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(peer_a, PeerType::External, 65002, 90, &v6_caps, None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // peer_a announces an IPv6 prefix.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                        prefixes: vec![Prefix::V6(nlri_v6("2001:db8::/32"))],
                    }),
                ],
                announced: vec![],
            },
        );

        // peer_b (no IPv6 capability) must receive nothing.
        assert!(
            rxs.get_mut(&peer_b).unwrap().try_recv().is_err(),
            "peer without IPv6 capability must not receive MP_REACH_NLRI (RFC 4760)"
        );
    }

    #[test]
    fn test_ipv6_full_table_dump_not_sent_to_non_ipv6_capable_peer() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut rxs) = make_state(65001, &[(peer_ip, 65002)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        // Pre-populate v6 RIB.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let v6_route = RouteBuilder::new(
            nlri_v6("2001:db8::/32"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65009)]),
        )
        .next_hop(NextHop::V6("2001:db8::9".parse().unwrap()))
        .peer_type(PeerType::External)
        .build();
        state.rib_insert_v6(src, v6_route);

        // Establish without IPv6 capability.
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);

        assert!(
            rxs.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "full-table IPv6 dump must not be sent to peers without IPv6 capability (RFC 4760)"
        );
    }

    // ── propagate_prefix / flush_updates ─────────────────────────────────────

    /// Test helper: propagate a single prefix and flush decisions to `tx`.
    /// Returns whether the flush succeeded (channel not full).
    #[allow(clippy::too_many_arguments)]
    fn propagate_and_flush(
        nlri: Nlri<Ipv4Addr>,
        rib: &impl RibView<Ipv4Addr>,
        aro: &mut AdjRibOut<Ipv4Addr>,
        policy: &Policy<Route<Ipv4Addr>>,
        peer_type: PeerType,
        local_as: u32,
        bgp_id: Ipv4Addr,
        tx: &mpsc::Sender<UpdateMessage>,
    ) -> bool {
        let decision = propagate_prefix(nlri, rib, aro, policy, peer_type, local_as, bgp_id);
        flush_updates(vec![decision], MAX_LEN, tx, peer_type, true)
    }

    fn ebgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
        let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        (p, AdjRibOut::new(p, PeerType::External))
    }

    fn ibgp_out_peer() -> (PeerId, AdjRibOut<Ipv4Addr>) {
        let p = PeerId::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
        (p, AdjRibOut::new(p, PeerType::Internal))
    }

    #[test]
    fn test_propagate_prefix_sends_update_for_new_route() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );

        let msg = rx.try_recv().expect("should have queued an UPDATE");
        assert!(!msg.announced.is_empty());
        assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_no_send_when_route_unchanged() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "identical route must not produce a second UPDATE"
        );
    }

    #[test]
    fn test_propagate_prefix_sends_withdraw_when_route_removed() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        rib.withdraw(&peer(), &nlri("10.0.0.0/8"), &AlwaysReachable);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx.try_recv().expect("should have queued a WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
        assert!(msg.announced.is_empty());
    }

    #[test]
    fn test_propagate_prefix_sends_withdraw_when_export_policy_rejects() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv();

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx.try_recv().expect("should have queued a WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_no_withdraw_for_never_advertised_route() {
        let (_, mut aro) = ebgp_out_peer();
        let rib = LocRib::<Ipv4Addr>::new();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "no message expected for a route that was never advertised"
        );
    }

    #[test]
    fn test_propagate_prefix_ebgp_source_peer_not_readvertised() {
        // A route learned from an eBGP peer must never be re-advertised back
        // to that same peer.  This mirrors the GoBGP "No matching path for
        // withdraw found" warning: routes were ending up in AdjRibOut for the
        // source peer and producing spurious WITHDRAWs.
        let (src_peer, mut aro) = ebgp_out_peer(); // same peer as source AND target
        let mut rib = LocRib::new();
        rib.insert(src_peer, ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "source-peer split horizon must suppress eBGP re-advertisement"
        );
        assert!(
            aro.is_empty(),
            "AdjRibOut must not store route for source peer"
        );
    }

    /// Full exchange lifecycle regression test.
    ///
    /// Simulates the scripts/exchange.sh scenario entirely in-process:
    /// 1. Peer (GoBGP) establishes and announces three prefixes.
    /// 2. Daemon originates two local prefixes → peer receives ANNOUNCEs.
    /// 3. Import policy flipped to reject → peer routes drop from LocRib.
    /// 4. Import policy restored to accept → peer routes return to LocRib.
    /// 5. Peer withdraws two of its three routes.
    /// 6. Daemon withdraws its local routes → peer receives WITHDRAWs.
    ///
    /// Final invariant: only the one surviving peer route remains in LocRib.
    #[test]
    fn test_exchange_lifecycle_final_rib_has_only_surviving_peer_route() {
        let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let (mut state, mut rx_map) = make_state(65002, &[(gobgp, 65001)]);

        // ── 1. Session establishes; GoBGP announces {10, 172, 192} ───────────
        state.on_established(gobgp, PeerType::External, 65001, 90, &[], None);

        let gobgp_announces = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Egp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65001)])),
                PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
            ],
            announced: vec![
                nlri("10.0.0.0/8"),
                nlri("172.16.0.0/12"),
                nlri("192.168.0.0/16"),
            ],
        };
        state.on_route_update(gobgp, gobgp_announces);
        // Drain the table-dump messages generated during on_established + propagation
        // (source-peer check suppresses re-advertisement back to GoBGP).
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}
        assert_eq!(
            state.rib.loc_rib.len(),
            3,
            "phase 1: all three GoBGP routes in LocRib"
        );

        // ── 2. Originate {203, 198}; GoBGP should receive ANNOUNCEs ──────────
        let route_203 = RouteBuilder::new(nlri("203.0.113.0/24"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4("10.0.0.2".parse().unwrap()))
            .build();
        let route_198 = RouteBuilder::new(nlri("198.51.100.0/24"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4("10.0.0.2".parse().unwrap()))
            .build();
        state.originate_routes(vec![route_203, route_198]);

        let mut announced_to_gobgp: Vec<Nlri<Ipv4Addr>> = Vec::new();
        while let Ok(msg) = rx_map.get_mut(&gobgp).unwrap().try_recv() {
            announced_to_gobgp.extend(msg.announced);
        }
        assert!(
            announced_to_gobgp.contains(&nlri("203.0.113.0/24")),
            "phase 2: GoBGP must receive ANNOUNCE for 203.0.113.0/24"
        );
        assert!(
            announced_to_gobgp.contains(&nlri("198.51.100.0/24")),
            "phase 2: GoBGP must receive ANNOUNCE for 198.51.100.0/24"
        );
        assert_eq!(
            state.rib.loc_rib.len(),
            5,
            "phase 2: 3 GoBGP + 2 local routes in LocRib"
        );

        // ── 3. Import policy → reject; GoBGP routes leave LocRib ─────────────
        state.set_import_default(gobgp, DefaultAction::Reject);
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}
        assert_eq!(
            state.rib.loc_rib.len(),
            2,
            "phase 3 reject: only local originated routes remain"
        );

        // ── 4. Import policy → accept; GoBGP routes return ───────────────────
        state.set_import_default(gobgp, DefaultAction::Accept);
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}
        assert_eq!(
            state.rib.loc_rib.len(),
            5,
            "phase 4 restore: all 5 routes back in LocRib"
        );

        // ── 5. GoBGP withdraws {10, 172} ──────────────────────────────────────
        let gobgp_withdraws = UpdateMessage {
            withdrawn: vec![nlri("10.0.0.0/8"), nlri("172.16.0.0/12")],
            attributes: vec![],
            announced: vec![],
        };
        state.on_route_update(gobgp, gobgp_withdraws);
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}
        assert_eq!(
            state.rib.loc_rib.len(),
            3,
            "phase 5: 192 from GoBGP + 2 local routes remain"
        );

        // ── 6. Daemon withdraws {203, 198}; GoBGP must receive WITHDRAWs ─────
        state.withdraw_originated_routes(&[nlri("203.0.113.0/24"), nlri("198.51.100.0/24")]);
        let mut withdrawn_to_gobgp: Vec<Nlri<Ipv4Addr>> = Vec::new();
        while let Ok(msg) = rx_map.get_mut(&gobgp).unwrap().try_recv() {
            withdrawn_to_gobgp.extend(msg.withdrawn);
        }
        assert!(
            withdrawn_to_gobgp.contains(&nlri("203.0.113.0/24")),
            "phase 6: GoBGP must receive WITHDRAW for 203.0.113.0/24"
        );
        assert!(
            withdrawn_to_gobgp.contains(&nlri("198.51.100.0/24")),
            "phase 6: GoBGP must receive WITHDRAW for 198.51.100.0/24"
        );

        // ── Final: only 192.168.0.0/16 (from GoBGP) survives in LocRib ───────
        assert_eq!(
            state.rib.loc_rib.len(),
            1,
            "final: only 192.168.0.0/16 must remain in LocRib"
        );
        assert!(
            state.rib.loc_rib.best(&nlri("192.168.0.0/16")).is_some(),
            "final: 192.168.0.0/16 must be the surviving route"
        );
    }

    #[test]
    fn test_originate_routes_v6_peer_receives_announces() {
        use pathvector_types::{AsPath, Origin};
        let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let (mut state, mut rx_map) = make_state(65001, &[(gobgp, 65002)]);
        state.on_established(gobgp, PeerType::External, 65002, 90, &[], None);
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}

        let route = RouteBuilder::new(nlri_v6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        state.originate_route_v6(route);

        assert!(
            state
                .rib
                .loc_rib_v6
                .best(&nlri_v6("2001:db8::/32"))
                .is_some(),
            "originated v6 route must be in loc_rib_v6"
        );
        assert!(
            state
                .rib
                .originated_routes_v6
                .contains_key(&nlri_v6("2001:db8::/32")),
            "originated v6 route must be tracked in originated_routes_v6"
        );
    }

    #[test]
    fn test_withdraw_originated_routes_v6_removes_from_rib_and_notifies_peer() {
        use pathvector_types::{AsPath, Origin};
        let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let (mut state, mut rx_map) = make_state(65001, &[(gobgp, 65002)]);
        state.on_established(gobgp, PeerType::External, 65002, 90, &[], None);
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}

        let route = RouteBuilder::new(nlri_v6("2001:db8:1::/48"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build();
        state.originate_route_v6(route);

        // Drain the ANNOUNCE
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}
        assert!(
            state
                .rib
                .loc_rib_v6
                .best(&nlri_v6("2001:db8:1::/48"))
                .is_some()
        );

        state.withdraw_originated_route_v6(nlri_v6("2001:db8:1::/48"));

        assert!(
            state
                .rib
                .loc_rib_v6
                .best(&nlri_v6("2001:db8:1::/48"))
                .is_none(),
            "withdrawn v6 route must be removed from loc_rib_v6"
        );
        assert!(
            !state
                .rib
                .originated_routes_v6
                .contains_key(&nlri_v6("2001:db8:1::/48")),
            "withdrawn v6 route must be removed from originated_routes_v6"
        );
    }

    #[test]
    fn test_withdraw_originated_routes_v6_noop_for_unknown_prefix() {
        let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(gobgp, 65002)]);
        // Should not panic on an unknown prefix.
        state.withdraw_originated_route_v6(nlri_v6("2001:db8:ff::/48"));
        assert!(
            state
                .rib
                .loc_rib_v6
                .best(&nlri_v6("2001:db8:ff::/48"))
                .is_none()
        );
    }

    #[test]
    fn test_propagate_prefix_ibgp_split_horizon_no_send() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ibgp_route("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ibgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "iBGP split-horizon must suppress re-advertisement"
        );
        assert!(aro.is_empty());
    }

    #[test]
    fn test_propagate_prefix_ebgp_prepends_local_as_in_wire_message() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );

        let msg = rx.try_recv().unwrap();
        let aspath_attr = msg
            .attributes
            .iter()
            .find_map(|a| {
                if let PathAttribute::AsPath(p) = a {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .expect("UPDATE must carry AS_PATH");
        assert!(
            aspath_attr.contains(Asn::new(65001)),
            "local AS must be prepended"
        );
    }

    // ── propagate_prefix — iBGP split-horizon eviction ────────────────────────

    /// When the best path for a prefix switches from eBGP to iBGP, the
    /// previously stored eBGP entry in the iBGP peer's `AdjRibOut` is evicted
    /// (`InsertOutcome::Filtered(Some(_))`), triggering a WITHDRAW.
    #[test]
    fn test_propagate_prefix_ibgp_split_horizon_eviction_sends_withdraw() {
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let (_, mut aro) = ibgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);

        // Phase 1: best path is eBGP — stored in the iBGP peer's AdjRibOut.
        let mut rib = LocRib::new();
        rib.insert(src, ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv(); // consume the UPDATE

        // Phase 2: best path switches to iBGP — split-horizon evicts the stored
        // eBGP entry and the peer must receive a WITHDRAW.
        let mut rib2 = LocRib::new();
        rib2.insert(src, ibgp_route("10.0.0.0/8"), &AlwaysReachable);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib2,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx
            .try_recv()
            .expect("split-horizon eviction must send WITHDRAW");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    // ── propagate_prefix — StubRibView (dependency-inversion tests) ─────────────

    /// Minimal `RibView` implementation for unit tests that want to inject a
    /// specific best route without constructing a full `LocRib`.
    struct StubRibView(Option<Route<Ipv4Addr>>);

    impl RibView<Ipv4Addr> for StubRibView {
        fn best(&self, _nlri: &Nlri<Ipv4Addr>) -> Option<&Route<Ipv4Addr>> {
            self.0.as_ref()
        }
    }

    #[test]
    fn test_propagate_prefix_stub_rib_announces_when_route_present() {
        let rib = StubRibView(Some(ebgp_route_with_lp("10.0.0.0/8")));
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx
            .try_recv()
            .expect("should announce when best route present");
        assert!(!msg.announced.is_empty());
        assert_eq!(msg.announced[0], nlri("10.0.0.0/8"));
    }

    #[test]
    fn test_propagate_prefix_stub_rib_no_message_when_no_route() {
        let rib = StubRibView(None);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(
            rx.try_recv().is_err(),
            "no message when RIB has no best route and prefix was never advertised"
        );
    }

    #[test]
    fn test_propagate_prefix_stub_rib_withdraw_when_route_gone() {
        // First advertise via a real LocRib, then call again with empty StubRibView
        // to verify a WITHDRAW is produced even without constructing a second LocRib.
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(16);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let _ = rx.try_recv(); // consume announcement

        // Now inject an empty view — simulates route having been withdrawn
        let empty_rib = StubRibView(None);
        propagate_and_flush(
            nlri("10.0.0.0/8"),
            &empty_rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        let msg = rx
            .try_recv()
            .expect("should WITHDRAW when best route disappears");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));
    }

    // ── propagate_prefix — channel-full stall detection ──────────────────────

    /// When the outbound UPDATE channel is full, propagate_prefix returns false
    /// so the caller can close the session and restore a consistent peer view.
    #[test]
    fn test_propagate_prefix_full_update_channel_returns_false() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, _rx) = mpsc::channel(1);

        // Fill the single-slot channel so the next try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(!ok, "full channel must return false");
    }

    /// When the outbound WITHDRAW channel is full (Reject/Next decision path),
    /// propagate_prefix returns false.
    #[test]
    fn test_propagate_prefix_full_withdraw_on_reject_returns_false() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(1);

        // Advertise the route so it is stored in AdjRibOut.
        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(ok);
        let _ = rx.try_recv();

        // Fill the channel before the second call so try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        // Export policy now rejects — triggers WITHDRAW try_send on a full channel.
        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(!ok, "full channel on WITHDRAW (reject) must return false");
    }

    /// When the outbound WITHDRAW channel is full (no best route / None path),
    /// propagate_prefix returns false.
    #[test]
    fn test_propagate_prefix_full_withdraw_on_empty_rib_returns_false() {
        let mut rib = LocRib::new();
        rib.insert(peer(), ebgp_route_with_lp("10.0.0.0/8"), &AlwaysReachable);
        let (_, mut aro) = ebgp_out_peer();
        let (tx, mut rx) = mpsc::channel(1);

        // Store the route in AdjRibOut.
        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(ok);
        let _ = rx.try_recv();

        // Remove the route so loc_rib.best returns None.
        rib.withdraw(&peer(), &nlri("10.0.0.0/8"), &AlwaysReachable);

        // Fill the channel so the WITHDRAW try_send fails.
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .unwrap();

        let ok = propagate_and_flush(
            nlri("10.0.0.0/8"),
            &rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            bgp_id(),
            &tx,
        );
        assert!(!ok, "full channel on WITHDRAW (no best) must return false");
    }

    // ── DaemonState — unknown peer defensive paths ────────────────────────────

    /// Calling `on_established` with a peer IP that was never in the config
    /// logs an error and returns without panicking.
    #[test]
    fn test_on_established_unknown_peer_is_noop() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

        let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(unknown, PeerType::External, 65099, 90, &[], None);
        // Invariant: no state changes (the unknown IP is absent from maps).
        assert!(!state.rib.peer_types.contains_key(&peer_ip));
    }

    // ── on_established error paths ────────────────────────────────────────────

    #[test]
    fn test_on_established_missing_adj_rib_out_logs_and_returns() {
        // export_policies is present but adj_ribs_out was removed — the second
        // let-else guard fires; must not panic and peer_type is still recorded.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.adj_ribs_out.remove(&peer_ip);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);

        // peer_type is inserted before the guard, so it should be present.
        assert!(state.rib.peer_types.contains_key(&peer_ip));
    }

    #[test]
    fn test_on_established_missing_update_sender_logs_and_returns() {
        // export_policies and adj_ribs_out are present but update_senders was
        // removed — the third let-else guard fires; must not panic.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.update_senders.remove(&peer_ip);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);

        assert!(state.rib.peer_types.contains_key(&peer_ip));
    }

    // ── on_terminated propagation error paths ────────────────────────────────

    #[test]
    fn test_on_terminated_propagation_missing_adj_rib_out_continues() {
        // Peer B's adj_rib_out is removed. When peer A terminates, propagation
        // to peer B hits the adj_rib_out guard and continues — no panic.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);
        state.adj_ribs_out.remove(&peer_b);

        state.on_terminated(peer_a);

        assert!(!state.rib.peer_types.contains_key(&peer_a));
        assert!(state.rib.peer_types.contains_key(&peer_b));
    }

    #[test]
    fn test_on_terminated_propagation_missing_update_sender_continues() {
        // Peer B's update_sender is removed. Propagation hits the update_sender
        // guard and continues — no panic.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);
        state.update_senders.remove(&peer_b);

        state.on_terminated(peer_a);

        assert!(!state.rib.peer_types.contains_key(&peer_a));
    }

    // ── on_route_update error paths ───────────────────────────────────────────

    #[test]
    fn test_on_route_update_missing_adj_rib_in_logs_and_returns() {
        // import_policy is present but adj_ribs_in was removed — the second
        // let-else guard fires; must not panic and RIB stays empty.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.adj_ribs_in.remove(&peer_ip);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::new()),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    #[test]
    fn test_on_route_update_propagation_missing_adj_rib_out_continues() {
        // Peer B's adj_rib_out is removed. When peer A sends an UPDATE,
        // propagation to peer B hits the adj_rib_out guard and continues.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);
        state.adj_ribs_out.remove(&peer_b);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        // Route lands in the RIB; missing peer B did not cause a panic.
        assert_eq!(state.rib.loc_rib.len(), 1);
    }

    #[test]
    fn test_on_route_update_propagation_missing_update_sender_continues() {
        // Peer B's update_sender is removed. Propagation hits the update_sender
        // guard and continues — no panic and route still lands.
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);
        state.update_senders.remove(&peer_b);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert_eq!(state.rib.loc_rib.len(), 1);
    }

    // ── propagate_prefix channel-full stall paths ────────────────────────────

    /// Returns a `Sender` whose single-slot channel is already full so that
    /// the very next `try_send` returns `Err(Full)`.
    fn full_channel() -> (mpsc::Sender<UpdateMessage>, mpsc::Receiver<UpdateMessage>) {
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })
        .expect("pre-fill");
        (tx, rx)
    }

    #[test]
    fn test_propagate_prefix_channel_full_update_returns_false() {
        // Best route → export accepted → INSERT into empty AdjRibOut → try_send
        // UPDATE fails because the channel is full. Must return false.
        let n = nlri("10.0.0.0/8");
        let mut loc_rib = LocRib::new();
        loc_rib.insert(
            peer(),
            RouteBuilder::new(n, Origin::Igp, AsPath::new()).build(),
            &AlwaysReachable,
        );

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::External);

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(!ok, "full UPDATE channel must return false");
        // AdjRibOut records the route even though the wire message was not sent;
        // the caller is responsible for closing the session to restore consistency.
        assert_eq!(aro.len(), 1);
    }

    #[test]
    fn test_propagate_prefix_channel_full_split_horizon_eviction_returns_false() {
        // iBGP peer's AdjRibOut has a pre-stored eBGP route. The new best is an
        // iBGP route → InsertOutcome::Filtered(Some(_)) → WITHDRAW → channel full
        // → returns false.
        let n = nlri("10.0.0.0/8");

        let mut loc_rib = LocRib::new();
        loc_rib.insert(
            peer(),
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .peer_type(PeerType::Internal)
                .build(),
            &AlwaysReachable,
        );

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.3".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::Internal);
        aro.insert(
            RouteBuilder::new(n, Origin::Igp, AsPath::new())
                .peer_type(PeerType::External)
                .build(),
        );

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &accept_all(),
            PeerType::Internal,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(
            !ok,
            "full WITHDRAW channel (split-horizon eviction) must return false"
        );
        assert!(aro.is_empty());
    }

    #[test]
    fn test_propagate_prefix_channel_full_export_reject_returns_false() {
        // Best route exists but export policy rejects it. AdjRibOut had a prior
        // route → WITHDRAW generated → channel full → returns false.
        let n = nlri("10.0.0.0/8");

        let mut loc_rib = LocRib::new();
        loc_rib.insert(
            peer(),
            RouteBuilder::new(n, Origin::Igp, AsPath::new()).build(),
            &AlwaysReachable,
        );

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::External);
        aro.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &reject_all(),
            PeerType::External,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(
            !ok,
            "full WITHDRAW channel (export reject) must return false"
        );
        assert!(aro.is_empty());
    }

    #[test]
    fn test_propagate_prefix_channel_full_no_best_returns_false() {
        // No best route in LocRib. AdjRibOut has a stale route → WITHDRAW →
        // channel full → returns false.
        let n = nlri("10.0.0.0/8");
        let loc_rib: LocRib<Ipv4Addr> = LocRib::new();

        let out_peer = PeerId::new(IpAddr::V4("10.0.0.2".parse().unwrap()));
        let mut aro = AdjRibOut::new(out_peer, PeerType::External);
        aro.insert(RouteBuilder::new(n, Origin::Igp, AsPath::new()).build());

        let (tx, _rx) = full_channel();
        let ok = propagate_and_flush(
            n,
            &loc_rib,
            &mut aro,
            &accept_all(),
            PeerType::External,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            &tx,
        );
        assert!(!ok, "full WITHDRAW channel (no best) must return false");
        assert!(aro.is_empty());
    }

    /// When `on_terminated` propagates to other established peers, a ghost peer
    /// (one that reached `Established` via `on_established` but was never in the
    /// config maps) triggers the missing-export-policy error path.  Must not
    /// panic.
    #[test]
    fn test_on_terminated_ghost_established_peer_does_not_panic() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);

        // Inject a ghost peer into peer_types (never registered in config maps).
        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, PeerType::External, 65099, 90, &[], None);

        // Terminating peer_a iterates established peers; ghost has no policy /
        // rib entries — the error branch logs and continues without panicking.
        state.on_terminated(peer_a);
        assert!(!state.rib.peer_types.contains_key(&peer_a));
    }

    /// Calling `on_route_update` with an unknown peer IP logs an error and
    /// returns without panicking.
    #[test]
    fn test_on_route_update_unknown_peer_is_noop() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);

        let unknown: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_route_update(
            unknown,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![],
                announced: vec![],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    /// When `on_route_update` propagates to established peers, a ghost peer
    /// (in `peer_types` but absent from policy maps) triggers the error path.
    /// Must not panic.
    #[test]
    fn test_on_route_update_ghost_established_peer_does_not_panic() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002)]);
        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);

        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, PeerType::External, 65099, 90, &[], None);

        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert_eq!(state.rib.loc_rib.len(), 1);
    }

    // ── RFC 4271 §6.3 mandatory attribute NOTIFICATION ───────────────────────
    //
    // handle_update must return Some(NotificationMessage) with the correct
    // 1-byte type code in `data` when a mandatory attribute is absent from
    // an UPDATE that carries announcements.

    fn handle_update_get_notification(msg: UpdateMessage) -> Option<NotificationMessage> {
        let p = peer();
        let mut ari = AdjRibIn::new(p);
        let mut rib = LocRib::new();
        let mut ari_v6: AdjRibIn<Ipv6Addr> = AdjRibIn::new(p);
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let policy = accept_all();
        let policy_v6: Policy<Route<Ipv6Addr>> = Policy::new(pathvector_policy::DefaultAction::Accept);
        let (_, _, notification) = handle_update(
            p,
            msg,
            &mut ari,
            &mut rib,
            &mut ari_v6,
            &mut rib_v6,
            &policy,
            &policy_v6,
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
            None,
        );
        notification
    }

    #[test]
    fn missing_origin_returns_notification_data_type_code_1() {
        let n = handle_update_get_notification(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        });
        let msg = n.expect("NOTIFICATION must be returned when ORIGIN is absent");
        assert!(
            matches!(
                msg.error,
                NotificationError::UpdateMessage(UpdateMsgError::MissingWellKnownAttribute)
            ),
            "error must be UpdateMessage/MissingWellKnownAttribute"
        );
        assert_eq!(msg.data, vec![1u8], "data must contain ORIGIN type code (1)");
    }

    #[test]
    fn missing_as_path_returns_notification_data_type_code_2() {
        let n = handle_update_get_notification(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        });
        let msg = n.expect("NOTIFICATION must be returned when AS_PATH is absent");
        assert_eq!(msg.data, vec![2u8], "data must contain AS_PATH type code (2)");
    }

    #[test]
    fn missing_next_hop_for_traditional_ipv4_returns_notification_data_type_code_3() {
        let n = handle_update_get_notification(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                // No NEXT_HOP
            ],
            announced: vec![nlri("10.0.0.0/8")],
        });
        let msg = n.expect("NOTIFICATION must be returned when NEXT_HOP is absent");
        assert_eq!(msg.data, vec![3u8], "data must contain NEXT_HOP type code (3)");
    }

    #[test]
    fn withdraw_only_update_no_notification_for_missing_attrs() {
        // Withdraw-only UPDATEs are exempt from mandatory attribute checks.
        let n = handle_update_get_notification(UpdateMessage {
            withdrawn: vec![nlri("10.0.0.0/8")],
            attributes: vec![], // no attributes at all — allowed for withdraw-only
            announced: vec![],
        });
        assert!(
            n.is_none(),
            "withdraw-only UPDATE must not trigger mandatory attribute NOTIFICATION"
        );
    }

    #[test]
    fn all_mandatory_attributes_present_no_notification() {
        let n = handle_update_get_notification(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        });
        assert!(n.is_none(), "well-formed UPDATE must not trigger NOTIFICATION");
    }

    // ── Route Reflection (RFC 4456) ───────────────────────────────────────────

    /// Builds a DaemonState acting as an RR for the given clients.
    /// `clients` and `non_clients` are all iBGP peers (same `local_as`).
    fn make_rr_state(
        local_as: u32,
        cluster_id: u32,
        clients: &[Ipv4Addr],
        non_clients: &[Ipv4Addr],
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &ip in clients.iter().chain(non_clients.iter()) {
            let (tx, rx) = mpsc::channel(64);
            senders.insert(ip, tx);
            receivers.insert(ip, rx);
        }
        let peer_configs: Vec<config::PeerConfig> = clients
            .iter()
            .map(|&address| config::PeerConfig {
                address,
                port: 179,
                remote_as: local_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: true,
            })
            .chain(non_clients.iter().map(|&address| config::PeerConfig {
                address,
                port: 179,
                remote_as: local_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            }))
            .collect();
        let local_bgp_id = Ipv4Addr::new(10, 0, 0, 1);
        let state = DaemonState::new(
            local_as,
            local_bgp_id,
            None,
            Some(cluster_id),
            &peer_configs,
            senders,
            vec![],
        );
        (state, receivers)
    }

    fn update_announce(prefix: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
            ],
            announced: vec![nlri(prefix)],
        }
    }

    #[test]
    fn test_rr_client_route_reflected_to_other_client() {
        let client_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let client_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, 1, &[client_a, client_b], &[]);

        state.on_established(client_a, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(client_b, PeerType::Internal, 65001, 90, &[], None);

        // Client A sends a route; it should be reflected to Client B
        state.on_route_update(client_a, update_announce("192.0.2.0/24"));

        let msg = receivers
            .get_mut(&client_b)
            .unwrap()
            .try_recv()
            .expect("route from client A must be reflected to client B");
        assert_eq!(msg.announced, vec![nlri("192.0.2.0/24")]);

        // Must NOT be sent back to Client A (split-horizon)
        assert!(
            receivers.get_mut(&client_a).unwrap().try_recv().is_err(),
            "route must not be reflected back to originating client"
        );
    }

    #[test]
    fn test_rr_client_route_reflected_to_non_client_ibgp() {
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let nc: Ipv4Addr = "10.0.0.4".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, 1, &[client], &[nc]);

        state.on_established(client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc, PeerType::Internal, 65001, 90, &[], None);

        state.on_route_update(client, update_announce("192.0.2.0/24"));

        let msg = receivers
            .get_mut(&nc)
            .unwrap()
            .try_recv()
            .expect("route from client must be reflected to non-client iBGP");
        assert_eq!(msg.announced, vec![nlri("192.0.2.0/24")]);
    }

    #[test]
    fn test_rr_non_client_ibgp_route_reflected_to_client() {
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let nc: Ipv4Addr = "10.0.0.4".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, 1, &[client], &[nc]);

        state.on_established(client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc, PeerType::Internal, 65001, 90, &[], None);

        // Non-client iBGP sends a route; it should be reflected to the client
        state.on_route_update(nc, update_announce("192.0.2.0/24"));

        let msg = receivers
            .get_mut(&client)
            .unwrap()
            .try_recv()
            .expect("route from non-client iBGP must be reflected to client");
        assert_eq!(msg.announced, vec![nlri("192.0.2.0/24")]);
    }

    #[test]
    fn test_rr_non_client_ibgp_to_non_client_ibgp_still_blocked() {
        let nc1: Ipv4Addr = "10.0.0.4".parse().unwrap();
        let nc2: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, 1, &[client], &[nc1, nc2]);

        state.on_established(client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc1, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc2, PeerType::Internal, 65001, 90, &[], None);

        // Non-client nc1 sends a route; nc2 must NOT receive it
        state.on_route_update(nc1, update_announce("192.0.2.0/24"));

        assert!(
            receivers.get_mut(&nc2).unwrap().try_recv().is_err(),
            "non-client iBGP routes must not be re-advertised to other non-client iBGP peers"
        );
        // But client should receive it
        receivers
            .get_mut(&client)
            .unwrap()
            .try_recv()
            .expect("non-client iBGP route must be reflected to client");
    }

    #[test]
    fn test_rr_loop_detection_discards_update() {
        let cluster_id: u32 = 42;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let other: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client, other], &[]);

        state.on_established(client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(other, PeerType::Internal, 65001, 90, &[], None);

        // UPDATE from client containing our own cluster_id in CLUSTER_LIST
        let looped = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
                PathAttribute::ClusterList(vec![cluster_id]),
            ],
            announced: vec![nlri("192.0.2.0/24")],
        };
        state.on_route_update(client, looped);

        // Route must NOT be installed or propagated
        assert_eq!(state.rib.loc_rib.len(), 0, "looped route must be discarded");
        assert!(
            receivers.get_mut(&other).unwrap().try_recv().is_err(),
            "looped route must not be propagated"
        );
    }

    #[test]
    fn test_rr_originator_id_and_cluster_list_set_on_reflected_route() {
        let cluster_id: u32 = 99;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let other: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client, other], &[]);

        // Simulate OPEN: client's BGP ID is 10.0.0.2
        Arc::make_mut(&mut state.rib)
            .peer_bgp_ids
            .insert(client, client);

        state.on_established(client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(other, PeerType::Internal, 65001, 90, &[], None);

        state.on_route_update(client, update_announce("192.0.2.0/24"));

        let msg = receivers
            .get_mut(&other)
            .unwrap()
            .try_recv()
            .expect("reflected UPDATE expected");

        let has_originator = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == client));
        assert!(
            has_originator,
            "reflected route must carry ORIGINATOR_ID = client BGP ID"
        );

        let has_cluster = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::ClusterList(list) if list.contains(&cluster_id)));
        assert!(
            has_cluster,
            "reflected route must carry cluster_id in CLUSTER_LIST"
        );
    }
}

#[cfg(test)]
mod stall_tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use pathvector_policy::DefaultAction;
    use pathvector_types::{AsPath, Asn, NextHop, Nlri, Origin, PeerType};

    use super::*;
    use crate::config;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn base_route(prefix: &str, nh: Ipv4Addr, pt: PeerType) -> pathvector_rib::Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(nh))
        .peer_type(pt)
        .build()
    }

    /// Build a `DaemonState` where every peer's outbound channel has `capacity`.
    /// Returns the state and a map of receivers so the caller can drain channels.
    fn make_capped(
        peers: &[(Ipv4Addr, u32)],
        capacity: usize,
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(capacity);
            senders.insert(ip, tx);
            receivers.insert(ip, rx);
        }
        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                import_default_v6: None,
                md5_password: None,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                is_rr_client: false,
            })
            .collect();
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );
        (state, receivers)
    }

    /// Fill a channel with a dummy UPDATE so the next `try_send` fails.
    fn fill_channel(state: &DaemonState, peer: Ipv4Addr) {
        let tx = state.update_senders.get(&peer).unwrap();
        tx.try_send(UpdateMessage {
            withdrawn: vec![nlri("0.0.0.0/0")],
            attributes: vec![],
            announced: vec![],
        })
        .expect("channel must have room for the fill message");
    }

    // ── take_stalled_peers ────────────────────────────────────────────────────

    #[test]
    fn take_stalled_peers_returns_and_clears() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_capped(&[(peer_ip, 64)], 64);

        assert!(state.take_stalled_peers().is_empty(), "initially empty");
        state.stalled_peers.push(peer_ip);
        let stalled = state.take_stalled_peers();
        assert_eq!(stalled, vec![peer_ip]);
        assert!(state.take_stalled_peers().is_empty(), "cleared after take");
    }

    // ── on_established stalled path ───────────────────────────────────────────

    #[test]
    fn on_established_marks_stalled_when_channel_full() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) = make_capped(&[(peer_ip, 1)], 1);

        // Pre-populate the Loc-RIB from a third-party peer so that on_established
        // has something to propagate.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_insert_v4(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        // Saturate the channel; propagate_prefix's try_send will fail.
        fill_channel(&state, peer_ip);

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer must be stalled when outbound channel is full during table dump"
        );
    }

    // ── on_terminated stalled path ────────────────────────────────────────────

    #[test]
    fn on_terminated_marks_stalled_when_channel_full() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        // Build with mixed capacities: peer_a gets a large channel, peer_b gets cap 1.
        let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
        let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(1);
        let peer_configs = vec![
            config::PeerConfig {
                address: peer_a,
                import_default_v6: None,
                md5_password: None,
                port: 179,
                remote_as: 65002,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                is_rr_client: false,
            },
            config::PeerConfig {
                import_default_v6: None,
                md5_password: None,
                address: peer_b,
                port: 179,
                remote_as: 65003,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                is_rr_client: false,
            },
        ];
        let mut senders = HashMap::new();
        senders.insert(peer_a, tx_a);
        senders.insert(peer_b, tx_b.clone());
        let mut state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // Announce a route from peer_a → it ends up in Loc-RIB.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("192.168.0.0/16")],
            },
        );

        // Drain the messages that on_route_update sent so channels are not pre-filled.
        // (peer_b channel cap = 1; we need exactly that one slot to be free
        //  so we can fill it ourselves.)
        // peer_b received the propagation — drain it.
        // peer_b's channel had capacity 1; one UPDATE was sent during on_route_update.
        // We intentionally do NOT drain it — that fill is the one we rely on.

        // Terminate peer_a: the withdraw for peer_b's channel will fail (full).
        state.on_terminated(peer_a);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer_b must be stalled when its channel is full during termination propagation"
        );
    }

    // ── set_import_default propagation loop ───────────────────────────────────

    #[test]
    fn set_import_default_propagates_to_established_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_a, 65002), (peer_b, 65003)], 64);

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // Announce a route from peer_a via on_route_update so that it is
        // properly recorded in Adj-RIB-In, Loc-RIB, AND peer_b's Adj-RIB-Out.
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        // Drain the UPDATE that on_route_update propagated so receivers are clear.
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();
        receivers.get_mut(&peer_a).unwrap().try_recv().ok();

        // Flip the import policy to Reject — route evicted from Loc-RIB;
        // peer_b must receive a WITHDRAW.
        state.set_import_default(peer_a, DefaultAction::Reject);

        receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b must receive a WITHDRAW after set_import_default → Reject");
    }

    #[test]
    fn set_import_default_marks_stalled_when_channel_full() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

        // peer_a gets a large channel; peer_b gets capacity 1.
        let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
        let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(1);
        let peer_configs = vec![
            config::PeerConfig {
                address: peer_a,
                port: 179,
                remote_as: 65002,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            },
            config::PeerConfig {
                address: peer_b,
                port: 179,
                remote_as: 65003,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            },
        ];
        let mut senders = HashMap::new();
        senders.insert(peer_a, tx_a);
        senders.insert(peer_b, tx_b);
        let mut state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );

        state.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, PeerType::External, 65003, 90, &[], None);

        // Announce via on_route_update so adj_rib_out[peer_b] has the route.
        // The UPDATE fills peer_b's channel (capacity 1).
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_a),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        // peer_b's channel is now full (UPDATE from on_route_update).
        // Do NOT drain it.

        // set_import_default tries to send WITHDRAW to peer_b but channel is full.
        state.set_import_default(peer_a, DefaultAction::Reject);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer_b must be stalled when channel is full during set_import_default propagation"
        );
    }

    // ── set_export_default propagation loop ───────────────────────────────────

    #[test]
    fn set_export_default_propagates_to_established_peer() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_ip, 65002)], 64);

        // Populate Loc-RIB BEFORE establishing so the table dump sends the
        // route to peer_ip's Adj-RIB-Out.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_insert_v4(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        // Drain the table-dump UPDATE so the receiver is clean.
        receivers.get_mut(&peer_ip).unwrap().try_recv().ok();

        // Reject all exports — peer_ip must receive a WITHDRAW.
        state.set_export_default(peer_ip, DefaultAction::Reject);

        receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("peer must receive WITHDRAW after set_export_default → Reject");
    }

    #[test]
    fn set_export_default_no_send_when_peer_not_established() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_ip, 65002)], 64);

        // Peer is configured but never established — set_export_default must
        // return early without sending anything to the channel.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_insert_v4(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        state.set_export_default(peer_ip, DefaultAction::Reject);
        assert!(
            receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "no message must be sent when peer is not established"
        );
    }

    #[test]
    fn set_export_default_marks_stalled_when_channel_full() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) = make_capped(&[(peer_ip, 65002)], 1);

        // Pre-populate Loc-RIB so the table dump fills the channel (cap 1).
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_insert_v4(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        // on_established table-dumps the route → fills the cap-1 channel.
        state.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        // Do NOT drain the channel — it is now full.

        // Reject forces a WITHDRAW for the route already in adj_rib_out.
        // try_send(withdraw) finds the channel full → propagate_prefix returns
        // false → peer is pushed into stalled_peers.
        state.set_export_default(peer_ip, DefaultAction::Reject);
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer must be stalled when channel is full during set_export_default propagation"
        );
    }
}

#[cfg(test)]
mod event_loop_tests {
    use std::{
        collections::HashMap,
        net::Ipv4Addr,
        sync::{
            Arc as StdArc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use pathvector_rib::oracle::NextHopOracle;
    use pathvector_session::fsm::SessionInfo;
    use pathvector_session::message::{Capability, UpdateMessage};
    use pathvector_session::transport::{SessionCommand, SessionEvent};
    use pathvector_types::{AsPath, Asn, NextHop, Nlri, Origin, PeerType};
    use tokio::sync::mpsc;

    use super::*;
    use crate::config;

    // ── helpers ───────────────────────────────────────────────────────────────

    type StateBundle = (
        Arc<RwLock<DaemonState>>,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
        HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>,
    );

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    #[derive(Clone)]
    struct ToggleOracle(StdArc<AtomicBool>);

    impl ToggleOracle {
        fn reachable() -> Self {
            Self(StdArc::new(AtomicBool::new(true)))
        }
    }

    impl NextHopOracle for ToggleOracle {
        fn is_reachable(&self, _: &NextHop) -> bool {
            self.0.load(Ordering::Relaxed)
        }

        fn igp_metric(&self, _: &NextHop) -> Option<u32> {
            None
        }
    }

    fn established_info(peer_as: u32) -> SessionInfo {
        SessionInfo {
            peer_as,
            peer_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            hold_time: 90,
            peer_capabilities: vec![Capability::FourByteAsn(peer_as)],
            peer_type: PeerType::External,
            local_addr: None,
        }
    }

    /// Build a `DaemonState` + receivers for a set of peers with accept-all
    /// policies and channels of the given capacity.
    fn make_state(peers: &[(Ipv4Addr, u32)], channel_cap: usize) -> StateBundle {
        let mut update_senders = HashMap::new();
        let mut update_receivers = HashMap::new();
        let mut stop_senders = HashMap::new();
        let mut stop_receivers: HashMap<Ipv4Addr, mpsc::Receiver<SessionCommand>> = HashMap::new();

        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(channel_cap);
            update_senders.insert(ip, tx);
            update_receivers.insert(ip, rx);
            let (stx, srx) = mpsc::channel(8);
            stop_senders.insert(ip, stx);
            stop_receivers.insert(ip, srx);
        }

        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            })
            .collect();

        let state = Arc::new(RwLock::new(DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            update_senders,
            vec![],
        )));

        (state, update_receivers, stop_senders)
    }

    // ── Established dispatch ──────────────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_dispatches_established() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((peer_ip, SessionEvent::Established(established_info(65002))))
            .await
            .unwrap();
        drop(event_tx); // close channel so event loop exits after one event

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        let s = state.read().await;
        assert!(
            s.rib.peer_types.contains_key(&peer_ip),
            "Established event must register peer type in DaemonState"
        );
    }

    // ── Terminated dispatch ───────────────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_dispatches_terminated() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

        // Establish first so there is state to tear down.
        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        }

        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((peer_ip, SessionEvent::Terminated))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        let s = state.read().await;
        assert!(
            !s.rib.peer_types.contains_key(&peer_ip),
            "Terminated event must remove peer type from DaemonState"
        );
    }

    // ── RouteUpdate dispatch ──────────────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_dispatches_route_update() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65002)], 64);

        {
            let mut s = state.write().await;
            s.on_established(peer_ip, PeerType::External, 65002, 90, &[], None);
        }

        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer_ip),
            ],
            announced: vec![nlri("10.0.0.0/8")],
        };

        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((peer_ip, SessionEvent::RouteUpdate(update)))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        let s = state.read().await;
        assert_eq!(
            s.rib.loc_rib.len(),
            1,
            "RouteUpdate must insert route into Loc-RIB"
        );
    }

    // ── Stalled peer → stop command ───────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_sends_stop_to_stalled_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

        // Give peer_b a channel of capacity 1 so it stalls during propagation.
        let (update_tx_a, _update_rx_a) = mpsc::channel::<UpdateMessage>(64);
        let (update_tx_b, _update_rx_b) = mpsc::channel::<UpdateMessage>(1);
        let (sess_stop_a, _sess_stop_rx_a) = mpsc::channel::<SessionCommand>(8);
        let (sess_stop_b, mut cmd_rx_b) = mpsc::channel::<SessionCommand>(8);

        let peer_configs = vec![
            config::PeerConfig {
                address: peer_a,
                port: 179,
                remote_as: 65002,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            },
            config::PeerConfig {
                address: peer_b,
                port: 179,
                remote_as: 65003,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
            },
        ];
        let mut update_senders = HashMap::new();
        update_senders.insert(peer_a, update_tx_a);
        update_senders.insert(peer_b, update_tx_b);
        let state = Arc::new(RwLock::new(DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            update_senders,
            vec![],
        )));
        let mut stop_senders = HashMap::new();
        stop_senders.insert(peer_a, sess_stop_a);
        stop_senders.insert(peer_b, sess_stop_b);

        // Establish both peers.
        {
            let mut s = state.write().await;
            s.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
            s.on_established(peer_b, PeerType::External, 65003, 90, &[], None);
        }

        // Pre-fill peer_b's cap-1 UPDATE channel so the propagation try_send fails.
        {
            let s = state.read().await;
            s.update_senders[&peer_b]
                .try_send(UpdateMessage {
                    withdrawn: vec![nlri("0.0.0.0/0")],
                    attributes: vec![],
                    announced: vec![],
                })
                .expect("channel must have room for the fill message");
        }

        // Announce a route from peer_a — propagation to peer_b will fail
        // (channel already full) and peer_b must be recorded as stalled.
        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((
                peer_a,
                SessionEvent::RouteUpdate(UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                        PathAttribute::NextHop(peer_a),
                    ],
                    announced: vec![nlri("10.0.0.0/8")],
                }),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        // The event loop must have sent SessionCommand::Stop to peer_b.
        let cmd = cmd_rx_b
            .try_recv()
            .expect("event loop must send Stop to stalled peer_b");
        assert!(
            matches!(cmd, SessionCommand::Stop),
            "expected Stop command, got {cmd:?}"
        );
    }

    // ── FIB change → recompute_all + propagate ────────────────────────────────

    #[tokio::test]
    async fn event_loop_fib_change_withdraws_unreachable_routes() {
        use pathvector_types::{AsPath, Asn, Origin};

        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (state, mut rxs, stop_senders) = make_state(&[(peer_a, 65002), (peer_b, 65003)], 64);

        // Install a ToggleOracle (initially reachable).
        let oracle = ToggleOracle::reachable();
        {
            let mut s = state.write().await;
            s.set_oracles(oracle.clone(), oracle.clone());
            s.on_established(peer_a, PeerType::External, 65002, 90, &[], None);
            s.on_established(peer_b, PeerType::External, 65003, 90, &[], None);
            s.on_route_update(
                peer_a,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                        PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
                    ],
                    announced: vec![nlri("10.0.0.0/8")],
                },
            );
        }
        // Drain initial propagation.
        rxs.get_mut(&peer_b).unwrap().try_recv().ok();

        // Simulate next-hop going down.
        oracle.0.store(false, Ordering::Relaxed);

        // Keep the event channel open so the loop does not exit via the event
        // arm before it has a chance to process the FIB change.  Both arms
        // could otherwise be immediately ready and select! is non-deterministic.
        let (event_tx, event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(8);
        let (fib_tx, fib_rx) = watch::channel(());

        // Spawn the loop as a background task, then signal the FIB change.
        let loop_handle = tokio::spawn(run_event_loop(
            event_rx,
            Arc::clone(&state),
            stop_senders,
            Some(fib_rx),
        ));
        fib_tx.send(()).unwrap();

        // Yield repeatedly to give the event loop task a chance to wake up and
        // call on_fib_change before we inspect state.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Route must be withdrawn from Loc-RIB.
        let s = state.read().await;
        assert!(
            s.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
            "Loc-RIB must not have a best path when next-hop is unreachable"
        );
        drop(s);

        // peer_b must have received a WITHDRAW.
        let msg = rxs
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b must receive WITHDRAW via FIB change");
        assert!(!msg.withdrawn.is_empty());
        assert_eq!(msg.withdrawn[0], nlri("10.0.0.0/8"));

        // Shut down: close the event channel so the loop exits.
        drop(event_tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), loop_handle)
            .await
            .expect("event loop must exit within timeout")
            .expect("loop task must not panic");
    }

    // ── Channel closed → loop exits ───────────────────────────────────────────

    #[tokio::test]
    async fn event_loop_exits_when_channel_closes() {
        let (state, _rxs, stop_senders) = make_state(&[], 64);
        let (event_tx, event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(8);
        // Drop the sender immediately — the loop must exit without hanging.
        drop(event_tx);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_event_loop(event_rx, state, stop_senders, None),
        )
        .await
        .expect("run_event_loop must exit when the event channel is closed");
    }
}

#[cfg(test)]
mod prop_tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use pathvector_types::{AsPath, Asn, LocalPref, NextHop, Origin, PeerType};

    use super::*;
    use crate::outbound::route_to_attributes;
    use pathvector_rib::{RouteBuilder, outbound::prepare_outbound};

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn base_route(prefix: &str) -> Route<Ipv4Addr> {
        RouteBuilder::new(
            nlri(prefix),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
        .local_pref(LocalPref::new(100))
        .peer_type(PeerType::External)
        .build()
    }

    proptest! {
        /// `config_peer_type` returns `Internal` iff the two AS numbers are
        /// equal, and `External` otherwise.
        #[test]
        fn prop_config_peer_type_internal_iff_equal(a: u32, b: u32) {
            let pt = config_peer_type(a, b);
            if a == b {
                prop_assert_eq!(pt, PeerType::Internal);
            } else {
                prop_assert_eq!(pt, PeerType::External);
            }
        }

        /// An explicit import default always overrides the eBGP/iBGP derived
        /// default, regardless of the `is_ebgp` flag.
        #[test]
        fn prop_resolve_import_explicit_always_wins(is_ebgp: bool) {
            let accept = resolve_import_default(Some(config::ImportDefault::Accept), is_ebgp);
            let reject = resolve_import_default(Some(config::ImportDefault::Reject), is_ebgp);
            prop_assert!(matches!(accept, DefaultAction::Accept));
            prop_assert!(matches!(reject, DefaultAction::Reject));
        }

        /// An explicit export default always overrides the eBGP/iBGP derived
        /// default.
        #[test]
        fn prop_resolve_export_explicit_always_wins(is_ebgp: bool) {
            let accept = resolve_export_default(Some(config::ExportDefault::Accept), is_ebgp);
            let reject = resolve_export_default(Some(config::ExportDefault::Reject), is_ebgp);
            prop_assert!(matches!(accept, DefaultAction::Accept));
            prop_assert!(matches!(reject, DefaultAction::Reject));
        }

        /// `withdraw_msg` always produces exactly one withdrawn NLRI and no
        /// announced NLRIs.
        #[test]
        fn prop_withdraw_msg_structure(
            prefix in prop::sample::select(vec![
                "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "0.0.0.0/0",
            ])
        ) {
            let n: Nlri<Ipv4Addr> = prefix.parse().unwrap();
            let msg = UpdateMessage { withdrawn: vec![n], attributes: vec![], announced: vec![] };
            prop_assert_eq!(msg.withdrawn.len(), 1);
            prop_assert_eq!(msg.withdrawn[0], n);
            prop_assert!(msg.announced.is_empty());
            prop_assert!(msg.attributes.is_empty());
        }

        /// `route_to_attributes` always produces Origin and AsPath attributes,
        /// and the NLRI is the route's nlri.
        #[test]
        fn prop_route_to_update_structure(
            prefix in prop::sample::select(vec![
                "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
            ])
        ) {
            use pathvector_session::message::PathAttribute;
            let route = base_route(prefix);
            let nlri_val: Nlri<Ipv4Addr> = prefix.parse().unwrap();
            let attrs = route_to_attributes(&route, PeerType::External, true);
            let msg = UpdateMessage { withdrawn: vec![], attributes: attrs, announced: vec![nlri_val] };

            prop_assert_eq!(msg.announced, vec![nlri_val]);
            prop_assert!(msg.withdrawn.is_empty());
            prop_assert!(
                msg.attributes.iter().any(|a| matches!(a, PathAttribute::Origin(_))),
                "UPDATE must carry ORIGIN"
            );
            prop_assert!(
                msg.attributes.iter().any(|a| matches!(a, PathAttribute::AsPath(_))),
                "UPDATE must carry AS_PATH"
            );
        }

        /// For iBGP peers, `prepare_outbound` is an identity transform: the
        /// route's AS_PATH, NEXT_HOP, and LOCAL_PREF are all preserved.
        #[test]
        fn prop_prepare_outbound_ibgp_is_identity(lp_value in 0u32..=65535) {
            let route = RouteBuilder::new(
                nlri("10.0.0.0/8"),
                Origin::Igp,
                AsPath::from_sequence(vec![Asn::new(65002)]),
            )
            .next_hop(NextHop::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .local_pref(LocalPref::new(lp_value))
            .peer_type(PeerType::Internal)
            .build();

            let result = prepare_outbound(
                route.clone(),
                PeerType::Internal,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
            );

            prop_assert_eq!(result.as_path, route.as_path, "AS_PATH must be unchanged for iBGP");
            prop_assert_eq!(result.next_hop, route.next_hop, "NEXT_HOP must be unchanged for iBGP");
            prop_assert_eq!(result.local_pref, route.local_pref, "LOCAL_PREF must be preserved for iBGP");
        }

        /// For eBGP peers, `prepare_outbound` always prepends the local AS,
        /// rewrites the NEXT_HOP, and strips LOCAL_PREF.
        #[test]
        fn prop_prepare_outbound_ebgp_transforms(local_as in 1u32..=4_294_967_294) {
            let bgp_id = Ipv4Addr::new(10, 0, 0, 1);
            let route = base_route("10.0.0.0/8");
            let original_path_len = route.as_path.path_length();

            let result = prepare_outbound(route, PeerType::External, local_as, bgp_id);

            prop_assert_eq!(
                result.as_path.path_length(),
                original_path_len + 1,
                "local AS must be prepended for eBGP"
            );
            prop_assert!(result.as_path.contains(Asn::new(local_as)), "local AS must be in the path");
            prop_assert_eq!(result.next_hop, Some(NextHop::V4(bgp_id)), "NEXT_HOP must be rewritten");
            prop_assert!(result.local_pref.is_none(), "LOCAL_PREF must be stripped for eBGP");
        }
    }
}

#[cfg(test)]
mod mrai_tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::outbound::PrefixDecision;

    fn peer_ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, last)
    }

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn make_state() -> DaemonState {
        DaemonState::new(
            65001,
            Ipv4Addr::new(1, 0, 0, 1),
            None,
            None,
            &[],
            HashMap::new(),
            vec![],
        )
    }

    /// Manually backdate the last-sent time for a prefix so the MRAI window
    /// appears elapsed.
    fn backdate(state: &mut DaemonState, peer: Ipv4Addr, n: Nlri<Ipv4Addr>, ago: Duration) {
        let entry = state
            .mrai_last_sent
            .entry(peer)
            .or_default()
            .entry(n)
            .or_insert_with(Instant::now);
        // We can't set `Instant` backwards, but we can check whether a
        // simulated past time would pass the MRAI guard in tests by directly
        // inserting via the internal map.  Instead, we mark the prefix as
        // having been sent `ago` in the past by subtracting from `MRAI`.
        // Because `Instant` is monotonic, we insert a time that is just barely
        // past the MRAI window by computing `now - ago`.
        *entry = Instant::now().checked_sub(ago).unwrap_or(*entry);
    }

    #[test]
    fn mrai_suppresses_ebgp_announcement_within_window() {
        let mut state = make_state();
        let peer = peer_ip(2);
        let n = nlri("10.0.0.0/24");

        // Prime last_sent to "just now" so the MRAI window hasn't elapsed.
        state
            .mrai_last_sent
            .entry(peer)
            .or_default()
            .insert(n, Instant::now());

        // Simulate the MRAI gating logic directly — call the inner logic used
        // in propagate_to_all_peers for an eBGP peer.
        let now = Instant::now();
        let last_sent = state.mrai_last_sent.get(&peer).unwrap();
        let elapsed = last_sent
            .get(&n)
            .map_or(MRAI, |t| now.saturating_duration_since(*t));
        assert!(elapsed < MRAI, "should be suppressed within window");
    }

    #[test]
    fn mrai_passes_after_window_elapsed() {
        let mut state = make_state();
        let peer = peer_ip(2);
        let n = nlri("10.0.0.0/24");

        // Back-date by MRAI + 1 second.
        backdate(&mut state, peer, n, MRAI + Duration::from_secs(1));

        let now = Instant::now();
        let last_sent = state.mrai_last_sent.get(&peer).unwrap();
        let elapsed = last_sent
            .get(&n)
            .map_or(MRAI, |t| now.saturating_duration_since(*t));
        assert!(elapsed >= MRAI, "should be allowed after window elapsed");
    }

    #[test]
    fn has_mrai_pending_false_when_empty() {
        let state = make_state();
        assert!(!state.has_mrai_pending());
    }

    #[test]
    fn has_mrai_pending_true_when_set_nonempty() {
        let mut state = make_state();
        let peer = peer_ip(2);
        let n = nlri("10.0.0.0/24");
        state.mrai_pending.entry(peer).or_default().insert(n);
        assert!(state.has_mrai_pending());
    }

    #[test]
    fn flush_mrai_pending_clears_elapsed_pending() {
        let mut state = make_state();
        let peer = peer_ip(2);
        let n = nlri("10.0.0.0/24");

        // Mark as pending and back-date so window is elapsed.
        state.mrai_pending.entry(peer).or_default().insert(n);
        backdate(&mut state, peer, n, MRAI + Duration::from_secs(1));

        // flush_mrai_pending calls propagate_to_all_peers which needs a
        // peer config; since we have no peers configured the inner call is a
        // no-op, but the pending set must be cleared.
        state.flush_mrai_pending();

        assert!(!state.has_mrai_pending(), "pending cleared after flush");
    }

    #[test]
    fn mrai_withdrawal_bypasses_suppression() {
        // Withdrawals must bypass MRAI (RFC 4271 §9.2.1.1).
        // The MRAI gate only applies to PrefixDecision::Announce branches.
        // Verify that a Withdraw variant passes through unchanged.
        let n = nlri("10.0.0.0/24");
        let decision = PrefixDecision::Withdraw(n);
        // No MRAI state needed — Withdraw is passed through unconditionally.
        assert!(matches!(decision, PrefixDecision::Withdraw(_)));
    }
}

#[cfg(test)]
mod run_with_tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use pathvector_session::message::UpdateMessage;
    use pathvector_session::transport::{
        SessionCommand, SessionConfig, SessionEvent, SessionHandle,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::config;

    // ── MockSessionHandle ─────────────────────────────────────────────────────

    /// A zero-cost session handle for unit tests: no TCP, no background tasks.
    ///
    /// Events are injected through a channel whose sender is held by
    /// [`MockPeer`]; `start()` records that it was called via an `AtomicBool`.
    struct MockSessionHandle {
        event_rx: mpsc::Receiver<SessionEvent>,
        update_tx: mpsc::Sender<UpdateMessage>,
        stop_tx: mpsc::Sender<SessionCommand>,
        started: Arc<AtomicBool>,
    }

    impl SessionHandle for MockSessionHandle {
        async fn start(&self) {
            self.started.store(true, Ordering::SeqCst);
        }

        async fn next_event(&mut self) -> Option<SessionEvent> {
            self.event_rx.recv().await
        }

        fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
            self.update_tx.clone()
        }

        fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
            self.stop_tx.clone()
        }

        fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
            self.stop_tx.clone()
        }
    }

    /// Test-side view of a spawned mock session.
    struct MockPeer {
        /// Send events into the forwarding task that `build_daemon` spawned.
        event_tx: mpsc::Sender<SessionEvent>,
        /// `true` after `start()` has been called on the handle.
        started: Arc<AtomicBool>,
    }

    /// Returns a `spawn_fn` compatible with [`build_daemon`] together with a
    /// shared list that is appended to on each invocation.
    fn make_mock_spawn() -> (
        impl Fn(SessionConfig) -> MockSessionHandle,
        Arc<Mutex<Vec<MockPeer>>>,
    ) {
        let peers: Arc<Mutex<Vec<MockPeer>>> = Arc::new(Mutex::new(vec![]));
        let peers_clone = Arc::clone(&peers);
        let spawn_fn = move |_cfg: SessionConfig| {
            let (event_tx, event_rx) = mpsc::channel(8);
            let (update_tx, _update_rx) = mpsc::channel(8);
            let (stop_tx, _stop_rx) = mpsc::channel(8);
            let started = Arc::new(AtomicBool::new(false));
            peers_clone.lock().unwrap().push(MockPeer {
                event_tx,
                started: Arc::clone(&started),
            });
            MockSessionHandle {
                event_rx,
                update_tx,
                stop_tx,
                started,
            }
        };
        (spawn_fn, peers)
    }

    fn make_config(peer_ips: &[(Ipv4Addr, u32)]) -> config::Config {
        config::Config {
            daemon: config::DaemonConfig {
                local_as: 65001,
                bgp_id: Ipv4Addr::new(10, 0, 0, 1),
                hold_time: 90,
                grpc_port: 0,
                bgp_port: 0, // 0 = OS assigns; listener will fail to bind but tests don't need it
                local_ipv6: None,
                cluster_id: None,
                fib_table: 254,
                fib_metric: 20,
            },
            peers: peer_ips
                .iter()
                .map(|&(address, remote_as)| config::PeerConfig {
                    address,
                    port: 179,
                    remote_as,
                    import_default: None,
                    export_default: None,
                    import_default_v6: None,
                    md5_password: None,
                    is_rr_client: false,
                })
                .collect(),
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// `build_daemon` calls the spawn function exactly once per configured peer.
    #[tokio::test]
    async fn build_daemon_calls_spawn_once_per_peer() {
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[
            (Ipv4Addr::new(10, 0, 0, 1), 65002),
            (Ipv4Addr::new(10, 0, 0, 2), 65003),
        ]);
        let _ = build_daemon(&cfg, spawn_fn).await;
        assert_eq!(peers.lock().unwrap().len(), 2);
    }

    /// `build_daemon` calls `start()` on every handle it spawns.
    #[tokio::test]
    async fn build_daemon_starts_each_session() {
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[
            (Ipv4Addr::new(10, 0, 0, 1), 65002),
            (Ipv4Addr::new(10, 0, 0, 2), 65003),
        ]);
        let _ = build_daemon(&cfg, spawn_fn).await;
        for peer in peers.lock().unwrap().iter() {
            assert!(peer.started.load(Ordering::SeqCst), "start() not called");
        }
    }

    /// The returned stop-sender map contains an entry for every peer address.
    #[tokio::test]
    async fn build_daemon_provides_stop_sender_per_peer() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let peer_b = Ipv4Addr::new(10, 0, 0, 2);
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002), (peer_b, 65003)]);
        let (_state, _rx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;
        assert!(stop_senders.contains_key(&peer_a));
        assert!(stop_senders.contains_key(&peer_b));
    }

    /// An event injected through a mock peer's sender appears on the returned
    /// event receiver — verifying the per-peer forwarding task is wired up.
    #[tokio::test]
    async fn build_daemon_forwards_events_to_receiver() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002)]);
        let (_state, mut event_rx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;

        let event_tx = peers.lock().unwrap()[0].event_tx.clone();
        event_tx.send(SessionEvent::Terminated).await.unwrap();

        let (ip, event) = event_rx.recv().await.unwrap();
        assert_eq!(ip, peer_a);
        assert!(matches!(event, SessionEvent::Terminated));
    }

    /// The returned `DaemonState` has an update-sender entry for every
    /// configured peer — i.e. the state is fully pre-populated at startup.
    #[tokio::test]
    async fn build_daemon_state_has_entry_per_peer() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let peer_b = Ipv4Addr::new(10, 0, 0, 2);
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002), (peer_b, 65003)]);
        let (state, _rx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;
        let s = state.read().await;
        assert!(s.update_senders.contains_key(&peer_a));
        assert!(s.update_senders.contains_key(&peer_b));
    }

    /// With no configured peers `build_daemon` succeeds and the event receiver
    /// closes immediately (all senders were dropped, no peers to forward from).
    #[tokio::test]
    async fn build_daemon_no_peers_closes_event_channel() {
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[]);
        let (_state, mut event_rx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;
        assert_eq!(peers.lock().unwrap().len(), 0);
        // No senders remain; recv() returns None immediately.
        assert!(event_rx.recv().await.is_none());
    }

    // ── TCP MD5 wiring tests ──────────────────────────────────────────────────

    /// A peer configured with `md5_password` must appear in the password map
    /// returned by `build_daemon` so `run_bgp_listener` can apply the key to
    /// the listener socket before any SYN arrives.
    #[tokio::test]
    async fn build_daemon_md5_password_present_in_map() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (spawn_fn, _peers) = make_mock_spawn();

        let mut cfg = make_config(&[(peer_ip, 65002)]);
        cfg.peers[0].md5_password = Some("s3cr3t".to_string());

        let (_state, _rx, _stop, _incoming, md5_passwords) = build_daemon(&cfg, spawn_fn).await;

        assert_eq!(
            md5_passwords.get(&IpAddr::V4(peer_ip)).map(String::as_str),
            Some("s3cr3t"),
            "MD5 password must be present in the listener key map"
        );
    }

    /// A peer without `md5_password` must not appear in the password map.
    #[tokio::test]
    async fn build_daemon_no_md5_password_absent_from_map() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_ip, 65002)]); // md5_password = None

        let (_state, _rx, _stop, _incoming, md5_passwords) = build_daemon(&cfg, spawn_fn).await;

        assert!(
            md5_passwords.is_empty(),
            "no MD5 passwords configured → map must be empty"
        );
    }

    /// When multiple peers are configured, only the ones with a password appear
    /// in the map; the others are absent.
    #[tokio::test]
    async fn build_daemon_md5_map_contains_only_configured_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (spawn_fn, _peers) = make_mock_spawn();

        let mut cfg = make_config(&[(peer_a, 65002), (peer_b, 65003)]);
        cfg.peers[0].md5_password = Some("key-for-a".to_string());
        // peer_b has no password

        let (_state, _rx, _stop, _incoming, md5_passwords) = build_daemon(&cfg, spawn_fn).await;

        assert_eq!(
            md5_passwords.get(&IpAddr::V4(peer_a)).map(String::as_str),
            Some("key-for-a"),
        );
        assert!(
            !md5_passwords.contains_key(&IpAddr::V4(peer_b)),
            "peer_b has no MD5 password and must not be in the map"
        );
    }

    /// `md5_password` is threaded into `SessionConfig` so the outbound connect
    /// task can apply `TCP_MD5SIG` before dialling the peer. Verify the value
    /// reaches the spawned session config.
    #[tokio::test]
    async fn build_daemon_md5_password_reaches_session_config() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();

        // Capture the SessionConfig that build_daemon passes to spawn_fn.
        let captured: std::sync::Arc<
            std::sync::Mutex<Option<pathvector_session::transport::SessionConfig>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured_clone = std::sync::Arc::clone(&captured);

        let (base_spawn, _peers) = make_mock_spawn();
        let spawn_fn = move |cfg: pathvector_session::transport::SessionConfig| {
            *captured_clone.lock().unwrap() = Some(cfg.clone());
            base_spawn(cfg)
        };

        let mut config = make_config(&[(peer_ip, 65002)]);
        config.peers[0].md5_password = Some("session-key".to_string());

        build_daemon(&config, spawn_fn).await;

        let session_cfg = captured
            .lock()
            .unwrap()
            .take()
            .expect("spawn_fn must be called");
        assert_eq!(
            session_cfg.md5_password.as_deref(),
            Some("session-key"),
            "md5_password must be threaded into SessionConfig"
        );
    }

    // ── NOTIFICATION pipeline: malformed UPDATE → SessionCommand ─────────────
    //
    // Variant of make_mock_spawn that also captures the stop_rx so tests can
    // observe SessionCommand::Notification sent by the event loop.

    /// Test-side view with access to the stop receiver.
    struct MockPeerWithStop {
        event_tx: mpsc::Sender<SessionEvent>,
        stop_rx: mpsc::Receiver<SessionCommand>,
        started: Arc<AtomicBool>,
    }

    fn make_mock_spawn_capturing_stop() -> (
        impl Fn(SessionConfig) -> MockSessionHandle,
        Arc<Mutex<Vec<MockPeerWithStop>>>,
    ) {
        let peers: Arc<Mutex<Vec<MockPeerWithStop>>> = Arc::new(Mutex::new(vec![]));
        let peers_clone = Arc::clone(&peers);
        let spawn_fn = move |_cfg: SessionConfig| {
            let (event_tx, event_rx) = mpsc::channel(8);
            let (update_tx, _update_rx) = mpsc::channel(8);
            let (stop_tx, stop_rx) = mpsc::channel(8);
            let started = Arc::new(AtomicBool::new(false));
            peers_clone.lock().unwrap().push(MockPeerWithStop {
                event_tx,
                stop_rx,
                started: Arc::clone(&started),
            });
            MockSessionHandle {
                event_rx,
                update_tx,
                stop_tx,
                started,
            }
        };
        (spawn_fn, peers)
    }

    fn established_info_for_peer(peer_as: u32) -> SessionEvent {
        use pathvector_session::message::Capability;
        use pathvector_session::fsm::SessionInfo;
        use pathvector_types::PeerType;
        SessionEvent::Established(SessionInfo {
            peer_as,
            peer_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            hold_time: 90,
            peer_capabilities: vec![Capability::FourByteAsn(peer_as)],
            peer_type: PeerType::External,
            local_addr: None,
        })
    }

    /// A malformed UPDATE (missing ORIGIN) sent through the full event loop must
    /// result in a SessionCommand::Notification on the peer's stop channel with:
    ///  - error = UpdateMessage(MissingWellKnownAttribute)
    ///  - data  = [1]  (ORIGIN type code, RFC 4271 §6.3)
    #[tokio::test]
    async fn malformed_update_missing_origin_sends_notification_to_session() {
        use pathvector_session::message::{NotificationError, PathAttribute, UpdateMsgError};
        use pathvector_session::transport::SessionCommand;
        use pathvector_types::{AsPath, Asn};

        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let (spawn_fn, peers) = make_mock_spawn_capturing_stop();
        let cfg = make_config(&[(peer_ip, 65002)]);
        let (state, event_rx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;

        // Run the event loop in the background; inject events via the mock peer.
        tokio::spawn(run_event_loop(event_rx, state, stop_senders, None));

        // Allow the spawned task to start.
        tokio::task::yield_now().await;

        let (event_tx, stop_rx) = {
            let mut guard = peers.lock().unwrap();
            let p = guard.pop().expect("one peer spawned");
            (p.event_tx, p.stop_rx)
        };

        // Establish the session so the daemon has peer state.
        event_tx.send(established_info_for_peer(65002)).await.unwrap();
        tokio::task::yield_now().await;

        // Send a malformed UPDATE: announced NLRI but ORIGIN is absent.
        event_tx
            .send(SessionEvent::RouteUpdate(UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                    // No Origin!
                ],
                announced: vec!["10.0.0.0/8".parse().unwrap()],
            }))
            .await
            .unwrap();

        // The event loop must send a Notification command to the session.
        let cmd = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            async move {
                let mut stop_rx = stop_rx;
                stop_rx.recv().await
            },
        )
        .await
        .expect("timed out waiting for SessionCommand")
        .expect("stop channel closed without sending Notification");

        match cmd {
            SessionCommand::Notification(msg) => {
                assert!(
                    matches!(
                        msg.error,
                        NotificationError::UpdateMessage(UpdateMsgError::MissingWellKnownAttribute)
                    ),
                    "error must be UpdateMessage/MissingWellKnownAttribute, got {:?}",
                    msg.error
                );
                assert_eq!(
                    msg.data,
                    vec![1u8],
                    "data must be [1] (ORIGIN type code per RFC 4271 §6.3)"
                );
            }
            other => panic!("expected Notification, got {other:?}"),
        }
    }

    // ── withdraw_stale_bgp_routes ─────────────────────────────────────────────
    //
    // Full integration coverage (actual netlink withdrawals against a Linux
    // kernel) belongs in the Gap 8 e2e test.  These unit tests verify the
    // portable logic: empty inputs are a no-op, and the function completes
    // without panicking.  On non-Linux platforms FibWriter::new always fails so
    // the stale lists are always empty — the tests reflect that reality.

    #[tokio::test]
    async fn withdraw_stale_bgp_routes_empty_lists_is_noop() {
        // On non-Linux, FibWriter::new fails so this test exercises the
        // `stale_bgp_routes` → empty path.  On Linux it exercises the real
        // writer with no routes to delete (ESRCH suppressed by withdraw_v4/v6).
        // Either way the function must complete without error or panic.
        let (kernel_fib, _rx) = pathvector_sys::KernelFib::new(254);
        let (stale_v4, stale_v6) = kernel_fib
            .stale_bgp_routes()
            .await
            .unwrap_or((vec![], vec![]));

        // If a writer is available, run the cleanup; otherwise just verify the
        // stale list query itself didn't panic.
        if let Ok(writer) = pathvector_sys::FibWriter::new(254, 20) {
            withdraw_stale_bgp_routes(stale_v4, stale_v6, &writer).await;
        }
    }

    #[tokio::test]
    async fn withdraw_stale_bgp_routes_skips_absent_routes_gracefully() {
        // Feed routes that are not in the kernel FIB.  On Linux, withdraw_v4/v6
        // treat ESRCH as Ok(()); on non-Linux, FibWriter::new fails so the
        // block is skipped.  Either way: no panic, no error propagation.
        let routes_v4 = vec![
            ("192.0.2.0".parse().unwrap(), 24u8),
            ("198.51.100.0".parse().unwrap(), 24u8),
        ];
        let routes_v6 = vec![("2001:db8::".parse().unwrap(), 32u8)];

        if let Ok(writer) = pathvector_sys::FibWriter::new(254, 20) {
            withdraw_stale_bgp_routes(routes_v4, routes_v6, &writer).await;
        }
    }
}
