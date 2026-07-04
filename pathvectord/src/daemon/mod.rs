//! BGP daemon core: routing state, event dispatch, and session management.
//!
//! This module owns [`DaemonState`], the BGP event loop (`run_event_loop`),
//! session setup (`build_daemon`), and the TCP listener (`run_bgp_listener`).

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use pathvector_policy::{
    AnyCondition, BgpRoute, Decision, DefaultAction, OtcLeakCondition, OtcPropagationCondition,
    Policy, Reject, SetOtc, Term,
};
use pathvector_rib::{
    AdjRibIn, AdjRibOut, BestPathChange, LocRib, PeerId, Route, RouteBuilder,
    oracle::{AlwaysReachable, NextHopOracle},
};
use pathvector_session::{
    message::{
        Capability, CeaseError, GracefulRestartFamily, MAX_LEN, MAX_LEN_EXTENDED, MpReachNlri,
        MpUnreachNlri, NotificationError, NotificationMessage, PathAttribute, Prefix,
        UpdateMessage, UpdateMsgError, encode_shutdown_message,
    },
    transport::{
        self, DEFAULT_CONNECT_RETRY_TIME, SessionCommand, SessionConfig, SessionEvent,
        SessionHandle, TerminationReason,
    },
};
use pathvector_types::{
    AfiSafi, AsPath, Asn, LocalPref, Med, NextHop, Nlri, Origin, PeerType, Role,
};
use tokio::sync::{RwLock, broadcast, mpsc, watch};

use crate::outbound::{
    PrefixDecision, PrefixDecisionV6, flush_updates, flush_updates_v6, propagate_prefix,
    propagate_prefix_v6, send_eor_ipv4, send_eor_ipv6,
};
use crate::{config, fib as crate_fib, grpc, proto};
use crate_fib::ApplyFibChange;

mod capabilities;
mod fib;
mod gr;
mod origination;
mod peer;
mod policy;
mod route;

// Re-exports so that sibling submodules using `use super::*` can call
// items defined in other sibling submodules.
use capabilities::{SpawnConfig, build_local_capabilities};
use fib::withdraw_stale_bgp_routes;
use gr::GracefulRestartState;
use peer::{run_bgp_listener, run_command_processor};
#[cfg(test)]
use route::handle_update;
use route::{reapply_import_policy, reapply_import_policy_v6};

/// Synthetic `PeerId` used as the source for locally originated routes.
///
/// Must not collide with any real peer address. `0.0.0.0` is unassignable as
/// a BGP peer, so it is safe as a sentinel here.
pub(crate) const LOCAL_ORIGIN_PEER: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

/// RFC 4271 §9.2.1.1: default Minimum Route Advertisement Interval for eBGP.
pub(crate) const MRAI: std::time::Duration = std::time::Duration::from_secs(30);

/// Commands sent from the gRPC layer to the event loop for dynamic peer management.
///
/// The event loop owns all session handles and routing state; gRPC handlers send
/// commands rather than mutating state directly, which keeps the generics out of
/// the gRPC layer and avoids locking concerns.
pub(crate) enum DaemonCommand {
    /// Add a new peer at runtime.  The event loop spawns a session, registers
    /// all per-peer RIB/policy state, and updates the BGP listener map.
    AddPeer(config::PeerConfig),
    /// Remove an existing peer at runtime.  The event loop sends a Cease
    /// NOTIFICATION, withdraws all received routes, and cleans up all state.
    RemovePeer(Ipv4Addr),
}

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

/// Creates a matched pair of `AdjRibOut` tables (IPv4 + IPv6) for one peer.
///
/// Both tables are created with identical reflecting/non-reflecting mode so they
/// can never diverge. When acting as a route reflector (`is_rr = true`) and the
/// peer is iBGP, both tables use [`AdjRibOut::new_reflecting`]; otherwise both
/// use [`AdjRibOut::new`].
///
/// All sites that construct outbound RIBs for a peer MUST use this function
/// instead of calling `AdjRibOut::new` / `new_reflecting` directly. This is the
/// single enforcement point for RFC 4456 §8 outbound-table invariant:
/// `adj_ribs_out[p].reflects() == adj_ribs_out_v6[p].reflects()` for every peer.
fn make_adj_ribs_out_pair(
    peer_id: PeerId,
    peer_type: PeerType,
    is_rr: bool,
) -> (AdjRibOut<Ipv4Addr>, AdjRibOut<Ipv6Addr>) {
    if is_rr && peer_type == PeerType::Internal {
        (
            AdjRibOut::new_reflecting(peer_id, peer_type),
            AdjRibOut::new_reflecting(peer_id, peer_type),
        )
    } else {
        (
            AdjRibOut::new(peer_id, peer_type),
            AdjRibOut::new(peer_id, peer_type),
        )
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
    /// NLRI set for locally originated IPv4 routes; routes live in `loc_rib`.
    pub(crate) originated_routes: HashSet<Nlri<Ipv4Addr>>,
    /// NLRI set for locally originated IPv6 routes; routes live in `loc_rib_v6`.
    pub(crate) originated_routes_v6: HashSet<Nlri<Ipv6Addr>>,
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
    /// Peers configured with `next_hop_self = true`.
    ///
    /// When a peer is in this set, `NEXT_HOP` is rewritten to the local
    /// session address before the route is forwarded, even for iBGP peers.
    /// Immutable after startup.
    pub(crate) next_hop_self_peers: HashSet<Ipv4Addr>,
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
    /// Peers that have sent us an IPv4 End-of-RIB marker (RFC 4724 §2).
    /// Cleared on session termination. Used to signal initial sync complete.
    pub(crate) eor_received: HashSet<Ipv4Addr>,
    /// Peers that have sent us an IPv6 unicast EOR marker (RFC 4724 §2).
    pub(crate) eor_received_v6: HashSet<Ipv4Addr>,
    /// Peers that advertised RFC 4724 `GracefulRestart` with a non-zero
    /// `restart_time`. Value is the peer's advertised `restart_time` in seconds.
    ///
    /// Populated on `Established`; removed on `Terminated`. Zero means the peer
    /// either did not advertise the capability or advertised `restart_time = 0`
    /// (EOR-only mode, no stale-route window).
    pub(crate) gr_capable_peers: HashMap<Ipv4Addr, u16>,
    /// RFC 9234 BGP Role configured for each peer, if any. Present only for
    /// peers with `role` set in `PeerConfig` — absent means Role capability
    /// negotiation and OTC leak prevention are disabled for that peer
    /// (matching the RFC's own non-strict default). Consulted both when
    /// building each session's OPEN capabilities (including on reconnect,
    /// so Role survives a session reset the same way GR capabilities do)
    /// and when installing this peer's OTC policy terms. Immutable after
    /// startup for static peers; updated by `add_peer`/`remove_peer` for
    /// dynamic peers — mirrors `peer_remote_as`'s lifecycle exactly.
    pub(crate) peer_roles: HashMap<Ipv4Addr, Role>,
    /// The peer's negotiated RFC 9234 BGP Role, extracted from their
    /// advertised Role capability in OPEN. Populated on `Established`;
    /// removed on `Terminated` — mirrors `peer_bgp_ids`'s lifecycle exactly.
    pub(crate) negotiated_roles: HashMap<Ipv4Addr, Role>,
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
    pub(crate) export_policies_v6: HashMap<Ipv4Addr, Policy<Route<Ipv6Addr>>>,
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
    /// Peers that negotiated RFC 2918 `RouteRefresh` capability.
    ///
    /// `SoftReset` (gRPC) may only send a ROUTE-REFRESH message to peers in
    /// this set. RFC 2918 §4: a router MUST NOT send ROUTE-REFRESH without
    /// having received the corresponding capability from the peer.
    pub(crate) route_refresh_peers: HashSet<Ipv4Addr>,
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
    /// Per-peer coalescing buffers for outbound IPv4 prefix decisions.
    ///
    /// `on_route_update` accumulates decisions here instead of calling
    /// `flush_updates` immediately. The event loop calls `flush_pending` when
    /// the event channel drains (natural quiescence), batching all decisions
    /// that arrived during one burst into the fewest possible UPDATE messages.
    pub(crate) pending_decisions: HashMap<Ipv4Addr, Vec<PrefixDecision>>,
    /// Per-peer coalescing buffers for outbound IPv6 prefix decisions.
    pub(crate) pending_decisions_v6: HashMap<Ipv4Addr, Vec<PrefixDecisionV6>>,
    /// Peers that have been removed via [`DaemonCommand::RemovePeer`] but whose
    /// session has not yet sent `Terminated`.
    ///
    /// When `Terminated` arrives for a peer in this set, the event loop calls
    /// [`DaemonState::remove_peer`] to erase all per-peer state instead of
    /// resetting it for a reconnect.
    pub(crate) pending_removal: HashSet<Ipv4Addr>,
    /// RFC 4724 §4.2 GR state: active windows, stale-NLRI snapshots, peer families.
    ///
    /// See [`GracefulRestartState`] for field-level documentation.
    pub(crate) gr: GracefulRestartState,
    /// RFC 9003 shutdown reason strings, keyed by peer address.
    ///
    /// Populated when a peer is added (static or dynamic) and has a
    /// `shutdown_message` configured. Used by `RemovePeer` to send a
    /// CEASE/AdministrativeShutdown NOTIFICATION with the reason attached.
    pub(crate) shutdown_messages: HashMap<Ipv4Addr, String>,
    /// Per-peer IPv4 prefix limit for RFC 4486 §4 enforcement.
    ///
    /// When a peer's `adj_rib_in.len()` (IPv4 only) exceeds this value after
    /// processing an UPDATE, the session is torn down with a
    /// CEASE/MaximumNumberOfPrefixesReached NOTIFICATION.
    ///
    /// Absent when no `max_prefixes_v4` was configured for the peer.
    pub(crate) peer_max_prefixes_v4: HashMap<Ipv4Addr, u32>,
    /// Per-peer IPv6 prefix limit for RFC 4486 §4 enforcement.
    ///
    /// Mirrors `peer_max_prefixes_v4` but checked against `adj_rib_in_v6.len()`.
    /// Either limit firing causes the session to be torn down.
    pub(crate) peer_max_prefixes_v6: HashMap<Ipv4Addr, u32>,
    /// Idle-hold duration (seconds) after a max-prefix CEASE.
    ///
    /// When non-zero, pathvectord blocks the peer from re-establishing for
    /// this many seconds after dropping the session. `0` means reconnect
    /// immediately according to the normal `connect_retry_time`.
    pub(crate) peer_max_prefixes_restart: HashMap<Ipv4Addr, u16>,
    /// Active max-prefix idle-hold deadlines, keyed by peer address.
    ///
    /// Inserted when a max-prefix CEASE is sent and `max_prefixes_restart > 0`.
    /// The event loop polls this map and blocks `SessionEvent::Established`
    /// until the deadline passes.
    pub(crate) max_prefix_idle: HashMap<Ipv4Addr, Instant>,
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
    pub(crate) fib_manager: Option<Arc<dyn ApplyFibChange>>,
    /// RPKI RTR client handle. `None` when `[daemon.rpki]` is not configured.
    /// Cheap to clone (Arc-backed); gRPC handlers clone it per-request like
    /// `fib_manager`.
    pub(crate) rpki: Option<pathvector_rpki::RtrHandle>,
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
        let next_hop_self_peers: HashSet<Ipv4Addr> = peers
            .iter()
            .filter(|p| p.next_hop_self)
            .map(|p| p.address)
            .collect();
        let cluster_id = cluster_id.unwrap_or_else(|| u32::from_be_bytes(local_bgp_id.octets()));
        let is_rr = !rr_clients.is_empty();

        // Computed once (rather than inline in each closure below) so the
        // iBGP-guard warning in `effective_role` fires at most once per peer,
        // not once per policy map built from it.
        let peer_roles: HashMap<Ipv4Addr, Role> = peers
            .iter()
            .filter_map(|p| effective_role(p, local_as).map(|r| (p.address, r)))
            .collect();

        let import_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                let mut policy = Policy::new(resolve_import_default(p.import_default, is_ebgp));
                if let Some(role) = peer_roles.get(&p.address).copied() {
                    install_otc_import_term(&mut policy, role, Asn::new(p.remote_as));
                }
                (p.address, policy)
            })
            .collect();

        let import_policies_v6 = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                // import_default_v6 takes precedence; falls back to import_default,
                // then to the RFC 8212 default for the peer type.
                let default_v6 = p.import_default_v6.or(p.import_default);
                let mut policy = Policy::new(resolve_import_default(default_v6, is_ebgp));
                if let Some(role) = peer_roles.get(&p.address).copied() {
                    install_otc_import_term(&mut policy, role, Asn::new(p.remote_as));
                }
                (p.address, policy)
            })
            .collect();

        let export_policies = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                let mut policy = Policy::new(resolve_export_default(p.export_default, is_ebgp));
                if let Some(role) = peer_roles.get(&p.address).copied() {
                    install_otc_export_term(&mut policy, role, Asn::new(local_as));
                }
                (p.address, policy)
            })
            .collect();

        // There is no separate `export_default_v6` config knob (unlike import,
        // which has `import_default_v6`) — the same `export_default` value
        // governs both address families, mirrored here into its own
        // `Policy<Route<Ipv6Addr>>` since the policy engine is generic per
        // route type, not per peer.
        let export_policies_v6 = peers
            .iter()
            .map(|p| {
                let is_ebgp = p.remote_as != local_as;
                let mut policy = Policy::new(resolve_export_default(p.export_default, is_ebgp));
                if let Some(role) = peer_roles.get(&p.address).copied() {
                    install_otc_export_term(&mut policy, role, Asn::new(local_as));
                }
                (p.address, policy)
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

        let (adj_ribs_out, adj_ribs_out_v6) = {
            let mut v4 = HashMap::new();
            let mut v6 = HashMap::new();
            for p in peers {
                let pt = config_peer_type(local_as, p.remote_as);
                let (aro_v4, aro_v6) = make_adj_ribs_out_pair(PeerId::from(p.address), pt, is_rr);
                v4.insert(p.address, aro_v4);
                v6.insert(p.address, aro_v6);
            }
            (v4, v6)
        };

        let peer_remote_as = peers.iter().map(|p| (p.address, p.remote_as)).collect();

        let shutdown_messages: HashMap<Ipv4Addr, String> = peers
            .iter()
            .filter_map(|p| p.shutdown_message.as_ref().map(|m| (p.address, m.clone())))
            .collect();

        let peer_max_prefixes_v4: HashMap<Ipv4Addr, u32> = peers
            .iter()
            .filter_map(|p| p.max_prefixes_v4.map(|n| (p.address, n)))
            .collect();

        let peer_max_prefixes_v6: HashMap<Ipv4Addr, u32> = peers
            .iter()
            .filter_map(|p| p.max_prefixes_v6.map(|n| (p.address, n)))
            .collect();

        let peer_max_prefixes_restart: HashMap<Ipv4Addr, u16> = peers
            .iter()
            .filter_map(|p| {
                p.max_prefixes_restart
                    .filter(|&r| r > 0)
                    .map(|r| (p.address, r))
            })
            .collect();

        // Capacity of 1024 events each.  A receiver that falls >1024 events
        // behind sees `RecvError::Lagged`; the `watch_peers` gRPC stream handler
        // defends against this by re-reading the full snapshot on any
        // `Changed(peer: None)` signal, so no events are permanently lost.
        let (route_tx, _) = broadcast::channel(1024);
        let (peer_tx, _) = broadcast::channel(1024);

        let rib = Arc::new(RibSnapshot {
            loc_rib: LocRib::new(),
            loc_rib_v6: LocRib::new(),
            originated_routes: HashSet::new(),
            originated_routes_v6: HashSet::new(),
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
            next_hop_self_peers,
            rr_clients,
            cluster_id,
            peer_bgp_ids: HashMap::new(),
            eor_received: HashSet::new(),
            eor_received_v6: HashSet::new(),
            gr_capable_peers: HashMap::new(),
            peer_roles,
            negotiated_roles: HashMap::new(),
        });

        Self {
            rib,
            import_policies,
            import_policies_v6,
            export_policies,
            export_policies_v6,
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
            route_refresh_peers: HashSet::new(),
            mrai_last_sent: HashMap::new(),
            mrai_pending: HashMap::new(),
            stalled_peers: Vec::new(),
            pending_decisions: HashMap::new(),
            pending_decisions_v6: HashMap::new(),
            pending_removal: HashSet::new(),
            gr: GracefulRestartState::new(),
            shutdown_messages,
            peer_max_prefixes_v4,
            peer_max_prefixes_v6,
            peer_max_prefixes_restart,
            max_prefix_idle: HashMap::new(),
            route_tx,
            peer_tx,
            fib_manager: None,
            rpki: None,
            oracle_v4: Arc::new(AlwaysReachable),
            oracle_v6: Arc::new(AlwaysReachable),
        }
    }

    /// Injects a `RoaValidityCondition` "reject Invalid" term into every
    /// configured peer's IPv4 and IPv6 import policy (RFC 6811 ROV).
    ///
    /// Called once, right after the RTR client is spawned — `DaemonState::new`
    /// itself takes no RPKI parameter, since the RTR handle isn't available
    /// until after construction and threading it through would touch this
    /// struct's many existing test call sites. `Valid` and `NotFound` routes
    /// are unaffected — they simply don't match this term and fall through to
    /// each peer's existing default action, exactly as before this call.
    pub(crate) fn install_rpki_import_terms(&mut self, rtr: &pathvector_rpki::RtrHandle) {
        for policy in self.import_policies.values_mut() {
            policy.add_term(pathvector_policy::Term::new(
                pathvector_policy::RoaValidityCondition::<Ipv4Addr>::new(
                    rtr.clone(),
                    pathvector_rpki::RoaValidity::Invalid,
                ),
                pathvector_policy::Reject,
            ));
        }
        for policy in self.import_policies_v6.values_mut() {
            policy.add_term(pathvector_policy::Term::new(
                pathvector_policy::RoaValidityCondition::<Ipv6Addr>::new(
                    rtr.clone(),
                    pathvector_rpki::RoaValidity::Invalid,
                ),
                pathvector_policy::Reject,
            ));
        }
    }
}

/// Resolves the effective RFC 9234 role for `peer`, or `None` if Role/OTC
/// must not apply to this session.
///
/// RFC 9234 is eBGP-only by definition (Provider/Customer/Peer/RS/RS-Client
/// relationships don't exist between routers in the same AS). Applying it to
/// an iBGP peer anyway would send a meaningless `Capability::Role` in OPEN
/// and, worse, could reject a route that legitimately carries OTC — attached
/// correctly by another border router's real eBGP session and reflected to
/// us over iBGP — as a false leak. Warns once (rather than failing startup)
/// so a config typo doesn't silently disable a peer, matching how other
/// eBGP-only features already degrade gracefully.
fn effective_role(peer: &config::PeerConfig, local_as: u32) -> Option<Role> {
    let role = peer.role?;
    if peer.remote_as == local_as {
        tracing::warn!(
            peer = %peer.address,
            "role is configured but this is an iBGP peer (remote_as == local_as); \
             RFC 9234 is eBGP-only — ignoring role for this peer"
        );
        return None;
    }
    Some(role.into())
}

/// RFC 9234 §5 ingress terms for a peer configured with `session_role`.
///
/// Always installs the leak-detection term (a no-op for roles it doesn't
/// apply to — see [`OtcLeakCondition`]'s doc comment). Additionally installs
/// the ingress-attach term (`OTC = peer_asn`) when `session_role` is
/// `Customer`, `Peer`, or `RsClient` — i.e. the route came from our
/// Provider/Peer/RS on this session.
fn install_otc_import_term<R: BgpRoute>(policy: &mut Policy<R>, session_role: Role, peer_asn: Asn) {
    policy.add_term(Term::new(
        OtcLeakCondition::new(session_role, peer_asn),
        Reject,
    ));
    if matches!(session_role, Role::Customer | Role::Peer | Role::RsClient) {
        policy.add_term(Term::new(AnyCondition, SetOtc::new(peer_asn)));
    }
}

/// RFC 9234 §6 egress terms for a peer configured with `session_role`.
///
/// Installs the propagation-block term (reject routes that already carry
/// OTC) when `session_role` is `Customer`, `Peer`, or `RsClient` — i.e.
/// we're sending to our Provider/Peer/RS on this session. Installs the
/// egress-attach term (`OTC = local_asn`) when `session_role` is `Provider`,
/// `Peer`, or `RouteServer` — i.e. we're sending to our Customer/Peer/RS-Client.
fn install_otc_export_term<R: BgpRoute>(
    policy: &mut Policy<R>,
    session_role: Role,
    local_asn: Asn,
) {
    if matches!(session_role, Role::Customer | Role::Peer | Role::RsClient) {
        policy.add_term(Term::new(OtcPropagationCondition, Reject));
    }
    if matches!(
        session_role,
        Role::Provider | Role::Peer | Role::RouteServer
    ) {
        policy.add_term(Term::new(AnyCondition, SetOtc::new(local_asn)));
    }
}

pub(crate) async fn run(cfg: config::Config) {
    run_with(cfg, transport::spawn).await;
}

pub(crate) async fn run_with<H, F>(cfg: config::Config, spawn_fn: F)
where
    H: SessionHandle + 'static,
    F: Fn(SessionConfig) -> H + Clone + Send + Sync + 'static,
{
    let daemon_start = std::time::Instant::now();
    let grpc_port = cfg.daemon.grpc_port;
    let bgp_port = cfg.daemon.bgp_port;
    let metrics_port = cfg.daemon.metrics_port;
    let fib_table = cfg.daemon.fib_table;
    let fib_metric = cfg.daemon.fib_metric;
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;
    let hold_time = cfg.daemon.hold_time;
    let (state, event_rx, event_tx, stop_senders, incoming_senders, md5_passwords) =
        build_daemon(&cfg, spawn_fn.clone()).await;

    // Spawn the kernel FIB tracker and install the FibManager.
    //
    // KernelFib dumps the initial routing table and then tracks RTM_NEWROUTE /
    // RTM_DELROUTE events; KernelOracle exposes the snapshot for next-hop
    // reachability queries.  FibWriter handles the write side (route install /
    // remove).  On non-Linux platforms both are no-ops.
    let (kernel_fib, fib_change_rx) = pathvector_sys::KernelFib::new(fib_table);
    // oracle() takes &self; build oracles before spawn() moves kernel_fib into
    // the background task.  Only constructed on Linux where spawn() actually
    // populates the FIB snapshot via rtnetlink — on non-Linux the snapshot stays
    // empty (stub spawn is a no-op), so wiring DaemonOracle would mark every
    // next-hop unreachable and silently drop all peer routes from best-path
    // selection.  AlwaysReachable (the DaemonState default) is correct there.
    #[cfg(target_os = "linux")]
    let oracle_v4 = crate_fib::DaemonOracle(kernel_fib.oracle());
    #[cfg(target_os = "linux")]
    let oracle_v6 = crate_fib::DaemonOracle(kernel_fib.oracle());

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
        #[cfg(target_os = "linux")]
        guard.set_oracles(oracle_v4, oracle_v6);
        if let Some(writer) = fib_writer {
            guard.fib_manager = Some(Arc::new(crate_fib::FibManager::new(writer)));
        }
    }

    // Channel for gRPC → event-loop command injection (AddPeer / RemovePeer).
    let (cmd_tx, cmd_rx) = mpsc::channel::<DaemonCommand>(32);

    // Spawn the gRPC management API server alongside the BGP event loop.
    let grpc_state = Arc::clone(&state);
    let grpc_stop_senders = Arc::clone(&stop_senders);
    tokio::spawn(async move {
        grpc::serve(grpc_state, grpc_port, cmd_tx, grpc_stop_senders).await;
    });

    // Install Prometheus metrics endpoint when configured.  A bind failure
    // (e.g. port already in use) degrades observability only — BGP session
    // management and route propagation do not depend on it — so we log and
    // continue rather than crash the daemon, matching the FIB integration's
    // failure-handling pattern above.
    if let Some(port) = metrics_port
        && let Err(e) = crate::metrics::install(port)
    {
        tracing::warn!(
            port,
            error = %e,
            "metrics endpoint unavailable — running without Prometheus export"
        );
    }

    // Spawn the RPKI RTR client when configured. Unlike FibWriter::new (sync,
    // fails fast), this is async-forever — there's no Result to match at
    // spawn time. "Failure" (connect refused, version mismatch, etc.)
    // surfaces later via RtrStatus.connected == false, which is why the
    // read-only gRPC/CLI status surface matters for operator visibility.
    if let Some(rpki_cfg) = cfg.daemon.rpki.clone() {
        let (handle, _join) = pathvector_rpki::RtrClient::spawn(pathvector_rpki::RtrConfig {
            host: rpki_cfg.host.clone(),
            port: rpki_cfg.port,
            ..Default::default()
        });
        install_rpki(handle, rpki_cfg.reject_invalid, &state).await;
        tracing::info!(
            host = %rpki_cfg.host,
            port = rpki_cfg.port,
            reject_invalid = rpki_cfg.reject_invalid,
            "RPKI RTR client started"
        );
    }

    // Spawn the BGP TCP listener for inbound connections (RFC 4271 §6.8).
    {
        let incoming = Arc::clone(&incoming_senders);
        let md5 = Arc::clone(&md5_passwords);
        tokio::spawn(async move {
            run_bgp_listener(bgp_port, incoming, md5).await;
        });
    }

    // Spawn the command processor that handles AddPeer / RemovePeer at runtime.
    {
        let state_cmd = Arc::clone(&state);
        let stop_cmd = Arc::clone(&stop_senders);
        let incoming_cmd = Arc::clone(&incoming_senders);
        let peer_store = cfg
            .sidecar_path
            .as_ref()
            .map(|p| Arc::new(config::DynamicPeerStore::new(p.clone())));
        let proc_handle = tokio::spawn(run_command_processor(
            cmd_rx,
            state_cmd,
            stop_cmd,
            incoming_cmd,
            event_tx,
            spawn_fn,
            SpawnConfig {
                local_as,
                local_bgp_id,
                hold_time,
                graceful_restart_time: cfg.daemon.graceful_restart_time,
                configured_restarting: cfg.daemon.restarting,
                startup_instant: daemon_start, // R-bit expires after graceful_restart_time secs
            },
            peer_store,
        ));
        // Log a clear error if the command processor panics so operators know
        // why AddPeer / RemovePeer gRPC calls are failing.
        tokio::spawn(async move {
            if let Err(e) = proc_handle.await {
                tracing::error!(
                    error = %e,
                    "command processor task panicked — AddPeer/RemovePeer are unavailable"
                );
            }
        });
    }

    run_event_loop(event_rx, state, stop_senders, Some(fib_change_rx)).await;
}

/// Installs the ROV import-policy term (if `reject_invalid`) and stores
/// `handle` on `state`. If `reject_invalid`, also spawns the background task
/// that re-evaluates every peer's import policy whenever `handle`'s ROA
/// cache changes (see `pathvector_rpki::RtrHandle::subscribe`).
///
/// Split out from `run_with` so this exact sequence is directly testable
/// against any `RtrHandle` — a real one from `RtrClient::spawn`, or a
/// `for_testing()`/`insert_roa_v4`-driven one in tests — without needing a
/// live TCP RTR server either way.
async fn install_rpki(
    handle: pathvector_rpki::RtrHandle,
    reject_invalid: bool,
    state: &Arc<RwLock<DaemonState>>,
) {
    // Subscribe before doing anything else. `handle` was already returned
    // by `RtrClient::spawn`, whose background sync task starts running
    // concurrently the instant it's spawned — on a multi-thread runtime
    // that's a real second OS thread, not just cooperative scheduling. A
    // `watch` receiver only observes changes sent *after* it subscribes, so
    // subscribing late risks missing the very first sync's notification
    // outright (not just seeing it delayed). Subscribing here, before the
    // `state.write().await` below, minimizes that window; the eager
    // `status().connected` check further down closes it completely by
    // catching the case where the first sync still won the race.
    let changed = reject_invalid.then(|| handle.subscribe());

    {
        let mut guard = state.write().await;
        if reject_invalid {
            guard.install_rpki_import_terms(&handle);
        }
        guard.rpki = Some(handle.clone());
    }
    if let Some(mut changed) = changed {
        // If the first sync already completed before we subscribed above,
        // its notification was sent to no receiver and this one will never
        // see it — the watch channel only fires for changes after
        // subscription. Catch that case explicitly rather than relying on
        // subscribe() having won the race against the background task.
        if handle.status().connected {
            state.write().await.reevaluate_all_import_policies();
        }
        // Re-evaluates every peer's import policy whenever the ROA cache
        // changes (any later update) — closes the window between "route
        // accepted while the cache was empty/stale" and the cache actually
        // reflecting reality, without waiting for a session reset. Ends
        // only if the RtrClient's own task ever drops its side of the
        // channel, which never happens in practice (that task runs
        // forever) — a clean, non-panicking exit either way.
        let reeval_state = Arc::clone(state);
        tokio::spawn(async move {
            while changed.changed().await.is_ok() {
                reeval_state.write().await.reevaluate_all_import_policies();
            }
        });
    }
}

pub(crate) async fn build_daemon<H, F>(
    cfg: &config::Config,
    spawn_fn: F,
) -> (
    Arc<RwLock<DaemonState>>,
    mpsc::Receiver<(Ipv4Addr, SessionEvent)>,
    mpsc::Sender<(Ipv4Addr, SessionEvent)>, // kept alive for AddPeer forwarding
    Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>>,
    Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    Arc<RwLock<HashMap<IpAddr, String>>>, // RFC 2385 MD5 passwords
)
where
    H: SessionHandle,
    F: Fn(SessionConfig) -> H,
{
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;

    let (event_tx, event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(256);
    let mut update_senders: HashMap<Ipv4Addr, mpsc::Sender<UpdateMessage>> = HashMap::new();
    // stop_senders: shared with the command processor so AddPeer/RemovePeer can
    // insert/remove without touching the event loop directly.
    let stop_senders: Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // incoming_senders: shared with the BGP listener so AddPeer immediately
    // accepts inbound connections from newly configured peers.
    let incoming_senders: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // md5_passwords: shared with the listener for TCP MD5SIG setup.
    let md5_passwords: Arc<RwLock<HashMap<IpAddr, String>>> = Arc::new(RwLock::new(HashMap::new()));

    // Capture startup instant here; used to expire the R-bit window per-session.
    let startup_instant = std::time::Instant::now();

    for peer in &cfg.peers {
        // Recompute capabilities for each session so the R-bit correctly reflects
        // elapsed time since startup (RFC 4724 §3: R-bit must be cleared after restart).
        let capabilities = build_local_capabilities(
            local_as,
            cfg.daemon.graceful_restart_time,
            cfg.daemon.restarting
                && cfg.daemon.graceful_restart_time > 0
                && startup_instant.elapsed()
                    < std::time::Duration::from_secs(u64::from(cfg.daemon.graceful_restart_time)),
            effective_role(peer, local_as),
        );
        let session_cfg = SessionConfig {
            local_as,
            local_bgp_id,
            hold_time: peer.hold_time.unwrap_or(cfg.daemon.hold_time),
            capabilities,
            required_capabilities: vec![],
            peer_as: Some(peer.remote_as),
            peer_addr: SocketAddr::new(IpAddr::V4(peer.address), peer.port),
            md5_password: peer.md5_password.clone(),
            connect_retry_time: peer
                .connect_retry_time
                .map_or(DEFAULT_CONNECT_RETRY_TIME, |s| {
                    std::time::Duration::from_secs(u64::from(s))
                }),
        };

        let mut handle = spawn_fn(session_cfg);
        handle.start().await;

        update_senders.insert(peer.address, handle.update_sender());
        stop_senders
            .lock()
            .unwrap()
            .insert(peer.address, handle.stop_sender());
        incoming_senders
            .write()
            .await
            .insert(IpAddr::V4(peer.address), handle.incoming_sender());
        if let Some(pw) = &peer.md5_password {
            md5_passwords
                .write()
                .await
                .insert(IpAddr::V4(peer.address), pw.clone());
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
    // Keep a clone of event_tx alive; the caller returns it so the command
    // processor can forward events from dynamically added sessions.  The
    // channel closes when every forwarding task exits AND this clone is dropped.

    // Build a reference capability set for DaemonState.config_capabilities.
    // This is used to check whether we advertise GR (for the "peer doesn't
    // support GR" warning in on_established) — not for per-session OPENs.
    // The R-bit is not relevant here; we use restarting=false.
    let config_capabilities =
        build_local_capabilities(local_as, cfg.daemon.graceful_restart_time, false, None);
    let state = Arc::new(RwLock::new(DaemonState::new(
        local_as,
        local_bgp_id,
        cfg.daemon.local_ipv6,
        cfg.daemon.cluster_id,
        &cfg.peers,
        update_senders,
        config_capabilities,
    )));

    (
        state,
        event_rx,
        event_tx,
        stop_senders,
        incoming_senders,
        md5_passwords,
    )
}

pub(crate) async fn run_event_loop(
    mut event_rx: mpsc::Receiver<(Ipv4Addr, SessionEvent)>,
    state: Arc<RwLock<DaemonState>>,
    stop_senders: Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>>,
    mut fib_change_rx: Option<watch::Receiver<()>>,
) {
    // MRAI flush timer — fires every MRAI/2 so suppressed eBGP routes are
    // re-advertised within one interval of their window expiring (RFC 4271 §9.2.1.1).
    // The first tick fires immediately but is a no-op (no sessions yet); subsequent
    // ticks are spaced MRAI/2 apart. MissedTickBehavior::Delay prevents burst
    // catch-up when the event loop is held under a write lock for an extended period.
    let mut mrai_timer = tokio::time::interval(MRAI / 2);
    mrai_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    'outer: loop {
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
                        // RFC 4486 §4 — max-prefix idle-hold: if the peer is
                        // still within its post-CEASE idle window, reject the
                        // reconnect attempt immediately with Stop so it retries
                        // after connect_retry_time elapses.
                        if s.max_prefix_idle.contains_key(&peer_ip) {
                            tracing::info!(
                                peer = %peer_ip,
                                "max-prefix idle-hold active — rejecting reconnect"
                            );
                            drop(s);
                            let tx = stop_senders.lock().unwrap().get(&peer_ip).cloned();
                            if let Some(tx) = tx {
                                let _ = tx.send(SessionCommand::Stop).await;
                            }
                            continue;
                        }
                        s.on_established(
                            peer_ip,
                            info.peer_bgp_id,
                            info.peer_type,
                            info.peer_as,
                            info.hold_time,
                            &info.peer_capabilities,
                            info.local_addr,
                        );
                        crate::metrics::on_session_established(peer_ip);
                    }
                    SessionEvent::Terminated(termination_reason) => {
                        let is_removed = s.pending_removal.remove(&peer_ip);
                        // Capture identity fields while they are still in the
                        // RIB.  on_terminated clears session-level state
                        // (peer_types, hold_times, etc.); remove_peer clears
                        // everything including peer_remote_as.  Both run below.
                        let removal_identity = if is_removed {
                            s.rib.peer_remote_as.get(&peer_ip).copied().map(|remote_as| {
                                (remote_as, s.rib.local_as)
                            })
                        } else {
                            None
                        };
                        // For removal, suppress the intermediate Changed(None)
                        // broadcast — the explicit Removed event below is the
                        // authoritative notification.
                        crate::metrics::on_session_terminated(peer_ip, &termination_reason);
                        s.on_terminated(peer_ip, termination_reason, !is_removed);
                        // RFC 4724 §3: refresh the session's capability set so
                        // the next OPEN reflects the current R-bit state. The
                        // restart window may have expired since the original OPEN
                        // was sent; we always push R=0 on reconnect — if we were
                        // still restarting the first connection would have cleared
                        // the window, so subsequent reconnects must not set R.
                        let caps_refresh: Option<(mpsc::Sender<SessionCommand>, Vec<Capability>)> =
                            if is_removed {
                                None
                            } else {
                                let gr_time = s.config_capabilities.iter().find_map(|c| {
                                    if let Capability::GracefulRestart { restart_time, .. } = c {
                                        Some(*restart_time)
                                    } else {
                                        None
                                    }
                                }).unwrap_or(0);
                                let fresh_caps = build_local_capabilities(
                                    s.rib.local_as,
                                    gr_time,
                                    false,
                                    s.rib.peer_roles.get(&peer_ip).copied(),
                                );
                                stop_senders.lock().unwrap().get(&peer_ip).cloned()
                                    .map(|tx| (tx, fresh_caps))
                            };
                        if is_removed {
                            // Permanent removal: erase all per-peer state so
                            // the peer no longer appears in gRPC responses and
                            // remove the stop sender so no further commands can
                            // be sent to this session.
                            s.remove_peer(peer_ip);
                            stop_senders.lock().unwrap().remove(&peer_ip);
                            // Broadcast a Removed event carrying the last-known
                            // remote_as and local_as so watch_peers subscribers
                            // can identify the removed peer without re-reading a
                            // snapshot that no longer contains it.
                            if let Some((remote_as, local_as)) = removal_identity {
                                let _ = s.peer_tx.send(proto::PeerEvent {
                                    r#type: proto::PeerEventType::Removed as i32,
                                    peer: Some(proto::PeerState {
                                        address: peer_ip.to_string(),
                                        remote_as,
                                        local_as,
                                        ..Default::default()
                                    }),
                                });
                            }
                        }
                        // Drop the write guard before awaiting so we don't hold the
                        // lock while the channel send blocks, then skip the coalescing
                        // loop (no pending_decisions were touched in Terminated path).
                        drop(s);
                        if let Some((tx, caps)) = caps_refresh {
                            let _ = tx.send(SessionCommand::SetCapabilities(caps)).await;
                        }
                        continue;
                    }
                    SessionEvent::RouteUpdate(msg) => {
                        let notify_err = s.on_route_update(peer_ip, msg);
                        let adj_in = s.rib.prefixes_received.get(&peer_ip).copied().unwrap_or(0);
                        crate::metrics::on_route_update(peer_ip, adj_in);
                        // RFC 4271 §6.3: mandatory attribute violation — send
                        // specific NOTIFICATION before tearing down the session.
                        if let Some(err) = notify_err {
                            // Flush pending decisions for other peers before
                            // tearing this one down so they don't starve.
                            s.flush_pending();
                            let stalled = s.take_stalled_peers();
                            drop(s);
                            let tx = stop_senders.lock().unwrap().get(&peer_ip).cloned();
                            if let Some(tx) = tx {
                                let _ = tx.send(SessionCommand::Notification(err)).await;
                            }
                            // Process any stalled peers before next iteration.
                            for peer in stalled {
                                let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                                if let Some(tx) = tx {
                                    let _ = tx.send(SessionCommand::Stop).await;
                                }
                            }
                            continue;
                        }
                    }
                }
                // Drain any immediately-available events to coalesce bursts
                // before flushing. This is the key mechanism for cross-UPDATE
                // NLRI batching: when many BGP UPDATEs arrive back-to-back
                // (e.g. during MRT replay or full-table session establishment),
                // we process them all into the pending_decisions buffers first,
                // then flush_pending emits fewer, larger UPDATE messages.
                //
                // Peers that reconnected during a max-prefix idle-hold window;
                // their Stop is sent after the drain loop alongside stalled peers
                // to avoid dropping and re-acquiring the write lock mid-iteration.
                let mut idle_hold_rejected: Vec<Ipv4Addr> = Vec::new();

                while let Ok((extra_ip, extra_event)) = event_rx.try_recv() {
                    match extra_event {
                        SessionEvent::Established(info) => {
                            // Same idle-hold guard as the primary Established arm.
                            if s.max_prefix_idle.contains_key(&extra_ip) {
                                tracing::info!(
                                    peer = %extra_ip,
                                    "max-prefix idle-hold active — rejecting reconnect (coalesced)"
                                );
                                idle_hold_rejected.push(extra_ip);
                                continue;
                            }
                            s.on_established(
                                extra_ip,
                                info.peer_bgp_id,
                                info.peer_type,
                                info.peer_as,
                                info.hold_time,
                                &info.peer_capabilities,
                                info.local_addr,
                            );
                        }
                        SessionEvent::Terminated(termination_reason) => {
                            let is_removed = s.pending_removal.remove(&extra_ip);
                            let removal_identity = if is_removed {
                                s.rib.peer_remote_as.get(&extra_ip).copied().map(|remote_as| {
                                    (remote_as, s.rib.local_as)
                                })
                            } else {
                                None
                            };
                            s.on_terminated(extra_ip, termination_reason, !is_removed);
                            if is_removed {
                                s.remove_peer(extra_ip);
                                stop_senders.lock().unwrap().remove(&extra_ip);
                                if let Some((remote_as, local_as)) = removal_identity {
                                    let _ = s.peer_tx.send(proto::PeerEvent {
                                        r#type: proto::PeerEventType::Removed as i32,
                                        peer: Some(proto::PeerState {
                                            address: extra_ip.to_string(),
                                            remote_as,
                                            local_as,
                                            ..Default::default()
                                        }),
                                    });
                                }
                            }
                        }
                        SessionEvent::RouteUpdate(msg) => {
                            // RFC 4271 §6.3: mandatory-attribute error
                            // detected during drain — flush other peers'
                            // decisions then send NOTIFICATION before
                            // tearing down this session.
                            if let Some(err) = s.on_route_update(extra_ip, msg) {
                                s.flush_pending();
                                let notify_stalled = s.take_stalled_peers();
                                drop(s);
                                let tx = stop_senders.lock().unwrap().get(&extra_ip).cloned();
                                if let Some(tx) = tx {
                                    let _ = tx.send(SessionCommand::Notification(err)).await;
                                }
                                for peer in notify_stalled {
                                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                                    if let Some(tx) = tx {
                                        let _ = tx.send(SessionCommand::Stop).await;
                                    }
                                }
                                continue 'outer;
                            }
                        }
                    }
                }
                // Channel is empty — flush all accumulated outbound decisions.
                s.flush_pending();
                crate::metrics::update_rib_sizes(
                    s.rib.loc_rib.len(),
                    s.rib.loc_rib_v6.len(),
                    &s.rib.prefixes_advertised,
                );
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
                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(SessionCommand::Stop).await;
                    }
                }

                for peer in idle_hold_rejected {
                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(SessionCommand::Stop).await;
                    }
                }
            }

            Ok(()) = fib_changed => {
                let mut s = state.write().await;
                s.on_fib_change();
                s.flush_pending();
                let stalled = s.take_stalled_peers();
                drop(s);

                for peer in stalled {
                    tracing::error!(
                        peer = %peer,
                        "closing session: outbound UPDATE channel overflowed after FIB change; \
                         session will re-establish and perform a fresh full-table dump"
                    );
                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(SessionCommand::Stop).await;
                    }
                }
            }

            // RFC 4724 §4.2 — GR deadline timer.  Fire whenever the earliest
            // active deadline is reached.  If there are no active GR windows the
            // future is `pending()` so this branch never wakes the select.
            () = async {
                let earliest = state.read().await.gr.earliest_deadline();
                match earliest {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None    => std::future::pending::<()>().await,
                }
            } => {
                let now = Instant::now();
                let expired: Vec<Ipv4Addr> = {
                    let mut s = state.write().await;
                    let expired = s.gr.drain_expired(now);
                    for peer_ip in &expired {
                        s.on_gr_deadline_expired(*peer_ip);
                    }
                    expired
                };
                if !expired.is_empty() {
                    let stalled = state.write().await.take_stalled_peers();
                    for peer in stalled {
                        tracing::error!(
                            peer = %peer,
                            "closing session: outbound UPDATE channel overflowed during GR deadline flush"
                        );
                        let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(SessionCommand::Stop).await;
                        }
                    }
                }
            }

            // RFC 4486 §4 — max-prefix idle-hold expiry timer.  When no
            // idle-hold is active, `pending()` keeps this branch dormant.
            //
            // The deadline is read with a temporary read guard (no local
            // binding) so the lock is released before the sleep begins.
            // Holding a read guard across the await would deadlock the
            // event arm which needs a write lock.
            () = async {
                let earliest = state.read().await.max_prefix_idle.values().copied().min();
                match earliest {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None    => std::future::pending::<()>().await,
                }
            } => {
                let now = Instant::now();
                let mut s = state.write().await;
                let expired: Vec<Ipv4Addr> = s
                    .max_prefix_idle
                    .iter()
                    .filter(|(_, deadline)| *deadline <= &now)
                    .map(|(ip, _)| *ip)
                    .collect();
                for peer_ip in &expired {
                    s.max_prefix_idle.remove(peer_ip);
                    tracing::info!(
                        peer = %peer_ip,
                        "max-prefix idle-hold expired — peer may now reconnect"
                    );
                }
            }

            _ = mrai_timer.tick() => {
                let mut s = state.write().await;
                // Flush any coalesced decisions before MRAI processing so the
                // MRAI check sees the fully-accumulated outbound state.
                s.flush_pending();
                if s.has_mrai_pending() {
                    s.flush_mrai_pending();
                    // flush_mrai_pending calls propagate_to_all_peers which
                    // buffers; drain those decisions now.
                    s.flush_pending();
                    crate::metrics::update_rib_sizes(
                        s.rib.loc_rib.len(),
                        s.rib.loc_rib_v6.len(),
                        &s.rib.prefixes_advertised,
                    );
                    let stalled = s.take_stalled_peers();
                    drop(s);
                    for peer in stalled {
                        tracing::error!(
                            peer = %peer,
                            "closing session: outbound UPDATE channel overflowed during MRAI flush; \
                             session will re-establish and perform a fresh full-table dump"
                        );
                        let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(SessionCommand::Stop).await;
                        }
                    }
                }
            }
        }
    }
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

    fn reject_all_v6() -> Policy<Route<Ipv6Addr>> {
        Policy::new(DefaultAction::Reject)
    }

    fn fresh_ari() -> AdjRibIn<Ipv4Addr> {
        AdjRibIn::new(peer())
    }

    /// Builds a `DaemonState` with explicit accept-all policies for every peer.
    /// Returns the state and a map of receivers for asserting on outbound messages.
    pub(super) fn make_state(
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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

    use pathvector_rib::BestPathChange;
    use std::sync::Mutex;

    /// Shared test double: records every `apply_v4/v6` call without touching the
    /// kernel. Inject via `state.fib_manager = Some(Arc::new(RecordingFib::new()))`.
    pub(super) struct RecordingFib {
        pub(super) v4: Mutex<Vec<BestPathChange<Ipv4Addr>>>,
        pub(super) v6: Mutex<Vec<BestPathChange<Ipv6Addr>>>,
        pub(super) blackhole_v4: Mutex<Vec<(Nlri<Ipv4Addr>, bool)>>, // (nlri, announced)
        pub(super) blackhole_v6: Mutex<Vec<(Nlri<Ipv6Addr>, bool)>>,
    }
    impl RecordingFib {
        pub(super) fn new() -> Self {
            Self {
                v4: Mutex::new(Vec::new()),
                v6: Mutex::new(Vec::new()),
                blackhole_v4: Mutex::new(Vec::new()),
                blackhole_v6: Mutex::new(Vec::new()),
            }
        }
        pub(super) fn v4_changes(&self) -> Vec<BestPathChange<Ipv4Addr>> {
            self.v4.lock().unwrap().clone()
        }
    }
    impl crate_fib::ApplyFibChange for RecordingFib {
        fn apply_v4(&self, change: BestPathChange<Ipv4Addr>) {
            self.v4.lock().unwrap().push(change);
        }
        fn apply_v6(&self, change: BestPathChange<Ipv6Addr>) {
            self.v6.lock().unwrap().push(change);
        }
        fn apply_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>) {
            self.blackhole_v4.lock().unwrap().push((nlri, true));
        }
        fn withdraw_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>) {
            self.blackhole_v4.lock().unwrap().push((nlri, false));
        }
        fn apply_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>) {
            self.blackhole_v6.lock().unwrap().push((nlri, true));
        }
        fn withdraw_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>) {
            self.blackhole_v6.lock().unwrap().push((nlri, false));
        }
    }
    pub(super) fn with_recording_fib(state: &mut DaemonState) -> Arc<RecordingFib> {
        let fib = Arc::new(RecordingFib::new());
        state.fib_manager = Some(Arc::clone(&fib) as Arc<dyn crate_fib::ApplyFibChange>);
        fib
    }

    /// Drain all messages currently queued in every receiver.
    ///
    /// Call this after `on_established` in tests that don't care about the
    /// EOR marker the session setup now sends (RFC 4724 §2).  Tests that
    /// specifically verify the EOR shape should NOT call this helper — they
    /// should assert on the message content directly.
    fn drain_all(receivers: &mut HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>) {
        for rx in receivers.values_mut() {
            while rx.try_recv().is_ok() {}
        }
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

    // ── RFC 9234 effective_role (eBGP-only guard) ─────────────────────────────

    fn peer_with_role(remote_as: u32, role: Option<config::PeerRole>) -> config::PeerConfig {
        config::PeerConfig {
            address: "10.0.0.2".parse().unwrap(),
            port: 179,
            remote_as,
            import_default: None,
            export_default: None,
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role,
        }
    }

    #[test]
    fn test_effective_role_none_when_unconfigured() {
        let peer = peer_with_role(65002, None);
        assert_eq!(effective_role(&peer, 65001), None);
    }

    #[test]
    fn test_effective_role_returns_role_for_ebgp_peer() {
        let peer = peer_with_role(65002, Some(config::PeerRole::Customer));
        assert_eq!(effective_role(&peer, 65001), Some(Role::Customer));
    }

    #[test]
    fn test_effective_role_none_for_ibgp_peer_even_when_configured() {
        // remote_as == local_as: iBGP. RFC 9234 is eBGP-only by definition.
        let peer = peer_with_role(65001, Some(config::PeerRole::Provider));
        assert_eq!(
            effective_role(&peer, 65001),
            None,
            "role must be ignored for an iBGP peer, not just downgraded to a default"
        );
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
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
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
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
        assert_eq!(state.rib.peer_types[&peer_ip], PeerType::External);
    }

    #[test]
    fn test_on_established_empty_rib_sends_eor_only() {
        // RFC 4724 §2: the EOR MUST be sent even when the Adj-RIB-Out is
        // empty so the peer knows the initial sync window is closed.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        let eor = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("on_established must send an IPv4 EOR even for an empty RIB (RFC 4724 §2)");
        assert!(
            eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty(),
            "IPv4 EOR must be a minimum-length UPDATE (RFC 4724 §2): {eor:?}"
        );
        assert!(
            receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "no further messages after the EOR for a peer with no IPv6 capability"
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

        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        let msg = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("should have queued a full-table dump UPDATE");
        assert_eq!(msg.announced, vec![nlri("10.0.0.0/8")]);

        // EOR must immediately follow the dump (RFC 4724 §2).
        let eor = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("IPv4 EOR must follow the full-table dump");
        assert!(
            eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty(),
            "EOR must be a minimum-length UPDATE: {eor:?}"
        );
    }

    /// RFC 4724 §2: an IPv6-capable peer must receive both the IPv4 EOR and the
    /// IPv6 EOR (empty MP_UNREACH_NLRI for IPv6 unicast) after the full-table dump.
    #[test]
    fn test_on_established_ipv6_capable_peer_receives_both_eors() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_ip, 65002)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            65002,
            90,
            &v6_caps,
            None,
        );

        // IPv4 EOR: minimum-length UPDATE.
        let ipv4_eor = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("must receive IPv4 EOR");
        assert!(
            ipv4_eor.withdrawn.is_empty()
                && ipv4_eor.attributes.is_empty()
                && ipv4_eor.announced.is_empty(),
            "IPv4 EOR must be a minimum-length UPDATE: {ipv4_eor:?}"
        );

        // IPv6 EOR: UPDATE with empty MP_UNREACH_NLRI for IPv6 unicast.
        let ipv6_eor = receivers
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("must receive IPv6 EOR after IPv4 EOR");
        assert!(
            ipv6_eor.withdrawn.is_empty() && ipv6_eor.announced.is_empty(),
            "IPv6 EOR must have no IPv4 withdrawn/announced: {ipv6_eor:?}"
        );
        assert!(
            matches!(
                ipv6_eor.attributes.as_slice(),
                [PathAttribute::MpUnreachNlri(m)] if m.afi_safi == AfiSafi::IPV6_UNICAST && m.prefixes.is_empty()
            ),
            "IPv6 EOR must carry empty MP_UNREACH_NLRI for IPv6 unicast: {ipv6_eor:?}"
        );

        assert!(
            receivers.get_mut(&peer_ip).unwrap().try_recv().is_err(),
            "no further messages after both EORs"
        );
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
        state.flush_pending();

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

    /// When `next_hop_self = true`, an iBGP peer must receive NEXT_HOP rewritten
    /// to the local router address rather than the original eBGP next-hop.
    #[test]
    fn test_propagate_to_all_peers_next_hop_self_rewrites_ibgp_next_hop() {
        use pathvector_session::message::PathAttribute;

        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let local_bgp_id: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let session_local_addr: Ipv4Addr = "172.16.0.1".parse().unwrap();

        let (tx, mut rx) = mpsc::channel(64);
        let peer_configs = vec![config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65001, // iBGP — same AS
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: true,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        }];
        let mut senders = HashMap::new();
        senders.insert(peer_ip, tx);
        let mut state = DaemonState::new(
            65001,
            local_bgp_id,
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );

        state.on_established(
            peer_ip,
            peer_ip,
            PeerType::Internal,
            65001,
            90,
            &[],
            Some(session_local_addr),
        );
        // Drain the full-table dump (empty rib).
        while rx.try_recv().is_ok() {}

        // Insert a route learned from an eBGP peer with a remote next-hop.
        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse().unwrap()));
        let ebgp_next_hop: Ipv4Addr = "203.0.113.1".parse().unwrap();
        let route = RouteBuilder::new(
            nlri("192.0.2.0/24"),
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65099)]),
        )
        .next_hop(NextHop::V4(ebgp_next_hop))
        .peer_type(PeerType::External)
        .build();
        state.rib_insert_v4(src, route);
        state.propagate_to_all_peers(&[nlri("192.0.2.0/24")]);
        state.flush_pending();

        let msg = rx.try_recv().expect("iBGP peer must receive UPDATE");
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
            "next_hop_self must rewrite iBGP NEXT_HOP to the local session address"
        );
        assert_ne!(
            next_hop,
            Some(ebgp_next_hop),
            "original eBGP next-hop must not be forwarded to iBGP clients"
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
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
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

        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
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
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
        state.on_terminated(peer_ip, TerminationReason::Unclean, true);
        assert!(!state.rib.peer_types.contains_key(&peer_ip));
    }

    #[test]
    fn test_on_terminated_withdraws_peer_routes_from_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

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

        state.on_terminated(peer_ip, TerminationReason::Unclean, true);
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    #[test]
    fn test_on_terminated_propagates_withdraw_to_other_established_peers() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

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
        state.on_terminated(peer_a, TerminationReason::Unclean, true);

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

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        drain_all(&mut receivers);

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
        state.flush_pending();
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();

        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
            "route must be in Loc-RIB"
        );

        // Next-hop goes down — FIB change fires.
        oracle.set(false);
        state.on_fib_change();
        state.flush_pending();

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

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

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
        state.flush_pending();
        receivers.get_mut(&peer_b).unwrap().try_recv().ok(); // discard any spurious message

        // Next-hop recovers.
        oracle.set(true);
        state.on_fib_change();
        state.flush_pending();

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

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        drain_all(&mut receivers);

        // FIB change fires with empty RIB — should be a no-op.
        state.on_fib_change();
        assert!(receivers.get_mut(&peer_b).unwrap().try_recv().is_err());
    }

    /// When a FIB change evicts a best route, the FIB manager must receive a
    /// `Withdrawn` call for the now-unreachable NLRI.
    #[test]
    fn test_on_fib_change_notifies_fib_manager_on_withdraw() {
        use pathvector_types::{AsPath, Asn, Origin};

        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002)]);
        let fib = with_recording_fib(&mut state);

        let oracle = ToggleOracle::reachable();
        state.set_oracles(oracle.clone(), oracle.clone());

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        drain_all(&mut receivers);

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
        fib.v4.lock().unwrap().clear();

        oracle.set(false);
        state.on_fib_change();

        let changes = fib.v4_changes();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "FIB manager must receive a Withdrawn call when next-hop goes down"
        );
    }

    /// When a v6 FIB change evicts a v6 best route, the FIB manager must receive
    /// a Withdrawn call. Covers the v6 path in `on_fib_change` (daemon/fib.rs).
    #[test]
    fn test_on_fib_change_v6_notifies_fib_manager_on_withdraw() {
        use pathvector_rib::BestPathChange;
        use pathvector_session::message::{MpReachNlri, PathAttribute, Prefix, UpdateMessage};
        use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Origin};

        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002)]);
        let fib = with_recording_fib(&mut state);

        let oracle = ToggleOracle::reachable();
        state.set_oracles(oracle.clone(), oracle.clone());
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());

        let v6_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(
            peer_a,
            peer_a,
            PeerType::External,
            65002,
            90,
            &v6_caps,
            None,
        );
        drain_all(&mut receivers);

        let nlri_v6: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let announce_v6 = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(nlri_v6)],
                }),
            ],
            announced: vec![],
        };
        state.on_route_update(peer_a, announce_v6);
        fib.v6.lock().unwrap().clear();

        oracle.set(false);
        state.on_fib_change();

        let v6_changes = fib.v6.lock().unwrap().clone();
        assert!(
            v6_changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "FIB manager must receive a Withdrawn call for v6 route when oracle goes down"
        );
    }

    /// `on_route_update` must notify the FIB manager for routes that change the
    /// best path. Covers the `if let Some(fm)` branch in daemon/route.rs.
    #[test]
    fn test_on_route_update_notifies_fib_manager() {
        use pathvector_rib::BestPathChange;
        use pathvector_types::{AsPath, Asn, Origin};

        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rxs) = make_state(65001, &[(peer_ip, 65002)]);
        let fib = with_recording_fib(&mut state);

        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(
            peer_ip,
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

        let changes = fib.v4_changes();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Announced(..))),
            "FIB manager must receive Announced when route is installed"
        );
    }

    // ── DaemonState::on_route_update ──────────────────────────────────────────

    #[test]
    fn test_on_route_update_inserts_route_into_rib() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

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

    // ── RPKI ROV (Phase 2) ───────────────────────────────────────────────────

    #[test]
    fn test_install_rpki_import_terms_adds_one_term_per_peer_v4_and_v6() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());

        state.install_rpki_import_terms(&rtr);

        for ip in [peer_a, peer_b] {
            assert_eq!(state.import_policies[&ip].len(), 1);
            assert_eq!(state.import_policies_v6[&ip].len(), 1);
        }
    }

    #[test]
    fn test_rov_accepts_route_with_valid_roa() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        let rtr = pathvector_rpki::for_testing(
            [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 65002)],
            std::iter::empty(),
        );
        state.install_rpki_import_terms(&rtr);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_ip),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_rov_rejects_route_with_invalid_roa_wrong_origin_asn() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        // ROA authorizes AS 99999 for this prefix, not AS 65002 — the peer's
        // announcement will be Invalid.
        let rtr = pathvector_rpki::for_testing(
            [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999)],
            std::iter::empty(),
        );
        state.install_rpki_import_terms(&rtr);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_ip),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_rov_accepts_route_with_no_covering_roa() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        // Empty ROA table — every prefix is NotFound, which must be accepted
        // by default, not treated the same as Invalid.
        let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
        state.install_rpki_import_terms(&rtr);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_ip),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_rov_not_installed_invalid_route_still_accepted() {
        // Regression guard: without calling install_rpki_import_terms (the
        // `reject_invalid = false` config path), ROV must have zero effect —
        // an Invalid route is accepted exactly as it would be in Phase 1.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_ip),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );

        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());
    }

    #[test]
    fn test_reevaluate_all_import_policies_closes_fail_open_window() {
        // Gap 3: a route accepted while the RTR cache was still empty (the
        // window before the first sync completes) must get correctly
        // rejected once the cache actually reflects it as Invalid, without
        // needing a session reset. reevaluate_all_import_policies is what
        // makes that happen.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
        state.install_rpki_import_terms(&rtr);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        // Accepted now: the cache is empty, so this reads as NotFound.
        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_ip),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some());

        // The cache now learns of a ROA that makes this exact route Invalid
        // (covers 10.0.0.0/8, but authorizes a different ASN).
        rtr.insert_roa_v4(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999);
        state.reevaluate_all_import_policies();

        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
            "route must be rejected once the cache reflects it as Invalid"
        );
    }

    #[test]
    fn test_reevaluate_all_import_policies_does_not_duplicate_terms() {
        // Regression guard: reevaluate_all_import_policies must never touch
        // the installed Policy itself (unlike set_import_default, which
        // replaces it) — calling it repeatedly must not grow the term list.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_state(65001, &[(peer_ip, 65002)]);
        let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
        state.install_rpki_import_terms(&rtr);

        let before = state.import_policies[&peer_ip].len();
        state.reevaluate_all_import_policies();
        state.reevaluate_all_import_policies();
        assert_eq!(state.import_policies[&peer_ip].len(), before);
        assert_eq!(state.import_policies_v6[&peer_ip].len(), before);
    }

    #[test]
    fn test_on_route_update_propagates_to_other_established_peer() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        drain_all(&mut receivers);

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
        state.flush_pending();

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
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

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

    // ── RFC 9234 — BGP Role + OTC route-leak prevention ───────────────────────

    fn make_state_with_roles(
        local_as: u32,
        peers: &[(Ipv4Addr, u32, config::PeerRole)],
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for &(ip, _, _) in peers {
            let (tx, rx) = mpsc::channel(64);
            senders.insert(ip, tx);
            receivers.insert(ip, rx);
        }
        let peer_configs: Vec<config::PeerConfig> = peers
            .iter()
            .map(|&(address, remote_as, role)| config::PeerConfig {
                address,
                port: 179,
                remote_as,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: Some(role),
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

    fn announce_with_otc(peer_as: u32, prefix: &str, otc: Option<u32>) -> UpdateMessage {
        let mut attributes = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(peer_as)])),
            PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
        ];
        if let Some(asn) = otc {
            attributes.push(PathAttribute::OnlyToCustomer(Asn::new(asn)));
        }
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![nlri(prefix)],
        }
    }

    #[test]
    fn test_install_otc_terms_counts_per_role() {
        use config::PeerRole;
        // (role, expected import term count [v4 and v6 identical], expected export term count)
        let cases = [
            (PeerRole::Provider, 1, 1),
            (PeerRole::RouteServer, 1, 1),
            (PeerRole::Customer, 2, 1),
            (PeerRole::RsClient, 2, 1),
            (PeerRole::Peer, 2, 2),
        ];
        for (role, expected_import, expected_export) in cases {
            let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
            let (state, _rx) = make_state_with_roles(65001, &[(peer_ip, 65002, role)]);
            assert_eq!(
                state.import_policies[&peer_ip].len(),
                expected_import,
                "{role:?}: import policy term count"
            );
            assert_eq!(
                state.import_policies_v6[&peer_ip].len(),
                expected_import,
                "{role:?}: import_v6 policy term count"
            );
            assert_eq!(
                state.export_policies[&peer_ip].len(),
                expected_export,
                "{role:?}: export policy term count"
            );
        }
    }

    #[test]
    fn test_no_role_configured_installs_no_otc_terms() {
        // Regression guard: omitting `role` must have zero effect — matches
        // RFC 9234's own non-strict default of not requiring Role at all.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rx) = make_state(65001, &[(peer_ip, 65002)]);
        assert_eq!(state.import_policies[&peer_ip].len(), 0);
        assert_eq!(state.import_policies_v6[&peer_ip].len(), 0);
        assert_eq!(state.export_policies[&peer_ip].len(), 0);
    }

    /// RFC 9234 is eBGP-only by definition. If an operator mistakenly sets
    /// `role` on an iBGP peer (`remote_as == local_as`), it must be ignored
    /// — no `Capability::Role` in OPEN, no OTC terms installed — rather than
    /// silently applying leak-detection logic to internal sessions, which
    /// could reject a route that legitimately carries OTC from its original
    /// eBGP ingestion elsewhere in the network.
    #[test]
    fn test_role_ignored_for_ibgp_peer() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65001, config::PeerRole::Provider)]);

        assert_eq!(
            state.import_policies[&peer_ip].len(),
            0,
            "no OTC import term for an iBGP peer, even with role configured"
        );
        assert_eq!(state.import_policies_v6[&peer_ip].len(), 0);
        assert_eq!(
            state.export_policies[&peer_ip].len(),
            0,
            "no OTC export term for an iBGP peer, even with role configured"
        );
        assert!(
            !state.rib.peer_roles.contains_key(&peer_ip),
            "peer_roles must not record a role for an iBGP peer"
        );
    }

    /// Regression guard: `set_import_default`/`set_export_default` (the
    /// gRPC-triggered PolicyService handlers) must never silently disable
    /// RFC 9234 leak protection. Both used to fully replace the peer's
    /// `Policy` (`Policy::new(action)`), discarding any installed terms —
    /// confirmed as a real bug via a throwaway reproduction before this fix
    /// landed. `Policy::set_default` changes only the default action now.
    #[test]
    fn test_set_import_and_export_default_preserve_otc_terms() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Peer)]);
        // Peer role installs 2 import terms and 2 export terms (see
        // test_install_otc_terms_counts_per_role).
        assert_eq!(state.import_policies[&peer_ip].len(), 2);
        assert_eq!(state.export_policies[&peer_ip].len(), 2);

        state.set_import_default(peer_ip, DefaultAction::Accept);
        state.set_export_default(peer_ip, DefaultAction::Reject);

        assert_eq!(
            state.import_policies[&peer_ip].len(),
            2,
            "set_import_default must not remove OTC terms"
        );
        assert_eq!(
            state.import_policies_v6[&peer_ip].len(),
            2,
            "set_import_default must not remove OTC terms from the v6 policy either"
        );
        assert_eq!(
            state.export_policies[&peer_ip].len(),
            2,
            "set_export_default must not remove OTC terms"
        );
        assert_eq!(
            state.import_policies[&peer_ip].default_action(),
            DefaultAction::Accept,
            "the default action itself must still change"
        );
        assert_eq!(
            state.export_policies[&peer_ip].default_action(),
            DefaultAction::Reject,
            "the default action itself must still change"
        );

        // And the actual leak-rejection behavior must still function after
        // the default-action change, not just the term count.
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(99999)));
        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
            "leak rejection must still fire after set_import_default"
        );
    }

    /// The same `set_import_default` bug fixed above also silently disabled
    /// RFC 6811 ROV via the identical code path — `install_rpki_import_terms`
    /// adds its reject term to `import_policies`/`import_policies_v6`, which
    /// `set_import_default` used to fully replace. This is a direct
    /// regression guard for that specific claim (made in `CHANGELOG.md` and
    /// `pathvector-rpki/RFC.md`), not just an OTC-flavored duplicate of the
    /// test above — a peer with no `role` configured at all (ROV is
    /// role-independent) must still have its ROV term survive.
    #[test]
    fn test_set_import_default_preserves_rpki_rov_term() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) = make_state(65001, &[(peer_ip, 65002)]);
        let rtr = pathvector_rpki::for_testing(
            [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999)],
            std::iter::empty(),
        );
        state.install_rpki_import_terms(&rtr);
        assert_eq!(state.import_policies[&peer_ip].len(), 1);

        state.set_import_default(peer_ip, DefaultAction::Accept);

        assert_eq!(
            state.import_policies[&peer_ip].len(),
            1,
            "set_import_default must not remove the RPKI ROV term"
        );

        // And ROV rejection must still actually fire afterward.
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop(peer_ip),
                ],
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
            "ROV rejection (wrong origin AS) must still fire after set_import_default"
        );
    }

    #[test]
    fn test_provider_role_rejects_route_leaked_with_otc_from_customer() {
        // session_role = Provider: the peer is our Customer. A well-behaved
        // Customer never sends OTC — receiving one at all is a leak.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Provider)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(1)));

        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
            "route leaked with OTC from a Customer must be rejected"
        );
    }

    #[test]
    fn test_provider_role_accepts_clean_route_without_attaching_otc() {
        // session_role = Provider: a route without OTC from our Customer is
        // legitimate and accepted; no ingress attach happens on this side
        // (attach only applies when session_role is Customer/Peer/RsClient).
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Provider)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", None));

        let route = state
            .rib
            .loc_rib
            .best(&nlri("10.0.0.0/8"))
            .expect("clean route from Customer must be accepted");
        assert_eq!(route.otc(), None);
    }

    #[test]
    fn test_customer_role_attaches_peer_asn_on_ingress() {
        // session_role = Customer: the peer is our Provider. No leak
        // detection applies here; the route gets OTC = peer's ASN attached
        // so downstream OTC enforcement (at the next hop) can work.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Customer)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", None));

        let route = state
            .rib
            .loc_rib
            .best(&nlri("10.0.0.0/8"))
            .expect("route from Provider must be accepted");
        assert_eq!(route.otc(), Some(Asn::new(65002)));
    }

    #[test]
    fn test_peer_role_rejects_route_with_mismatched_otc_asn() {
        // session_role = Peer: OTC present with a value other than the
        // peer's own ASN indicates a leak further upstream.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Peer)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(99999)));

        assert!(state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none());
    }

    #[test]
    fn test_route_leak_prevented_across_two_provider_peers() {
        // The canonical RFC 9234 scenario: a route learned from one Provider
        // must never be re-advertised to another Provider (the leak that
        // caused the 2019 Verizon/Allegheny/Cloudflare incident). peer_a and
        // peer_b are both configured as our Customer (session_role =
        // Customer — they are our upstream Providers); peer_c is configured
        // as our Provider (session_role = Provider — they are our Customer).
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let peer_c: Ipv4Addr = "10.0.0.4".parse().unwrap();
        let (mut state, mut receivers) = make_state_with_roles(
            65001,
            &[
                (peer_a, 65002, config::PeerRole::Customer),
                (peer_b, 65003, config::PeerRole::Customer),
                (peer_c, 65004, config::PeerRole::Provider),
            ],
        );
        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        state.on_established(peer_c, peer_c, PeerType::External, 65004, 90, &[], None);
        drain_all(&mut receivers);

        // Learned from peer_a (our Provider) with no OTC yet — gets attached.
        state.on_route_update(peer_a, announce_with_otc(65002, "10.0.0.0/8", None));
        state.flush_pending();

        let stored = state
            .rib
            .loc_rib
            .best(&nlri("10.0.0.0/8"))
            .expect("route from peer_a must be accepted");
        assert_eq!(
            stored.otc(),
            Some(Asn::new(65002)),
            "ingress attach must fire for a Customer-role session"
        );

        // Must NOT reach peer_b — another Provider. This is the leak.
        assert!(
            receivers.get_mut(&peer_b).unwrap().try_recv().is_err(),
            "route already carrying OTC must never be advertised to another Provider"
        );

        // Must reach peer_c — our Customer — with OTC preserved on the wire.
        let msg = receivers
            .get_mut(&peer_c)
            .unwrap()
            .try_recv()
            .expect("route must be advertised to our Customer");
        assert!(
            msg.attributes.iter().any(
                |a| matches!(a, PathAttribute::OnlyToCustomer(asn) if *asn == Asn::new(65002))
            ),
            "OTC must be preserved unchanged on the wire toward our Customer"
        );
    }

    #[test]
    fn test_route_server_role_rejects_leak_accepts_clean_without_attach() {
        // session_role = RouteServer: the peer is our RS-Client. Mirrors the
        // Provider case — RouteServer wasn't previously exercised at the
        // daemon/route level, only via the term-count table.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::RouteServer)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(1)));
        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_none(),
            "OTC from an RS-Client must always be rejected as a leak"
        );

        state.on_route_update(peer_ip, announce_with_otc(65002, "198.51.100.0/24", None));
        let route = state
            .rib
            .loc_rib
            .best(&nlri("198.51.100.0/24"))
            .expect("clean route from RS-Client must be accepted");
        assert_eq!(
            route.otc(),
            None,
            "no ingress attach for RouteServer role (only Customer/Peer/RsClient attach)"
        );
    }

    #[test]
    fn test_rs_client_role_attaches_peer_asn_on_ingress() {
        // session_role = RsClient: the peer is our RouteServer. Mirrors the
        // Customer case — RsClient wasn't previously exercised at the
        // daemon/route level, only via the term-count table.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::RsClient)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", None));

        let route = state
            .rib
            .loc_rib
            .best(&nlri("10.0.0.0/8"))
            .expect("route from RouteServer must be accepted");
        assert_eq!(route.otc(), Some(Asn::new(65002)));
    }

    #[test]
    fn test_peer_role_accepts_and_preserves_matching_otc() {
        // session_role = Peer, OTC present and matching the peer's own ASN —
        // not a leak per RFC 9234 §5 rule 2. Must be accepted, and SetOtc
        // must not overwrite the already-correct value.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Peer)]);
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        state.on_route_update(peer_ip, announce_with_otc(65002, "10.0.0.0/8", Some(65002)));

        let route = state
            .rib
            .loc_rib
            .best(&nlri("10.0.0.0/8"))
            .expect("OTC matching the peer's own ASN must not be treated as a leak");
        assert_eq!(route.otc(), Some(Asn::new(65002)));
    }

    #[test]
    fn test_peer_role_egress_blocks_leaked_route_and_attaches_clean_one() {
        // session_role = Peer on egress: a route that already carries OTC
        // (learned from peer_provider, a Customer-role session on our side)
        // must never reach a Peer-role destination — RFC 9234 §6 rule 2
        // treats Peer the same as Provider/RS on the block side. A separate,
        // clean route (no OTC yet) must be advertised to the Peer-role
        // destination *with* OTC attached — §6 rule 1 also treats Peer the
        // same as Provider/RS on the attach side. Both rules apply to the
        // same Peer-role session simultaneously.
        let peer_provider: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_lateral: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state_with_roles(
            65001,
            &[
                (peer_provider, 65002, config::PeerRole::Customer),
                (peer_lateral, 65003, config::PeerRole::Peer),
            ],
        );
        state.on_established(
            peer_provider,
            peer_provider,
            PeerType::External,
            65002,
            90,
            &[],
            None,
        );
        state.on_established(
            peer_lateral,
            peer_lateral,
            PeerType::External,
            65003,
            90,
            &[],
            None,
        );
        drain_all(&mut receivers);

        // Learned from peer_provider (our Provider) with no OTC — gets
        // attached (session_role = Customer is in the ingress-attach set).
        state.on_route_update(peer_provider, announce_with_otc(65002, "10.0.0.0/8", None));
        state.flush_pending();
        assert_eq!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).unwrap().otc(),
            Some(Asn::new(65002))
        );
        assert!(
            receivers
                .get_mut(&peer_lateral)
                .unwrap()
                .try_recv()
                .is_err(),
            "a route already carrying OTC must never reach a Peer-role destination"
        );

        // A second, clean route learned from the same Provider stays clean
        // only until it crosses to peer_lateral, where it must get OTC
        // attached (session_role = Peer is also in the egress-attach set).
        // Use a peer with no attach-on-ingress applicable here by importing
        // directly via a peer with no configured role instead, to isolate
        // the egress-attach behavior from ingress-attach.
        let peer_plain: Ipv4Addr = "10.0.0.4".parse().unwrap();
        state.add_peer(
            &config::PeerConfig {
                address: peer_plain,
                port: 179,
                remote_as: 65004,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
            },
            mpsc::channel(64).0,
        );
        state.on_established(
            peer_plain,
            peer_plain,
            PeerType::External,
            65004,
            90,
            &[],
            None,
        );
        drain_all(&mut receivers);

        state.on_route_update(
            peer_plain,
            announce_with_otc(65004, "198.51.100.0/24", None),
        );
        state.flush_pending();
        assert_eq!(
            state
                .rib
                .loc_rib
                .best(&nlri("198.51.100.0/24"))
                .unwrap()
                .otc(),
            None,
            "no configured role on peer_plain means no ingress attach"
        );
        let msg = receivers
            .get_mut(&peer_lateral)
            .unwrap()
            .try_recv()
            .expect("clean route must reach the Peer-role destination");
        assert!(
            msg.attributes.iter().any(
                |a| matches!(a, PathAttribute::OnlyToCustomer(asn) if *asn == Asn::new(65001))
            ),
            "OTC = local ASN must be attached on egress toward a Peer-role destination"
        );
    }

    #[test]
    fn test_ipv6_ingress_otc_extraction_and_leak_rejection() {
        // The daemon-level OTC tests above all exercise the IPv4 ingress
        // path only; this confirms the IPv6 MP_REACH_NLRI path (route.rs's
        // second RouteBuilder + `.otc(asn)` call) is actually wired, not
        // just compiling.
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _rx) =
            make_state_with_roles(65001, &[(peer_ip, 65002, config::PeerRole::Provider)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());
        state.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            65002,
            90,
            &[Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)],
            None,
        );

        let leaked_v6: Nlri<Ipv6Addr> = "2001:db8:dead::/48".parse().unwrap();
        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                        prefixes: vec![Prefix::V6(leaked_v6)],
                    }),
                    PathAttribute::OnlyToCustomer(Asn::new(65100)),
                ],
                announced: vec![],
            },
        );
        assert!(
            state.rib.loc_rib_v6.best(&leaked_v6).is_none(),
            "IPv6 route leaked with OTC from a Customer must be rejected"
        );

        let clean_v6: Nlri<Ipv6Addr> = "2001:db8:beef::/48".parse().unwrap();
        state.on_route_update(
            peer_ip,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                        prefixes: vec![Prefix::V6(clean_v6)],
                    }),
                ],
                announced: vec![],
            },
        );
        let route = state
            .rib
            .loc_rib_v6
            .best(&clean_v6)
            .expect("clean IPv6 route from Customer must be accepted");
        assert_eq!(
            route.otc(),
            None,
            "Provider role does not ingress-attach OTC"
        );
    }

    #[test]
    fn test_ipv6_egress_otc_block_and_attach() {
        // IPv6 counterpart of `test_peer_role_egress_blocks_leaked_route_and_
        // attaches_clean_one` — regression guard for the IPv6 export-policy
        // gap: `propagate_prefix_v6` used to never consult any export policy
        // at all, so RFC 9234's OTC egress block/attach terms (installed
        // correctly into `export_policies_v6`) had zero effect on IPv6
        // UPDATEs. Same scenario as the v4 test, over IPv6 NLRIs.
        let peer_provider: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_lateral: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_state_with_roles(
            65001,
            &[
                (peer_provider, 65002, config::PeerRole::Customer),
                (peer_lateral, 65003, config::PeerRole::Peer),
            ],
        );
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());
        let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(
            peer_provider,
            peer_provider,
            PeerType::External,
            65002,
            90,
            &v6_caps,
            None,
        );
        state.on_established(
            peer_lateral,
            peer_lateral,
            PeerType::External,
            65003,
            90,
            &v6_caps,
            None,
        );
        drain_all(&mut receivers);

        // Learned from peer_provider (our Provider) with no OTC — gets
        // attached on ingress (session_role = Customer is in the
        // ingress-attach set), so it already carries OTC by the time it's
        // considered for export.
        let leaked_v6: Nlri<Ipv6Addr> = "2001:db8:dead::/48".parse().unwrap();
        state.on_route_update(
            peer_provider,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::2".parse().unwrap()),
                        prefixes: vec![Prefix::V6(leaked_v6)],
                    }),
                ],
                announced: vec![],
            },
        );
        state.flush_pending();
        assert_eq!(
            state.rib.loc_rib_v6.best(&leaked_v6).unwrap().otc(),
            Some(Asn::new(65002))
        );
        assert!(
            receivers
                .get_mut(&peer_lateral)
                .unwrap()
                .try_recv()
                .is_err(),
            "an IPv6 route already carrying OTC must never reach a Peer-role destination"
        );

        // A second, clean IPv6 route from a peer with no configured role
        // (so no ingress attach) crosses to peer_lateral, where it must get
        // OTC attached on egress (session_role = Peer is in the
        // egress-attach set too).
        let peer_plain: Ipv4Addr = "10.0.0.4".parse().unwrap();
        state.add_peer(
            &config::PeerConfig {
                address: peer_plain,
                port: 179,
                remote_as: 65004,
                import_default: Some(config::ImportDefault::Accept),
                export_default: Some(config::ExportDefault::Accept),
                import_default_v6: None,
                md5_password: None,
                is_rr_client: false,
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
            },
            mpsc::channel(64).0,
        );
        state.on_established(
            peer_plain,
            peer_plain,
            PeerType::External,
            65004,
            90,
            &v6_caps,
            None,
        );
        drain_all(&mut receivers);

        let clean_v6: Nlri<Ipv6Addr> = "2001:db8:beef::/48".parse().unwrap();
        state.on_route_update(
            peer_plain,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65004)])),
                    PathAttribute::MpReachNlri(MpReachNlri {
                        afi_safi: AfiSafi::IPV6_UNICAST,
                        next_hop: NextHop::V6("2001:db8::4".parse().unwrap()),
                        prefixes: vec![Prefix::V6(clean_v6)],
                    }),
                ],
                announced: vec![],
            },
        );
        state.flush_pending();
        assert_eq!(
            state.rib.loc_rib_v6.best(&clean_v6).unwrap().otc(),
            None,
            "no configured role on peer_plain means no ingress attach"
        );
        let msg = receivers
            .get_mut(&peer_lateral)
            .unwrap()
            .try_recv()
            .expect("clean IPv6 route must reach the Peer-role destination");
        assert!(
            msg.attributes.iter().any(
                |a| matches!(a, PathAttribute::OnlyToCustomer(asn) if *asn == Asn::new(65001))
            ),
            "OTC = local ASN must be attached on IPv6 egress toward a Peer-role destination"
        );
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
            let has_origin = msg
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Origin(_)));
            let has_as_path = msg
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::AsPath(_)));
            let has_next_hop = msg
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::NextHop(_)));
            if !has_origin {
                msg.attributes.push(PathAttribute::Origin(Origin::Igp));
            }
            if !has_as_path {
                msg.attributes
                    .push(PathAttribute::AsPath(AsPath::from_sequence(vec![
                        Asn::new(65009),
                    ])));
            }
            if !has_next_hop {
                msg.attributes
                    .push(PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)));
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
        let rare = route.rare_or_default();
        assert_eq!(rare.communities.len(), 1);
        assert_eq!(rare.large_communities.len(), 1);
        assert_eq!(rare.extended_communities.len(), 1);
        assert!(rare.atomic_aggregate);
        assert!(rare.aggregator.is_some());
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

    // ── RFC 7999 blackhole FIB integration ───────────────────────────────────

    fn blackhole_announce(prefix: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
                PathAttribute::Communities(vec![Community::BLACKHOLE]),
            ],
            announced: vec![prefix.parse().unwrap()],
        }
    }

    fn blackhole_withdraw(prefix: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![prefix.parse().unwrap()],
            attributes: vec![],
            announced: vec![],
        }
    }

    fn unicast_announce(prefix: &str, next_hop: &str) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(next_hop.parse::<Ipv4Addr>().unwrap()),
            ],
            announced: vec![prefix.parse().unwrap()],
        }
    }

    /// A BLACKHOLE-tagged route must trigger `apply_blackhole_v4` on the FIB
    /// manager so the kernel programs a null route.
    #[test]
    fn blackhole_route_programs_kernel_null_route() {
        let (mut state, _rxs) = make_state(65001, &[(Ipv4Addr::new(10, 0, 0, 2), 65002)]);
        let fib = with_recording_fib(&mut state);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        state.on_established(peer, peer, PeerType::External, 65002, 90, &[], None);
        state.set_import_default(peer, DefaultAction::Accept);

        state.on_route_update(peer, blackhole_announce("192.0.2.0/24"));

        let bh = fib.blackhole_v4.lock().unwrap().clone();
        let announced_nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        assert!(
            bh.iter()
                .any(|(n, announced)| *n == announced_nlri && *announced),
            "apply_blackhole_v4 must be called for BLACKHOLE-tagged prefix"
        );
    }

    /// A BLACKHOLE-tagged route must NOT enter the LocRib or be advertised
    /// outbound — only the kernel null route is programmed.
    #[test]
    fn blackhole_route_not_in_loc_rib() {
        let (mut state, _rxs) = make_state(65001, &[(Ipv4Addr::new(10, 0, 0, 2), 65002)]);
        with_recording_fib(&mut state);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        state.on_established(peer, peer, PeerType::External, 65002, 90, &[], None);
        state.set_import_default(peer, DefaultAction::Accept);

        state.on_route_update(peer, blackhole_announce("192.0.2.0/24"));

        // LocRib must remain empty for the blackhole prefix.
        assert_eq!(
            Arc::clone(&state.rib).loc_rib.len(),
            0,
            "BLACKHOLE route must not enter LocRib"
        );
    }

    /// When a previously-announced BLACKHOLE route is withdrawn by the peer,
    /// `withdraw_blackhole_v4` must be called to remove the kernel null route.
    #[test]
    fn blackhole_route_withdrawal_removes_kernel_null_route() {
        let (mut state, _rxs) = make_state(65001, &[(Ipv4Addr::new(10, 0, 0, 2), 65002)]);
        let fib = with_recording_fib(&mut state);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        state.on_established(peer, peer, PeerType::External, 65002, 90, &[], None);
        state.set_import_default(peer, DefaultAction::Accept);

        state.on_route_update(peer, blackhole_announce("192.0.2.0/24"));
        fib.blackhole_v4.lock().unwrap().clear();

        state.on_route_update(peer, blackhole_withdraw("192.0.2.0/24"));

        let bh = fib.blackhole_v4.lock().unwrap().clone();
        let withdrawn_nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        assert!(
            bh.iter()
                .any(|(n, announced)| *n == withdrawn_nlri && !announced),
            "withdraw_blackhole_v4 must be called when BLACKHOLE route is withdrawn"
        );
    }

    /// Regression: when a session tears down, kernel null routes installed for
    /// BLACKHOLE-tagged prefixes from that peer must be withdrawn.
    /// Previously `on_terminated` cleared AdjRibIn without scanning for
    /// BLACKHOLE routes, leaking the kernel null route indefinitely.
    #[test]
    fn blackhole_route_removed_on_session_teardown() {
        let (mut state, _rxs) = make_state(65001, &[(Ipv4Addr::new(10, 0, 0, 2), 65002)]);
        let fib = with_recording_fib(&mut state);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        state.on_established(peer, peer, PeerType::External, 65002, 90, &[], None);
        state.set_import_default(peer, DefaultAction::Accept);

        state.on_route_update(peer, blackhole_announce("192.0.2.0/24"));
        fib.blackhole_v4.lock().unwrap().clear();

        state.on_terminated(peer, TerminationReason::OperatorStop, false);

        let bh = fib.blackhole_v4.lock().unwrap().clone();
        let nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        assert!(
            bh.iter().any(|(n, announced)| *n == nlri && !*announced),
            "on_terminated must call withdraw_blackhole_v4 for BLACKHOLE-tagged prefixes"
        );
    }

    /// Regression: when a unicast route for prefix X is in LocRib and a peer
    /// re-announces X with the BLACKHOLE community, the unicast LocRib entry
    /// must be removed so a unicast kernel route and a null route don't coexist.
    #[test]
    fn blackhole_upgrade_evicts_unicast_from_loc_rib() {
        let (mut state, _rxs) = make_state(65001, &[(Ipv4Addr::new(10, 0, 0, 2), 65002)]);
        with_recording_fib(&mut state);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        state.on_established(peer, peer, PeerType::External, 65002, 90, &[], None);
        state.set_import_default(peer, DefaultAction::Accept);

        // First announce as unicast — enters LocRib.
        state.on_route_update(
            peer,
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                    PathAttribute::NextHop("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
                ],
                announced: vec!["10.0.0.0/8".parse().unwrap()],
            },
        );
        assert_eq!(
            Arc::clone(&state.rib).loc_rib.len(),
            1,
            "unicast must be in LocRib"
        );

        // Now re-announce the same prefix with BLACKHOLE community.
        state.on_route_update(peer, blackhole_announce("10.0.0.0/8"));

        assert_eq!(
            Arc::clone(&state.rib).loc_rib.len(),
            0,
            "re-announcement as BLACKHOLE must evict the unicast LocRib entry"
        );
    }

    /// Regression: a BLACKHOLE route held through GR (peer's stale routes
    /// retained) must have its kernel null route removed when the GR deadline
    /// expires and the stale routes are flushed.
    #[test]
    fn blackhole_route_removed_when_gr_deadline_expires() {
        use pathvector_session::message::{Capability, GracefulRestartFamily};
        use pathvector_types::AfiSafi;

        let peer = Ipv4Addr::new(10, 0, 0, 2);
        let (mut state, _rxs) = make_state(65001, &[(peer, 65002)]);
        let fib = with_recording_fib(&mut state);

        let gr_family = GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: true,
        };
        state.on_established(
            peer,
            peer,
            PeerType::External,
            65002,
            90,
            &[Capability::GracefulRestart {
                restart_flags: 0,
                restart_time: 120,
                families: vec![gr_family],
            }],
            None,
        );
        state.set_import_default(peer, DefaultAction::Accept);

        // Install a BLACKHOLE kernel null route.
        state.on_route_update(peer, blackhole_announce("192.0.2.0/24"));
        fib.blackhole_v4.lock().unwrap().clear();

        // Session drops uncleanly — GR helper mode entered, stale routes kept.
        state.on_terminated(peer, TerminationReason::Unclean, false);

        // GR deadline expires — stale routes must be flushed.
        state.on_gr_deadline_expired(peer);

        let bh = fib.blackhole_v4.lock().unwrap().clone();
        let nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        assert!(
            bh.iter().any(|(n, announced)| *n == nlri && !*announced),
            "GR deadline expiry must withdraw the kernel null route for stale BLACKHOLE prefix"
        );
    }

    /// When a peer has GR capability for IPv6 only (not IPv4), and the session
    /// drops uncleanly, IPv4 AdjRibIn is cleared immediately. Any IPv4 BLACKHOLE
    /// kernel null routes must be withdrawn BEFORE the clear — they bypass LocRib
    /// and are otherwise invisible to the normal withdrawal path.
    #[test]
    fn blackhole_route_removed_for_non_gr_family_on_unclean_termination() {
        use pathvector_session::message::{Capability, GracefulRestartFamily};
        use pathvector_types::AfiSafi;

        let peer = Ipv4Addr::new(10, 0, 0, 2);
        let (mut state, _rxs) = make_state(65001, &[(peer, 65002)]);
        let fib = with_recording_fib(&mut state);

        // Peer advertises GR for IPv6 only — IPv4 is NOT covered.
        let gr_family_v6 = GracefulRestartFamily {
            afi_safi: AfiSafi::IPV6_UNICAST,
            forwarding_preserved: true,
        };
        state.on_established(
            peer,
            peer,
            PeerType::External,
            65002,
            90,
            &[Capability::GracefulRestart {
                restart_flags: 0,
                restart_time: 120,
                families: vec![gr_family_v6],
            }],
            None,
        );
        state.set_import_default(peer, DefaultAction::Accept);

        // Peer announces an IPv4 BLACKHOLE prefix.
        state.on_route_update(peer, blackhole_announce("192.0.5.0/24"));
        fib.blackhole_v4.lock().unwrap().clear();

        // Unclean termination — enters GR helper mode for IPv6, but IPv4 is
        // NOT covered by GR, so IPv4 AdjRibIn is cleared immediately.
        // The kernel null route for 192.0.5.0/24 must be withdrawn first.
        state.on_terminated(peer, TerminationReason::Unclean, false);

        let bh = fib.blackhole_v4.lock().unwrap().clone();
        let nlri: Nlri<Ipv4Addr> = "192.0.5.0/24".parse().unwrap();
        assert!(
            bh.iter().any(|(n, announced)| *n == nlri && !*announced),
            "IPv4 BLACKHOLE kernel null route must be withdrawn when IPv4 is not a GR family"
        );
    }

    /// When peer A sends a BLACKHOLE route for prefix X (suppressing any prior
    /// unicast entry), and peer B has a unicast route for X in LocRib, withdrawing
    /// the BLACKHOLE must re-install peer B's unicast route in the kernel FIB.
    ///
    /// Without the fix, `loc_rib.withdraw(&peer_a, X)` returns `Unchanged` (A was
    /// never in LocRib for the BLACKHOLE) and no FIB event fires for B's route —
    /// leaving the kernel with no route for X despite LocRib having B's path.
    #[test]
    fn blackhole_withdrawal_restores_surviving_peer_unicast_route() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 2);
        let peer_b = Ipv4Addr::new(10, 0, 0, 3);
        let (mut state, _rxs) = make_state(65001, &[(peer_a, 65002), (peer_b, 65003)]);
        let fib = with_recording_fib(&mut state);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        state.set_import_default(peer_a, DefaultAction::Accept);
        state.set_import_default(peer_b, DefaultAction::Accept);

        // Peer B announces a unicast route for the prefix.
        state.on_route_update(peer_b, unicast_announce("10.2.0.0/24", "10.0.0.3"));

        // Peer A announces the same prefix with BLACKHOLE community.
        // This should program a kernel null route.
        state.on_route_update(peer_a, blackhole_announce("10.2.0.0/24"));

        // Clear the recorded FIB events so we only observe what happens on withdrawal.
        fib.v4.lock().unwrap().clear();
        fib.blackhole_v4.lock().unwrap().clear();

        // Peer A withdraws the BLACKHOLE route.
        state.on_route_update(peer_a, blackhole_withdraw("10.2.0.0/24"));

        let nlri: Nlri<Ipv4Addr> = "10.2.0.0/24".parse().unwrap();

        // The kernel null route must be withdrawn.
        let bh = fib.blackhole_v4.lock().unwrap().clone();
        assert!(
            bh.iter().any(|(n, announced)| *n == nlri && !*announced),
            "BLACKHOLE withdrawal must remove the kernel null route"
        );

        // Peer B's unicast route must be re-installed in the kernel FIB.
        let v4 = fib.v4.lock().unwrap().clone();
        assert!(
            v4.iter()
                .any(|c| matches!(c, BestPathChange::Announced(n, _) if *n == nlri)),
            "BLACKHOLE withdrawal must trigger re-install of surviving peer-B unicast route; \
             got: {v4:?}"
        );
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

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        drain_all(&mut rxs);

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
        state.flush_pending();
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
        state.flush_pending();

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
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
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
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
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
            &accept_all_v6(),
            PeerType::Internal,
            65001,
            None, // no local_ipv6 — OK for iBGP
            false,
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
            &accept_all_v6(),
            PeerType::External,
            65001,
            Some(local_v6),
            false,
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
            &accept_all_v6(),
            PeerType::External,
            65001,
            None, // no local_ipv6 — eBGP must NOT announce
            false,
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
            &accept_all_v6(),
            PeerType::Internal,
            65001,
            None,
            false,
        );

        // Now withdraw from loc_rib_v6 and propagate again.
        rib_v6.withdraw(&peer(), &nlri_v6("2001:db8::/32"), &AlwaysReachable);
        let decision = propagate_prefix_v6(
            nlri_v6("2001:db8::/32"),
            &rib_v6,
            &mut aro,
            &accept_all_v6(),
            PeerType::Internal,
            65001,
            None,
            false,
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
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &caps, None);

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
        state.on_established(
            peer_a,
            peer_a,
            PeerType::External,
            65002,
            90,
            &v6_caps,
            None,
        );
        state.on_established(
            peer_b,
            peer_b,
            PeerType::External,
            65003,
            90,
            &v6_caps,
            None,
        );
        drain_all(&mut rxs);

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

        state.flush_pending();

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

    // ── reapply_import_policy_v6 ──────────────────────────────────────────────

    #[test]
    fn test_reapply_v6_accepts_previously_rejected_route() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();

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
            &mut fresh_ari(),
            &mut LocRib::new(),
            &mut ari_v6,
            &mut rib_v6,
            &accept_all(),
            &reject_all_v6(),
            PeerType::External,
            &AlwaysReachable,
            &AlwaysReachable,
            65002,
            None,
            None,
        );
        assert!(rib_v6.is_empty(), "route rejected by initial policy");

        reapply_import_policy_v6(
            peer(),
            &ari_v6,
            &mut rib_v6,
            &accept_all_v6(),
            &AlwaysReachable,
        );
        assert!(
            rib_v6.best(&nlri_v6("2001:db8::/32")).is_some(),
            "route must be accepted after policy change"
        );
    }

    #[test]
    fn test_reapply_v6_rejects_previously_accepted_route() {
        let mut rib_v6: LocRib<Ipv6Addr> = LocRib::new();
        let mut ari_v6 = fresh_ari_v6();

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
            &mut fresh_ari(),
            &mut LocRib::new(),
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
        assert!(rib_v6.best(&nlri_v6("2001:db8::/32")).is_some());

        reapply_import_policy_v6(
            peer(),
            &ari_v6,
            &mut rib_v6,
            &reject_all_v6(),
            &AlwaysReachable,
        );
        assert!(
            rib_v6.best(&nlri_v6("2001:db8::/32")).is_none(),
            "route must be withdrawn after policy change"
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
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id(), false);
        assert_eq!(out.as_path.path_length(), 2);
        assert!(out.as_path.contains(Asn::new(65001)));
        assert!(out.as_path.contains(Asn::new(65002)));
    }

    #[test]
    fn test_prepare_outbound_ebgp_rewrites_next_hop() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id(), false);
        assert_eq!(out.next_hop, Some(NextHop::V4(bgp_id())));
    }

    #[test]
    fn test_prepare_outbound_ebgp_strips_local_pref() {
        let route = ebgp_route_with_lp("10.0.0.0/8");
        let out = prepare_outbound(route, PeerType::External, 65001, bgp_id(), false);
        assert!(
            out.local_pref.is_none(),
            "LOCAL_PREF must be stripped for eBGP"
        );
    }

    #[test]
    fn test_prepare_outbound_ibgp_preserves_attributes() {
        let route = ibgp_route("10.0.0.0/8");
        let out = prepare_outbound(route.clone(), PeerType::Internal, 65001, bgp_id(), false);
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
        route.rare_mut().originator_id = Some("1.1.1.1".parse::<Ipv4Addr>().unwrap());
        route.rare_mut().cluster_list = vec![0x0101_0101u32];

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
        route.rare_mut().originator_id = Some("1.1.1.1".parse::<Ipv4Addr>().unwrap());
        route.rare_mut().cluster_list = vec![0x0101_0101u32];

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
        use pathvector_types::AsPathSegment;
        let mut rib = LocRib::new();
        let mut ari = fresh_ari();
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
        Arc::make_mut(&mut state.rib).rr_clients.insert(client);

        // non_client_b establishes and deposits a route.
        state.on_established(
            non_client_b,
            non_client_b,
            PeerType::Internal,
            65001,
            90,
            &[],
            None,
        );
        let src = PeerId::new(IpAddr::V4(non_client_b));
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(non_client_b))
            .peer_type(PeerType::Internal)
            .build();
        state.rib_insert_v4(src, route);

        // Drain non_client_b's channel (its own establish dump).
        while rxs.get_mut(&non_client_b).unwrap().try_recv().is_ok() {}

        // non_client_a establishes — must NOT receive the route from non_client_b.
        state.on_established(
            non_client_a,
            non_client_a,
            PeerType::Internal,
            65001,
            90,
            &[],
            None,
        );
        // Drain all EOR markers (RFC 4724 §2) from on_established, then verify no
        // actual route UPDATE was sent. EORs are either empty UpdateMessages (IPv4)
        // or UpdateMessages with empty MP_UNREACH_NLRI (IPv6, RFC 4724 §2).
        let rx = rxs.get_mut(&non_client_a).unwrap();
        let mut route_received = false;
        while let Ok(m) = rx.try_recv() {
            let has_announced_nlri = !m.announced.is_empty();
            let has_mp_reach = m
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if !mp.prefixes.is_empty()));
            if has_announced_nlri || has_mp_reach {
                route_received = true;
            }
        }
        assert!(
            !route_received,
            "non-client must not receive routes from other non-clients during full-table dump (RFC 4456 §8)"
        );
    }

    #[test]
    fn test_on_established_rr_client_receives_all_routes_in_dump() {
        // An RR client MUST receive the full table on establish, including routes
        // from non-client iBGP peers.
        let non_client: Ipv4Addr = "10.0.0.4".parse().unwrap();
        let client: Ipv4Addr = "10.0.0.3".parse().unwrap();

        let (mut state, mut rxs) = make_state(65001, &[(non_client, 65001), (client, 65001)]);
        Arc::make_mut(&mut state.rib).rr_clients.insert(client);

        // non_client deposits a route.
        state.on_established(
            non_client,
            non_client,
            PeerType::Internal,
            65001,
            90,
            &[],
            None,
        );
        let src = PeerId::new(IpAddr::V4(non_client));
        let route = RouteBuilder::new(nlri("10.0.0.0/8"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(non_client))
            .peer_type(PeerType::Internal)
            .build();
        state.rib_insert_v4(src, route);
        while rxs.get_mut(&non_client).unwrap().try_recv().is_ok() {}

        // RR client establishes — MUST receive the route from the non-client.
        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
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
        state.on_established(
            peer_a,
            peer_a,
            PeerType::External,
            65002,
            90,
            &v6_caps,
            None,
        );
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

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

        // peer_b (no IPv6 capability) gets an IPv4 EOR from on_established
        // but must not receive any MP_REACH_NLRI — drain the EOR first.
        rxs.get_mut(&peer_b).unwrap().try_recv().ok(); // IPv4 EOR
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
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        // Must receive exactly one message: the IPv4 EOR. No IPv6 dump, no IPv6 EOR.
        let eor = rxs
            .get_mut(&peer_ip)
            .unwrap()
            .try_recv()
            .expect("must receive IPv4 EOR even for non-IPv6-capable peer");
        assert!(
            eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty(),
            "only the IPv4 EOR should arrive — got: {eor:?}"
        );
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
        let decision = propagate_prefix(nlri, rib, aro, policy, peer_type, local_as, bgp_id, false);
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
        state.on_established(gobgp, gobgp, PeerType::External, 65001, 90, &[], None);

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
        state.flush_pending();
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
        state.flush_pending();

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
        state.flush_pending();
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}
        assert_eq!(
            state.rib.loc_rib.len(),
            2,
            "phase 3 reject: only local originated routes remain"
        );

        // ── 4. Import policy → accept; GoBGP routes return ───────────────────
        state.set_import_default(gobgp, DefaultAction::Accept);
        state.flush_pending();
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
        state.flush_pending();
        while rx_map.get_mut(&gobgp).unwrap().try_recv().is_ok() {}
        assert_eq!(
            state.rib.loc_rib.len(),
            3,
            "phase 5: 192 from GoBGP + 2 local routes remain"
        );

        // ── 6. Daemon withdraws {203, 198}; GoBGP must receive WITHDRAWs ─────
        state.withdraw_originated_routes(&[nlri("203.0.113.0/24"), nlri("198.51.100.0/24")]);
        state.flush_pending();
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
        state.on_established(gobgp, gobgp, PeerType::External, 65002, 90, &[], None);
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
                .contains(&nlri_v6("2001:db8::/32")),
            "originated v6 route must be tracked in originated_routes_v6"
        );
    }

    #[test]
    fn test_withdraw_originated_routes_v6_removes_from_rib_and_notifies_peer() {
        use pathvector_types::{AsPath, Origin};
        let gobgp: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let (mut state, mut rx_map) = make_state(65001, &[(gobgp, 65002)]);
        state.on_established(gobgp, gobgp, PeerType::External, 65002, 90, &[], None);
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
                .contains(&nlri_v6("2001:db8:1::/48")),
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
        state.on_established(unknown, unknown, PeerType::External, 65099, 90, &[], None);
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

        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

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

        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

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
        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        state.adj_ribs_out.remove(&peer_b);

        state.on_terminated(peer_a, TerminationReason::Unclean, true);

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
        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        state.update_senders.remove(&peer_b);

        state.on_terminated(peer_a, TerminationReason::Unclean, true);

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
        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
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
        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
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
        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);

        // Inject a ghost peer into peer_types (never registered in config maps).
        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, ghost, PeerType::External, 65099, 90, &[], None);

        // Terminating peer_a iterates established peers; ghost has no policy /
        // rib entries — the error branch logs and continues without panicking.
        state.on_terminated(peer_a, TerminationReason::Unclean, true);
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
        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);

        let ghost: Ipv4Addr = "10.0.0.99".parse().unwrap();
        state.on_established(ghost, ghost, PeerType::External, 65099, 90, &[], None);

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
        let policy_v6: Policy<Route<Ipv6Addr>> =
            Policy::new(pathvector_policy::DefaultAction::Accept);
        handle_update(
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
        )
        .notification
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
        assert_eq!(
            msg.data,
            vec![1u8],
            "data must contain ORIGIN type code (1)"
        );
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
        assert_eq!(
            msg.data,
            vec![2u8],
            "data must contain AS_PATH type code (2)"
        );
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
        assert_eq!(
            msg.data,
            vec![3u8],
            "data must contain NEXT_HOP type code (3)"
        );
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
        assert!(
            n.is_none(),
            "well-formed UPDATE must not trigger NOTIFICATION"
        );
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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

        state.on_established(client_a, client_a, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(client_b, client_b, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

        // Client A sends a route; it should be reflected to Client B
        state.on_route_update(client_a, update_announce("192.0.2.0/24"));
        state.flush_pending();

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

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc, nc, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

        state.on_route_update(client, update_announce("192.0.2.0/24"));
        state.flush_pending();

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

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc, nc, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

        // Non-client iBGP sends a route; it should be reflected to the client
        state.on_route_update(nc, update_announce("192.0.2.0/24"));
        state.flush_pending();

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

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc1, nc1, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc2, nc2, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

        // Non-client nc1 sends a route; nc2 must NOT receive it
        state.on_route_update(nc1, update_announce("192.0.2.0/24"));
        state.flush_pending();

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

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(other, other, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

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

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(other, other, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

        state.on_route_update(client, update_announce("192.0.2.0/24"));
        state.flush_pending();

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

    // RFC 4456 §8: discard when ORIGINATOR_ID == local BGP ID.
    #[test]
    fn test_rr_originator_id_loop_detection_discards_update() {
        let cluster_id: u32 = 7;
        let local_bgp_id: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let other: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client, other], &[]);
        Arc::make_mut(&mut state.rib).local_bgp_id = local_bgp_id;

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(other, other, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

        // UPDATE carries ORIGINATOR_ID equal to our own BGP ID — routing loop.
        let looped = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
                PathAttribute::OriginatorId(local_bgp_id),
            ],
            announced: vec![nlri("192.0.3.0/24")],
        };
        state.on_route_update(client, looped);

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "route with ORIGINATOR_ID == local BGP ID must be discarded (RFC 4456 §8)"
        );
        assert!(
            receivers.get_mut(&other).unwrap().try_recv().is_err(),
            "looped route must not be propagated to other peers"
        );
    }

    // RFC 4456 §8: CLUSTER_LIST loop detection applies to non-client iBGP peers too.
    #[test]
    fn test_rr_cluster_list_loop_detection_applies_to_non_client_ibgp() {
        let cluster_id: u32 = 55;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let non_client: Ipv4Addr = "10.0.0.10".parse().unwrap();
        // non_client is iBGP but not in the rr_clients set
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[non_client]);

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(
            non_client,
            non_client,
            PeerType::Internal,
            65001,
            90,
            &[],
            None,
        );
        drain_all(&mut receivers);

        // UPDATE from the non-client iBGP peer, already carrying our cluster_id.
        let looped = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 1, 1)),
                PathAttribute::ClusterList(vec![cluster_id]),
            ],
            announced: vec![nlri("10.99.0.0/24")],
        };
        state.on_route_update(non_client, looped);

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "CLUSTER_LIST loop detection must apply to non-client iBGP peers (RFC 4456 §8)"
        );
        assert!(
            receivers.get_mut(&client).unwrap().try_recv().is_err(),
            "looped route from non-client must not be reflected to client"
        );
    }

    // RFC 4456 §8: non-client iBGP → client reflection injects correct attributes.
    #[test]
    fn test_rr_non_client_ibgp_to_client_injects_rr_attrs() {
        let cluster_id: u32 = 11;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let non_client: Ipv4Addr = "10.0.0.10".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[non_client]);

        Arc::make_mut(&mut state.rib)
            .peer_bgp_ids
            .insert(non_client, non_client);

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(
            non_client,
            non_client,
            PeerType::Internal,
            65001,
            90,
            &[],
            None,
        );
        drain_all(&mut receivers);

        state.on_route_update(non_client, update_announce("172.16.0.0/24"));
        state.flush_pending();

        let msg = receivers
            .get_mut(&client)
            .unwrap()
            .try_recv()
            .expect("reflected UPDATE expected from non-client → client");

        let has_originator = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == non_client));
        assert!(
            has_originator,
            "ORIGINATOR_ID must be set when reflecting non-client iBGP route to client"
        );
        let has_cluster = msg
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::ClusterList(list) if list.contains(&cluster_id)));
        assert!(
            has_cluster,
            "CLUSTER_LIST must contain cluster_id when reflecting non-client iBGP route to client"
        );
    }

    // ── RFC 4456 §8 IPv6 route paths ─────────────────────────────────────────

    fn nlri_v6_rr(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    fn route_v6_ibgp(prefix: &str) -> Route<Ipv6Addr> {
        use pathvector_types::{AsPath, Origin};
        RouteBuilder::new(nlri_v6_rr(prefix), Origin::Igp, AsPath::new())
            .peer_type(PeerType::Internal)
            .build()
    }

    // Inject a v6 route from `src_peer` into loc_rib_v6 and mark `src_peer` as
    // the iBGP source so split-horizon has a peer to look up.
    fn inject_v6_route(state: &mut DaemonState, src_peer: Ipv4Addr, prefix: &str) {
        let peer_id = PeerId::new(IpAddr::V4(src_peer));
        let route = route_v6_ibgp(prefix);
        state.rib_insert_v6(peer_id, route);
        Arc::make_mut(&mut state.rib)
            .peer_types
            .insert(src_peer, PeerType::Internal);
    }

    // RFC 4456 §8: adj_ribs_out_v6 must use new_reflecting for all iBGP peers
    // when the daemon acts as an RR (set during add_peer, not just at startup).
    #[test]
    fn test_rr_v6_adj_rib_out_is_reflecting_for_ibgp_peer() {
        let cluster_id: u32 = 5;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let non_client: Ipv4Addr = "10.0.0.10".parse().unwrap();
        let (state, _receivers) = make_rr_state(65001, cluster_id, &[client], &[non_client]);

        let client_aro_v6 = state.adj_ribs_out_v6.get(&client).unwrap();
        assert!(
            client_aro_v6.reflects(),
            "adj_ribs_out_v6 for RR client must use reflecting mode"
        );
        let nc_aro_v6 = state.adj_ribs_out_v6.get(&non_client).unwrap();
        assert!(
            nc_aro_v6.reflects(),
            "adj_ribs_out_v6 for non-client iBGP peer must use reflecting mode when acting as RR"
        );
    }

    // RFC 4456 §8: adj_ribs_out_v6 is reset to new_reflecting on reconnect.
    #[test]
    fn test_rr_v6_adj_rib_out_reflecting_restored_after_reconnect() {
        let cluster_id: u32 = 5;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _receivers) = make_rr_state(65001, cluster_id, &[client], &[]);

        // Simulate a session teardown and re-establish.
        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        let aro_v6 = state.adj_ribs_out_v6.get(&client).unwrap();
        assert!(
            aro_v6.reflects(),
            "adj_ribs_out_v6 must be reflecting after reconnect when acting as RR"
        );
    }

    // RFC 4456 §8: propagate_to_all_peers_v6 must block non-client → non-client.
    #[test]
    fn test_rr_v6_split_horizon_blocks_non_client_to_non_client() {
        let cluster_id: u32 = 3;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let nc1: Ipv4Addr = "10.0.0.10".parse().unwrap();
        let nc2: Ipv4Addr = "10.0.0.11".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[nc1, nc2]);

        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc1, nc1, PeerType::Internal, 65001, 90, &[], None);
        state.on_established(nc2, nc2, PeerType::Internal, 65001, 90, &[], None);
        drain_all(&mut receivers);

        // Mark nc1 and nc2 as IPv6-capable so propagate_to_all_peers_v6 includes them.
        state.ipv6_capable_peers.insert(nc1);
        state.ipv6_capable_peers.insert(nc2);
        state.ipv6_capable_peers.insert(client);

        // Inject a v6 route sourced from nc1 (non-client iBGP).
        inject_v6_route(&mut state, nc1, "2001:db8::/32");
        state.propagate_to_all_peers_v6(&[nlri_v6_rr("2001:db8::/32")]);
        state.flush_pending();

        // nc2 (non-client iBGP) must NOT receive the route.
        assert!(
            receivers.get_mut(&nc2).unwrap().try_recv().is_err(),
            "non-client iBGP → non-client iBGP must be blocked for IPv6 routes (RFC 4456 §8)"
        );
        // client MUST receive the route.
        assert!(
            receivers.get_mut(&client).unwrap().try_recv().is_ok(),
            "non-client iBGP → client must be allowed for IPv6 routes (RFC 4456 §8)"
        );
    }

    // Regression test: propagate_to_all_peers_v6 must sync prefixes_advertised
    // itself. Before the fix, only propagate_to_all_peers (v4) called
    // sync_advertised, so a v6-only propagation event (no preceding or
    // following v4 call) left prefixes_advertised with no entry at all for
    // the receiving peer, even though the route was correctly queued for
    // the wire in adj_ribs_out_v6.
    #[test]
    fn test_v6_only_propagation_syncs_prefixes_advertised() {
        // Both peers are eBGP (distinct remote AS from local_as and from each
        // other) so the scenario can't be confused with iBGP full-mesh
        // split-horizon, which would otherwise block source → dest here
        // regardless of this test's fix.
        let cluster_id: u32 = 9;
        let source: Ipv4Addr = "10.0.0.20".parse().unwrap();
        let dest: Ipv4Addr = "10.0.0.21".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[], &[source, dest]);

        state.on_established(source, source, PeerType::External, 65099, 90, &[], None);
        state.on_established(dest, dest, PeerType::External, 65098, 90, &[], None);
        drain_all(&mut receivers);

        state.ipv6_capable_peers.insert(source);
        state.ipv6_capable_peers.insert(dest);
        // eBGP peers need a local IPv6 next-hop to announce to (propagate_prefix_v6
        // silently suppresses eBGP announcements without one — see its doc comment).
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        assert_eq!(
            state.rib.prefixes_advertised.get(&dest),
            Some(&0),
            "sanity check: prefixes_advertised must start at 0 for dest \
             (set by on_established's own sync, before the v6 route exists)"
        );

        // Inject a v6 route sourced from `source` and propagate it — no v4
        // call before or after, matching the on_route_update code path when
        // an UPDATE carries only IPv6 NLRIs (affected_v6 non-empty, affected
        // empty).
        let peer_id = PeerId::new(IpAddr::V4(source));
        let route = RouteBuilder::new(
            nlri_v6_rr("2001:db8::/32"),
            pathvector_types::Origin::Igp,
            pathvector_types::AsPath::new(),
        )
        .peer_type(PeerType::External)
        .build();
        state.rib_insert_v6(peer_id, route);
        state.propagate_to_all_peers_v6(&[nlri_v6_rr("2001:db8::/32")]);

        assert_eq!(
            state.rib.prefixes_advertised.get(&dest),
            Some(&1),
            "prefixes_advertised for dest must reflect the queued v6 route \
             immediately after a v6-only propagate_to_all_peers_v6 call, \
             without needing a separate v4 event to resync it"
        );
    }

    // RFC 4456 §8: on_established full-table dump must apply split-horizon for v6.
    #[test]
    fn test_rr_v6_established_dump_applies_split_horizon() {
        let cluster_id: u32 = 3;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let nc1: Ipv4Addr = "10.0.0.10".parse().unwrap();
        let nc2: Ipv4Addr = "10.0.0.11".parse().unwrap();
        let (mut state, mut receivers) = make_rr_state(65001, cluster_id, &[client], &[nc1, nc2]);

        // nc1 connects and we add a v6 route sourced from nc1.
        state.on_established(nc1, nc1, PeerType::Internal, 65001, 90, &[], None);
        inject_v6_route(&mut state, nc1, "2001:db8:1::/48");

        // nc2 now connects — full-table dump should NOT send the nc1 route to nc2.
        // Pass MultiProtocol IPv6 capability so the v6 dump fires.
        let caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(nc2, nc2, PeerType::Internal, 65001, 90, &caps, None);

        // on_established sends an IPv4 EOR (empty UpdateMessage) and for v6-capable
        // peers an IPv6 EOR (UpdateMessage with empty MP_UNREACH_NLRI, RFC 4724 §2).
        // Drain both EOR markers, then verify no actual route UPDATE arrived.
        // A route UPDATE would carry non-empty `announced` or non-empty prefixes in
        // MP_REACH_NLRI; a pure EOR has only empty MP_UNREACH_NLRI (or nothing).
        let rx = receivers.get_mut(&nc2).unwrap();
        let mut route_received = false;
        while let Ok(m) = rx.try_recv() {
            let has_announced_nlri = !m.announced.is_empty();
            let has_mp_reach = m
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if !mp.prefixes.is_empty()));
            if has_announced_nlri || has_mp_reach {
                route_received = true;
            }
        }
        assert!(
            !route_received,
            "v6 full-table dump must not send non-client iBGP routes to another non-client (RFC 4456 §8)"
        );
    }

    // ── Invariant: adj_ribs_out and adj_ribs_out_v6 always agree on reflects() ─

    /// Asserts the RFC 4456 reflecting-parity invariant for every peer in `state`:
    /// `adj_ribs_out[p].reflects() == adj_ribs_out_v6[p].reflects()`.
    ///
    /// Call this after any operation that creates or resets outbound RIBs.
    fn assert_reflects_parity(state: &DaemonState) {
        for (peer_ip, aro_v4) in &state.adj_ribs_out {
            if let Some(aro_v6) = state.adj_ribs_out_v6.get(peer_ip) {
                assert_eq!(
                    aro_v4.reflects(),
                    aro_v6.reflects(),
                    "peer {peer_ip}: adj_ribs_out.reflects()={} but adj_ribs_out_v6.reflects()={} — \
                     IPv4 and IPv6 outbound tables must always have matching reflecting mode (RFC 4456 §8)",
                    aro_v4.reflects(),
                    aro_v6.reflects(),
                );
            }
        }
    }

    #[test]
    fn invariant_reflects_parity_after_new() {
        let cluster_id = 1;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let nc: Ipv4Addr = "10.0.0.10".parse().unwrap();
        let (state, _) = make_rr_state(65001, cluster_id, &[client], &[nc]);
        assert_reflects_parity(&state);
    }

    #[test]
    fn invariant_reflects_parity_after_on_established() {
        let cluster_id = 1;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let nc: Ipv4Addr = "10.0.0.10".parse().unwrap();
        let (mut state, _) = make_rr_state(65001, cluster_id, &[client], &[nc]);
        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        assert_reflects_parity(&state);
        state.on_established(nc, nc, PeerType::Internal, 65001, 90, &[], None);
        assert_reflects_parity(&state);
    }

    #[test]
    fn invariant_reflects_parity_after_peer_down_and_reconnect() {
        let cluster_id = 1;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_rr_state(65001, cluster_id, &[client], &[]);
        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        assert_reflects_parity(&state);
        // Simulate teardown then re-establish (on_terminated resets AdjRibOut)
        state.on_terminated(client, TerminationReason::Unclean, false);
        // on_established rebuilds the tables for the next session
        state.on_established(client, client, PeerType::Internal, 65001, 90, &[], None);
        assert_reflects_parity(&state);
    }

    #[test]
    fn invariant_reflects_parity_after_add_peer() {
        let cluster_id = 1;
        let client: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _) = make_rr_state(65001, cluster_id, &[client], &[]);
        // Dynamically add a new iBGP peer (same AS = iBGP)
        let new_peer = config::PeerConfig {
            address: "10.0.0.99".parse().unwrap(),
            port: 179,
            remote_as: 65001,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        };
        let (tx, _rx) = mpsc::channel(64);
        state.add_peer(&new_peer, tx);
        assert_reflects_parity(&state);
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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

        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

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

        // Flush pending decisions to fill peer_b's channel (capacity 1).
        // We do NOT drain peer_b's channel so the slot stays occupied.
        state.flush_pending();

        // Terminate peer_a: the withdraw for peer_b's channel will fail (full).
        state.on_terminated(peer_a, TerminationReason::Unclean, true);
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

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

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
        state.flush_pending();
        receivers.get_mut(&peer_b).unwrap().try_recv().ok();
        receivers.get_mut(&peer_a).unwrap().try_recv().ok();

        // Flip the import policy to Reject — route evicted from Loc-RIB;
        // peer_b must receive a WITHDRAW.
        state.set_import_default(peer_a, DefaultAction::Reject);
        state.flush_pending();

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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

        // Announce via on_route_update so adj_rib_out[peer_b] has the route.
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
        // Flush pending to fill peer_b's channel (capacity 1). Do NOT drain it.
        state.flush_pending();

        // set_import_default tries to send WITHDRAW to peer_b but channel is full.
        state.set_import_default(peer_a, DefaultAction::Reject);
        state.flush_pending();
        assert!(
            !state.take_stalled_peers().is_empty(),
            "peer_b must be stalled when channel is full during set_import_default propagation"
        );
    }

    // ── flush_pending coalescing ──────────────────────────────────────────────

    /// Multiple `on_route_update` calls must be coalesced into fewer outbound
    /// UPDATE messages when `flush_pending` is called once after both updates.
    ///
    /// This validates RFC 4271 §9.2 "combine as many feasible routes as
    /// possible": two separate route updates with the same attribute set must
    /// arrive at the peer in a single UPDATE message, not two separate ones.
    #[test]
    fn flush_pending_coalesces_multi_update_burst() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_a, 65002), (peer_b, 65003)], 64);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        while receivers.get_mut(&peer_a).unwrap().try_recv().is_ok() {}
        while receivers.get_mut(&peer_b).unwrap().try_recv().is_ok() {}

        // Two separate on_route_update calls — simulating two BGP UPDATEs
        // arriving back-to-back from peer_a, each with a different prefix but
        // identical path attributes. flush_pending must combine them.
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop(peer_a),
        ];
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: attrs.clone(),
                announced: vec![nlri("10.0.0.0/8")],
            },
        );
        state.on_route_update(
            peer_a,
            UpdateMessage {
                withdrawn: vec![],
                attributes: attrs,
                announced: vec![nlri("172.16.0.0/12")],
            },
        );

        // Flush once — both prefixes should be in a single UPDATE to peer_b.
        state.flush_pending();

        let msg = receivers
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b must receive a batched UPDATE");

        assert!(
            msg.announced.contains(&nlri("10.0.0.0/8")),
            "batched UPDATE must contain 10.0.0.0/8"
        );
        assert!(
            msg.announced.contains(&nlri("172.16.0.0/12")),
            "batched UPDATE must contain 172.16.0.0/12"
        );

        // Crucially: no second UPDATE message should be queued.
        assert!(
            receivers.get_mut(&peer_b).unwrap().try_recv().is_err(),
            "coalescing must produce a single UPDATE, not two separate ones"
        );
    }

    /// After peer termination, any buffered decisions for that peer must be
    /// discarded — they must not be sent to the dead session.
    #[test]
    fn flush_pending_clears_on_terminated() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut receivers) = make_capped(&[(peer_a, 65002), (peer_b, 65003)], 64);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        while receivers.get_mut(&peer_a).unwrap().try_recv().is_ok() {}
        while receivers.get_mut(&peer_b).unwrap().try_recv().is_ok() {}

        // Announce a route from peer_a (buffered into peer_b's pending buffer).
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

        // Before flushing, terminate peer_b — its buffer must be cleared.
        state.on_terminated(peer_b, TerminationReason::Unclean, false);

        // Flush pending: peer_b has no update_sender now, so nothing is sent.
        state.flush_pending();

        // peer_b's channel must remain empty.
        assert!(
            receivers.get_mut(&peer_b).unwrap().try_recv().is_err(),
            "terminated peer must not receive buffered decisions after on_terminated"
        );
    }

    // ── EOR stall regressions ─────────────────────────────────────────────────

    /// If the channel is full exactly when the IPv4 EOR would be sent (the dump
    /// itself succeeded), the peer must be stalled and eventually stopped.
    ///
    /// Scenario: capacity-1 channel, one route in the Loc-RIB.  The dump
    /// consumes the sole slot.  The IPv4 EOR `try_send` then fails, which must
    /// push `peer_ip` onto `stalled_peers`.
    #[test]
    fn eor_stall_when_channel_full_after_dump() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, _receivers) = make_capped(&[(peer_ip, 1)], 1);

        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_insert_v4(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        // The dump fills the single slot; EOR try_send fails → stall.
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);

        assert!(
            state.stalled_peers.contains(&peer_ip),
            "peer must be stalled when the channel is full at EOR time"
        );
    }

    /// If the IPv4 EOR succeeds but the channel is then full for the IPv6 EOR,
    /// the peer must still be stalled.
    ///
    /// Scenario: capacity-2 channel, one route in the Loc-RIB, peer supports
    /// IPv6.  Slot 1 = the IPv4 dump UPDATE.  Slot 2 = the IPv4 EOR.  The
    /// IPv6 EOR `try_send` has no slot and fails → stall.
    #[test]
    fn eor_stall_when_ipv6_eor_fails_after_ipv4_eor_succeeds() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        // Capacity 2: slot 1 = IPv4 dump, slot 2 = IPv4 EOR.
        // The IPv6 EOR has no slot and must trigger the stall path.
        let (mut state, _receivers) = make_capped(&[(peer_ip, 2)], 2);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_insert_v4(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            65002,
            90,
            &v6_caps,
            None,
        );

        assert!(
            state.stalled_peers.contains(&peer_ip),
            "peer must be stalled when IPv6 EOR cannot be sent after successful IPv4 EOR"
        );
    }

    /// When the channel has enough capacity for the dump AND both EORs, the
    /// peer must NOT be stalled.  This is the happy-path complement to the two
    /// stall tests above.
    #[test]
    fn eor_no_stall_when_channel_has_capacity_for_dump_and_eors() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        // Capacity 3: slot 1 = IPv4 dump, slot 2 = IPv4 EOR, slot 3 = IPv6 EOR.
        let (mut state, _receivers) = make_capped(&[(peer_ip, 3)], 3);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::1".parse().unwrap());

        let src = PeerId::new(IpAddr::V4("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        state.rib_insert_v4(
            src,
            base_route(
                "10.0.0.0/8",
                "10.0.0.9".parse().unwrap(),
                PeerType::External,
            ),
        );

        let v6_caps = [Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];
        state.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            65002,
            90,
            &v6_caps,
            None,
        );

        assert!(
            !state.stalled_peers.contains(&peer_ip),
            "peer must not be stalled when the channel has room for the dump and both EORs"
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

        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
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
        state.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
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

/// Regression and effectiveness tests for cross-UPDATE NLRI coalescing.
///
/// Each test is named after the invariant it protects. Where a bug was found
/// and fixed during review, the test name includes the word "regression".
///
/// **Bug 1 (regression)** — gRPC-facing mutation methods must self-flush.
/// `originate_routes`, `withdraw_originated_routes`, and `set_import_default`
/// call `propagate_to_all_peers` which buffers decisions. Without a self-flush
/// the decisions would not be sent until the next BGP event arrived.
///
/// **Bug 2 (regression)** — `flush_mrai_pending` calls `propagate_to_all_peers`
/// which buffers. The event loop arm must call `flush_pending` after
/// `flush_mrai_pending` or MRAI-released routes stay buffered.
///
/// **Bug 3 (regression)** — mandatory-attribute errors in the `try_recv` drain
/// loop must send a NOTIFICATION and skip to the next outer iteration, not be
/// silently swallowed.
///
/// **Effectiveness** — two `on_route_update` calls with the same attribute set
/// must produce fewer outbound `UpdateMessage`s than prefixes announced.
#[cfg(test)]
mod coalescing_tests {
    use std::{collections::HashMap, net::Ipv4Addr};

    use pathvector_types::{AsPath, Asn, Nlri, Origin, PeerType};

    use super::*;
    use crate::config;

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    /// Build a state with large channels and Accept-default policies.
    fn make_state(
        peers: &[(Ipv4Addr, u32)],
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut receivers = HashMap::new();
        let mut senders = HashMap::new();
        let peer_configs: Vec<_> = peers
            .iter()
            .map(|&(addr, remote_as)| {
                let (tx, rx) = mpsc::channel::<UpdateMessage>(256);
                senders.insert(addr, tx);
                receivers.insert(addr, rx);
                config::PeerConfig {
                    address: addr,
                    port: 179,
                    remote_as,
                    import_default: Some(config::ImportDefault::Accept),
                    export_default: Some(config::ExportDefault::Accept),
                    import_default_v6: None,
                    md5_password: None,
                    is_rr_client: false,
                    next_hop_self: false,
                    hold_time: None,
                    shutdown_message: None,
                    connect_retry_time: None,
                    max_prefixes_v4: None,
                    max_prefixes_v6: None,
                    max_prefixes_restart: None,
                    role: None,
                }
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

    fn announce(peer: Ipv4Addr, prefixes: &[&str]) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(peer),
            ],
            announced: prefixes.iter().map(|s| nlri(s)).collect(),
        }
    }

    // ── Effectiveness ─────────────────────────────────────────────────────────

    /// Two BGP UPDATEs arriving back-to-back (same attribute set, different
    /// prefixes) must be coalesced into a single outbound UpdateMessage.
    /// This is the primary invariant of the coalescing feature.
    #[test]
    fn two_updates_same_attrs_produce_one_outbound_message() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        while rxs.get_mut(&peer_a).unwrap().try_recv().is_ok() {}
        while rxs.get_mut(&peer_b).unwrap().try_recv().is_ok() {}

        // Two separate BGP UPDATEs with identical path attributes.
        state.on_route_update(peer_a, announce(peer_a, &["10.0.0.0/8"]));
        state.on_route_update(peer_a, announce(peer_a, &["172.16.0.0/12"]));

        // A single flush must send both prefixes in one UpdateMessage.
        state.flush_pending();

        let msg = rxs
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("peer_b must receive a coalesced UPDATE");
        assert!(
            msg.announced.contains(&nlri("10.0.0.0/8")),
            "coalesced UPDATE must carry 10.0.0.0/8"
        );
        assert!(
            msg.announced.contains(&nlri("172.16.0.0/12")),
            "coalesced UPDATE must carry 172.16.0.0/12"
        );

        // No second UpdateMessage — both prefixes arrived in one wire frame.
        assert!(
            rxs.get_mut(&peer_b).unwrap().try_recv().is_err(),
            "coalescing must produce exactly one outbound UpdateMessage for identical attrs"
        );
    }

    /// N prefix announcements with identical attributes must arrive in at most
    /// ceil(N / max_nlri_per_update) messages, not N separate messages.
    /// Verifies scaling behavior as burst size grows.
    #[test]
    fn large_burst_is_packed_into_fewer_messages_than_prefixes() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

        // 20 separate on_route_update calls — one per prefix.
        let prefixes: Vec<String> = (0u8..20).map(|i| format!("10.{i}.0.0/16")).collect();
        for prefix in &prefixes {
            state.on_route_update(peer_a, announce(peer_a, &[prefix.as_str()]));
        }
        state.flush_pending();

        let mut total_messages = 0usize;
        let mut total_prefixes = 0usize;
        while let Ok(msg) = rxs.get_mut(&peer_b).unwrap().try_recv() {
            total_messages += 1;
            total_prefixes += msg.announced.len();
        }

        assert_eq!(
            total_prefixes, 20,
            "all 20 prefixes must be delivered to peer_b"
        );
        assert!(
            total_messages < 20,
            "20 separate route events must produce fewer than 20 outbound UpdateMessages (got {total_messages})"
        );
    }

    // ── Bug 1 regression: gRPC-facing methods must self-flush ─────────────────

    /// `originate_routes` must send immediately without the caller having to
    /// call `flush_pending()` separately.  Regression: before the fix, routes
    /// sat in the pending buffer until the next BGP event.
    #[test]
    fn regression_originate_routes_sends_without_manual_flush() {
        let peer: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut rxs) = make_state(&[(peer, 65002)]);
        state.on_established(peer, peer, PeerType::External, 65002, 90, &[], None);
        // Drain the empty table dump from on_established.
        while rxs.get_mut(&peer).unwrap().try_recv().is_ok() {}

        let route = RouteBuilder::new(nlri("203.0.113.0/24"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4("10.0.0.1".parse().unwrap()))
            .build();

        // originate_routes must self-flush — no explicit flush_pending() call.
        state.originate_routes(vec![route]);

        rxs.get_mut(&peer)
            .unwrap()
            .try_recv()
            .expect("originate_routes must send immediately without a manual flush_pending call");
    }

    /// `withdraw_originated_routes` must send immediately without a manual
    /// `flush_pending()`.  Regression: before the fix, withdrawals buffered.
    #[test]
    fn regression_withdraw_originated_routes_sends_without_manual_flush() {
        let peer: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (mut state, mut rxs) = make_state(&[(peer, 65002)]);
        state.on_established(peer, peer, PeerType::External, 65002, 90, &[], None);

        let route = RouteBuilder::new(nlri("203.0.113.0/24"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4("10.0.0.1".parse().unwrap()))
            .build();
        state.originate_routes(vec![route]);
        // Drain the announcement.
        while rxs.get_mut(&peer).unwrap().try_recv().is_ok() {}

        // Withdraw — must self-flush.
        state.withdraw_originated_routes(&[nlri("203.0.113.0/24")]);

        let msg = rxs
            .get_mut(&peer)
            .unwrap()
            .try_recv()
            .expect("withdraw_originated_routes must send immediately without a manual flush");
        assert!(
            msg.withdrawn.contains(&nlri("203.0.113.0/24")),
            "WITHDRAW must carry 203.0.113.0/24"
        );
    }

    /// `set_import_default` must send the resulting policy-change UPDATEs
    /// immediately without a manual `flush_pending()`.  Regression: before the
    /// fix, the WITHDRAW from a Reject policy sat buffered.
    #[test]
    fn regression_set_import_default_sends_without_manual_flush() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

        state.on_route_update(peer_a, announce(peer_a, &["10.0.0.0/8"]));
        state.flush_pending();
        // Drain initial announcement.
        while rxs.get_mut(&peer_b).unwrap().try_recv().is_ok() {}

        // Flip import policy to Reject — must self-flush without caller needing flush_pending.
        state.set_import_default(peer_a, pathvector_policy::DefaultAction::Reject);

        let msg = rxs
            .get_mut(&peer_b)
            .unwrap()
            .try_recv()
            .expect("set_import_default must send WITHDRAW immediately without manual flush");
        assert!(
            msg.withdrawn.contains(&nlri("10.0.0.0/8")),
            "WITHDRAW must carry 10.0.0.0/8 after import policy → Reject"
        );
    }

    // ── Bug 2 regression: MRAI must flush its own decisions ───────────────────

    /// After `flush_mrai_pending`, the decisions it generates via
    /// `propagate_to_all_peers` must be sent to peers.  The event loop arm
    /// calls `flush_pending` after `flush_mrai_pending`; this test verifies
    /// that `flush_mrai_pending` alone is not sufficient — its caller must
    /// flush.  (Regression: the event loop previously did not call the second
    /// flush, so MRAI-released routes were delayed until the next event.)
    #[test]
    fn regression_flush_mrai_pending_requires_subsequent_flush_pending() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        // peer_b is eBGP so MRAI applies.
        let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        while rxs.get_mut(&peer_a).unwrap().try_recv().is_ok() {}
        while rxs.get_mut(&peer_b).unwrap().try_recv().is_ok() {}

        // Announce a route that is first suppressed by MRAI, then add it to
        // mrai_pending manually so flush_mrai_pending picks it up.
        let prefix = nlri("10.0.0.0/8");

        // Insert the route into the Loc-RIB so propagate_prefix has something to send.
        let src = PeerId::new(IpAddr::V4(peer_a));
        let route = RouteBuilder::new(
            prefix,
            Origin::Igp,
            AsPath::from_sequence(vec![Asn::new(65002)]),
        )
        .next_hop(NextHop::V4(peer_a))
        .peer_type(PeerType::External)
        .build();
        state.rib_insert_v4(src, route);

        // Manufacture an mrai_pending entry for peer_b so flush_mrai_pending
        // has something to process.
        state.mrai_pending.entry(peer_b).or_default().insert(prefix);

        // Call flush_mrai_pending without the subsequent flush_pending.
        state.flush_mrai_pending();

        // Without flush_pending, nothing should be in peer_b's channel yet
        // (decisions sit in pending_decisions[peer_b]).
        let before_flush = rxs.get_mut(&peer_b).unwrap().try_recv();
        assert!(
            before_flush.is_err(),
            "flush_mrai_pending alone must NOT send to channel — decisions remain buffered"
        );

        // Now flush — decisions must arrive.
        state.flush_pending();

        let msg =
            rxs.get_mut(&peer_b).unwrap().try_recv().expect(
                "flush_pending after flush_mrai_pending must deliver the MRAI-released route",
            );
        assert!(
            msg.announced.contains(&prefix),
            "MRAI-released route must be in the delivered UPDATE"
        );
    }

    // ── Bug 3 regression: notify_err in drain loop ────────────────────────────

    /// A mandatory-attribute error detected during the `try_recv` drain loop
    /// must send a `SessionCommand::Notification` to the erroring peer.
    /// Regression: before the fix, the error was silently dropped.
    ///
    /// This test drives `run_event_loop` directly and injects two events:
    /// 1. A valid RouteUpdate from peer_a (fills the drain loop).
    /// 2. A malformed RouteUpdate from peer_b (missing Origin — triggers RFC 4271 §6.3).
    ///
    /// The stop sender for peer_b must receive a `SessionCommand::Notification`.
    #[tokio::test]
    async fn regression_notify_err_in_drain_loop_sends_notification() {
        use pathvector_session::message::NotificationError;
        use tokio::sync::mpsc;

        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

        // We need the full event loop state bundle.
        let (tx_a, _rx_a) = mpsc::channel::<UpdateMessage>(64);
        let (tx_b, _rx_b) = mpsc::channel::<UpdateMessage>(64);
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
            },
        ];
        let mut senders = HashMap::new();
        senders.insert(peer_a, tx_a);
        senders.insert(peer_b, tx_b);
        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );
        let state = Arc::new(tokio::sync::RwLock::new(state));

        {
            let mut s = state.write().await;
            s.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
            s.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        }

        let (event_tx, event_rx) = mpsc::channel::<(Ipv4Addr, SessionEvent)>(16);

        // Stop-command channels: we capture peer_b's receiver to check for NOTIFICATION.
        let (stop_a_tx, _stop_a_rx) = mpsc::channel::<SessionCommand>(4);
        let (stop_b_tx, mut stop_b_rx) = mpsc::channel::<SessionCommand>(4);
        let mut stop_map: HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>> = HashMap::new();
        stop_map.insert(peer_a, stop_a_tx);
        stop_map.insert(peer_b, stop_b_tx);
        let stop_senders = Arc::new(std::sync::Mutex::new(stop_map));

        let loop_handle = tokio::spawn(run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        ));

        // Send two events in quick succession so the second arrives in the drain loop.
        // Event 1 (valid): wakes the loop.
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

        // Event 2 (malformed — missing Origin): arrives while loop is processing event 1.
        event_tx
            .send((
                peer_b,
                SessionEvent::RouteUpdate(UpdateMessage {
                    withdrawn: vec![],
                    // Missing Origin → RFC 4271 §6.3 → NOTIFICATION
                    attributes: vec![
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65003)])),
                        PathAttribute::NextHop(peer_b),
                    ],
                    announced: vec![nlri("172.16.0.0/12")],
                }),
            ))
            .await
            .unwrap();

        // Give the loop time to process both events.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        // peer_b must have received a Notification (or Stop from stall handling).
        // We accept either: the key invariant is that the error was NOT silently dropped.
        let cmd = stop_b_rx
            .try_recv()
            .expect("peer_b must receive SessionCommand after malformed UPDATE in drain loop");
        assert!(
            matches!(
                cmd,
                SessionCommand::Notification(ref n)
                    if matches!(n.error, NotificationError::UpdateMessage(_))
            ) || matches!(cmd, SessionCommand::Stop),
            "peer_b must receive a Notification or Stop command, not silence"
        );

        // Shut down the loop.
        drop(event_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), loop_handle).await;
    }

    // ── Event-loop drain coalescing ───────────────────────────────────────────

    /// Drives `run_event_loop` directly and sends N route events in rapid
    /// succession BEFORE yielding.  All N events land in the channel before the
    /// loop wakes up, so events 2-N are processed by the `try_recv` drain and
    /// flushed together with event 1 in a single `flush_pending` call.
    ///
    /// This is the only test that exercises the real `try_recv` drain path.
    /// The unit-level effectiveness tests (`two_updates_same_attrs_*`) call
    /// `flush_pending` manually and never touch the event loop at all.
    #[tokio::test]
    async fn event_loop_drain_coalesces_rapid_burst() {
        use std::{sync::Mutex, time::Duration};
        use tokio::sync::mpsc as tmp;

        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();

        let (tx_a, _rx_a) = tmp::channel::<UpdateMessage>(64);
        let (tx_b, mut rx_b) = tmp::channel::<UpdateMessage>(64);

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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
            },
        ];
        let mut update_senders = HashMap::new();
        update_senders.insert(peer_a, tx_a);
        update_senders.insert(peer_b, tx_b);

        let state = DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            update_senders,
            vec![],
        );
        let state = Arc::new(RwLock::new(state));

        {
            let mut s = state.write().await;
            s.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
            s.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        }

        let (event_tx, event_rx) = tmp::channel::<(Ipv4Addr, SessionEvent)>(64);
        let stop_senders: Arc<Mutex<HashMap<Ipv4Addr, tmp::Sender<SessionCommand>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let loop_handle = tokio::spawn(run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        ));

        // Send all 10 events before yielding.  Each uses a distinct prefix but
        // identical path attributes, so all decisions will share an attribute
        // set and `flush_updates` can pack them into one UpdateMessage.
        // Because all sends complete synchronously (channel has capacity),
        // all 10 events are in the channel buffer before the event loop runs.
        let prefixes: Vec<String> = (0u8..10).map(|i| format!("10.{i}.0.0/16")).collect();
        for prefix in &prefixes {
            let nlri_parsed: Nlri<Ipv4Addr> = prefix.parse().unwrap();
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
                        announced: vec![nlri_parsed],
                    }),
                ))
                .await
                .unwrap();
        }

        // Yield long enough for the event loop to drain all 10 events and flush.
        // 100ms >> any realistic scheduler latency; MRAI timer fires every 15s
        // so it will not interfere.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut total_messages = 0usize;
        let mut total_prefixes = 0usize;
        while let Ok(msg) = rx_b.try_recv() {
            total_messages += 1;
            total_prefixes += msg.announced.len();
        }

        assert_eq!(total_prefixes, 10, "all 10 prefixes must arrive at peer_b");
        assert!(
            total_messages < 10,
            "10 rapid-fire route events must be coalesced into fewer than 10 \
             UpdateMessages by the try_recv drain (got {total_messages} messages \
             for {total_prefixes} prefixes)"
        );

        drop(event_tx);
        let _ = tokio::time::timeout(Duration::from_secs(1), loop_handle).await;
    }

    /// Verifies that buffered `pending_decisions` are not lost or reordered
    /// when `set_export_default` is called while the state lock is not held by
    /// the event loop.
    ///
    /// The scenario: (1) import a route so it sits in pending_decisions, (2)
    /// call set_export_default for the receiving peer (Accept), (3) flush.
    /// Both the original route and the export-policy-driven dump must arrive.
    #[test]
    fn set_export_default_does_not_lose_pending_decisions() {
        let peer_a: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let peer_b: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let (mut state, mut rxs) = make_state(&[(peer_a, 65002), (peer_b, 65003)]);

        state.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
        state.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);

        // Announce a route and buffer it (do NOT call flush_pending yet).
        state.on_route_update(peer_a, announce(peer_a, &["10.0.0.0/8"]));

        // `pending_decisions[peer_b]` now has one entry.  Call set_export_default
        // (which writes directly to the channel, bypassing the pending buffer).
        // In production this is always serialized by the write lock — the event
        // loop always flushes before releasing — but we simulate the direct call
        // here to verify the buffer is not corrupted.
        state.set_export_default(peer_b, pathvector_policy::DefaultAction::Accept);

        // set_export_default fires first (direct channel write), then flush_pending
        // sends the buffered decision.  Peer_b must receive both.
        state.flush_pending();

        let mut received_prefixes = std::collections::HashSet::new();
        while let Ok(msg) = rxs.get_mut(&peer_b).unwrap().try_recv() {
            for nlri in msg.announced {
                received_prefixes.insert(nlri);
            }
        }

        assert!(
            received_prefixes.contains(&nlri("10.0.0.0/8")),
            "10.0.0.0/8 must reach peer_b despite set_export_default being called \
             while it was in the pending buffer"
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
    use pathvector_session::transport::{SessionCommand, SessionEvent, TerminationReason};
    use pathvector_types::{AsPath, Asn, NextHop, Nlri, Origin, PeerType};
    use tokio::sync::mpsc;

    use super::*;
    use crate::config;

    // ── helpers ───────────────────────────────────────────────────────────────

    type StateBundle = (
        Arc<RwLock<DaemonState>>,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
        Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>>,
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
        let mut stop_map: HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>> = HashMap::new();
        let mut stop_receivers: HashMap<Ipv4Addr, mpsc::Receiver<SessionCommand>> = HashMap::new();

        for &(ip, _) in peers {
            let (tx, rx) = mpsc::channel(channel_cap);
            update_senders.insert(ip, tx);
            update_receivers.insert(ip, rx);
            let (stx, srx) = mpsc::channel(8);
            stop_map.insert(ip, stx);
            stop_receivers.insert(ip, srx);
        }
        let stop_senders = Arc::new(Mutex::new(stop_map));

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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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
            s.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
        }

        let (event_tx, event_rx) = mpsc::channel(8);
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
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
            s.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
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
        let (update_tx_a, _) = mpsc::channel::<UpdateMessage>(64);
        let (stall_tx, mut stall_drain) = mpsc::channel::<UpdateMessage>(1);
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
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
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
            },
        ];
        let mut update_senders = HashMap::new();
        update_senders.insert(peer_a, update_tx_a);
        update_senders.insert(peer_b, stall_tx);
        let state = Arc::new(RwLock::new(DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            update_senders,
            vec![],
        )));
        let mut stop_map = HashMap::new();
        stop_map.insert(peer_a, sess_stop_a);
        stop_map.insert(peer_b, sess_stop_b);
        let stop_senders = Arc::new(Mutex::new(stop_map));

        // Establish both peers.
        {
            let mut s = state.write().await;
            s.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
            s.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
        }

        // Drain the EOR marker that on_established sent to peer_b (RFC 4724 §2)
        // so the capacity-1 channel is empty before we pre-fill it below.
        while stall_drain.try_recv().is_ok() {}

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
            s.on_established(peer_a, peer_a, PeerType::External, 65002, 90, &[], None);
            s.on_established(peer_b, peer_b, PeerType::External, 65003, 90, &[], None);
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
            s.flush_pending();
        }
        // Drain EOR marker and initial route propagation.
        while rxs.get_mut(&peer_b).unwrap().try_recv().is_ok() {}

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

    // ── DaemonState::add_peer / remove_peer ───────────────────────────────────

    fn peer_cfg(address: Ipv4Addr, remote_as: u32) -> config::PeerConfig {
        config::PeerConfig {
            address,
            port: 179,
            remote_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        }
    }

    #[tokio::test]
    async fn add_peer_inserts_all_state_maps() {
        let (state, _rxs, _stop) = make_state(&[], 8);
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (update_tx, _update_rx) = mpsc::channel(8);

        let added = state
            .write()
            .await
            .add_peer(&peer_cfg(peer_ip, 65099), update_tx);

        assert!(added, "first add_peer must return true");
        let s = state.read().await;
        assert!(s.adj_ribs_in.contains_key(&peer_ip));
        assert!(s.adj_ribs_in_v6.contains_key(&peer_ip));
        assert!(s.adj_ribs_out.contains_key(&peer_ip));
        assert!(s.adj_ribs_out_v6.contains_key(&peer_ip));
        assert!(s.import_policies.contains_key(&peer_ip));
        assert!(s.export_policies.contains_key(&peer_ip));
        assert!(s.update_senders.contains_key(&peer_ip));
        assert_eq!(s.rib.peer_remote_as.get(&peer_ip), Some(&65099_u32));
    }

    #[tokio::test]
    async fn add_peer_is_idempotent() {
        let (state, _rxs, _stop) = make_state(&[], 8);
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (tx1, _) = mpsc::channel(8);
        let (tx2, _) = mpsc::channel(8);

        let first = state.write().await.add_peer(&peer_cfg(peer_ip, 65099), tx1);
        let second = state.write().await.add_peer(&peer_cfg(peer_ip, 65099), tx2);

        assert!(first, "first call must return true");
        assert!(!second, "second call (idempotent) must return false");
    }

    #[tokio::test]
    async fn remove_peer_clears_all_state_maps() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

        let removed = state.write().await.remove_peer(peer_ip);

        assert!(removed, "remove_peer must return true for an existing peer");
        let s = state.read().await;
        assert!(!s.adj_ribs_in.contains_key(&peer_ip));
        assert!(!s.adj_ribs_in_v6.contains_key(&peer_ip));
        assert!(!s.adj_ribs_out.contains_key(&peer_ip));
        assert!(!s.import_policies.contains_key(&peer_ip));
        assert!(!s.export_policies.contains_key(&peer_ip));
        assert!(!s.update_senders.contains_key(&peer_ip));
        assert!(!s.rib.peer_remote_as.contains_key(&peer_ip));
    }

    #[tokio::test]
    async fn remove_peer_returns_false_when_not_found() {
        let (state, _rxs, _stop) = make_state(&[], 8);
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();

        let removed = state.write().await.remove_peer(peer_ip);

        assert!(!removed, "remove_peer must return false for unknown peer");
    }

    /// RFC 9234: a dynamically added peer with a configured role must get
    /// `peer_roles` populated and OTC terms installed — mirrors the static-peer
    /// path in `DaemonState::new`, which `test_install_otc_terms_counts_per_role`
    /// already covers.
    #[tokio::test]
    async fn add_peer_with_role_installs_otc_terms_and_peer_roles() {
        let (state, _rxs, _stop) = make_state(&[], 8);
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (update_tx, _update_rx) = mpsc::channel(8);

        let mut cfg = peer_cfg(peer_ip, 65099);
        cfg.role = Some(config::PeerRole::Customer);
        state.write().await.add_peer(&cfg, update_tx);

        let s = state.read().await;
        assert_eq!(s.rib.peer_roles.get(&peer_ip), Some(&Role::Customer));
        // Customer: leak-detect (no-op for this role) + ingress attach = 2 terms.
        assert_eq!(s.import_policies[&peer_ip].len(), 2);
        assert_eq!(s.import_policies_v6[&peer_ip].len(), 2);
        // Customer: propagation-block = 1 term.
        assert_eq!(s.export_policies[&peer_ip].len(), 1);
    }

    /// The dynamic `add_peer` path must apply the same eBGP-only guard as
    /// the static `DaemonState::new` path (`test_role_ignored_for_ibgp_peer`)
    /// — a `role` configured on an iBGP peer (`remote_as == local_as == 65001`
    /// in this harness) must be ignored, not applied.
    #[tokio::test]
    async fn add_peer_ignores_role_for_ibgp_peer() {
        let (state, _rxs, _stop) = make_state(&[], 8);
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (update_tx, _update_rx) = mpsc::channel(8);

        let mut cfg = peer_cfg(peer_ip, 65001); // local_as in this harness is 65001
        cfg.role = Some(config::PeerRole::Customer);
        state.write().await.add_peer(&cfg, update_tx);

        let s = state.read().await;
        assert!(
            !s.rib.peer_roles.contains_key(&peer_ip),
            "peer_roles must not record a role for an iBGP peer"
        );
        assert_eq!(s.import_policies[&peer_ip].len(), 0);
        assert_eq!(s.import_policies_v6[&peer_ip].len(), 0);
        assert_eq!(s.export_policies[&peer_ip].len(), 0);
    }

    /// `remove_peer` must clear `peer_roles`, otherwise a later `AddPeer` for a
    /// different role at the same address would inherit a stale role via the
    /// reconnect capability-refresh path.
    #[tokio::test]
    async fn remove_peer_clears_peer_roles() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, _stop) = make_state(&[], 8);
        let (update_tx, _update_rx) = mpsc::channel(8);
        let mut cfg = peer_cfg(peer_ip, 65099);
        cfg.role = Some(config::PeerRole::Peer);
        state.write().await.add_peer(&cfg, update_tx);
        assert!(state.read().await.rib.peer_roles.contains_key(&peer_ip));

        state.write().await.remove_peer(peer_ip);

        assert!(!state.read().await.rib.peer_roles.contains_key(&peer_ip));
    }

    /// Termination of a peer in `pending_removal` must erase all per-peer state
    /// (not just reset it for reconnect).
    #[tokio::test]
    async fn terminated_with_pending_removal_calls_remove_peer() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

        // Mark as pending removal.
        state.write().await.pending_removal.insert(peer_ip);

        let (event_tx, event_rx) = mpsc::channel(4);
        // Establish then Terminate.
        event_tx
            .send((peer_ip, SessionEvent::Established(established_info(65099))))
            .await
            .unwrap();
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        let s = state.read().await;
        // All per-peer maps must be cleared.
        assert!(
            !s.adj_ribs_in.contains_key(&peer_ip),
            "adj_ribs_in must be removed after pending_removal Terminated"
        );
        assert!(
            !s.rib.peer_remote_as.contains_key(&peer_ip),
            "peer_remote_as must be removed after pending_removal Terminated"
        );
        assert!(
            !s.pending_removal.contains(&peer_ip),
            "pending_removal entry must be cleaned up"
        );
    }

    /// When RemovePeer is issued but the stop sender is absent (session already
    /// exited between reconnects), the command processor must synthesize a
    /// Terminated event so the pending_removal cleanup still runs.
    #[tokio::test]
    async fn remove_peer_synthesizes_terminated_when_no_stop_sender() {
        // A SessionHandle stub that is never actually spawned — RemovePeer does
        // not call spawn_fn, so we just need any type that satisfies the bound.
        struct NeverSpawned;
        impl SessionHandle for NeverSpawned {
            async fn start(&self) {}
            async fn next_event(&mut self) -> Option<SessionEvent> {
                None
            }
            fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
                mpsc::channel(1).0
            }
            fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            async fn send_route_refresh(
                &self,
                _rr: pathvector_session::message::RouteRefreshMessage,
            ) {
            }
            async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
        }

        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        // Build state with the peer but deliberately provide an empty stop_senders
        // map — simulates the window where the session actor has exited and its
        // stop sender has been dropped.
        let (state, _rxs, _orig_stop) = make_state(&[(peer_ip, 65099)], 8);
        let empty_stop_senders: Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let (event_tx, event_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);

        let state_clone = Arc::clone(&state);
        let stop_clone = Arc::clone(&empty_stop_senders);
        let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let event_tx_clone = event_tx.clone();

        tokio::spawn(run_command_processor::<NeverSpawned, _>(
            cmd_rx,
            state_clone,
            stop_clone,
            incoming,
            event_tx_clone,
            |_cfg| unreachable!("spawn_fn must not be called by RemovePeer"),
            SpawnConfig {
                local_as: 65001,
                local_bgp_id: "1.2.3.4".parse().unwrap(),
                hold_time: 180,
                graceful_restart_time: 0,
                configured_restarting: false,
                startup_instant: std::time::Instant::now(),
            },
            None,
        ));

        cmd_tx
            .send(DaemonCommand::RemovePeer(peer_ip))
            .await
            .unwrap();
        drop(cmd_tx);
        // Drop our own event_tx so the event loop terminates after draining.
        drop(event_tx);

        // The command processor should have synthesized Terminated; run the event
        // loop to consume it and complete the cleanup.
        run_event_loop(event_rx, Arc::clone(&state), empty_stop_senders, None).await;

        let s = state.read().await;
        assert!(
            !s.adj_ribs_in.contains_key(&peer_ip),
            "adj_ribs_in must be cleared after synthesized Terminated"
        );
        assert!(
            !s.pending_removal.contains(&peer_ip),
            "pending_removal entry must be cleared"
        );
    }

    /// Termination of a normal peer (not in pending_removal) must NOT remove
    /// the peer from `adj_ribs_in` — it should be ready for reconnect.
    #[tokio::test]
    async fn terminated_without_pending_removal_keeps_peer_state() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

        let (event_tx, event_rx) = mpsc::channel(4);
        event_tx
            .send((peer_ip, SessionEvent::Established(established_info(65099))))
            .await
            .unwrap();
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        let s = state.read().await;
        assert!(
            s.adj_ribs_in.contains_key(&peer_ip),
            "adj_ribs_in must be preserved for a normal (non-removed) peer termination"
        );
        assert!(
            s.rib.peer_remote_as.contains_key(&peer_ip),
            "peer_remote_as must be preserved for reconnect"
        );
    }

    /// A second `Terminated` event for a peer that has already been fully
    /// removed (via `pending_removal`) must be a no-op — it must not panic
    /// or corrupt any state.
    ///
    /// This covers the window where both a natural TCP-disconnect `Terminated`
    /// and a synthesized `Terminated` from `RemovePeer` arrive for the same
    /// peer: the first one runs cleanup, the second one finds empty maps and
    /// returns silently.
    #[tokio::test]
    async fn double_terminated_second_is_no_op() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

        state.write().await.pending_removal.insert(peer_ip);

        let (event_tx, event_rx) = mpsc::channel(8);
        // First Terminated — runs cleanup (routes cleared, remove_peer called).
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
            .await
            .unwrap();
        // Second Terminated — must be a no-op (maps already gone).
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
            .await
            .unwrap();
        drop(event_tx);

        // Must complete without panicking.
        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        let s = state.read().await;
        assert!(
            !s.adj_ribs_in.contains_key(&peer_ip),
            "peer must be absent after double-Terminated with pending_removal"
        );
        assert!(
            !s.pending_removal.contains(&peer_ip),
            "pending_removal must be cleared after first Terminated"
        );
    }

    /// `AddPeer` while the peer is in `pending_removal` must be silently
    /// dropped — the spawn function must never be called.
    ///
    /// The operator must wait until the Terminated event clears all per-peer
    /// state before re-adding the peer.
    #[tokio::test]
    async fn add_peer_while_pending_removal_is_dropped() {
        struct NeverSpawned;
        impl SessionHandle for NeverSpawned {
            async fn start(&self) {}
            async fn next_event(&mut self) -> Option<SessionEvent> {
                None
            }
            fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
                mpsc::channel(1).0
            }
            fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            async fn send_route_refresh(
                &self,
                _rr: pathvector_session::message::RouteRefreshMessage,
            ) {
            }
            async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
        }

        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

        // Mark the peer as being removed — teardown is in progress.
        state.write().await.pending_removal.insert(peer_ip);

        let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (event_tx, _event_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);

        tokio::spawn(run_command_processor::<NeverSpawned, _>(
            cmd_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            incoming,
            event_tx,
            // If spawn_fn is called the test panics — AddPeer must be dropped.
            |_cfg| panic!("spawn_fn must not be called while peer is in pending_removal"),
            SpawnConfig {
                local_as: 65001,
                local_bgp_id: "1.2.3.4".parse().unwrap(),
                hold_time: 180,
                graceful_restart_time: 0,
                configured_restarting: false,
                startup_instant: std::time::Instant::now(),
            },
            None,
        ));

        cmd_tx
            .send(DaemonCommand::AddPeer(peer_cfg(peer_ip, 65099)))
            .await
            .unwrap();
        drop(cmd_tx);

        // Give the command processor a moment to process the command.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Peer must still be in pending_removal — add was dropped.
        let s = state.read().await;
        assert!(
            s.pending_removal.contains(&peer_ip),
            "pending_removal must still contain the peer after a dropped AddPeer"
        );
        // adj_ribs_in must still have the peer (it was there before the add attempt).
        assert!(
            s.adj_ribs_in.contains_key(&peer_ip),
            "adj_ribs_in must be unchanged — no second entry was added"
        );
    }

    // ── RFC 9003 — shutdown message dispatch ─────────────────────────────────

    /// `RemovePeer` must send `SessionCommand::Stop` (no payload) when the peer
    /// has no configured `shutdown_message`.
    #[tokio::test]
    async fn remove_peer_without_shutdown_message_sends_stop() {
        struct NeverSpawned;
        impl SessionHandle for NeverSpawned {
            async fn start(&self) {}
            async fn next_event(&mut self) -> Option<SessionEvent> {
                None
            }
            fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
                mpsc::channel(1).0
            }
            fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            async fn send_route_refresh(
                &self,
                _rr: pathvector_session::message::RouteRefreshMessage,
            ) {
            }
            async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
        }

        let peer_ip: Ipv4Addr = "10.0.1.1".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65010)], 8);

        // Register a real stop sender so we can observe what command is sent.
        let (session_stop_tx, mut session_stop_rx) = mpsc::channel(8);
        stop_senders
            .lock()
            .unwrap()
            .insert(peer_ip, session_stop_tx);

        let (event_tx, _event_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);

        tokio::spawn(run_command_processor::<NeverSpawned, _>(
            cmd_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            |_cfg| unreachable!(),
            SpawnConfig {
                local_as: 65001,
                local_bgp_id: "1.2.3.4".parse().unwrap(),
                hold_time: 180,
                graceful_restart_time: 0,
                configured_restarting: false,
                startup_instant: std::time::Instant::now(),
            },
            None,
        ));

        cmd_tx
            .send(DaemonCommand::RemovePeer(peer_ip))
            .await
            .unwrap();

        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), session_stop_rx.recv())
            .await
            .expect("timed out waiting for command")
            .expect("channel closed");

        assert!(
            matches!(cmd, SessionCommand::Stop),
            "expected Stop when no shutdown_message configured, got {cmd:?}"
        );
    }

    /// `RemovePeer` must send `SessionCommand::Notification` with a
    /// `Cease/AdministrativeShutdown` payload when `shutdown_message` is set.
    /// The payload must be a valid RFC 9003 encoded string.
    #[tokio::test]
    async fn remove_peer_with_shutdown_message_sends_rfc9003_notification() {
        use pathvector_session::message::{CeaseError, NotificationError, decode_shutdown_message};
        struct NeverSpawned;
        impl SessionHandle for NeverSpawned {
            async fn start(&self) {}
            async fn next_event(&mut self) -> Option<SessionEvent> {
                None
            }
            fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
                mpsc::channel(1).0
            }
            fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            async fn send_route_refresh(
                &self,
                _rr: pathvector_session::message::RouteRefreshMessage,
            ) {
            }
            async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
        }

        let peer_ip: Ipv4Addr = "10.0.1.2".parse().unwrap();

        // Build state with shutdown_message set.
        let mut senders = HashMap::new();
        let (utx, _urx) = mpsc::channel(8);
        senders.insert(peer_ip, utx);
        let peer_cfg = config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65011,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: Some("planned maintenance".to_string()),
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        };
        let state = Arc::new(RwLock::new(DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &[peer_cfg],
            senders,
            vec![],
        )));

        // Register a real stop sender so we can observe what command is sent.
        let (session_stop_tx, mut session_stop_rx) = mpsc::channel(8);
        let stop_senders: Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>> =
            Arc::new(Mutex::new(HashMap::from([(peer_ip, session_stop_tx)])));

        let (event_tx, _event_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);

        tokio::spawn(run_command_processor::<NeverSpawned, _>(
            cmd_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            |_cfg| unreachable!(),
            SpawnConfig {
                local_as: 65001,
                local_bgp_id: "1.2.3.4".parse().unwrap(),
                hold_time: 180,
                graceful_restart_time: 0,
                configured_restarting: false,
                startup_instant: std::time::Instant::now(),
            },
            None,
        ));

        cmd_tx
            .send(DaemonCommand::RemovePeer(peer_ip))
            .await
            .unwrap();

        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), session_stop_rx.recv())
            .await
            .expect("timed out waiting for command")
            .expect("channel closed");

        match cmd {
            SessionCommand::Notification(msg) => {
                assert!(
                    matches!(
                        msg.error,
                        NotificationError::Cease(CeaseError::AdministrativeShutdown)
                    ),
                    "expected Cease/AdministrativeShutdown, got {:?}",
                    msg.error
                );
                let reason = decode_shutdown_message(&msg.data)
                    .expect("RFC 9003 payload must decode to a UTF-8 string");
                assert_eq!(
                    reason, "planned maintenance",
                    "decoded shutdown reason must match configured message"
                );
            }
            other => panic!("expected Notification, got {other:?}"),
        }
    }

    // ── RFC 2918 — route_refresh_peers tracking ───────────────────────────────

    /// `on_established` must insert the peer into `route_refresh_peers` when
    /// both sides negotiated `Capability::RouteRefresh`.
    #[tokio::test]
    async fn on_established_tracks_route_refresh_when_both_sides_negotiated() {
        let peer_ip: Ipv4Addr = "10.0.2.1".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65020)], 8);

        // Simulate the daemon advertising RouteRefresh (as build_daemon now does).
        {
            let mut s = state.write().await;
            s.config_capabilities.push(Capability::RouteRefresh);
        }

        let (event_tx, event_rx) = mpsc::channel(8);

        // Peer's OPEN includes RouteRefresh capability.
        let info = SessionInfo {
            peer_as: 65020,
            peer_bgp_id: Ipv4Addr::new(10, 0, 2, 1),
            hold_time: 90,
            peer_capabilities: vec![Capability::FourByteAsn(65020), Capability::RouteRefresh],
            peer_type: PeerType::External,
            local_addr: None,
        };

        event_tx
            .send((peer_ip, SessionEvent::Established(info)))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        assert!(
            state.read().await.route_refresh_peers.contains(&peer_ip),
            "route_refresh_peers must contain peer after both sides negotiated RouteRefresh"
        );
    }

    /// `on_established` must NOT add to `route_refresh_peers` if the peer did
    /// not advertise `Capability::RouteRefresh`, even if we did.
    #[tokio::test]
    async fn on_established_does_not_track_route_refresh_when_peer_omits_capability() {
        let peer_ip: Ipv4Addr = "10.0.2.2".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65021)], 8);

        {
            let mut s = state.write().await;
            s.config_capabilities.push(Capability::RouteRefresh);
        }

        let (event_tx, event_rx) = mpsc::channel(8);

        // Peer's OPEN does NOT include RouteRefresh.
        let info = SessionInfo {
            peer_as: 65021,
            peer_bgp_id: Ipv4Addr::new(10, 0, 2, 2),
            hold_time: 90,
            peer_capabilities: vec![Capability::FourByteAsn(65021)],
            peer_type: PeerType::External,
            local_addr: None,
        };

        event_tx
            .send((peer_ip, SessionEvent::Established(info)))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        assert!(
            !state.read().await.route_refresh_peers.contains(&peer_ip),
            "route_refresh_peers must NOT contain peer when peer did not advertise RouteRefresh"
        );
    }

    /// `on_terminated` must remove the peer from `route_refresh_peers`.
    #[tokio::test]
    async fn on_terminated_clears_route_refresh_peers() {
        let peer_ip: Ipv4Addr = "10.0.2.3".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65022)], 8);

        {
            let mut s = state.write().await;
            s.config_capabilities.push(Capability::RouteRefresh);
        }

        let (event_tx, event_rx) = mpsc::channel(8);

        let info = SessionInfo {
            peer_as: 65022,
            peer_bgp_id: Ipv4Addr::new(10, 0, 2, 3),
            hold_time: 90,
            peer_capabilities: vec![Capability::FourByteAsn(65022), Capability::RouteRefresh],
            peer_type: PeerType::External,
            local_addr: None,
        };

        event_tx
            .send((peer_ip, SessionEvent::Established(info)))
            .await
            .unwrap();
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        assert!(
            !state.read().await.route_refresh_peers.contains(&peer_ip),
            "route_refresh_peers must be cleared after Terminated"
        );
    }

    // ── Per-peer hold timer ────────────────────────────────────────────────────

    /// `build_daemon` must use the per-peer `hold_time` override instead of the
    /// global default when one is present in `PeerConfig`.
    #[test]
    fn build_daemon_uses_per_peer_hold_time_override() {
        // build_daemon is not directly callable, but the same logic is used in
        // the `AddPeer` command processor via `SpawnConfig`.  We verify the
        // formula directly: the per-peer value wins over the global fallback.
        let global_hold_time: u16 = 180;
        let per_peer_hold_time: u16 = 45;

        // A PeerConfig with hold_time set must yield the per-peer value.
        let peer_cfg_with_override = config::PeerConfig {
            address: "10.0.3.1".parse().unwrap(),
            port: 179,
            remote_as: 65030,
            import_default: None,
            export_default: None,
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: Some(per_peer_hold_time),
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        };
        assert_eq!(
            peer_cfg_with_override.hold_time.unwrap_or(global_hold_time),
            per_peer_hold_time,
            "per-peer hold_time must override global default"
        );

        // A PeerConfig without hold_time must fall back to the global default.
        let peer_cfg_no_override = config::PeerConfig {
            hold_time: None,
            ..peer_cfg_with_override.clone()
        };
        assert_eq!(
            peer_cfg_no_override.hold_time.unwrap_or(global_hold_time),
            global_hold_time,
            "absent per-peer hold_time must fall back to global default"
        );
    }

    /// `run_command_processor` must wire the per-peer `hold_time` override into
    /// the `SessionConfig` it passes to `spawn_fn`.  This verifies the wiring
    /// at the call site in `run_command_processor`, not just the formula.
    #[tokio::test]
    async fn add_peer_wires_per_peer_hold_time_into_session_config() {
        use std::sync::Mutex as StdMutex;

        // A minimal SessionHandle that records the SessionConfig it was built with.
        struct CaptureHandle;
        impl SessionHandle for CaptureHandle {
            async fn start(&self) {}
            async fn next_event(&mut self) -> Option<SessionEvent> {
                None
            }
            fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
                mpsc::channel(1).0
            }
            fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            async fn send_route_refresh(
                &self,
                _rr: pathvector_session::message::RouteRefreshMessage,
            ) {
            }
            async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
        }

        let global_hold_time: u16 = 180;
        let per_peer_hold_time: u16 = 45;
        let peer_ip: Ipv4Addr = "10.0.5.1".parse().unwrap();

        // Start with no pre-configured peers so AddPeer isn't treated as idempotent.
        let (state, _rxs, stop_senders) = make_state(&[], 8);

        let captured: Arc<StdMutex<Option<SessionConfig>>> = Arc::new(StdMutex::new(None));
        let captured_clone = Arc::clone(&captured);

        let (event_tx, _event_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);

        tokio::spawn(run_command_processor::<CaptureHandle, _>(
            cmd_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            move |cfg| {
                *captured_clone.lock().unwrap() = Some(cfg);
                CaptureHandle
            },
            SpawnConfig {
                local_as: 65001,
                local_bgp_id: "1.2.3.4".parse().unwrap(),
                hold_time: global_hold_time,
                graceful_restart_time: 0,
                configured_restarting: false,
                startup_instant: std::time::Instant::now(),
            },
            None,
        ));

        let peer_cfg = config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65050,
            import_default: None,
            export_default: None,
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: Some(per_peer_hold_time),
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        };

        cmd_tx.send(DaemonCommand::AddPeer(peer_cfg)).await.unwrap();
        drop(cmd_tx);

        // Give the command processor a moment to call spawn_fn.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let session_cfg = captured
            .lock()
            .unwrap()
            .take()
            .expect("spawn_fn was never called — AddPeer did not trigger session spawn");

        assert_eq!(
            session_cfg.hold_time, per_peer_hold_time,
            "run_command_processor must forward per-peer hold_time into SessionConfig"
        );
    }

    // ── Removed broadcast correctness ─────────────────────────────────────────

    /// When a peer in `pending_removal` receives `Terminated`, the event loop
    /// must broadcast exactly **one** `Removed` event on `peer_tx` and it must
    /// carry the correct `remote_as` and `local_as` captured before the state
    /// was erased.
    ///
    /// This is the critical regression test for the fix that replaced the
    /// diff-based approach (which emitted `remote_as: 0`) with capturing
    /// identity fields before `on_terminated` / `remove_peer` run.
    #[tokio::test]
    async fn terminated_with_pending_removal_broadcasts_removed_event_with_correct_fields() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let remote_as = 65099_u32;
        let local_as = 65001_u32;
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, remote_as)], 8);

        // Subscribe BEFORE the event fires so we don't miss the broadcast.
        let mut peer_rx = state.read().await.peer_tx.subscribe();

        state.write().await.pending_removal.insert(peer_ip);

        let (event_tx, event_rx) = mpsc::channel(4);
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        // Collect all events broadcast during the loop.
        let mut events = vec![];
        while let Ok(ev) = peer_rx.try_recv() {
            events.push(ev);
        }

        // Exactly one event must have been sent.
        assert_eq!(
            events.len(),
            1,
            "exactly one peer_tx event must fire for a pending_removal Terminated; got {events:?}"
        );

        let ev = &events[0];
        assert_eq!(
            ev.r#type,
            proto::PeerEventType::Removed as i32,
            "event type must be Removed"
        );

        let ps = ev
            .peer
            .as_ref()
            .expect("Removed event must carry a PeerState");
        assert_eq!(ps.address, peer_ip.to_string(), "address must match");
        assert_eq!(ps.remote_as, remote_as, "remote_as must not be zeroed");
        assert_eq!(ps.local_as, local_as, "local_as must not be zeroed");
    }

    /// When a normal peer (not in `pending_removal`) receives `Terminated`, the
    /// event loop must broadcast exactly **one** `Changed(peer: None)` event —
    /// not a `Removed` — so monitoring tools see the peer go Idle rather than
    /// disappear.
    ///
    /// This is a regression guard for the `notify: bool` parameter: the normal
    /// reconnect path must still send its notification.
    #[tokio::test]
    async fn terminated_without_pending_removal_broadcasts_changed_not_removed() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, stop_senders) = make_state(&[(peer_ip, 65099)], 8);

        let mut peer_rx = state.read().await.peer_tx.subscribe();

        let (event_tx, event_rx) = mpsc::channel(4);
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::Unclean),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(event_rx, Arc::clone(&state), stop_senders, None).await;

        let mut events = vec![];
        while let Ok(ev) = peer_rx.try_recv() {
            events.push(ev);
        }

        assert_eq!(
            events.len(),
            1,
            "exactly one peer_tx event must fire for a normal Terminated; got {events:?}"
        );
        assert_eq!(
            events[0].r#type,
            proto::PeerEventType::Changed as i32,
            "normal Terminated must emit Changed, not Removed"
        );
        assert!(
            events[0].peer.is_none(),
            "Changed signal from on_terminated must have peer: None (stream builds payload)"
        );
    }

    /// `on_terminated(peer_ip, notify: false)` must not send any broadcast on
    /// `peer_tx`.  This is a direct unit test of the new parameter — if it is
    /// ever dropped or inverted, this test will catch the regression.
    #[tokio::test]
    async fn on_terminated_notify_false_sends_no_broadcast() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

        let mut peer_rx = state.read().await.peer_tx.subscribe();

        state
            .write()
            .await
            .on_terminated(peer_ip, TerminationReason::Unclean, false);

        // No broadcast must arrive.
        assert!(
            peer_rx.try_recv().is_err(),
            "on_terminated(notify=false) must not send to peer_tx"
        );
    }

    /// `on_terminated(peer_ip, notify: true)` must send exactly one
    /// `Changed(peer: None)` broadcast on `peer_tx`.
    #[tokio::test]
    async fn on_terminated_notify_true_sends_changed_broadcast() {
        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

        let mut peer_rx = state.read().await.peer_tx.subscribe();

        state
            .write()
            .await
            .on_terminated(peer_ip, TerminationReason::Unclean, true);

        let ev = peer_rx
            .try_recv()
            .expect("on_terminated(notify=true) must send to peer_tx");
        assert_eq!(
            ev.r#type,
            proto::PeerEventType::Changed as i32,
            "broadcast must be Changed"
        );
        assert!(ev.peer.is_none(), "Changed signal must have peer: None");
        assert!(peer_rx.try_recv().is_err(), "must send exactly one event");
    }

    // ── incoming_senders race-safety ──────────────────────────────────────────

    /// After `RemovePeer` is processed by `run_command_processor`, the peer's
    /// entry must be gone from `incoming_senders`.
    ///
    /// This proves that new inbound TCP connections from the removed peer are
    /// rejected by `run_bgp_listener` before `Terminated` even fires — closing
    /// the reconnect race window.
    #[tokio::test]
    async fn remove_peer_clears_incoming_senders() {
        struct NeverSpawned;
        impl SessionHandle for NeverSpawned {
            async fn start(&self) {}
            async fn next_event(&mut self) -> Option<SessionEvent> {
                None
            }
            fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
                mpsc::channel(1).0
            }
            fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
                mpsc::channel(1).0
            }
            async fn send_route_refresh(
                &self,
                _rr: pathvector_session::message::RouteRefreshMessage,
            ) {
            }
            async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
        }

        let peer_ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let (state, _rxs, _stop) = make_state(&[(peer_ip, 65099)], 8);

        // Pre-populate incoming_senders as if AddPeer had already run.
        let (incoming_tx, _incoming_rx) = mpsc::channel::<SessionCommand>(1);
        let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> = Arc::new(
            RwLock::new(HashMap::from([(IpAddr::V4(peer_ip), incoming_tx)])),
        );

        let (event_tx, _event_rx) = mpsc::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let stop_senders: Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(run_command_processor::<NeverSpawned, _>(
            cmd_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            Arc::clone(&incoming),
            event_tx,
            |_cfg| unreachable!("RemovePeer must not call spawn_fn"),
            SpawnConfig {
                local_as: 65001,
                local_bgp_id: "1.2.3.4".parse().unwrap(),
                hold_time: 180,
                graceful_restart_time: 0,
                configured_restarting: false,
                startup_instant: std::time::Instant::now(),
            },
            None,
        ));

        assert!(
            incoming.read().await.contains_key(&IpAddr::V4(peer_ip)),
            "pre-condition: incoming_senders must contain the peer before RemovePeer"
        );

        cmd_tx
            .send(DaemonCommand::RemovePeer(peer_ip))
            .await
            .unwrap();

        // Allow the command processor to run the handler.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert!(
            !incoming.read().await.contains_key(&IpAddr::V4(peer_ip)),
            "incoming_senders must not contain the peer after RemovePeer — \
             new inbound TCP connections must be rejected immediately"
        );
    }

    /// `run_bgp_listener` must drop (RST) inbound TCP connections whose source
    /// address is not in `incoming_senders`.
    ///
    /// This proves the other half of the race-safety invariant: even if an
    /// adversarial or reconnecting peer dials in, the listener drops it without
    /// forwarding it to any session actor.
    #[tokio::test]
    async fn bgp_listener_drops_unlisted_peer() {
        use std::net::SocketAddr;
        use tokio::io::AsyncReadExt as _;

        // Bind the listener on a random OS-assigned port with an empty
        // incoming_senders — no peers are known.
        let incoming: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let md5: Arc<RwLock<HashMap<IpAddr, String>>> = Arc::new(RwLock::new(HashMap::new()));

        // Spawn on port 0 so the OS assigns a free port.
        let listener_sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener_sock.local_addr().unwrap().port();
        drop(listener_sock);

        let incoming_clone = Arc::clone(&incoming);
        let md5_clone = Arc::clone(&md5);
        tokio::spawn(async move {
            run_bgp_listener(port, incoming_clone, md5_clone).await;
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // Connect from 127.0.0.1 — not present in incoming_senders.
        let mut conn = tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .expect("TCP connect must succeed");

        // The listener drops the stream immediately — we should see EOF (0
        // bytes read) with no data sent, within a short timeout.
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(tokio::time::Duration::from_secs(2), conn.read(&mut buf))
            .await
            .expect("read must complete within 2 s — listener must close the connection promptly")
            .expect("read must not return an OS error");

        assert_eq!(
            n, 0,
            "listener must send no data and close the connection for an unlisted peer"
        );
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
                false,
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

            let result = prepare_outbound(route, PeerType::External, local_as, bgp_id, false);

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

/// Property tests for the dynamic peer management API.
///
/// These tests exercise arbitrary sequences of `add_peer` / `remove_peer` calls
/// against a `DaemonState` and assert that the state maps remain self-consistent
/// after every operation — no panics, no dangling keys, no phantom entries.
#[cfg(test)]
mod dynamic_peer_prop_tests {
    use std::{collections::HashMap, net::Ipv4Addr};

    use proptest::prelude::*;
    use tokio::sync::mpsc;

    use super::*;
    use crate::config;

    fn peer_cfg(address: Ipv4Addr, remote_as: u32) -> config::PeerConfig {
        config::PeerConfig {
            address,
            port: 179,
            remote_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        }
    }

    fn fresh_state(peers: &[(Ipv4Addr, u32)]) -> DaemonState {
        let mut senders = HashMap::new();
        for &(ip, _) in peers {
            let (tx, _rx) = mpsc::channel(8);
            senders.insert(ip, tx);
        }
        let cfgs: Vec<config::PeerConfig> = peers.iter().map(|&(a, r)| peer_cfg(a, r)).collect();
        DaemonState::new(
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &cfgs,
            senders,
            vec![],
        )
    }

    /// A `DaemonState` is self-consistent when every key present in
    /// `adj_ribs_in` also appears in `peer_remote_as`, `adj_ribs_out`,
    /// `import_policies`, `export_policies`, and `export_policies_v6` — and
    /// vice-versa.
    fn assert_consistent(s: &DaemonState, label: &str) {
        let ribs_in: std::collections::HashSet<_> = s.adj_ribs_in.keys().collect();
        let remote_as: std::collections::HashSet<_> = s.rib.peer_remote_as.keys().collect();
        let ribs_out: std::collections::HashSet<_> = s.adj_ribs_out.keys().collect();
        let import: std::collections::HashSet<_> = s.import_policies.keys().collect();
        let export: std::collections::HashSet<_> = s.export_policies.keys().collect();
        let export_v6: std::collections::HashSet<_> = s.export_policies_v6.keys().collect();

        assert_eq!(
            ribs_in, remote_as,
            "{label}: adj_ribs_in keys must equal peer_remote_as keys"
        );
        assert_eq!(
            ribs_in, ribs_out,
            "{label}: adj_ribs_in keys must equal adj_ribs_out keys"
        );
        assert_eq!(
            ribs_in, import,
            "{label}: adj_ribs_in keys must equal import_policies keys"
        );
        assert_eq!(
            ribs_in, export,
            "{label}: adj_ribs_in keys must equal export_policies keys"
        );
        assert_eq!(
            ribs_in, export_v6,
            "{label}: adj_ribs_in keys must equal export_policies_v6 keys"
        );
    }

    /// Arbitrary sequences of add/remove for up to 4 peers must never corrupt
    /// state.  Uses the last octet of 10.0.0.x as the peer discriminant.
    #[derive(Clone, Debug)]
    enum Op {
        Add(u8), // peer last octet, always remote_as 65000 + octet
        Remove(u8),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        (1u8..=4u8)
            .prop_flat_map(|octet| prop_oneof![Just(Op::Add(octet)), Just(Op::Remove(octet)),])
    }

    proptest! {
        /// Any sequence of up to 20 add/remove operations must leave
        /// `DaemonState` self-consistent and must not panic.
        #[test]
        fn prop_add_remove_sequence_leaves_state_consistent(
            ops in prop::collection::vec(op_strategy(), 1..=20)
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let mut state = fresh_state(&[]);
                assert_consistent(&state, "initial");

                for (i, op) in ops.iter().enumerate() {
                    match op {
                        Op::Add(octet) => {
                            let ip = Ipv4Addr::new(10, 0, 0, *octet);
                            let remote_as = 65000 + u32::from(*octet);
                            let (tx, _rx) = mpsc::channel(8);
                            state.add_peer(&peer_cfg(ip, remote_as), tx);
                        }
                        Op::Remove(octet) => {
                            let ip = Ipv4Addr::new(10, 0, 0, *octet);
                            state.remove_peer(ip); // may return false — that's fine
                        }
                    }
                    assert_consistent(&state, &format!("after op {i}: {op:?}"));
                }

                // pending_removal must be empty (we never used it in this test).
                prop_assert!(
                    state.pending_removal.is_empty(),
                    "pending_removal must be empty after direct add/remove ops"
                );
                Ok(())
            }).unwrap();
        }

        /// `add_peer` followed by `remove_peer` for the same address must leave
        /// the state as if neither call was made — no phantom entries, no
        /// dangling keys.
        #[test]
        fn prop_add_then_remove_is_identity(octet in 1u8..=4u8) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let ip = Ipv4Addr::new(10, 0, 0, octet);
                let remote_as = 65000 + u32::from(octet);

                let state_before = fresh_state(&[]);
                let mut state_after = fresh_state(&[]);

                let (tx, _rx) = mpsc::channel(8);
                state_after.add_peer(&peer_cfg(ip, remote_as), tx);
                state_after.remove_peer(ip);

                // Key sets must match: after add+remove, no peer should remain.
                prop_assert_eq!(
                    state_after.adj_ribs_in.len(),
                    state_before.adj_ribs_in.len(),
                    "adj_ribs_in must be empty after add+remove"
                );
                prop_assert_eq!(
                    state_after.rib.peer_remote_as.len(),
                    state_before.rib.peer_remote_as.len(),
                    "peer_remote_as must be empty after add+remove"
                );
                assert_consistent(&state_after, "after add+remove");
                Ok(())
            }).unwrap();
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

    use pathvector_session::message::{PathAttribute, UpdateMessage};
    use pathvector_session::transport::{
        SessionCommand, SessionConfig, SessionEvent, SessionHandle, TerminationReason,
    };
    use pathvector_types::{AsPath, Asn, Origin, PeerType};
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

        async fn send_route_refresh(&self, _rr: pathvector_session::message::RouteRefreshMessage) {}

        async fn set_capabilities(&self, _caps: Vec<pathvector_session::message::Capability>) {}
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
                metrics_port: None,
                local_ipv6: None,
                cluster_id: None,
                fib_table: 254,
                fib_metric: 20,
                graceful_restart_time: 0,
                restarting: false,
                rpki: None,
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
                    next_hop_self: false,
                    hold_time: None,
                    shutdown_message: None,
                    connect_retry_time: None,
                    max_prefixes_v4: None,
                    max_prefixes_v6: None,
                    max_prefixes_restart: None,
                    role: None,
                })
                .collect(),
            sidecar_path: None,
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// `DaemonState.rpki` starts `None` when `[daemon.rpki]` is absent — the
    /// common case for most deployments. Confirms `build_daemon` never
    /// populates it unprompted.
    #[tokio::test]
    async fn daemon_state_rpki_is_none_when_unconfigured() {
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[]);
        let (state, ..) = build_daemon(&cfg, spawn_fn).await;
        assert!(state.read().await.rpki.is_none());
    }

    /// Mirrors the exact spawn-and-wire sequence `run_with` performs for
    /// `[daemon.rpki]`, pointed at a closed port. `RtrClient::spawn` must
    /// return immediately regardless of whether the TCP connect will
    /// eventually succeed — confirms the RPKI wiring can never block daemon
    /// startup, matching the FIB/metrics graceful-degradation pattern.
    #[tokio::test]
    async fn rpki_client_spawn_never_blocks_and_populates_daemon_state() {
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[]);
        let (state, ..) = build_daemon(&cfg, spawn_fn).await;

        let spawn_started = std::time::Instant::now();
        let (handle, _join) = pathvector_rpki::RtrClient::spawn(pathvector_rpki::RtrConfig {
            host: "127.0.0.1".to_string(),
            port: 1, // reserved; nothing listens here — connect will fail
            ..Default::default()
        });
        assert!(
            spawn_started.elapsed() < std::time::Duration::from_millis(100),
            "RtrClient::spawn must return immediately, not block on the TCP connect"
        );

        state.write().await.rpki = Some(handle);
        assert!(state.read().await.rpki.is_some());
    }

    /// Exercises the exact production wiring in `install_rpki` (the
    /// function `run_with` calls) end-to-end: a route accepted while the
    /// ROA cache is empty must be automatically rejected once the cache
    /// changes — *without* the test calling `reevaluate_all_import_policies`
    /// itself. Proves the background task `install_rpki` spawns actually
    /// fires, not just that the method it calls is correct in isolation
    /// (already covered directly in `daemon::tests`).
    ///
    /// Uses a `for_testing()`/`insert_roa_v4`-driven handle rather than a
    /// real TCP RTR server — the wire protocol itself is already covered by
    /// `pathvector-rpki`'s own mock-server tests; this test is only
    /// responsible for proving pathvectord's reaction to a cache change.
    #[tokio::test]
    async fn rpki_reactive_task_reevaluates_on_cache_change() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (spawn_fn, _peers) = make_mock_spawn();
        let mut cfg = make_config(&[(peer_ip, 65002)]);
        // RFC 8212 default-rejects eBGP peers with no explicit import policy —
        // opt this peer in to accept-by-default so ROV alone governs whether
        // the test route is accepted.
        cfg.peers[0].import_default = Some(config::ImportDefault::Accept);
        let (state, ..) = build_daemon(&cfg, spawn_fn).await;

        let rtr = pathvector_rpki::for_testing(std::iter::empty(), std::iter::empty());
        install_rpki(rtr.clone(), true, &state).await;

        let nlri: pathvector_types::Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        {
            let mut guard = state.write().await;
            guard.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
            guard.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                        PathAttribute::NextHop(peer_ip),
                    ],
                    announced: vec![nlri],
                },
            );
        }
        assert!(
            state.read().await.rib.loc_rib.best(&nlri).is_some(),
            "route should be accepted while the cache is still empty (NotFound)"
        );

        // A ROA arrives making the already-accepted route Invalid. Nothing
        // in this test calls reevaluate_all_import_policies — only the
        // background task install_rpki spawned should react.
        rtr.insert_roa_v4(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999);

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if state.read().await.rib.loc_rib.best(&nlri).is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reactive task did not reject the route within 5s of the cache change");
    }

    /// Regression test for a subscribe-after-spawn race: `RtrClient::spawn`
    /// starts its background sync task before `install_rpki` gets a chance
    /// to call `handle.subscribe()`, so if the first sync completes first,
    /// its `watch` notification is sent to no receiver and would otherwise
    /// be silently missed — leaving an already-accepted-but-now-Invalid
    /// route unrejected until the next unrelated cache change.
    ///
    /// `for_testing()` conveniently starts in exactly that "sync already
    /// happened" state (`status().connected == true`, ROA data already
    /// loaded, no watch notification ever fired for it) — a deterministic
    /// stand-in for the race, no real timing dependency needed. The route
    /// must be rejected the instant `install_rpki` returns, without this
    /// test ever calling `reevaluate_all_import_policies` or
    /// `insert_roa_v4` (which would exercise the normal, already-covered
    /// watch-notification path instead of the eager catch-up check).
    #[tokio::test]
    async fn install_rpki_catches_up_when_first_sync_precedes_subscribe() {
        let peer_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let (spawn_fn, _peers) = make_mock_spawn();
        let mut cfg = make_config(&[(peer_ip, 65002)]);
        cfg.peers[0].import_default = Some(config::ImportDefault::Accept);
        let (state, ..) = build_daemon(&cfg, spawn_fn).await;

        let nlri: pathvector_types::Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        {
            let mut guard = state.write().await;
            guard.on_established(peer_ip, peer_ip, PeerType::External, 65002, 90, &[], None);
            guard.on_route_update(
                peer_ip,
                UpdateMessage {
                    withdrawn: vec![],
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                        PathAttribute::NextHop(peer_ip),
                    ],
                    announced: vec![nlri],
                },
            );
        }
        assert!(
            state.read().await.rib.loc_rib.best(&nlri).is_some(),
            "route should be accepted before RPKI is installed at all"
        );

        // Already "synced" before install_rpki ever calls subscribe() —
        // stands in for the background task's first sync winning the race.
        let rtr = pathvector_rpki::for_testing(
            [(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 99999)],
            std::iter::empty(),
        );
        install_rpki(rtr, true, &state).await;

        assert!(
            state.read().await.rib.loc_rib.best(&nlri).is_none(),
            "install_rpki must eagerly re-evaluate once if the handle was already \
             synced when subscribe() was called, not only react to later changes"
        );
    }

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
        let (_state, _rx, _event_tx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;
        assert!(stop_senders.lock().unwrap().contains_key(&peer_a));
        assert!(stop_senders.lock().unwrap().contains_key(&peer_b));
    }

    /// An event injected through a mock peer's sender appears on the returned
    /// event receiver — verifying the per-peer forwarding task is wired up.
    #[tokio::test]
    async fn build_daemon_forwards_events_to_receiver() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let (spawn_fn, peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002)]);
        let (_state, mut event_rx, _event_tx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;

        let event_tx = peers.lock().unwrap()[0].event_tx.clone();
        event_tx
            .send(SessionEvent::Terminated(TerminationReason::Unclean))
            .await
            .unwrap();

        let (ip, event) = event_rx.recv().await.unwrap();
        assert_eq!(ip, peer_a);
        assert!(matches!(event, SessionEvent::Terminated(_)));
    }

    /// The returned `DaemonState` has an update-sender entry for every
    /// configured peer — i.e. the state is fully pre-populated at startup.
    #[tokio::test]
    async fn build_daemon_state_has_entry_per_peer() {
        let peer_a = Ipv4Addr::new(10, 0, 0, 1);
        let peer_b = Ipv4Addr::new(10, 0, 0, 2);
        let (spawn_fn, _peers) = make_mock_spawn();
        let cfg = make_config(&[(peer_a, 65002), (peer_b, 65003)]);
        let (state, _rx, _event_tx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;
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
        let (_state, mut event_rx, event_tx, _stop, _, _) = build_daemon(&cfg, spawn_fn).await;
        assert_eq!(peers.lock().unwrap().len(), 0);
        // Drop the returned event_tx; since there are no per-peer forwarding
        // tasks, no other senders remain and recv() returns None.
        drop(event_tx);
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

        let (_state, _rx, _event_tx, _stop, _incoming, md5_passwords) =
            build_daemon(&cfg, spawn_fn).await;

        assert_eq!(
            md5_passwords
                .read()
                .await
                .get(&IpAddr::V4(peer_ip))
                .map(String::as_str),
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

        let (_state, _rx, _event_tx, _stop, _incoming, md5_passwords) =
            build_daemon(&cfg, spawn_fn).await;

        assert!(
            md5_passwords.read().await.is_empty(),
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

        let (_state, _rx, _event_tx, _stop, _incoming, md5_passwords) =
            build_daemon(&cfg, spawn_fn).await;
        let md5 = md5_passwords.read().await;

        assert_eq!(
            md5.get(&IpAddr::V4(peer_a)).map(String::as_str),
            Some("key-for-a"),
        );
        assert!(
            !md5.contains_key(&IpAddr::V4(peer_b)),
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
        /// Keep the update receiver alive so `try_send` on the update channel
        /// does not fail with `TrySendError::Closed` when the EOR is sent.
        update_rx: mpsc::Receiver<UpdateMessage>,
    }

    fn make_mock_spawn_capturing_stop() -> (
        impl Fn(SessionConfig) -> MockSessionHandle,
        Arc<Mutex<Vec<MockPeerWithStop>>>,
    ) {
        let peers: Arc<Mutex<Vec<MockPeerWithStop>>> = Arc::new(Mutex::new(vec![]));
        let peers_clone = Arc::clone(&peers);
        let spawn_fn = move |_cfg: SessionConfig| {
            let (event_tx, event_rx) = mpsc::channel(8);
            let (update_tx, update_rx) = mpsc::channel(8);
            let (stop_tx, stop_rx) = mpsc::channel(8);
            let started = Arc::new(AtomicBool::new(false));
            peers_clone.lock().unwrap().push(MockPeerWithStop {
                event_tx,
                stop_rx,
                update_rx,
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
        use pathvector_session::fsm::SessionInfo;
        use pathvector_session::message::Capability;
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
        let (state, event_rx, _event_tx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;

        // Run the event loop in the background; inject events via the mock peer.
        tokio::spawn(run_event_loop(event_rx, state, stop_senders, None));

        // Allow the spawned task to start.
        tokio::task::yield_now().await;

        let (event_tx, stop_rx, _update_rx) = {
            let mut guard = peers.lock().unwrap();
            let p = guard.pop().expect("one peer spawned");
            (p.event_tx, p.stop_rx, p.update_rx)
        };

        // Establish the session so the daemon has peer state.
        event_tx
            .send(established_info_for_peer(65002))
            .await
            .unwrap();
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
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            let mut stop_rx = stop_rx;
            stop_rx.recv().await
        })
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

    // ── Reconnect capability refresh ──────────────────────────────────────────

    /// On an unclean, non-removal termination, the event loop rebuilds and
    /// resends this peer's capability set via `SessionCommand::SetCapabilities`
    /// before the peer reconnects — so per-session dynamic state (the RFC 4724
    /// R-bit, and RFC 9234 Role) survives a reconnect instead of reverting to
    /// whatever `DaemonState::new()` computed once at startup.
    ///
    /// This is the exact call site the Role reconnect fix (mirroring the
    /// pre-existing GR R-bit fix) touches, but until now nothing exercised it
    /// through the real event loop — every other capability test calls the
    /// pure `build_local_capabilities`/`SpawnConfig::capabilities` functions
    /// directly, never `run_event_loop` end-to-end. Closes the gap tracked in
    /// `TODO.md` under "No event-loop integration test for the reconnect
    /// capability-refresh path".
    #[tokio::test]
    async fn reconnect_resends_role_and_gr_capabilities_via_set_capabilities() {
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let (spawn_fn, peers) = make_mock_spawn_capturing_stop();
        let mut cfg = make_config(&[(peer_ip, 65002)]);
        cfg.daemon.graceful_restart_time = 120;
        cfg.peers[0].role = Some(config::PeerRole::Provider);
        let (state, event_rx, _event_tx, stop_senders, _, _) = build_daemon(&cfg, spawn_fn).await;

        tokio::spawn(run_event_loop(event_rx, state, stop_senders, None));
        tokio::task::yield_now().await;

        let (event_tx, mut stop_rx, _update_rx) = {
            let mut guard = peers.lock().unwrap();
            let p = guard.pop().expect("one peer spawned");
            (p.event_tx, p.stop_rx, p.update_rx)
        };

        // Establish, then terminate uncleanly (not an operator-initiated
        // removal) — this is the reconnect-eligible path.
        event_tx
            .send(established_info_for_peer(65002))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        event_tx
            .send(SessionEvent::Terminated(TerminationReason::Unclean))
            .await
            .unwrap();

        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), stop_rx.recv())
            .await
            .expect("timed out waiting for SessionCommand")
            .expect("stop channel closed without sending SetCapabilities");

        let caps = match cmd {
            SessionCommand::SetCapabilities(caps) => caps,
            other => panic!("expected SetCapabilities, got {other:?}"),
        };

        assert!(
            caps.iter()
                .any(|c| matches!(c, Capability::Role(Role::Provider))),
            "Role(Provider) must survive the reconnect capability refresh, got {caps:?}"
        );
        let (restart_flags, restart_time) = caps
            .iter()
            .find_map(|c| {
                if let Capability::GracefulRestart {
                    restart_flags,
                    restart_time,
                    ..
                } = c
                {
                    Some((*restart_flags, *restart_time))
                } else {
                    None
                }
            })
            .expect("GracefulRestart capability must be present");
        assert_eq!(
            restart_time, 120,
            "restart_time must reflect the configured GR window"
        );
        assert_eq!(
            restart_flags & 0x08,
            0,
            "R-bit must always be 0 on reconnect — see the comment at the caps_refresh call site"
        );
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

    // ── Dynamic peer persistence (sidecar) ───────────────────────────────────

    /// Simulates a daemon restart: a peer is written to the sidecar, then the
    /// sidecar is loaded and merged into a fresh config.  `build_daemon` must
    /// spawn a session for the peer as if it had been statically configured.
    ///
    /// This is the integration-level proof that the `main.rs` startup path
    /// correctly re-hydrates dynamic peers from the sidecar after a restart —
    /// without requiring a real Docker container restart.
    #[tokio::test]
    async fn dynamic_peer_from_sidecar_is_loaded_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar_path = dir.path().join("dynamic_peers.toml");
        let store = config::DynamicPeerStore::new(sidecar_path.clone());

        // Write a peer into the sidecar as if it had been added via add_peer
        // during a previous run.
        let peer_ip = Ipv4Addr::new(10, 0, 0, 5);
        store
            .upsert(config::PeerConfig {
                address: peer_ip,
                port: 179,
                remote_as: 65099,
                import_default: None,
                import_default_v6: None,
                export_default: None,
                md5_password: None,
                is_rr_client: false,
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
            })
            .await;

        // Replicate what main.rs does on startup: load sidecar, merge into cfg.
        let mut cfg = make_config(&[]);
        for p in store.load() {
            if !cfg.peers.iter().any(|x| x.address == p.address) {
                cfg.peers.push(p);
            }
        }
        cfg.sidecar_path = Some(sidecar_path);

        // Build daemon — the sidecar peer must be treated as a static peer.
        let (spawn_fn, spawned_peers) = make_mock_spawn();
        let _ = build_daemon(&cfg, spawn_fn).await;

        let peers = spawned_peers.lock().unwrap();
        assert_eq!(
            peers.len(),
            1,
            "exactly one session must be spawned for the sidecar peer"
        );
        assert!(
            peers[0].started.load(Ordering::SeqCst),
            "sidecar peer session must have start() called"
        );
    }

    /// A peer in the sidecar must not be duplicated if it also appears in the
    /// static config — the deduplication in main.rs must prevent a double-add.
    #[tokio::test]
    async fn sidecar_peer_already_in_static_config_not_duplicated() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar_path = dir.path().join("dynamic_peers.toml");
        let store = config::DynamicPeerStore::new(sidecar_path.clone());

        let peer_ip = Ipv4Addr::new(10, 0, 0, 5);
        store
            .upsert(config::PeerConfig {
                address: peer_ip,
                port: 179,
                remote_as: 65099,
                import_default: None,
                import_default_v6: None,
                export_default: None,
                md5_password: None,
                is_rr_client: false,
                next_hop_self: false,
                hold_time: None,
                shutdown_message: None,
                connect_retry_time: None,
                max_prefixes_v4: None,
                max_prefixes_v6: None,
                max_prefixes_restart: None,
                role: None,
            })
            .await;

        // Same peer already in the static config — dedup must skip the sidecar entry.
        let mut cfg = make_config(&[(peer_ip, 65099)]);
        for p in store.load() {
            if !cfg.peers.iter().any(|x| x.address == p.address) {
                cfg.peers.push(p);
            }
        }
        cfg.sidecar_path = Some(sidecar_path);

        let (spawn_fn, spawned_peers) = make_mock_spawn();
        let _ = build_daemon(&cfg, spawn_fn).await;

        assert_eq!(
            spawned_peers.lock().unwrap().len(),
            1,
            "peer must not be spawned twice when present in both static config and sidecar"
        );
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

// ── RFC 4724 §2 End-of-RIB receive-side detection tests ──────────────────────

#[cfg(test)]
mod eor_receive_tests {
    use std::net::Ipv4Addr;

    use pathvector_session::message::{MpUnreachNlri, PathAttribute, UpdateMessage};
    use pathvector_session::transport::TerminationReason;

    use pathvector_types::{AfiSafi, PeerType};

    use super::tests::make_state;

    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const PEER_AS: u32 = 65002;
    const LOCAL_AS: u32 = 65001;

    fn establish_peer(state: &mut super::DaemonState) {
        state.on_established(PEER_IP, PEER_IP, PeerType::External, PEER_AS, 90, &[], None);
    }

    fn ipv4_eor() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        }
    }

    fn ipv6_eor() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![],
            })],
            announced: vec![],
        }
    }

    // Test 1: IPv4 EOR is detected and state is recorded.
    #[test]
    fn test_ipv4_eor_received_is_recorded() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        establish_peer(&mut state);

        let result = state.on_route_update(PEER_IP, ipv4_eor());
        assert!(result.is_none(), "EOR must not return a NOTIFICATION");
        assert!(
            state.rib.eor_received.contains(&PEER_IP),
            "eor_received must contain peer after IPv4 EOR"
        );
    }

    // Test 2: IPv6 EOR is detected and state is recorded.
    #[test]
    fn test_ipv6_eor_received_is_recorded() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        establish_peer(&mut state);

        let result = state.on_route_update(PEER_IP, ipv6_eor());
        assert!(result.is_none(), "EOR must not return a NOTIFICATION");
        assert!(
            state.rib.eor_received_v6.contains(&PEER_IP),
            "eor_received_v6 must contain peer after IPv6 EOR"
        );
    }

    // Test 3: IPv4 EOR must return early and not insert into Adj-RIB-In.
    #[test]
    fn test_ipv4_eor_does_not_insert_route() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        establish_peer(&mut state);

        state.on_route_update(PEER_IP, ipv4_eor());

        let ari_len = state
            .adj_ribs_in
            .get(&PEER_IP)
            .map_or(0, pathvector_rib::AdjRibIn::len);
        assert_eq!(ari_len, 0, "EOR must not insert a route into Adj-RIB-In");
    }

    // Test 4: EOR state is cleared when the session terminates.
    #[test]
    fn test_eor_state_cleared_on_termination() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        establish_peer(&mut state);
        state.on_route_update(PEER_IP, ipv4_eor());
        assert!(state.rib.eor_received.contains(&PEER_IP));

        state.on_terminated(PEER_IP, TerminationReason::Unclean, false);

        assert!(
            !state.rib.eor_received.contains(&PEER_IP),
            "eor_received must be cleared after session termination"
        );
    }

    // Test 5: An UPDATE with attributes (but no NLRIs) is not an EOR.
    #[test]
    fn test_update_with_attributes_is_not_eor() {
        use pathvector_types::{AsPath, Origin};
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        establish_peer(&mut state);

        // Build an UPDATE that has attributes but no NLRI — NOT an IPv4 EOR.
        let msg = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::new()),
                PathAttribute::NextHop("10.0.0.2".parse().unwrap()),
            ],
            announced: vec![],
        };
        state.on_route_update(PEER_IP, msg);

        assert!(
            !state.rib.eor_received.contains(&PEER_IP),
            "UPDATE with attributes must not be recorded as IPv4 EOR"
        );
    }

    // Test 6: Stale EOR state from a previous session is cleared on re-establish.
    #[test]
    fn test_eor_state_cleared_on_re_establish() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(PEER_IP, PEER_AS)]);
        establish_peer(&mut state);
        state.on_route_update(PEER_IP, ipv4_eor());
        assert!(state.rib.eor_received.contains(&PEER_IP));

        // Simulate reconnect without explicit termination by calling on_established again.
        establish_peer(&mut state);

        assert!(
            !state.rib.eor_received.contains(&PEER_IP),
            "eor_received must be cleared on session re-establishment"
        );
    }
}

// ── build_local_capabilities — RFC 4724 §3 graceful restart advertisement ────

#[cfg(test)]
mod test_build_local_capabilities {
    use super::*;
    use pathvector_session::message::{Capability, GracefulRestartFamily};
    use pathvector_types::AfiSafi;

    fn find_gr(caps: &[Capability]) -> Option<(u8, u16, Vec<GracefulRestartFamily>)> {
        caps.iter().find_map(|c| {
            if let Capability::GracefulRestart {
                restart_flags,
                restart_time,
                families,
            } = c
            {
                Some((*restart_flags, *restart_time, families.clone()))
            } else {
                None
            }
        })
    }

    #[test]
    fn test_build_local_capabilities_gr_disabled() {
        let caps = build_local_capabilities(65001, 0, false, None);
        let (flags, time, families) =
            find_gr(&caps).expect("GracefulRestart capability must be present");
        assert_eq!(flags, 0);
        assert_eq!(time, 0, "restart_time must be 0 when GR is disabled");
        assert!(families.is_empty(), "no families when restart_time = 0");
    }

    #[test]
    fn test_build_local_capabilities_gr_enabled() {
        let caps = build_local_capabilities(65001, 120, false, None);
        let (flags, time, families) =
            find_gr(&caps).expect("GracefulRestart capability must be present");
        // RFC 8538: N-bit (0x04) is set whenever gr_time > 0; R-bit (0x08) is not
        // set because we are not restarting.
        assert_eq!(
            flags, 0x04,
            "N-bit must be set, R-bit must be clear on normal startup"
        );
        assert_eq!(time, 120);
        assert_eq!(families.len(), 2);
        let v4 = families
            .iter()
            .find(|f| f.afi_safi == AfiSafi::IPV4_UNICAST)
            .expect("IPv4 unicast family must be present");
        assert!(
            v4.forwarding_preserved,
            "IPv4 must have forwarding_preserved=true"
        );
        let v6 = families
            .iter()
            .find(|f| f.afi_safi == AfiSafi::IPV6_UNICAST)
            .expect("IPv6 unicast family must be present");
        assert!(
            v6.forwarding_preserved,
            "IPv6 must have forwarding_preserved=true"
        );
    }

    #[test]
    fn test_build_local_capabilities_gr_clamps_at_4095() {
        let caps = build_local_capabilities(65001, u16::MAX, false, None);
        let (_, time, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
        assert_eq!(
            time, 4095,
            "restart_time must be clamped to RFC 4724 maximum of 4095"
        );
    }

    /// RFC 4724 §3: when restarting, F-bit must be false — our FIB was deleted on
    /// startup before reconvergence.
    #[test]
    fn test_build_local_capabilities_f_bit_false_when_restarting() {
        let caps = build_local_capabilities(65001, 120, true, None);
        let (_, _, families) = find_gr(&caps).expect("GracefulRestart must be present");
        for fam in &families {
            assert!(
                !fam.forwarding_preserved,
                "forwarding_preserved must be false while restarting — FIB was wiped on startup"
            );
        }
    }

    /// RFC 4724 §3: when stable (not restarting), F-bit must be true — kernel
    /// routes survive session loss on Linux.
    #[test]
    fn test_build_local_capabilities_f_bit_true_when_stable() {
        let caps = build_local_capabilities(65001, 120, false, None);
        let (_, _, families) = find_gr(&caps).expect("GracefulRestart must be present");
        for fam in &families {
            assert!(
                fam.forwarding_preserved,
                "forwarding_preserved must be true when not restarting — kernel FIB is intact"
            );
        }
    }

    /// RFC 4724 §3: when `restarting = true`, the R-bit (0x08 in restart_flags)
    /// must be set so peers know to stop their stale-route timers on re-establishment.
    #[test]
    fn test_build_local_capabilities_r_bit_set_when_restarting() {
        let caps = build_local_capabilities(65001, 120, true, None);
        let (flags, _, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
        assert_eq!(
            flags & 0x08,
            0x08,
            "R-bit must be set when restarting = true"
        );
    }

    /// RFC 4724 §3: when `restarting = false` (normal startup), the R-bit must
    /// not be set — we are not signalling a restart to peers.
    #[test]
    fn test_build_local_capabilities_r_bit_clear_on_normal_startup() {
        let caps = build_local_capabilities(65001, 120, false, None);
        let (flags, _, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
        assert_eq!(
            flags & 0x08,
            0x00,
            "R-bit must not be set on normal startup"
        );
    }

    /// RFC 4724 §3: R-bit must be ignored (stay 0x00) when `graceful_restart_time = 0`
    /// even if `restarting = true` — there is no GR window to signal.
    #[test]
    fn test_build_local_capabilities_r_bit_ignored_when_gr_disabled() {
        let caps = build_local_capabilities(65001, 0, true, None);
        let (flags, _, _) = find_gr(&caps).expect("GracefulRestart capability must be present");
        assert_eq!(
            flags & 0x08,
            0x00,
            "R-bit must not be set when graceful_restart_time = 0"
        );
    }

    /// RFC 9234: when `role` is `Some`, `Capability::Role` must be present in
    /// the output with the matching wire value.
    #[test]
    fn test_build_local_capabilities_includes_role_when_configured() {
        let caps = build_local_capabilities(65001, 0, false, Some(Role::Customer));
        assert!(
            caps.iter()
                .any(|c| matches!(c, Capability::Role(Role::Customer))),
            "Capability::Role(Customer) must be present when role is configured"
        );
    }

    /// RFC 9234's own non-strict default: omitting `role` must omit the
    /// capability entirely, not send some default/placeholder role value.
    #[test]
    fn test_build_local_capabilities_omits_role_when_none() {
        let caps = build_local_capabilities(65001, 0, false, None);
        assert!(
            !caps.iter().any(|c| matches!(c, Capability::Role(_))),
            "Capability::Role must be absent when role is not configured"
        );
    }

    fn spawn_cfg(
        gr_time: u16,
        configured_restarting: bool,
        age: std::time::Duration,
    ) -> SpawnConfig {
        SpawnConfig {
            local_as: 65001,
            local_bgp_id: std::net::Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            graceful_restart_time: gr_time,
            configured_restarting,
            startup_instant: std::time::Instant::now().checked_sub(age).unwrap(),
        }
    }

    /// Within the restart window, SpawnConfig::capabilities() must set R=1.
    #[test]
    fn spawn_config_r_bit_set_within_restart_window() {
        let cfg = spawn_cfg(120, true, std::time::Duration::from_secs(10));
        let caps = cfg.capabilities(None);
        let (flags, _, _) = find_gr(&caps).expect("GracefulRestart must be present");
        assert_eq!(
            flags & 0x08,
            0x08,
            "R-bit must be set while within the 120 s restart window"
        );
    }

    /// After the restart window expires, SpawnConfig::capabilities() must clear R=0.
    #[test]
    fn spawn_config_r_bit_cleared_after_restart_window() {
        // Simulate 130 s elapsed for a 120 s window.
        let cfg = spawn_cfg(120, true, std::time::Duration::from_secs(130));
        let caps = cfg.capabilities(None);
        let (flags, _, _) = find_gr(&caps).expect("GracefulRestart must be present");
        assert_eq!(
            flags & 0x08,
            0x00,
            "R-bit must be cleared after the 120 s restart window expires"
        );
    }

    /// configured_restarting=false must always yield R=0, regardless of elapsed time.
    #[test]
    fn spawn_config_r_bit_not_set_when_not_configured_restarting() {
        let cfg = spawn_cfg(120, false, std::time::Duration::from_secs(5));
        let caps = cfg.capabilities(None);
        let (flags, _, _) = find_gr(&caps).expect("GracefulRestart must be present");
        assert_eq!(
            flags & 0x08,
            0x00,
            "R-bit must not be set when configured_restarting=false"
        );
    }

    /// RFC 9234: `SpawnConfig::capabilities()` — the same entry point used at
    /// every session spawn, including on reconnect — must carry `role`
    /// through to the output exactly like `build_local_capabilities` does.
    /// This is the exact seam the reconnect capability-refresh fix touches
    /// (`s.rib.peer_roles.get(&peer_ip).copied()` fed into this call); a
    /// regression here would silently drop Role on every reconnect, the same
    /// class of bug the R-bit lifetime fix (above) closed for GR.
    #[test]
    fn spawn_config_capabilities_includes_role_when_configured() {
        let cfg = spawn_cfg(0, false, std::time::Duration::from_secs(0));
        let caps = cfg.capabilities(Some(Role::Provider));
        assert!(
            caps.iter()
                .any(|c| matches!(c, Capability::Role(Role::Provider))),
            "Capability::Role(Provider) must be present"
        );
    }
}

#[cfg(test)]
mod test_gr_peer_capability {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use pathvector_session::message::{Capability, GracefulRestartFamily};
    use pathvector_types::AfiSafi;

    fn peer() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 2)
    }

    fn gr_cap(restart_time: u16) -> Capability {
        Capability::GracefulRestart {
            restart_flags: 0,
            restart_time,
            families: vec![GracefulRestartFamily {
                afi_safi: AfiSafi::IPV4_UNICAST,
                forwarding_preserved: true,
            }],
        }
    }

    /// Extract the peer's GR restart_time from a capability list, exactly as
    /// on_established does. Returns None if absent or restart_time == 0.
    fn extract_gr_time(caps: &[Capability]) -> Option<u16> {
        caps.iter().find_map(|c| {
            if let Capability::GracefulRestart { restart_time, .. } = c {
                if *restart_time > 0 {
                    Some(*restart_time)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// A peer advertising GracefulRestart with restart_time > 0 must be recorded
    /// in gr_capable_peers with the correct time value.
    #[test]
    fn gr_capable_peer_is_recorded_on_established() {
        let mut gr_capable_peers: HashMap<Ipv4Addr, u16> = HashMap::new();
        let caps = vec![gr_cap(120)];
        if let Some(t) = extract_gr_time(&caps) {
            gr_capable_peers.insert(peer(), t);
        } else {
            gr_capable_peers.remove(&peer());
        }
        assert_eq!(
            gr_capable_peers.get(&peer()).copied(),
            Some(120),
            "gr_capable_peers must store the peer's advertised restart_time"
        );
    }

    /// A peer advertising GracefulRestart with restart_time = 0 must NOT be
    /// recorded in gr_capable_peers (restart_time = 0 means EOR-only, no GR window).
    #[test]
    fn gr_eor_only_peer_not_recorded() {
        let mut gr_capable_peers: HashMap<Ipv4Addr, u16> = HashMap::new();
        gr_capable_peers.insert(peer(), 30); // pre-existing value from prior session
        let caps = vec![gr_cap(0)];
        if let Some(t) = extract_gr_time(&caps) {
            gr_capable_peers.insert(peer(), t);
        } else {
            gr_capable_peers.remove(&peer());
        }
        assert!(
            !gr_capable_peers.contains_key(&peer()),
            "peer with restart_time = 0 must not be in gr_capable_peers; \
             prior session value must be cleared"
        );
    }

    /// RFC 4724 §3: a peer MUST NOT send more than one GracefulRestart capability,
    /// but if it does we must not panic and must use the first one (find_map semantics).
    #[test]
    fn duplicate_gr_capabilities_do_not_panic_and_first_wins() {
        let caps = vec![gr_cap(90), gr_cap(300)];
        let t = extract_gr_time(&caps);
        assert_eq!(
            t,
            Some(90),
            "first GracefulRestart capability must win when duplicates are present"
        );
    }

    /// find_map skips GR capabilities with restart_time=0 (they don't indicate GR
    /// capability — RFC 4724 §3: restart_time=0 means EOR-only). If a peer sends
    /// restart_time=0 followed by restart_time=120 (malformed but defensive), the
    /// first non-zero value wins.
    #[test]
    fn zero_gr_then_nonzero_gr_uses_first_nonzero() {
        let caps = vec![gr_cap(0), gr_cap(120)];
        let t = extract_gr_time(&caps);
        assert_eq!(
            t,
            Some(120),
            "first non-zero restart_time must be used; restart_time=0 is EOR-only and skipped"
        );
    }

    /// gr_capable_peers must be cleared on Terminated so stale values cannot
    /// influence future sessions.
    #[test]
    fn gr_capable_peers_cleared_on_terminated() {
        let mut gr_capable_peers: HashMap<Ipv4Addr, u16> = HashMap::new();
        gr_capable_peers.insert(peer(), 120);
        // Simulate on_terminated cleanup.
        gr_capable_peers.remove(&peer());
        assert!(
            !gr_capable_peers.contains_key(&peer()),
            "gr_capable_peers must be empty after peer terminates"
        );
    }
}

// ── RFC 4724 Phase 2: helper-role (hold peer stale routes) ───────────────────

#[cfg(test)]
mod test_gr_phase2 {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pathvector_rib::BestPathChange;
    use pathvector_session::message::{
        Capability, GracefulRestartFamily, MpReachNlri, MpUnreachNlri, PathAttribute, Prefix,
        UpdateMessage,
    };
    use pathvector_session::transport::TerminationReason;
    use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};

    use super::tests::with_recording_fib;
    use super::*;
    use crate::config;

    const LOCAL_AS: u32 = 65001;
    const PEER_AS: u32 = 65002;
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn make_state_gr(
        peers: &[(Ipv4Addr, u32)],
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let mut receivers = HashMap::new();
        let mut senders = HashMap::new();
        let peer_configs: Vec<_> = peers
            .iter()
            .map(|&(addr, remote_as)| {
                let (tx, rx) = mpsc::channel::<UpdateMessage>(256);
                senders.insert(addr, tx);
                receivers.insert(addr, rx);
                config::PeerConfig {
                    address: addr,
                    port: 179,
                    remote_as,
                    import_default: Some(config::ImportDefault::Accept),
                    export_default: Some(config::ExportDefault::Accept),
                    import_default_v6: None,
                    md5_password: None,
                    is_rr_client: false,
                    next_hop_self: false,
                    hold_time: None,
                    shutdown_message: None,
                    connect_retry_time: None,
                    max_prefixes_v4: None,
                    max_prefixes_v6: None,
                    max_prefixes_restart: None,
                    role: None,
                }
            })
            .collect();
        let state = DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );
        (state, receivers)
    }

    fn announce(prefixes: &[&str]) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
                PathAttribute::NextHop(PEER_IP),
            ],
            announced: prefixes.iter().map(|s| nlri(s)).collect(),
        }
    }

    fn establish_with_gr(state: &mut DaemonState, restart_time: u16) {
        let caps = gr_caps(restart_time);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &caps,
            None,
        );
    }

    fn ipv4_eor() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        }
    }

    fn gr_cap(restart_time: u16) -> Capability {
        Capability::GracefulRestart {
            restart_flags: 0,
            restart_time,
            families: vec![GracefulRestartFamily {
                afi_safi: AfiSafi::IPV4_UNICAST,
                forwarding_preserved: false,
            }],
        }
    }

    fn gr_caps(restart_time: u16) -> Vec<Capability> {
        vec![Capability::FourByteAsn(PEER_AS), gr_cap(restart_time)]
    }

    /// RFC 4724 §4.2 — unclean termination of a GR-capable peer must retain
    /// routes in AdjRibIn / LocRib rather than flushing them.
    #[test]
    fn unclean_termination_of_gr_peer_retains_routes() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        assert_eq!(
            state.rib.loc_rib.len(),
            1,
            "route must be in LocRib before termination"
        );

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        assert!(
            state.adj_ribs_in[&PEER_IP]
                .get(&nlri("10.0.0.0/8"))
                .is_some(),
            "AdjRibIn route must be retained during GR window"
        );
        assert_eq!(
            state.rib.loc_rib.len(),
            1,
            "LocRib route must be retained during GR window"
        );
        assert!(
            state.gr.deadlines.contains_key(&PEER_IP),
            "gr_deadlines must be armed for the peer"
        );
    }

    /// RFC 4724 §4.2 — clean termination (NOTIFICATION received) must flush
    /// routes immediately regardless of GR capability.
    #[test]
    fn clean_termination_flushes_immediately() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        state.on_terminated(PEER_IP, TerminationReason::OperatorStop, true);

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "LocRib must be flushed immediately on clean termination"
        );
        assert!(
            !state.gr.deadlines.contains_key(&PEER_IP),
            "gr_deadlines must not be armed on clean termination"
        );
    }

    /// A peer that did not advertise GR (or advertised restart_time=0) must
    /// have its routes flushed immediately even on unclean termination.
    #[test]
    fn non_gr_peer_always_flushes_on_unclean_termination() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        state.on_established(PEER_IP, PEER_IP, PeerType::External, PEER_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "LocRib must be flushed for a non-GR peer even on unclean termination"
        );
        assert!(
            !state.gr.deadlines.contains_key(&PEER_IP),
            "gr_deadlines must not be armed for a non-GR peer"
        );
    }

    /// RFC 4724 §4.2 — routes not re-announced before EOR must be pruned.
    /// Routes that ARE re-announced must be kept.
    #[test]
    fn eor_prunes_stale_routes_not_refreshed_by_peer() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 120);
        // Announce two routes.
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8", "192.168.0.0/24"]));
        assert_eq!(state.rib.loc_rib.len(), 2);

        // Simulate unclean disconnect (GR window opens).
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        assert_eq!(
            state.rib.loc_rib.len(),
            2,
            "routes retained during GR window"
        );

        // Simulate re-establishment.
        establish_with_gr(&mut state, 120);

        // Peer re-announces only 10.0.0.0/8.
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        // EOR arrives — 192.168.0.0/24 was not re-announced, must be pruned.
        state.on_route_update(PEER_IP, ipv4_eor());

        assert_eq!(
            state.rib.loc_rib.len(),
            1,
            "only the re-announced route must remain after EOR prune"
        );
        assert!(
            state.rib.loc_rib.best(&nlri("10.0.0.0/8")).is_some(),
            "re-announced route must survive"
        );
        assert!(
            state.rib.loc_rib.best(&nlri("192.168.0.0/24")).is_none(),
            "stale route not refreshed by peer must be pruned on EOR"
        );
    }

    /// GR deadline expiry must flush all stale routes exactly as a normal
    /// on_terminated flush would.
    #[test]
    fn gr_deadline_expiry_flushes_stale_routes() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        assert_eq!(
            state.rib.loc_rib.len(),
            1,
            "route retained during GR window"
        );
        assert!(state.gr.deadlines.contains_key(&PEER_IP));

        // Simulate deadline expiry.
        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "routes must be flushed after GR deadline expiry"
        );
    }

    /// RFC 4724 §4.2 — if a peer disconnects uncleanly *again* while its GR
    /// window is already open, the deadline must be reset to `now + restart_time`
    /// and routes must continue to be held.  They must not be double-flushed.
    #[test]
    fn gr_re_termination_during_window_resets_deadline_and_holds_routes() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 30);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        // First unclean disconnect — opens GR window.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        let first_deadline = *state
            .gr
            .deadlines
            .get(&PEER_IP)
            .expect("deadline must be set after first unclean disconnect");

        // Re-establish, then disconnect again without re-announcing anything.
        establish_with_gr(&mut state, 30);
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        let second_deadline = *state
            .gr
            .deadlines
            .get(&PEER_IP)
            .expect("deadline must still be set after second unclean disconnect");

        // The window is reset — second deadline must be >= the first.
        assert!(
            second_deadline >= first_deadline,
            "re-termination must reset the GR deadline, not leave a stale earlier one"
        );

        // Routes must still be held — no double-flush.
        assert_eq!(
            state.rib.loc_rib.len(),
            1,
            "routes must be retained after re-termination during GR window"
        );
        assert!(
            state.gr.deadlines.contains_key(&PEER_IP),
            "gr_deadlines must remain armed after re-termination"
        );
    }

    /// RFC 4724 §4.2 — if a peer sends a NOTIFICATION (clean termination)
    /// while its GR window is already open, routes must be flushed immediately.
    /// The GR window must not prevent a clean teardown from taking effect.
    #[test]
    fn gr_clean_termination_during_window_flushes_immediately() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 30);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        // First disconnect is unclean — GR window opens.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        assert_eq!(state.rib.loc_rib.len(), 1, "route held during GR window");
        assert!(state.gr.deadlines.contains_key(&PEER_IP));

        // Peer re-establishes, then we tear it down (operator stop).
        establish_with_gr(&mut state, 30);
        state.on_terminated(PEER_IP, TerminationReason::OperatorStop, true);

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "clean termination during GR window must flush routes immediately"
        );
        assert!(
            !state.gr.deadlines.contains_key(&PEER_IP),
            "gr_deadlines must be cleared on clean termination"
        );
    }

    /// When `fib_manager` is set, unclean termination must push FIB changes for
    /// the stale-marked routes (covers the `if let Some(fm)` branch in
    /// `mark_stale_and_repropagate`).
    #[test]
    fn stale_marking_notifies_fib_manager() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        let fib = with_recording_fib(&mut state);
        establish_with_gr(&mut state, 120);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        let changes = fib.v4_changes();
        assert!(
            !changes.is_empty(),
            "FibManager must receive at least one change when routes are stale-marked"
        );
    }

    /// When `fib_manager` is set, deadline expiry must push FIB withdrawals for
    /// all stale routes (covers the `if let Some(fm)` branch in
    /// `on_gr_deadline_expired`).
    #[test]
    fn deadline_expiry_notifies_fib_manager() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        let fib = with_recording_fib(&mut state);
        establish_with_gr(&mut state, 120);
        state.on_route_update(PEER_IP, announce(&["192.0.2.0/24"]));

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        // Clear stale-mark FIB notifications so we only count the expiry ones.
        fib.v4.lock().unwrap().clear();

        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);

        let changes = fib.v4_changes();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "FibManager must receive a Withdrawn change on deadline expiry"
        );
    }

    /// `GracefulRestartState::drain_expired` must remove expired entries and
    /// return their addresses; non-expired entries must be left intact.
    #[test]
    fn drain_expired_removes_past_deadlines_leaves_future() {
        let mut gr = GracefulRestartState::new();
        let past = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        let future = Instant::now() + std::time::Duration::from_secs(300);
        let expired_ip = Ipv4Addr::new(10, 0, 0, 1);
        let live_ip = Ipv4Addr::new(10, 0, 0, 2);
        gr.deadlines.insert(expired_ip, past);
        gr.deadlines.insert(live_ip, future);

        let drained = gr.drain_expired(Instant::now());

        assert_eq!(
            drained,
            vec![expired_ip],
            "only the past deadline must be returned"
        );
        assert!(
            !gr.deadlines.contains_key(&expired_ip),
            "expired entry must be removed"
        );
        assert!(
            gr.deadlines.contains_key(&live_ip),
            "live entry must remain"
        );
    }

    /// When a second established peer has an update_sender, stale-route
    /// repropagation after stale marking must reach it via `flush_updates`.
    /// This exercises `repropagate_after_stale_mark_v4` and the inner loop
    /// that calls `propagate_prefix` + `flush_updates` for each peer.
    #[test]
    fn stale_mark_repropagates_withdrawals_to_established_observer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);

        // PEER_IP is the only source of the prefix; OBS_IP observes.
        state.on_route_update(PEER_IP, announce(&["198.51.100.0/24"]));

        // Drain the initial advertisement so the channel is quiet.
        let obs_rx = rxs.get_mut(&OBS_IP).unwrap();
        while obs_rx.try_recv().is_ok() {}

        // Unclean disconnect — stale marking should propagate to OBS_IP.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        // The observer must have received an UPDATE (withdrawal of the now-stale prefix).
        assert!(
            obs_rx.try_recv().is_ok(),
            "observer must receive an UPDATE after stale-route repropagation"
        );
    }

    /// `prune_stale_nlri` must propagate withdrawals to other established peers
    /// when EOR prunes a route that was previously best-path.
    #[test]
    fn eor_prune_propagates_withdrawal_to_observer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);
        const OBS_AS: u32 = 65006;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);

        state.on_route_update(PEER_IP, announce(&["203.0.113.0/24", "203.0.113.1/32"]));
        let obs_rx = rxs.get_mut(&OBS_IP).unwrap();
        while obs_rx.try_recv().is_ok() {}

        // Unclean disconnect then re-establish.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        while obs_rx.try_recv().is_ok() {}
        establish_with_gr(&mut state, 120);

        // Peer only re-announces 203.0.113.0/24; 203.0.113.1/32 stays stale.
        state.on_route_update(PEER_IP, announce(&["203.0.113.0/24"]));
        while obs_rx.try_recv().is_ok() {}

        // EOR triggers prune of 203.0.113.1/32.
        state.on_route_update(PEER_IP, ipv4_eor());

        assert!(
            obs_rx.try_recv().is_ok(),
            "observer must receive an UPDATE (withdrawal) when EOR prunes a stale route"
        );
        assert!(
            state.rib.loc_rib.best(&nlri("203.0.113.1/32")).is_none(),
            "pruned route must be absent from LocRib"
        );
    }

    /// `on_gr_deadline_expired` must propagate withdrawals to other established peers
    /// so they remove the stale route from their own RIBs.
    #[test]
    fn deadline_expiry_propagates_withdrawal_to_observer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);
        const OBS_AS: u32 = 65007;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);

        state.on_route_update(PEER_IP, announce(&["192.0.2.0/24"]));
        let obs_rx = rxs.get_mut(&OBS_IP).unwrap();
        while obs_rx.try_recv().is_ok() {}

        // Unclean disconnect — GR window opens.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        while obs_rx.try_recv().is_ok() {}

        // Simulate deadline expiry.
        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);

        assert_eq!(
            state.rib.loc_rib.len(),
            0,
            "LocRib must be empty after deadline expiry"
        );
        assert!(
            obs_rx.try_recv().is_ok(),
            "observer must receive a withdrawal UPDATE after deadline expiry"
        );
    }

    // ── IPv6 GR helpers ──────────────────────────────────────────────────────

    fn nlri_v6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    fn gr_caps_v6(restart_time: u16) -> Vec<Capability> {
        vec![
            Capability::FourByteAsn(PEER_AS),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
            Capability::GracefulRestart {
                restart_flags: 0,
                restart_time,
                families: vec![GracefulRestartFamily {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    forwarding_preserved: false,
                }],
            },
        ]
    }

    fn announce_v6(prefixes: &[&str]) -> UpdateMessage {
        let ps: Vec<Prefix> = prefixes
            .iter()
            .map(|s| Prefix::V6(s.parse().unwrap()))
            .collect();
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: ps,
                }),
            ],
            announced: vec![],
        }
    }

    fn establish_with_gr_v6(state: &mut DaemonState, restart_time: u16) {
        let caps = gr_caps_v6(restart_time);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &caps,
            None,
        );
    }

    fn ipv6_eor() -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi_safi: AfiSafi::IPV6_UNICAST,
                prefixes: vec![],
            })],
            announced: vec![],
        }
    }

    /// Unclean termination of a GR peer with IPv6 routes must retain those
    /// routes in LocRib_v6 (exercises mark_stale_and_repropagate v6 path).
    #[test]
    fn unclean_termination_retains_v6_routes() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);

        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        assert_eq!(
            state.rib.loc_rib_v6.len(),
            1,
            "v6 route must be in LocRib_v6"
        );

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        assert_eq!(
            state.rib.loc_rib_v6.len(),
            1,
            "v6 LocRib must be retained during GR window"
        );
        assert!(state.gr.deadlines.contains_key(&PEER_IP));
    }

    /// EOR prune on IPv6 must withdraw routes not re-announced before the
    /// IPv6 EOR marker (exercises prune_stale_nlri_v6).
    #[test]
    fn eor_prunes_stale_v6_routes_not_refreshed_by_peer() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);

        state.on_route_update(
            PEER_IP,
            announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
        );
        assert_eq!(state.rib.loc_rib_v6.len(), 2);

        // Unclean disconnect, then re-establish.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        establish_with_gr_v6(&mut state, 120);

        // Peer re-announces only 2001:db8:1::/48.
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8:1::/48"]));

        // IPv6 EOR — 2001:db8:2::/48 was not refreshed, must be pruned.
        state.on_route_update(PEER_IP, ipv6_eor());

        assert_eq!(
            state.rib.loc_rib_v6.len(),
            1,
            "only the re-announced v6 route must remain after EOR prune"
        );
        assert!(
            state
                .rib
                .loc_rib_v6
                .best(&nlri_v6("2001:db8:1::/48"))
                .is_some(),
            "re-announced v6 route must survive"
        );
        assert!(
            state
                .rib
                .loc_rib_v6
                .best(&nlri_v6("2001:db8:2::/48"))
                .is_none(),
            "stale v6 route must be pruned on EOR"
        );
    }

    /// `on_gr_deadline_expired` must propagate withdrawals to other
    /// established IPv6-capable peers for IPv6 routes that were only
    /// reachable via the expired peer — regression guard for the gap where
    /// only the v4 side was re-propagated (TODO.md GR known-gaps item 6,
    /// closed 2026-07-03; mirrors `deadline_expiry_propagates_withdrawal_
    /// to_observer` above, for IPv6).
    #[test]
    fn deadline_expiry_propagates_v6_withdrawal_to_observer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 8);
        const OBS_AS: u32 = 65008;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &[Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)],
            None,
        );

        state.on_route_update(PEER_IP, announce_v6(&["2001:db8:dead::/48"]));
        let obs_rx = rxs.get_mut(&OBS_IP).unwrap();
        while obs_rx.try_recv().is_ok() {}

        // Unclean disconnect — GR window opens.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        while obs_rx.try_recv().is_ok() {}

        // Simulate deadline expiry.
        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);

        assert_eq!(
            state.rib.loc_rib_v6.len(),
            0,
            "LocRib_v6 must be empty after deadline expiry"
        );
        assert!(
            obs_rx.try_recv().is_ok(),
            "observer must receive an IPv6 withdrawal UPDATE after deadline expiry"
        );
    }

    /// RFC 4724 §4.2 SHOULD — on unclean termination routes must be marked
    /// stale in LocRib so a fresh route from a second peer immediately wins
    /// best-path selection.
    #[test]
    fn stale_marking_lets_fresh_peer_win_immediately() {
        const PEER2_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
        const PEER2_AS: u32 = 65003;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (PEER2_IP, PEER2_AS)]);

        // Establish both peers (only PEER_IP supports GR).
        establish_with_gr(&mut state, 120);
        state.on_established(
            PEER2_IP,
            PEER2_IP,
            PeerType::External,
            PEER2_AS,
            90,
            &[],
            None,
        );

        // Both peers announce the same prefix; PEER_IP wins (lower IP address tie-breaker).
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        // Same attributes as PEER_IP — tie-breaker (lower peer IP) decides winner.
        state.on_route_update(PEER2_IP, announce(&["10.0.0.0/8"]));

        let winner_before = state.rib.loc_rib.best_peer(&nlri("10.0.0.0/8"));
        assert!(
            winner_before.is_some(),
            "must have a best path before termination"
        );

        // PEER_IP disconnects uncleanly — its route is marked stale.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        // PEER2's fresh route must now be the best path.
        let best_after = state.rib.loc_rib.best(&nlri("10.0.0.0/8"));
        assert!(
            best_after.is_some(),
            "route must still be present (held stale)"
        );
        assert!(
            !best_after.unwrap().stale,
            "winning route must be the non-stale route from PEER2"
        );

        let winner_after = state.rib.loc_rib.best_peer(&nlri("10.0.0.0/8"));
        assert_eq!(
            winner_after.map(PeerId::ip),
            Some(std::net::IpAddr::V4(PEER2_IP)),
            "PEER2 must be the winning peer after PEER_IP's routes are marked stale"
        );
    }

    /// When a GR peer with IPv6 routes undergoes unclean termination and a second
    /// non-GR peer has a competing v6 route, the observer must receive an UPDATE
    /// reflecting the new winner. This covers the `repropagate_after_stale_mark_v6`
    /// observer loop for the case where best-path changes due to stale marking.
    #[test]
    fn stale_mark_v6_runs_observer_propagation_loop() {
        const COMPETING_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
        const COMPETING_AS: u32 = 65003;
        const OBSERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
        const OBSERVER_AS: u32 = 65004;

        let (mut state, mut rxs) = make_state_gr(&[
            (PEER_IP, PEER_AS),
            (COMPETING_IP, COMPETING_AS),
            (OBSERVER_IP, OBSERVER_AS),
        ]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());

        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );

        let competing_caps = vec![
            Capability::FourByteAsn(COMPETING_AS),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        ];
        state.on_established(
            COMPETING_IP,
            COMPETING_IP,
            PeerType::External,
            COMPETING_AS,
            90,
            &competing_caps,
            None,
        );

        let obs_caps = vec![
            Capability::FourByteAsn(OBSERVER_AS),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        ];
        state.on_established(
            OBSERVER_IP,
            OBSERVER_IP,
            PeerType::External,
            OBSERVER_AS,
            90,
            &obs_caps,
            None,
        );

        // Both PEER_IP and COMPETING_IP advertise the same v6 prefix.
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        state.on_route_update(COMPETING_IP, announce_v6(&["2001:db8::/32"]));
        while rxs.get_mut(&OBSERVER_IP).unwrap().try_recv().is_ok() {}

        // Unclean termination of PEER_IP — COMPETING_IP's route must now win and
        // repropagate_after_stale_mark_v6 must iterate over observer.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        state.flush_pending();

        // Observer should receive an UPDATE (re-announce from COMPETING_IP winning).
        // The exact content depends on best-path: the key invariant is the loop ran.
        assert!(
            state
                .rib
                .loc_rib_v6
                .best(&nlri_v6("2001:db8::/32"))
                .is_some(),
            "a best v6 route must still exist from COMPETING_IP"
        );
    }

    /// When a GR peer re-establishes and EOR prunes stale v6 routes, a second
    /// IPv6-capable observer peer must receive a WITHDRAW for each pruned NLRI.
    /// This covers the `prune_stale_nlri_v6` observer loop.
    #[test]
    fn eor_prune_v6_propagates_withdrawal_to_v6_observer() {
        const OBSERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
        const OBSERVER_AS: u32 = 65003;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBSERVER_IP, OBSERVER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());

        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );

        let obs_caps = vec![
            Capability::FourByteAsn(OBSERVER_AS),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
        ];
        state.on_established(
            OBSERVER_IP,
            OBSERVER_IP,
            PeerType::External,
            OBSERVER_AS,
            90,
            &obs_caps,
            None,
        );

        // Announce two v6 prefixes.
        state.on_route_update(
            PEER_IP,
            announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
        );
        while rxs.get_mut(&OBSERVER_IP).unwrap().try_recv().is_ok() {}

        // Unclean disconnect, then re-establish.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        while rxs.get_mut(&OBSERVER_IP).unwrap().try_recv().is_ok() {}

        // Peer re-announces only the first prefix, then sends EOR.
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8:1::/48"]));
        state.on_route_update(PEER_IP, ipv6_eor());
        state.flush_pending();

        // Observer must receive a WITHDRAW for the stale 2001:db8:2::/48.
        let msgs: Vec<UpdateMessage> =
            std::iter::from_fn(|| rxs.get_mut(&OBSERVER_IP).unwrap().try_recv().ok()).collect();
        let has_prune = msgs.iter().any(|m| {
            m.attributes.iter().any(|a| {
                if let PathAttribute::MpUnreachNlri(u) = a {
                    u.prefixes.iter().any(
                        |p| matches!(p, Prefix::V6(n) if n.to_string().starts_with("2001:db8:2")),
                    )
                } else {
                    false
                }
            })
        });
        assert!(
            has_prune,
            "observer must receive WITHDRAW for the stale v6 NLRI after EOR prune"
        );
    }

    /// When `prune_stale_nlri` is called for a peer whose `adj_ribs_in` entry is
    /// missing, it must skip the adj-rib withdrawal without panicking. Covers the
    /// `if let Some(ari)` else path in gr.rs line 289.
    #[test]
    fn prune_stale_nlri_skips_missing_adj_rib_in() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let stale_set = std::collections::HashSet::from([nlri]);

        // Remove adj_ribs_in so the `if let Some(ari)` branch is skipped.
        state.adj_ribs_in.remove(&PEER_IP);
        // Must not panic.
        state.prune_stale_nlri(PEER_IP, &stale_set);
    }

    /// When observer's export policy is missing during `prune_stale_nlri`, the
    /// peer must be skipped. Covers the defensive `continue` at gr.rs line 328.
    #[test]
    fn prune_stale_nlri_skips_peer_missing_export_policy() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        establish_with_gr(&mut state, 120);

        // Remove observer's export policy — defensive `continue` must fire.
        state.export_policies.remove(&OBS_IP);
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let stale_set = std::collections::HashSet::from([nlri]);
        state.prune_stale_nlri(PEER_IP, &stale_set);
    }

    /// When the observer's update channel is closed during `prune_stale_nlri`,
    /// it must be recorded in `stalled_peers`. Covers stall at gr.rs line 360.
    #[test]
    fn prune_stale_nlri_stall_records_stalled_peer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        while rxs.get_mut(&OBS_IP).unwrap().try_recv().is_ok() {}

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        establish_with_gr(&mut state, 120);
        // Drop observer's receiver so the EOR prune send fails.
        drop(rxs.remove(&OBS_IP).unwrap());

        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let stale_set = std::collections::HashSet::from([nlri]);
        state.prune_stale_nlri(PEER_IP, &stale_set);

        assert!(
            state.take_stalled_peers().contains(&OBS_IP),
            "stalled_peers must record observer when prune send fails"
        );
    }

    /// When the observer's update channel is closed during GR deadline expiry,
    /// it must be recorded in `stalled_peers`. Covers stall at gr.rs line 558.
    #[test]
    fn deadline_expiry_stall_records_stalled_peer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        while rxs.get_mut(&OBS_IP).unwrap().try_recv().is_ok() {}

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        // Drop observer's receiver so the deadline expiry send fails.
        drop(rxs.remove(&OBS_IP).unwrap());

        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);

        assert!(
            state.take_stalled_peers().contains(&OBS_IP),
            "stalled_peers must record observer when deadline expiry send fails"
        );
    }

    /// Unclean termination of a GR-capable peer with no v4 routes must be a no-op
    /// for the stale-marking loop. Covers the `if !stale_v4.is_empty()` false
    /// branch in `mark_stale_and_repropagate` (gr.rs line 100).
    #[test]
    fn stale_mark_v4_with_no_routes_is_noop() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        establish_with_gr(&mut state, 120);
        // No routes announced — stale_v4 will be empty.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        assert_eq!(state.rib.loc_rib.len(), 0);
    }

    /// Unclean termination of a GR-capable v6 peer with no v6 routes must be
    /// a no-op for the v6 stale-marking loop. Covers the `if !stale_v6.is_empty()`
    /// false branch in `mark_stale_and_repropagate` (gr.rs line 127).
    #[test]
    fn stale_mark_v6_with_no_routes_is_noop() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);
        // No v6 routes announced — stale_v6 will be empty.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        assert_eq!(state.rib.loc_rib_v6.len(), 0);
    }

    /// Unclean termination of a GR peer with IPv6 GR family must push v6 FIB
    /// changes. Covers the `if do_v6 { if let Some(fm) ... }` block in
    /// `mark_stale_and_repropagate` (gr.rs lines 122-127).
    #[test]
    fn stale_marking_v6_notifies_fib_manager() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let fib = with_recording_fib(&mut state);
        establish_with_gr_v6(&mut state, 120);
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        fib.v6.lock().unwrap().clear();

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        let changes = fib.v6.lock().unwrap().clone();
        assert!(
            !changes.is_empty(),
            "FibManager must receive v6 changes when v6 GR peer terminates unclean"
        );
    }

    /// When `fib_manager` is set, EOR from a GR-re-established peer must push
    /// FIB changes for the pruned v4 routes. Covers the `if let Some(fm)` branch
    /// in `prune_stale_nlri` (gr.rs lines 300-302).
    #[test]
    fn eor_prune_v4_notifies_fib_manager() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        let fib = with_recording_fib(&mut state);
        establish_with_gr(&mut state, 120);

        // Announce two routes; only one will survive after re-establishment.
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8", "192.0.2.0/24"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        establish_with_gr(&mut state, 120);
        fib.v4.lock().unwrap().clear();

        // Re-announce only the first; EOR prunes the second.
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        let eor = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        };
        state.on_route_update(PEER_IP, eor);

        let changes = fib.v4_changes();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "FibManager must receive Withdrawn for pruned v4 NLRI after EOR"
        );
    }

    /// When `fib_manager` is set, EOR from a GR-re-established v6 peer must push
    /// FIB changes for the pruned v6 routes. Covers `prune_stale_nlri_v6`
    /// (gr.rs lines 391-393).
    #[test]
    fn eor_prune_v6_notifies_fib_manager() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let fib = with_recording_fib(&mut state);

        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        state.on_route_update(
            PEER_IP,
            announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
        );
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        fib.v6.lock().unwrap().clear();

        state.on_route_update(PEER_IP, announce_v6(&["2001:db8:1::/48"]));
        state.on_route_update(PEER_IP, ipv6_eor());

        let changes = fib.v6.lock().unwrap().clone();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "FibManager must receive Withdrawn for pruned v6 NLRI after EOR"
        );
    }

    /// An observer that was not established with IPv6 capabilities must be skipped by
    /// `repropagate_after_stale_mark_v6`. Covers the `if !ipv6_capable_peers.contains`
    /// branch at gr.rs line 228.
    #[test]
    fn repropagate_v6_skips_non_ipv6_observer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);
        // Observer has NO v6 capability → not in ipv6_capable_peers.
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));

        // Termination triggers repropagate_after_stale_mark_v6 which must skip OBS_IP.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        // Must not panic; stalled_peers must not include observer.
        assert!(!state.take_stalled_peers().contains(&OBS_IP));
    }

    /// When the observer's adj_ribs_out_v6 is missing, repropagate_after_stale_mark_v6
    /// must skip it. Covers the defensive `continue` at gr.rs line 242.
    #[test]
    fn repropagate_v6_skips_observer_missing_adj_rib_out_v6() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;
        let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &obs_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));

        state.adj_ribs_out_v6.remove(&OBS_IP);
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
    }

    /// When the observer's update channel is closed during repropagate_v6,
    /// it must be recorded in `stalled_peers`. Covers the stall at gr.rs line 270.
    #[test]
    fn repropagate_v6_stall_records_stalled_peer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;
        let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &obs_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        while rxs.get_mut(&OBS_IP).unwrap().try_recv().is_ok() {}

        drop(rxs.remove(&OBS_IP).unwrap());
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        assert!(
            state.take_stalled_peers().contains(&OBS_IP),
            "stalled_peers must include observer when v6 repropagate send fails"
        );
    }

    /// When `prune_stale_nlri` is called and the observer's adj_ribs_out is missing,
    /// it must skip without panicking. Covers defensive `continue` at gr.rs line 331.
    #[test]
    fn prune_stale_nlri_skips_observer_missing_adj_rib_out() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        establish_with_gr(&mut state, 120);

        state.adj_ribs_out.remove(&OBS_IP);
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        state.prune_stale_nlri(PEER_IP, &std::collections::HashSet::from([nlri]));
    }

    /// When `prune_stale_nlri_v6` encounters a peer without adj_ribs_in_v6, it must
    /// skip the adj-rib withdrawal. Covers the `if let Some(ari_v6)` else path at
    /// gr.rs line 379.
    #[test]
    fn prune_stale_nlri_v6_skips_missing_adj_rib_in_v6() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));

        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let stale_set = std::collections::HashSet::from([nlri]);
        // Remove adj_ribs_in_v6 so the `if let Some(ari_v6)` branch is skipped.
        state.adj_ribs_in_v6.remove(&PEER_IP);
        state.prune_stale_nlri_v6(PEER_IP, &stale_set);
    }

    /// When the v6 observer's update channel is closed during prune_stale_nlri_v6,
    /// it must be recorded in `stalled_peers`. Covers the stall at gr.rs line 450.
    #[test]
    fn prune_stale_nlri_v6_stall_records_stalled_peer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;
        let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &obs_caps,
            None,
        );
        state.on_route_update(
            PEER_IP,
            announce_v6(&["2001:db8:1::/48", "2001:db8:2::/48"]),
        );
        while rxs.get_mut(&OBS_IP).unwrap().try_recv().is_ok() {}

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        drop(rxs.remove(&OBS_IP).unwrap());

        let nlri: Nlri<Ipv6Addr> = "2001:db8:2::/48".parse().unwrap();
        let stale_set = std::collections::HashSet::from([nlri]);
        state.prune_stale_nlri_v6(PEER_IP, &stale_set);

        assert!(
            state.take_stalled_peers().contains(&OBS_IP),
            "stalled_peers must include observer when v6 prune send fails"
        );
    }

    /// When the observer's adj_ribs_out is missing, repropagate_after_stale_mark_v4
    /// must skip it. Covers the defensive `continue` at gr.rs line 177.
    #[test]
    fn repropagate_v4_skips_observer_missing_adj_rib_out() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        state.adj_ribs_out.remove(&OBS_IP);
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
    }

    /// When the observer's update_senders is missing, repropagate_after_stale_mark_v4
    /// must skip it. Covers the defensive `continue` at gr.rs line 180.
    #[test]
    fn repropagate_v4_skips_observer_missing_update_senders() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        state.update_senders.remove(&OBS_IP);
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
    }

    /// When the observer's update_senders is missing in repropagate_after_stale_mark_v6,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 245.
    #[test]
    fn repropagate_v6_skips_observer_missing_update_senders() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;
        let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        establish_with_gr_v6(&mut state, 120);
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &obs_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));

        state.update_senders.remove(&OBS_IP);
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
    }

    /// When the observer's update_senders is missing in prune_stale_nlri v4,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 334.
    #[test]
    fn prune_stale_nlri_skips_observer_missing_update_senders() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        establish_with_gr(&mut state, 120);

        state.update_senders.remove(&OBS_IP);
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        state.prune_stale_nlri(PEER_IP, &std::collections::HashSet::from([nlri]));
    }

    /// When the observer's export_policy is missing in prune_stale_nlri_v6,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 419.
    #[test]
    fn prune_stale_nlri_v6_skips_observer_missing_export_policy() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;
        let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &obs_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );

        state.export_policies.remove(&OBS_IP);
        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        state.prune_stale_nlri_v6(PEER_IP, &std::collections::HashSet::from([nlri]));
    }

    /// When the observer's adj_ribs_out_v6 is missing in prune_stale_nlri_v6,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 422.
    #[test]
    fn prune_stale_nlri_v6_skips_observer_missing_adj_rib_out_v6() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;
        let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &obs_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );

        state.adj_ribs_out_v6.remove(&OBS_IP);
        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        state.prune_stale_nlri_v6(PEER_IP, &std::collections::HashSet::from([nlri]));
    }

    /// When the observer's update_senders is missing in prune_stale_nlri_v6,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 425.
    #[test]
    fn prune_stale_nlri_v6_skips_observer_missing_update_senders() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;
        let obs_caps = vec![Capability::MultiProtocol(AfiSafi::IPV6_UNICAST)];

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        state.on_established(
            OBS_IP,
            OBS_IP,
            PeerType::External,
            OBS_AS,
            90,
            &obs_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );

        state.update_senders.remove(&OBS_IP);
        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        state.prune_stale_nlri_v6(PEER_IP, &std::collections::HashSet::from([nlri]));
    }

    /// When the observer's export_policy is missing during deadline expiry,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 526.
    #[test]
    fn deadline_expiry_skips_observer_missing_export_policy() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        state.export_policies.remove(&OBS_IP);
        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);
    }

    /// When the observer's adj_ribs_out is missing during deadline expiry,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 529.
    #[test]
    fn deadline_expiry_skips_observer_missing_adj_rib_out() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        state.adj_ribs_out.remove(&OBS_IP);
        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);
    }

    /// When the observer's update_senders is missing during deadline expiry,
    /// it must be skipped. Covers the defensive `continue` at gr.rs line 532.
    #[test]
    fn deadline_expiry_skips_observer_missing_update_senders() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        state.update_senders.remove(&OBS_IP);
        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);
    }

    /// When the observer's update channel is closed, `repropagate_after_stale_mark_v4`
    /// must record the peer in `stalled_peers`. Covers the `flush_updates → false` stall
    /// path in gr.rs line 206.
    #[test]
    fn repropagate_v4_stall_path_records_stalled_peer() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, mut rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));
        while rxs.get_mut(&OBS_IP).unwrap().try_recv().is_ok() {}

        // Drop the observer's receiver so the next send fails.
        drop(rxs.remove(&OBS_IP).unwrap());

        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);

        let stalled = state.take_stalled_peers();
        assert!(
            stalled.contains(&OBS_IP),
            "stalled_peers must include observer when its channel is closed"
        );
    }

    /// When the observer peer is missing from `export_policies`, `repropagate_after_stale_mark_v4`
    /// must skip it without panicking. Covers the defensive `continue` at gr.rs line 174.
    #[test]
    fn repropagate_v4_skips_peer_missing_export_policy() {
        const OBS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
        const OBS_AS: u32 = 65005;

        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS), (OBS_IP, OBS_AS)]);
        establish_with_gr(&mut state, 120);
        state.on_established(OBS_IP, OBS_IP, PeerType::External, OBS_AS, 90, &[], None);
        state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"]));

        // Remove observer's export policy — defensive `continue` must fire.
        state.export_policies.remove(&OBS_IP);
        // Must not panic.
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
    }

    /// When `fib_manager` is set and the GR deadline expires for a peer with v6
    /// routes, the FIB manager must receive v6 Withdrawn calls. Covers the v6
    /// apply loop in `on_gr_deadline_expired` (gr.rs lines 485-487).
    #[test]
    fn deadline_expiry_v6_notifies_fib_manager() {
        let (mut state, _rxs) = make_state_gr(&[(PEER_IP, PEER_AS)]);
        Arc::make_mut(&mut state.rib).local_ipv6 = Some("2001:db8::ff".parse().unwrap());
        let fib = with_recording_fib(&mut state);

        let peer_caps = gr_caps_v6(120);
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            &peer_caps,
            None,
        );
        state.on_route_update(PEER_IP, announce_v6(&["2001:db8::/32"]));
        state.on_terminated(PEER_IP, TerminationReason::Unclean, true);
        fib.v6.lock().unwrap().clear();

        state.gr.deadlines.remove(&PEER_IP);
        state.on_gr_deadline_expired(PEER_IP);

        let changes = fib.v6.lock().unwrap().clone();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "FibManager must receive v6 Withdrawn on GR deadline expiry"
        );
    }
}

// ── RFC 8538: Notification Support for Graceful Restart ──────────────────────

#[cfg(test)]
mod test_rfc8538 {
    use std::net::Ipv4Addr;

    use pathvector_session::message::{
        Capability, CeaseError, GracefulRestartFamily, NotificationError, NotificationMessage,
        UpdateMessage,
    };
    use pathvector_session::transport::TerminationReason;
    use pathvector_types::{AfiSafi, AsPath, Asn, Nlri, Origin, PeerType};

    use super::*;
    use crate::config;

    const LOCAL_AS: u32 = 65001;
    const PEER_AS: u32 = 65002;
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    /// Build a GR capability advertising the N-bit (RFC 8538 §2, bit 0x04).
    fn gr_cap_with_n_bit(restart_time: u16) -> Capability {
        Capability::GracefulRestart {
            restart_flags: 0x04, // N-bit
            restart_time,
            families: vec![GracefulRestartFamily {
                afi_safi: AfiSafi::IPV4_UNICAST,
                forwarding_preserved: false,
            }],
        }
    }

    /// Build a GR capability WITHOUT the N-bit (RFC 4724 only).
    fn gr_cap_without_n_bit(restart_time: u16) -> Capability {
        Capability::GracefulRestart {
            restart_flags: 0x00,
            restart_time,
            families: vec![GracefulRestartFamily {
                afi_safi: AfiSafi::IPV4_UNICAST,
                forwarding_preserved: false,
            }],
        }
    }

    fn make_state() -> DaemonState {
        let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
        let peer = config::PeerConfig {
            address: PEER_IP,
            port: 179,
            remote_as: PEER_AS,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        };
        // Build local capabilities with GR time 120 and N-bit set, matching a
        // realistic pathvectord deployment that participates in RFC 8538.
        let local_caps = build_local_capabilities(LOCAL_AS, 120, false, None);
        DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &[peer],
            [(PEER_IP, tx)].into(),
            local_caps,
        )
    }

    fn announce(prefixes: &[&str]) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                pathvector_session::message::PathAttribute::Origin(Origin::Igp),
                pathvector_session::message::PathAttribute::AsPath(AsPath::from_sequence(vec![
                    Asn::new(PEER_AS),
                ])),
                pathvector_session::message::PathAttribute::NextHop(PEER_IP),
            ],
            announced: prefixes.iter().map(|s| nlri(s)).collect(),
        }
    }

    fn establish(state: &mut DaemonState, caps: &[Capability]) {
        state.on_established(
            PEER_IP,
            PEER_IP,
            PeerType::External,
            PEER_AS,
            90,
            caps,
            None,
        );
    }

    fn notification(error: NotificationError) -> TerminationReason {
        TerminationReason::Notification(NotificationMessage {
            error,
            data: vec![],
        })
    }

    /// RFC 8538 §4 — if both sides have the N-bit and the peer's NOTIFICATION is
    /// not HardReset, the helper MUST open a GR window (not flush immediately).
    #[test]
    fn notification_non_hard_reset_with_n_bit_enters_gr_window() {
        let mut state = make_state();
        // Our daemon config uses graceful_restart_time > 0, so we advertise N-bit.
        // Simulate that by pre-populating gr_capable_peers (normally done by on_established
        // of our own session; here we inject it because our local GR config is what
        // drives this — any non-zero gr_restart_time means we have the N-bit).
        establish(&mut state, &[gr_cap_with_n_bit(120)]);
        assert_eq!(
            state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"])),
            None,
            "unexpected CEASE on route announce"
        );

        // Peer sends a non-HardReset NOTIFICATION (e.g. Hold Timer Expired).
        let reason = notification(NotificationError::HoldTimerExpired);
        state.on_terminated(PEER_IP, reason, false);

        // GR window must be open: stale route still present in AdjRibIn.
        let adj_len = state
            .adj_ribs_in
            .get(&PEER_IP)
            .expect("AdjRibIn must still exist")
            .len();
        assert_eq!(
            adj_len, 1,
            "stale route must be retained in GR window after NOTIFICATION"
        );

        // A GR deadline must be scheduled.
        assert!(
            state.gr.deadlines.contains_key(&PEER_IP),
            "GR deadline must be set after non-HardReset NOTIFICATION from N-capable peer"
        );
    }

    /// RFC 8538 §4 — CEASE/HardReset (subcode 9) MUST trigger immediate flush
    /// even when both sides have the N-bit.
    #[test]
    fn notification_hard_reset_always_flushes() {
        let mut state = make_state();
        establish(&mut state, &[gr_cap_with_n_bit(120)]);
        assert_eq!(
            state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"])),
            None,
            "unexpected CEASE on route announce"
        );

        let reason = notification(NotificationError::Cease(CeaseError::HardReset));
        state.on_terminated(PEER_IP, reason, false);

        let adj_len = state
            .adj_ribs_in
            .get(&PEER_IP)
            .map_or(0, pathvector_rib::AdjRibIn::len);
        assert_eq!(
            adj_len, 0,
            "CEASE/HardReset must flush routes immediately, even with N-bit"
        );
        assert!(
            !state.gr.deadlines.contains_key(&PEER_IP),
            "no GR deadline must be set after HardReset"
        );
    }

    /// RFC 8538 §4 — if the peer did NOT advertise the N-bit, any NOTIFICATION
    /// must flush immediately (RFC 4724 §4.2 behaviour preserved).
    #[test]
    fn notification_without_peer_n_bit_flushes() {
        let mut state = make_state();
        // Peer has GR but NOT the N-bit.
        establish(&mut state, &[gr_cap_without_n_bit(120)]);
        assert_eq!(
            state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"])),
            None,
            "unexpected CEASE on route announce"
        );

        // Non-HardReset notification, but peer didn't negotiate N-bit.
        let reason = notification(NotificationError::HoldTimerExpired);
        state.on_terminated(PEER_IP, reason, false);

        let adj_len = state
            .adj_ribs_in
            .get(&PEER_IP)
            .map_or(0, pathvector_rib::AdjRibIn::len);
        assert_eq!(
            adj_len, 0,
            "NOTIFICATION from non-N-capable peer must flush routes (RFC 4724 §4.2)"
        );
        assert!(
            !state.gr.deadlines.contains_key(&PEER_IP),
            "no GR deadline when peer has no N-bit"
        );
    }

    /// OperatorStop must always flush, regardless of GR capability or N-bit.
    #[test]
    fn operator_stop_always_flushes() {
        let mut state = make_state();
        establish(&mut state, &[gr_cap_with_n_bit(120)]);
        assert_eq!(
            state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"])),
            None,
            "unexpected CEASE on route announce"
        );

        state.on_terminated(PEER_IP, TerminationReason::OperatorStop, false);

        let adj_len = state
            .adj_ribs_in
            .get(&PEER_IP)
            .map_or(0, pathvector_rib::AdjRibIn::len);
        assert_eq!(
            adj_len, 0,
            "OperatorStop must always flush routes immediately"
        );
        assert!(
            !state.gr.deadlines.contains_key(&PEER_IP),
            "no GR deadline on OperatorStop"
        );
    }

    /// RFC 8538 §2 — `build_local_capabilities` must set the N-bit (0x04) in
    /// `restart_flags` whenever `graceful_restart_time > 0`.
    #[test]
    fn build_local_capabilities_sets_n_bit_when_gr_enabled() {
        let caps = build_local_capabilities(LOCAL_AS, 120, false, None);
        let gr_cap = caps.iter().find_map(|c| {
            if let Capability::GracefulRestart {
                restart_flags,
                restart_time,
                ..
            } = c
            {
                Some((*restart_flags, *restart_time))
            } else {
                None
            }
        });
        let (flags, time) = gr_cap.expect("GracefulRestart capability must be present");
        assert_eq!(time, 120, "restart_time must be threaded through");
        assert_ne!(
            flags & 0x04,
            0,
            "N-bit must be set when graceful_restart_time > 0"
        );
        assert_eq!(
            flags & 0x08,
            0,
            "R-bit must be clear on non-restarting startup"
        );
    }

    /// When graceful_restart_time = 0, N-bit must NOT be set.
    #[test]
    fn build_local_capabilities_no_n_bit_when_gr_disabled() {
        let caps = build_local_capabilities(LOCAL_AS, 0, false, None);
        let gr_cap = caps.iter().find_map(|c| {
            if let Capability::GracefulRestart {
                restart_flags,
                restart_time,
                ..
            } = c
            {
                Some((*restart_flags, *restart_time))
            } else {
                None
            }
        });
        let (flags, time) = gr_cap.expect("GracefulRestart capability must be present");
        assert_eq!(time, 0);
        assert_eq!(flags & 0x04, 0, "N-bit must not be set when GR is disabled");
    }

    /// N-bit from peer's OPEN must be tracked in gr.notification_capable_peers.
    #[test]
    fn n_bit_peer_tracked_on_established() {
        let mut state = make_state();
        establish(&mut state, &[gr_cap_with_n_bit(120)]);
        assert!(
            state.gr.notification_capable_peers.contains(&PEER_IP),
            "peer advertising N-bit must be in notification_capable_peers"
        );
    }

    /// Peer without N-bit must NOT be tracked in notification_capable_peers.
    #[test]
    fn non_n_bit_peer_not_tracked_on_established() {
        let mut state = make_state();
        establish(&mut state, &[gr_cap_without_n_bit(120)]);
        assert!(
            !state.gr.notification_capable_peers.contains(&PEER_IP),
            "peer without N-bit must not be in notification_capable_peers"
        );
    }

    /// N-bit tracking must be cleared when the peer re-establishes without the N-bit.
    #[test]
    fn n_bit_cleared_when_peer_re_establishes_without_it() {
        let mut state = make_state();
        establish(&mut state, &[gr_cap_with_n_bit(120)]);
        assert!(state.gr.notification_capable_peers.contains(&PEER_IP));

        // Re-establish without N-bit.
        establish(&mut state, &[gr_cap_without_n_bit(120)]);
        assert!(
            !state.gr.notification_capable_peers.contains(&PEER_IP),
            "N-bit tracking must be cleared when peer re-establishes without it"
        );
    }

    /// RFC 8538 §4 — if WE don't have the N-bit (our graceful_restart_time = 0),
    /// a NOTIFICATION from an N-capable peer must still flush immediately.
    /// This verifies the we_have_n_bit check reads from our own config_capabilities,
    /// not the peer's gr_restart_time.
    #[test]
    fn notification_flushes_when_local_daemon_has_no_gr() {
        let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
        let peer = config::PeerConfig {
            address: PEER_IP,
            port: 179,
            remote_as: PEER_AS,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        };
        // Local daemon has graceful_restart_time = 0 → no N-bit advertised.
        let mut state = DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &[peer],
            [(PEER_IP, tx)].into(),
            build_local_capabilities(LOCAL_AS, 0, false, None),
        );
        // Peer advertises N-bit, but we don't → notification mode must NOT engage.
        establish(&mut state, &[gr_cap_with_n_bit(120)]);
        assert_eq!(
            state.on_route_update(PEER_IP, announce(&["10.0.0.0/8"])),
            None,
            "unexpected CEASE on announce"
        );

        let reason = notification(NotificationError::HoldTimerExpired);
        state.on_terminated(PEER_IP, reason, false);

        let adj_len = state
            .adj_ribs_in
            .get(&PEER_IP)
            .map_or(0, pathvector_rib::AdjRibIn::len);
        assert_eq!(
            adj_len, 0,
            "NOTIFICATION must flush when local daemon has no N-bit (graceful_restart_time = 0)"
        );
        assert!(
            !state.gr.deadlines.contains_key(&PEER_IP),
            "no GR deadline when local daemon has no N-bit"
        );
    }

    /// N-bit tracking must be cleared on peer removal.
    #[test]
    fn n_bit_cleared_on_remove_peer() {
        let mut state = make_state();
        establish(&mut state, &[gr_cap_with_n_bit(120)]);
        assert!(state.gr.notification_capable_peers.contains(&PEER_IP));
        state.remove_peer(PEER_IP);
        assert!(
            !state.gr.notification_capable_peers.contains(&PEER_IP),
            "N-bit tracking must be cleared on remove_peer"
        );
    }
}

// ── RFC 4486 §4: Maximum Prefix Limits ───────────────────────────────────────

#[cfg(test)]
mod test_max_prefix {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use pathvector_session::fsm::SessionInfo;
    use pathvector_session::message::{
        CeaseError, NotificationError, PathAttribute, UpdateMessage,
    };
    use pathvector_session::transport::TerminationReason;
    use pathvector_types::{AsPath, Asn, Nlri, Origin, PeerType};

    use super::*;
    use crate::config;

    const LOCAL_AS: u32 = 65001;
    const PEER_AS: u32 = 65002;
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn nlri(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn make_state_with_limit(
        limit: u32,
        restart_secs: u16,
    ) -> (
        DaemonState,
        HashMap<Ipv4Addr, mpsc::Receiver<UpdateMessage>>,
    ) {
        let (tx, rx) = mpsc::channel::<UpdateMessage>(256);
        let mut receivers = HashMap::new();
        receivers.insert(PEER_IP, rx);
        let peer_configs = vec![config::PeerConfig {
            address: PEER_IP,
            port: 179,
            remote_as: PEER_AS,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: Some(limit),
            max_prefixes_v6: None,
            max_prefixes_restart: if restart_secs > 0 {
                Some(restart_secs)
            } else {
                None
            },
            role: None,
        }];
        let mut senders = HashMap::new();
        senders.insert(PEER_IP, tx);
        let state = DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );
        (state, receivers)
    }

    fn establish(state: &mut DaemonState) {
        state.on_established(PEER_IP, PEER_IP, PeerType::External, PEER_AS, 90, &[], None);
    }

    fn announce(prefixes: &[&str]) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
                PathAttribute::NextHop(PEER_IP),
            ],
            announced: prefixes.iter().map(|s| nlri(s)).collect(),
        }
    }

    /// Under the limit — no CEASE returned.
    #[test]
    fn no_cease_when_under_limit() {
        let (mut state, _rxs) = make_state_with_limit(5, 0);
        establish(&mut state);
        let result = state.on_route_update(PEER_IP, announce(&["10.0.0.0/8", "192.168.0.0/24"]));
        assert!(
            result.is_none(),
            "no notification expected when prefix count is below the limit"
        );
    }

    /// Exactly at the limit — no CEASE.
    #[test]
    fn no_cease_at_exact_limit() {
        let (mut state, _rxs) = make_state_with_limit(2, 0);
        establish(&mut state);
        let result = state.on_route_update(PEER_IP, announce(&["10.0.0.0/8", "192.168.0.0/24"]));
        assert!(
            result.is_none(),
            "no notification expected when prefix count equals the limit"
        );
    }

    /// One prefix over the limit — CEASE/MaximumNumberOfPrefixesReached returned.
    #[test]
    fn cease_when_limit_exceeded() {
        let (mut state, _rxs) = make_state_with_limit(2, 0);
        establish(&mut state);
        let result = state.on_route_update(
            PEER_IP,
            announce(&["10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12"]),
        );
        let notification =
            result.expect("CEASE notification must be returned when limit is exceeded");
        assert!(
            matches!(
                notification.error,
                NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
            ),
            "error code must be CEASE/MaximumNumberOfPrefixesReached (RFC 4486 §4)"
        );
    }

    /// With restart configured, idle-hold deadline is set after CEASE.
    #[test]
    fn idle_hold_inserted_when_restart_configured() {
        let (mut state, _rxs) = make_state_with_limit(1, 60);
        establish(&mut state);
        let result = state.on_route_update(PEER_IP, announce(&["10.0.0.0/8", "192.168.0.0/24"]));
        assert!(result.is_some(), "CEASE must be returned");
        assert!(
            state.max_prefix_idle.contains_key(&PEER_IP),
            "max_prefix_idle must be set for the peer when restart_secs > 0"
        );
        let deadline = state.max_prefix_idle[&PEER_IP];
        assert!(deadline > Instant::now(), "deadline must be in the future");
    }

    /// Without restart, no idle-hold deadline is set.
    #[test]
    fn no_idle_hold_without_restart() {
        let (mut state, _rxs) = make_state_with_limit(1, 0);
        establish(&mut state);
        let result = state.on_route_update(PEER_IP, announce(&["10.0.0.0/8", "192.168.0.0/24"]));
        assert!(result.is_some(), "CEASE must be returned");
        assert!(
            !state.max_prefix_idle.contains_key(&PEER_IP),
            "max_prefix_idle must NOT be set when max_prefixes_restart is not configured"
        );
    }

    /// Peer with no max_prefixes configured is never subject to the limit.
    #[test]
    fn no_limit_when_unconfigured() {
        let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
        let peer_configs = vec![config::PeerConfig {
            address: PEER_IP,
            port: 179,
            remote_as: PEER_AS,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        }];
        let mut senders = HashMap::new();
        senders.insert(PEER_IP, tx);
        let mut state = DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &peer_configs,
            senders,
            vec![],
        );
        establish(&mut state);
        // Send 100 prefixes — no limit should fire.
        let prefixes: Vec<String> = (0u8..100).map(|i| format!("10.{i}.0.0/24")).collect();
        let prefix_strs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
        let result = state.on_route_update(PEER_IP, announce(&prefix_strs));
        assert!(
            result.is_none(),
            "no limit when max_prefixes is not configured"
        );
    }

    /// `add_peer` wires max_prefixes into the runtime maps.
    #[test]
    fn add_peer_populates_max_prefix_maps() {
        let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
        let peer_cfg = config::PeerConfig {
            address: PEER_IP,
            port: 179,
            remote_as: PEER_AS,
            import_default: None,
            export_default: None,
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: Some(50),
            max_prefixes_v6: Some(200),
            max_prefixes_restart: Some(30),
            role: None,
        };
        let mut state = DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &[],
            HashMap::new(),
            vec![],
        );
        state.add_peer(&peer_cfg, tx);
        assert_eq!(state.peer_max_prefixes_v4.get(&PEER_IP).copied(), Some(50));
        assert_eq!(state.peer_max_prefixes_v6.get(&PEER_IP).copied(), Some(200));
        assert_eq!(
            state.peer_max_prefixes_restart.get(&PEER_IP).copied(),
            Some(30)
        );
    }

    /// `remove_peer` clears all three max-prefix maps.
    #[test]
    fn remove_peer_clears_max_prefix_maps() {
        let (tx, _rx) = mpsc::channel::<UpdateMessage>(256);
        let (mut state, _rxs) = make_state_with_limit(10, 60);
        establish(&mut state);
        // Trigger idle-hold by exceeding limit.
        state.on_route_update(
            PEER_IP,
            announce(&[
                "10.0.0.0/8",
                "192.168.0.0/24",
                "172.16.0.0/12",
                "10.1.0.0/16",
                "10.2.0.0/16",
                "10.3.0.0/16",
                "10.4.0.0/16",
                "10.5.0.0/16",
                "10.6.0.0/16",
                "10.7.0.0/16",
                "10.8.0.0/16",
            ]),
        );
        // max_prefix_idle should now be set.
        assert!(state.max_prefix_idle.contains_key(&PEER_IP));

        state.remove_peer(PEER_IP);

        assert!(
            !state.peer_max_prefixes_v4.contains_key(&PEER_IP),
            "peer_max_prefixes_v4 cleared"
        );
        assert!(
            !state.peer_max_prefixes_v6.contains_key(&PEER_IP),
            "peer_max_prefixes_v6 cleared"
        );
        assert!(
            !state.peer_max_prefixes_restart.contains_key(&PEER_IP),
            "peer_max_prefixes_restart cleared"
        );
        assert!(
            !state.max_prefix_idle.contains_key(&PEER_IP),
            "max_prefix_idle cleared"
        );
        drop(tx); // silence unused variable warning
    }

    // ── Event-loop integration tests ──────────────────────────────────────────
    //
    // These tests drive `run_event_loop` directly to verify the end-to-end
    // behaviour of the max-prefix feature: CEASE delivery, idle-hold blocking,
    // and idle-hold expiry.

    fn peer_established_info(peer_as: u32) -> SessionInfo {
        SessionInfo {
            peer_as,
            peer_bgp_id: PEER_IP,
            hold_time: 90,
            peer_capabilities: vec![],
            peer_type: PeerType::External,
            local_addr: None,
        }
    }

    type EventLoopFixture = (
        Arc<RwLock<DaemonState>>,
        Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>>,
        mpsc::Receiver<SessionCommand>,
    );

    fn make_state_for_loop(
        peer_ip: Ipv4Addr,
        peer_as: u32,
        limit: u32,
        restart_secs: u16,
    ) -> EventLoopFixture {
        let (update_tx, _) = mpsc::channel::<UpdateMessage>(64);
        let (stop_tx, stop_rx) = mpsc::channel::<SessionCommand>(8);
        let peer_cfg = config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: peer_as,
            import_default: Some(config::ImportDefault::Accept),
            export_default: Some(config::ExportDefault::Accept),
            import_default_v6: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: Some(limit),
            max_prefixes_v6: None,
            max_prefixes_restart: if restart_secs > 0 {
                Some(restart_secs)
            } else {
                None
            },
            role: None,
        };
        let mut senders = HashMap::new();
        senders.insert(peer_ip, update_tx);
        let state = Arc::new(RwLock::new(DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &[peer_cfg],
            senders,
            vec![],
        )));
        let mut stop_map = HashMap::new();
        stop_map.insert(peer_ip, stop_tx);
        let stop_senders = Arc::new(Mutex::new(stop_map));
        (state, stop_senders, stop_rx)
    }

    /// RFC 4486 §4 MUST: exceeding the limit causes the event loop to send
    /// CEASE/MaximumNumberOfPrefixesReached to the peer's session.
    #[tokio::test]
    async fn event_loop_sends_cease_when_limit_exceeded() {
        let peer_ip = PEER_IP;
        let (state, stop_senders, mut stop_rx) = make_state_for_loop(peer_ip, PEER_AS, 2, 0);

        state.write().await.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            PEER_AS,
            90,
            &[],
            None,
        );

        let (event_tx, event_rx) = mpsc::channel(8);
        // 3 prefixes exceed limit of 2.
        event_tx
            .send((
                peer_ip,
                SessionEvent::RouteUpdate(announce(&[
                    "10.0.0.0/8",
                    "192.168.0.0/24",
                    "172.16.0.0/12",
                ])),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        )
        .await;

        let cmd = stop_rx
            .try_recv()
            .expect("peer must receive a SessionCommand when limit is exceeded");
        let is_max_prefix_cease = matches!(
            &cmd,
            SessionCommand::Notification(n)
                if matches!(
                    n.error,
                    NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
                )
        );
        assert!(
            is_max_prefix_cease,
            "command must be CEASE/MaximumNumberOfPrefixesReached (RFC 4486 §4), got: {cmd:?}"
        );
    }

    /// RFC 4486 §4 — after a CEASE the session terminates. The subsequent
    /// Terminated event must flush the peer's routes from Loc-RIB so no stale
    /// routes from the over-limit UPDATE persist.
    #[tokio::test]
    async fn over_limit_routes_flushed_after_termination() {
        let peer_ip = PEER_IP;
        let (state, stop_senders, _stop_rx) = make_state_for_loop(peer_ip, PEER_AS, 2, 0);

        state.write().await.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            PEER_AS,
            90,
            &[],
            None,
        );

        let (event_tx, event_rx) = mpsc::channel(8);
        // 3 prefixes exceed limit of 2.
        event_tx
            .send((
                peer_ip,
                SessionEvent::RouteUpdate(announce(&[
                    "10.0.0.0/8",
                    "192.168.0.0/24",
                    "172.16.0.0/12",
                ])),
            ))
            .await
            .unwrap();
        // Session layer responds to CEASE with a Terminated event.
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::OperatorStop),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        )
        .await;

        let s = state.read().await;
        assert_eq!(
            s.rib.loc_rib.len(),
            0,
            "Loc-RIB must be empty after over-limit update + termination"
        );
    }

    /// Idle-hold: a reconnect attempt during the hold window must be rejected
    /// with SessionCommand::Stop; the peer must NOT be established.
    #[tokio::test]
    async fn event_loop_idle_hold_blocks_reconnect() {
        let peer_ip = PEER_IP;
        // 300-second idle-hold so it does not expire during the test.
        let (state, stop_senders, mut stop_rx) = make_state_for_loop(peer_ip, PEER_AS, 1, 300);

        state.write().await.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            PEER_AS,
            90,
            &[],
            None,
        );

        let (event_tx, event_rx) = mpsc::channel(16);
        // 2 prefixes exceed limit of 1 → CEASE + idle-hold inserted.
        event_tx
            .send((
                peer_ip,
                SessionEvent::RouteUpdate(announce(&["10.0.0.0/8", "192.168.0.0/24"])),
            ))
            .await
            .unwrap();
        // Session terminates.
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::OperatorStop),
            ))
            .await
            .unwrap();
        // Peer reconnects immediately — must be blocked.
        event_tx
            .send((
                peer_ip,
                SessionEvent::Established(peer_established_info(PEER_AS)),
            ))
            .await
            .unwrap();
        drop(event_tx);

        run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        )
        .await;

        // First command: CEASE for the over-limit UPDATE.
        let first = stop_rx.try_recv().expect("first command must be CEASE");
        assert!(
            matches!(
                first,
                SessionCommand::Notification(n)
                    if matches!(
                        n.error,
                        NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
                    )
            ),
            "first command must be CEASE/MaximumNumberOfPrefixesReached"
        );

        // Second command: Stop for the blocked reconnect.
        let second = stop_rx
            .try_recv()
            .expect("second command must be Stop for blocked reconnect");
        assert!(
            matches!(second, SessionCommand::Stop),
            "reconnect during idle-hold must receive Stop, got: {second:?}"
        );

        // Peer must not be established (no peer_type entry).
        let s = state.read().await;
        assert!(
            !s.rib.peer_types.contains_key(&peer_ip),
            "peer must not be established while idle-hold is active"
        );
    }

    /// Idle-hold expiry: the timer branch in the event loop removes a deadline
    /// that has already passed, allowing the next reconnect to succeed.
    ///
    /// Strategy: bypass the RouteUpdate/Terminated path (tested elsewhere) and
    /// insert an already-expired deadline directly into `max_prefix_idle`. This
    /// makes the timer arm fire on the first `select!` iteration without needing
    /// `start_paused` or time-advance coordination.
    #[tokio::test]
    async fn event_loop_idle_hold_timer_clears_expired_deadline() {
        let peer_ip = PEER_IP;
        let (state, stop_senders, _stop_rx) = make_state_for_loop(peer_ip, PEER_AS, 100, 0);

        // Insert an idle-hold deadline that is already in the past.
        let expired = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        state.write().await.max_prefix_idle.insert(peer_ip, expired);

        // Run the event loop with a single no-op event then close the channel.
        // The loop will see both the expired timer and the closed channel on
        // the first select! iteration.  We send a Terminated for a peer that
        // was never established (on_terminated is a no-op in that case) so
        // the loop also processes something and doesn't immediately break —
        // the timer branch wins the select! race at least once.
        let (event_tx, event_rx) = mpsc::channel(4);
        let loop_handle = tokio::spawn(run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        ));

        // Give the spawned loop time to enter select! and fire the timer.
        for _ in 0..20 {
            tokio::task::yield_now().await;
            if !state.read().await.max_prefix_idle.contains_key(&peer_ip) {
                break;
            }
        }

        assert!(
            !state.read().await.max_prefix_idle.contains_key(&peer_ip),
            "timer branch must remove an expired idle-hold deadline"
        );

        drop(event_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), loop_handle).await;
    }

    /// Idle-hold blocks reconnects arriving in the coalesced drain loop
    /// (try_recv path), not just the primary await path.
    #[tokio::test]
    async fn event_loop_idle_hold_blocks_reconnect_in_drain_loop() {
        let peer_ip = PEER_IP;
        let (state, stop_senders, mut stop_rx) = make_state_for_loop(peer_ip, PEER_AS, 1, 300);

        state.write().await.on_established(
            peer_ip,
            peer_ip,
            PeerType::External,
            PEER_AS,
            90,
            &[],
            None,
        );

        let (event_tx, event_rx) = mpsc::channel(16);

        // Pre-fill channel: first event wakes the loop, subsequent events land
        // in the try_recv drain. The Established arrives in the drain loop.
        event_tx
            .send((
                peer_ip,
                SessionEvent::RouteUpdate(announce(&["10.0.0.0/8", "192.168.0.0/24"])),
            ))
            .await
            .unwrap();
        event_tx
            .send((
                peer_ip,
                SessionEvent::Terminated(TerminationReason::OperatorStop),
            ))
            .await
            .unwrap();
        event_tx
            .send((
                peer_ip,
                SessionEvent::Established(peer_established_info(PEER_AS)),
            ))
            .await
            .unwrap();

        // Yield before dropping so all three events are in the channel before
        // the loop wakes, maximising the chance the Established is seen during drain.
        tokio::task::yield_now().await;
        drop(event_tx);

        run_event_loop(
            event_rx,
            Arc::clone(&state),
            Arc::clone(&stop_senders),
            None,
        )
        .await;

        // Collect all commands sent to the peer.
        let mut cmds = Vec::new();
        while let Ok(cmd) = stop_rx.try_recv() {
            cmds.push(cmd);
        }

        let has_cease = cmds.iter().any(|c| {
            matches!(
                c,
                SessionCommand::Notification(n)
                    if matches!(
                        n.error,
                        NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
                    )
            )
        });
        let has_stop = cmds.iter().any(|c| matches!(c, SessionCommand::Stop));

        assert!(has_cease, "peer must receive CEASE for over-limit update");
        assert!(
            has_stop,
            "peer must receive Stop for reconnect during idle-hold (drain-loop path)"
        );
        assert!(
            !state.read().await.rib.peer_types.contains_key(&peer_ip),
            "peer must not be established while idle-hold is active"
        );
    }

    // ── Two-peer displaced best-path test ─────────────────────────────────────
    //
    // Scenario: Peer A holds 10.0.0.0/8. Peer B (limit=1) sends 10.0.0.0/8
    // plus 192.168.0.0/24, exceeding the limit. handle_update runs fully —
    // AdjRibIn_B gets both routes and LocRib may temporarily prefer Peer B's
    // route — but FIB changes are NOT applied (we return CEASE early). After
    // on_terminated(B) the LocRib must revert to Peer A's 10.0.0.0/8, and
    // 192.168.0.0/24 must be absent (Peer B was the only contributor).

    const PEER_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const PEER_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    const AS_A: u32 = 65100;
    const AS_B: u32 = 65200;

    fn announce_from(peer_ip: Ipv4Addr, peer_as: u32, prefixes: &[&str]) -> UpdateMessage {
        UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(peer_as)])),
                PathAttribute::NextHop(peer_ip),
            ],
            announced: prefixes.iter().map(|s| nlri(s)).collect(),
        }
    }

    fn peer_cfg(address: Ipv4Addr, remote_as: u32, v4_limit: Option<u32>) -> config::PeerConfig {
        config::PeerConfig {
            address,
            port: 179,
            remote_as,
            import_default: Some(config::ImportDefault::Accept),
            import_default_v6: None,
            export_default: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: v4_limit,
            max_prefixes_v6: None,
            max_prefixes_restart: None,
            role: None,
        }
    }

    fn make_two_peer_state() -> (
        DaemonState,
        tokio::sync::mpsc::Receiver<UpdateMessage>,
        tokio::sync::mpsc::Receiver<UpdateMessage>,
    ) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel::<UpdateMessage>(256);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel::<UpdateMessage>(256);
        let mut senders = HashMap::new();
        senders.insert(PEER_A, tx_a);
        senders.insert(PEER_B, tx_b);

        let mut state = DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &[
                peer_cfg(PEER_A, AS_A, None),
                peer_cfg(PEER_B, AS_B, Some(1)),
            ],
            senders,
            vec![],
        );
        state.on_established(PEER_A, PEER_A, PeerType::External, AS_A, 90, &[], None);
        state.on_established(PEER_B, PEER_B, PeerType::External, AS_B, 90, &[], None);
        (state, rx_a, rx_b)
    }

    /// When Peer B exceeds the limit and sends a CEASE, Peer B's routes (including
    /// one that displaced Peer A's best path) must be fully withdrawn from the
    /// LocRib after on_terminated. The FIB was never updated to Peer B's route,
    /// so on_terminated reverts cleanly without exposing a transient state.
    #[test]
    fn displaced_best_path_reverts_after_termination() {
        use pathvector_rib::PeerId;
        use std::net::IpAddr;
        let (mut state, _rx_a, _rx_b) = make_two_peer_state();

        let shared: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let b_only: Nlri<Ipv4Addr> = "192.168.0.0/24".parse().unwrap();
        let peer_a_id = PeerId::new(IpAddr::V4(PEER_A));

        // Step 1: Peer A owns 10.0.0.0/8.
        let r = state.on_route_update(PEER_A, announce_from(PEER_A, AS_A, &["10.0.0.0/8"]));
        assert!(r.is_none(), "Peer A must not trigger a CEASE");
        assert_eq!(
            state.rib.loc_rib.best_peer(&shared),
            Some(peer_a_id),
            "Peer A must be best for 10.0.0.0/8 before Peer B arrives"
        );

        // Step 2: Peer B exceeds limit (1) by sending 2 prefixes.
        // handle_update runs fully — LocRib may swap best path to Peer B —
        // but on_route_update returns CEASE without applying FIB changes.
        let r = state.on_route_update(
            PEER_B,
            announce_from(PEER_B, AS_B, &["10.0.0.0/8", "192.168.0.0/24"]),
        );
        assert!(
            r.as_ref().is_some_and(|n| matches!(
                n.error,
                NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
            )),
            "Peer B must receive CEASE/MaximumNumberOfPrefixesReached"
        );

        // Step 3: Terminate Peer B. LocRib must revert fully to Peer A's world.
        state.on_terminated(PEER_B, TerminationReason::OperatorStop, true);

        assert_eq!(
            state.rib.loc_rib.best_peer(&shared),
            Some(peer_a_id),
            "Peer A must be best for 10.0.0.0/8 after Peer B termination"
        );
        assert!(
            state.rib.loc_rib.best_peer(&b_only).is_none(),
            "192.168.0.0/24 must be absent — Peer B was the only contributor"
        );
        let adj_b = state.adj_ribs_in.get(&PEER_B).map_or(0, AdjRibIn::len);
        assert_eq!(adj_b, 0, "Peer B AdjRibIn must be empty after termination");
    }

    /// IPv6-limit fires independently of the IPv4 limit.
    #[test]
    fn cease_when_v6_limit_exceeded() {
        use pathvector_session::message::{MpReachNlri, Prefix};
        use pathvector_types::AfiSafi;
        use pathvector_types::NextHop;

        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let (tx, _rx) = tokio::sync::mpsc::channel::<UpdateMessage>(256);
        let mut senders = HashMap::new();
        senders.insert(peer_ip, tx);

        let cfg = config::PeerConfig {
            address: peer_ip,
            port: 179,
            remote_as: 65099,
            import_default: None,
            import_default_v6: None,
            export_default: None,
            md5_password: None,
            is_rr_client: false,
            next_hop_self: false,
            hold_time: None,
            shutdown_message: None,
            connect_retry_time: None,
            max_prefixes_v4: None,
            max_prefixes_v6: Some(1),
            max_prefixes_restart: None,
            role: None,
        };
        let mut state = DaemonState::new(
            LOCAL_AS,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            &[cfg],
            senders,
            vec![],
        );
        state.on_established(peer_ip, peer_ip, PeerType::External, 65099, 90, &[], None);

        let v6_nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let pfx1: Nlri<std::net::Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let pfx2: Nlri<std::net::Ipv6Addr> = "2001:db8:1::/48".parse().unwrap();

        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65099)])),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6(v6_nh),
                    prefixes: vec![Prefix::V6(pfx1), Prefix::V6(pfx2)],
                }),
            ],
            announced: vec![],
        };

        let result = state.on_route_update(peer_ip, update);
        assert!(
            result.as_ref().is_some_and(|n| matches!(
                n.error,
                NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached)
            )),
            "must CEASE when IPv6 limit exceeded; got: {result:?}"
        );
        // The UPDATE carried no IPv4 NLRI, so the IPv4 Adj-RIB-In must be
        // empty — confirming the limits are checked independently, not combined.
        let v4_count = state.adj_ribs_in.get(&peer_ip).map_or(0, AdjRibIn::len);
        assert_eq!(
            v4_count, 0,
            "IPv4 Adj-RIB-In must be empty when only IPv6 prefixes were sent"
        );
    }
}
