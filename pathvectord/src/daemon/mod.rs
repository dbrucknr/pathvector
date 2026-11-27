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
        self, DEFAULT_CONNECT_RETRY_TIME, SendHoldTime, SessionCommand, SessionConfig,
        SessionEvent, SessionHandle, TerminationReason,
        listener::{BgpListener, Inbound, ListenerKeys, ListenerProtection},
        tcp_md5::{KernelTcpMd5, Md5Enforcement, TcpMd5Auth, TcpMd5Port},
    },
};
use pathvector_types::{
    AfiSafi, AsPath, Asn, LocalPref, Med, NextHop, Nlri, Origin, PeerType, Role, UnknownAttribute,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{RwLock, broadcast, mpsc, watch};

use crate::outbound::{
    PrefixDecision, PrefixDecisionV6, flush_updates, flush_updates_v6, propagate_prefix,
    propagate_prefix_v6, send_eor_ipv4, send_eor_ipv6,
};
use crate::{config, fib as crate_fib, grpc, proto};
use crate_fib::ApplyFibChange;

mod blackhole;
mod capabilities;
mod deferral;
mod fib;
mod gr;
mod import;
#[cfg(test)]
mod import_reject_tests;
mod ingress;
// Issue #138: announcements dropped before import policy still withdraw the
// peer's older route.
#[cfg(test)]
mod as_content_tests;
#[cfg(test)]
mod ingress_drop_tests;
#[cfg(test)]
mod last_feasible_tests;
#[cfg(test)]
mod listener_md5_tests;
#[cfg(test)]
mod mrai_flush_tests;
mod origination;
mod peer;
mod peer_stats;
mod policy;
mod route;
// Issue #160: session loss must withdraw or replace routes in both families.
#[cfg(test)]
mod session_loss_tests;
// Issue #178: UPDATEs stay within the negotiated maximum message size.
#[cfg(test)]
mod update_size_tests;

// Issues #81 and #82: BLACKHOLE authorization and import eligibility through
// Graceful Restart.
#[cfg(test)]
mod blackhole_tests;
#[cfg(test)]
mod issue_81_82_tests;

// Issue #68: conventional-GR stale routes keep their ordinary preference.
#[cfg(test)]
mod gr_preference_tests;

// Issue #69: RFC 4456 §9 reflected-route tie-breakers through ingestion.
#[cfg(test)]
mod rr_tie_break_tests;

// Issues #177 / #135: RFC 4456 §8 attributes are added on reflection.
#[cfg(test)]
mod rr_reflection_tests;

// Issue #168: RFC 4456 §6 non-client split-horizon on every send path.
#[cfg(test)]
mod rr_split_horizon_tests;

// Issue #159: UPDATEs sent to a peer, applied in order, match its Adj-RIB-Out.
#[cfg(test)]
mod outbound_order_tests;

// Sessions the daemon resets on its own authority must reconnect.
#[cfg(test)]
mod session_restart_tests;

// Re-exports so that sibling submodules using `use super::*` can call
// items defined in other sibling submodules.
use blackhole::{BlackholeBook, BlackholeBooks, BlackholeChange, PeerBlackhole};
use capabilities::{
    Md5Keys, SpawnConfig, build_local_capabilities, remove_listener_key, session_tcp_md5,
    set_listener_key, warn_if_md5_best_effort,
};
use deferral::SelectionDeferral;
use fib::{changed_nlris, withdraw_stale_bgp_routes};
use gr::GracefulRestartState;
#[cfg(test)]
use import::reapply_without_blackholes;
use import::{
    ImportPipeline, ImportTally, RibEffects, import_announcement, import_ineligible,
    reapply_import_policy, retire_routes, withdraw_route,
};
use ingress::{Disposition, IngressDrop, IngressGate};
use peer::{run_bgp_listener, run_command_processor};
use route::MraiTracker;
#[cfg(test)]
use route::handle_update;
#[cfg(test)]
use tests::must_v4;
#[cfg(test)]
mod tests;

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
    RemovePeer(IpAddr),
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

/// Derives the peer type (iBGP / eBGP / confederation Member-AS) from the
/// configured AS numbers and confederation membership.
///
/// `local_as == remote_as` is checked first regardless of `confed_member`:
/// a peer with matching AS numbers is definitionally same-AS iBGP even if
/// `confederation_member` was mistakenly also set (matches BIRD's
/// `is_internal`, which is likewise computed independently of confederation
/// state).
fn config_peer_type(local_as: u32, remote_as: u32, confed_member: bool) -> PeerType {
    if local_as == remote_as {
        PeerType::Internal
    } else if confed_member {
        PeerType::ConfedMember
    } else {
        PeerType::External
    }
}

/// Resolves the AS number this daemon presents to a specific peer, in the
/// OPEN message's `my_as` field and the `FourByteAsn` capability.
///
/// RFC 5065 §4: "A member of a BGP confederation MUST use its AS
/// Confederation Identifier in all transactions with peers that are not
/// members of its confederation... this number is used in OPEN messages...
/// A member of a BGP confederation MUST use its Member-AS Number in all
/// transactions with peers that are members of the same confederation."
/// `local_as` is the private Member-AS Number; only `External` peers see
/// `confederation_id` instead. Falls back to `local_as` when no
/// confederation is configured, so behavior is unchanged for non-confederation
/// deployments.
fn effective_session_as(local_as: u32, confederation_id: Option<u32>, peer_type: PeerType) -> u32 {
    match peer_type {
        PeerType::External => confederation_id.unwrap_or(local_as),
        PeerType::Internal | PeerType::ConfedMember | PeerType::Local => local_as,
    }
}

/// Creates a matched pair of `AdjRibOut` tables (IPv4 + IPv6) for one peer.
///
/// Both tables are created with identical reflecting/non-reflecting mode so they
/// can never diverge. When acting as a route reflector (`reflector_cluster_id`
/// is `Some`) and the peer is iBGP, both tables use
/// [`AdjRibOut::new_reflecting`]; otherwise both use [`AdjRibOut::new`].
///
/// All sites that construct outbound RIBs for a peer MUST use this function
/// instead of calling `AdjRibOut::new` / `new_reflecting` directly. This is the
/// single enforcement point for RFC 4456 §8 outbound-table invariant:
/// `adj_ribs_out[p].reflects() == adj_ribs_out_v6[p].reflects()` for every peer.
fn make_adj_ribs_out_pair(
    peer_id: PeerId,
    peer_type: PeerType,
    reflector_cluster_id: Option<u32>,
) -> (AdjRibOut<Ipv4Addr>, AdjRibOut<Ipv6Addr>) {
    match reflector_cluster_id {
        Some(cluster_id) if peer_type == PeerType::Internal => (
            AdjRibOut::new_reflecting(peer_id, peer_type, cluster_id),
            AdjRibOut::new_reflecting(peer_id, peer_type, cluster_id),
        ),
        _ => (
            AdjRibOut::new(peer_id, peer_type),
            AdjRibOut::new(peer_id, peer_type),
        ),
    }
}

/// Immutable-ish snapshot of the read-heavy routing state.
///
/// Stored inside `DaemonState` as an `Arc<RibSnapshot>`. The event loop
/// mutates it via [`Arc::make_mut`] (zero-cost when no readers hold a clone;
/// a full deep copy of both Loc-RIBs when one does). Handlers that must walk
/// the table (`list_routes`, `watch_routes`, ...) clone the `Arc` in O(1) and
/// release the outer `RwLock`; that clone is the price of a slow scan.
/// Handlers that only need per-peer facts (`list_peers`, `get_peer`,
/// `watch_peers`) must not take that clone: they read the counters through
/// [`peer_stats`] under the read guard, which costs O(peers) and never
/// triggers a copy (issue #106).
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
    pub(crate) peer_remote_as: HashMap<IpAddr, u32>,
    /// Live session state: present while a peer is Established.
    pub(crate) peer_types: HashMap<IpAddr, PeerType>,
    /// Wall-clock instant at which each peer last reached Established.
    pub(crate) established_at: HashMap<IpAddr, std::time::Instant>,
    /// Negotiated hold-timer value per established peer.
    pub(crate) hold_times: HashMap<IpAddr, u16>,
    /// Derived from `adj_ribs_in[peer].len()`; synced after each mutation.
    pub(crate) prefixes_received: HashMap<IpAddr, usize>,
    /// Derived from `adj_ribs_out[peer].len()`; synced after each propagation.
    pub(crate) prefixes_advertised: HashMap<IpAddr, usize>,
    /// Local TCP address per established peer, captured at connect time.
    ///
    /// Used as the eBGP NEXT_HOP (RFC 4271 §5.1.3) instead of `local_bgp_id`
    /// so the NEXT_HOP is the interface address reachable by the peer.
    /// Stores the full `IpAddr` (v4 or v6, matching that peer's transport
    /// session) — consumers extract the v4 variant specifically for IPv4
    /// NEXT_HOP rewrite, falling back to `local_bgp_id` when the session's
    /// local address is v6-only.
    pub(crate) local_addrs: HashMap<IpAddr, IpAddr>,
    /// Peers configured with `next_hop_self = true`.
    ///
    /// When a peer is in this set, `NEXT_HOP` is rewritten to the local
    /// session address before the route is forwarded, even for iBGP peers.
    /// Immutable after startup.
    pub(crate) next_hop_self_peers: HashSet<IpAddr>,
    /// Set of configured Route Reflector clients (RFC 4456).
    ///
    /// Empty when this daemon is not acting as a Route Reflector.
    /// Immutable after startup.
    pub(crate) rr_clients: std::collections::HashSet<IpAddr>,
    /// Cluster identifier used in `CLUSTER_LIST` when reflecting routes (RFC 4456).
    ///
    /// Defaults to the 32-bit representation of `bgp_id` when not explicitly
    /// configured. Immutable after startup.
    pub(crate) cluster_id: u32,
    /// RFC 5065 Confederation Identifier, if this daemon is a confederation
    /// Member-AS. `None` disables confederation support entirely. Immutable
    /// after startup.
    pub(crate) confederation_id: Option<u32>,
    /// BGP Identifier of each established peer, received in their OPEN message.
    ///
    /// Copied onto each route the peer sends (`Route::peer_bgp_id`), where it
    /// supplies the `ORIGINATOR_ID` when the route is reflected (RFC 4456 §8).
    /// Populated on `Established`; removed on `Terminated`.
    pub(crate) peer_bgp_ids: HashMap<IpAddr, Ipv4Addr>,
    /// Peers that have sent us an IPv4 End-of-RIB marker (RFC 4724 §2).
    /// Cleared on session termination. Used to signal initial sync complete.
    pub(crate) eor_received: HashSet<IpAddr>,
    /// Peers that have sent us an IPv6 unicast EOR marker (RFC 4724 §2).
    pub(crate) eor_received_v6: HashSet<IpAddr>,
    /// Peers that advertised RFC 4724 `GracefulRestart` with a non-zero
    /// `restart_time`. Value is the peer's advertised `restart_time` in seconds.
    ///
    /// Populated on `Established`; removed on `Terminated`. Zero means the peer
    /// either did not advertise the capability or advertised `restart_time = 0`
    /// (EOR-only mode, no stale-route window).
    pub(crate) gr_capable_peers: HashMap<IpAddr, u16>,
    /// Peers whose most-recent OPEN advertised the GracefulRestart
    /// capability at all — including `restart_time == 0` (EOR-only mode).
    ///
    /// Distinct from `gr_capable_peers`, which only tracks `restart_time >
    /// 0` peers for stale-route-retention purposes. RFC 4724 §3 explicitly
    /// recommends advertising the capability with `restart_time == 0` "to
    /// indicate its intention of generating the End-of-RIB marker," and RFC
    /// 4724 §4.1's Restarting-Speaker wait-set (`daemon/deferral.rs`)
    /// excludes only peers that "do not advertise the graceful restart
    /// capability" at all — an EOR-only peer must still be waited on.
    /// Populated on `Established`; removed on `Terminated`.
    pub(crate) gr_advertised_peers: HashSet<IpAddr>,
    /// Peers whose most-recent GracefulRestart capability had the Restart
    /// State (R) bit set, i.e. they advertised that *they themselves* are
    /// currently restarting. RFC 4724 §4.1 excludes such peers from the
    /// Restarting-Speaker's own EOR wait-set, since a peer that is itself
    /// mid-restart cannot be expected to have already re-sent its table.
    /// Populated alongside `gr_advertised_peers` in `on_established`;
    /// removed on `Terminated`.
    pub(crate) gr_peer_restarting: HashSet<IpAddr>,
    /// RFC 9234 BGP Role configured for each peer, if any. Present only for
    /// peers with `role` set in `PeerConfig` — absent means Role capability
    /// negotiation and OTC leak prevention are disabled for that peer
    /// (matching the RFC's own non-strict default). Consulted both when
    /// building each session's OPEN capabilities (including on reconnect,
    /// so Role survives a session reset the same way GR capabilities do)
    /// and when installing this peer's OTC policy terms. Immutable after
    /// startup for static peers; updated by `add_peer`/`remove_peer` for
    /// dynamic peers — mirrors `peer_remote_as`'s lifecycle exactly.
    pub(crate) peer_roles: HashMap<IpAddr, Role>,
    /// The peer's negotiated RFC 9234 BGP Role, extracted from their
    /// advertised Role capability in OPEN. Populated on `Established`;
    /// removed on `Terminated` — mirrors `peer_bgp_ids`'s lifecycle exactly.
    pub(crate) negotiated_roles: HashMap<IpAddr, Role>,
}

impl RibSnapshot {
    /// The `CLUSTER_ID` to reflect routes with, or `None` when this speaker is
    /// not a route reflector (RFC 4456).
    fn reflector_cluster_id(&self) -> Option<u32> {
        (!self.rr_clients.is_empty()).then_some(self.cluster_id)
    }
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
    pub(crate) import_policies: HashMap<IpAddr, Policy<Route<Ipv4Addr>>>,
    pub(crate) import_policies_v6: HashMap<IpAddr, Policy<Route<Ipv6Addr>>>,
    pub(crate) export_policies: HashMap<IpAddr, Policy<Route<Ipv4Addr>>>,
    pub(crate) export_policies_v6: HashMap<IpAddr, Policy<Route<Ipv6Addr>>>,
    pub(crate) adj_ribs_in: HashMap<IpAddr, AdjRibIn<Ipv4Addr>>,
    pub(crate) adj_ribs_out: HashMap<IpAddr, AdjRibOut<Ipv4Addr>>,
    pub(crate) adj_ribs_in_v6: HashMap<IpAddr, AdjRibIn<Ipv6Addr>>,
    pub(crate) adj_ribs_out_v6: HashMap<IpAddr, AdjRibOut<Ipv6Addr>>,
    /// Static peer type derived from config; used to reset `AdjRibOut` on reconnect.
    pub(crate) peer_config_types: HashMap<IpAddr, PeerType>,
    pub(crate) update_senders: HashMap<IpAddr, mpsc::Sender<UpdateMessage>>,
    /// Local capabilities advertised in OPEN messages; used to determine the
    /// negotiated message size limit after `Established`.
    pub(crate) config_capabilities: Vec<Capability>,
    /// Negotiated maximum BGP message size per established peer.
    ///
    /// Set to [`MAX_LEN_EXTENDED`] (65535) when both sides negotiated
    /// `Capability::ExtendedMessage`; otherwise [`MAX_LEN`] (4096).
    /// Removed when the peer transitions out of Established.
    pub(crate) negotiated_max_len: HashMap<IpAddr, usize>,
    /// Peers that negotiated the IPv6 unicast Multi-Protocol capability (RFC 4760).
    ///
    /// Only these peers receive IPv6 MP_REACH_NLRI / MP_UNREACH_NLRI.
    pub(crate) ipv6_capable_peers: HashSet<IpAddr>,
    /// Peers that negotiated RFC 6793 `FourByteAsn` capability.
    ///
    /// AS_PATH is sent unchanged to these peers. For absent peers, AS_PATH is
    /// downgraded (4-byte ASNs replaced with AS_TRANS) and AS4_PATH is added.
    pub(crate) four_byte_peers: HashSet<IpAddr>,
    /// Peers that negotiated RFC 2918 `RouteRefresh` capability.
    ///
    /// `SoftReset` (gRPC) may only send a ROUTE-REFRESH message to peers in
    /// this set. RFC 2918 §4: a router MUST NOT send ROUTE-REFRESH without
    /// having received the corresponding capability from the peer.
    pub(crate) route_refresh_peers: HashSet<IpAddr>,
    /// RFC 4271 §9.2.1.1 Minimum Route Advertisement Interval state for IPv4
    /// unicast toward eBGP peers. See [`MraiTracker`].
    pub(crate) mrai: MraiTracker<Ipv4Addr>,
    /// RFC 4271 §9.2.1.1 MRAI state for IPv6 unicast toward eBGP peers.
    pub(crate) mrai_v6: MraiTracker<Ipv6Addr>,
    /// Peers whose outbound UPDATE channel overflowed during the current event.
    ///
    /// The event loop drains this list after each event via [`take_stalled_peers`]
    /// and resets each affected session ([`SessionCommand::AutomaticStop`]) so it
    /// re-establishes and performs a clean full-table dump.
    ///
    /// [`take_stalled_peers`]: DaemonState::take_stalled_peers
    stalled_peers: Vec<IpAddr>,
    /// Per-peer coalescing buffers for outbound IPv4 prefix decisions, in the
    /// order the decisions were made.
    ///
    /// `on_route_update` accumulates decisions here instead of calling
    /// `flush_updates` immediately. The event loop calls `flush_pending` when
    /// the event channel drains (natural quiescence), batching all decisions
    /// that arrived during one burst into the fewest possible UPDATE messages.
    /// Paths that must send at once go through `send_decisions`, which drains
    /// this buffer with them so that nothing overtakes an older decision.
    pub(crate) pending_decisions: HashMap<IpAddr, Vec<PrefixDecision>>,
    /// Per-peer coalescing buffers for outbound IPv6 prefix decisions.
    pub(crate) pending_decisions_v6: HashMap<IpAddr, Vec<PrefixDecisionV6>>,
    /// Peers that have been removed via [`DaemonCommand::RemovePeer`] but whose
    /// session has not yet sent `Terminated`.
    ///
    /// When `Terminated` arrives for a peer in this set, the event loop calls
    /// [`DaemonState::remove_peer`] to erase all per-peer state instead of
    /// resetting it for a reconnect.
    pub(crate) pending_removal: HashSet<IpAddr>,
    /// RFC 4724 §4.2 GR state: active windows, stale-NLRI snapshots, peer families.
    ///
    /// See [`GracefulRestartState`] for field-level documentation.
    pub(crate) gr: GracefulRestartState,
    /// RFC 4724 §4.1 Restarting-Speaker outbound-advertisement deferral.
    ///
    /// `SelectionDeferral::disabled()` until `run_with` wires the real
    /// `daemon_start`/`selection_deferral_time` post-construction — mirrors
    /// `install_rpki_import_terms`'s pattern to avoid touching this
    /// struct's ~30 existing `DaemonState::new()` test call sites.
    pub(crate) selection_deferral: SelectionDeferral,
    /// RFC 9003 shutdown reason strings, keyed by peer address.
    ///
    /// Populated when a peer is added (static or dynamic) and has a
    /// `shutdown_message` configured. Used by `RemovePeer` to send a
    /// CEASE/AdministrativeShutdown NOTIFICATION with the reason attached.
    pub(crate) shutdown_messages: HashMap<IpAddr, String>,
    /// Per-peer IPv4 prefix limit for RFC 4486 §4 enforcement.
    ///
    /// When a peer's `adj_rib_in.len()` (IPv4 only) exceeds this value after
    /// processing an UPDATE, the session is torn down with a
    /// CEASE/MaximumNumberOfPrefixesReached NOTIFICATION.
    ///
    /// Absent when no `max_prefixes_v4` was configured for the peer.
    pub(crate) peer_max_prefixes_v4: HashMap<IpAddr, u32>,
    /// Per-peer IPv6 prefix limit for RFC 4486 §4 enforcement.
    ///
    /// Mirrors `peer_max_prefixes_v4` but checked against `adj_rib_in_v6.len()`.
    /// Either limit firing causes the session to be torn down.
    pub(crate) peer_max_prefixes_v6: HashMap<IpAddr, u32>,
    /// Idle-hold duration (seconds) after a max-prefix CEASE.
    ///
    /// When non-zero, the session is started again this many seconds after the
    /// CEASE. A peer with no entry (`max_prefixes_restart` absent or `0`)
    /// stays down: see `max_prefix_latched`.
    pub(crate) peer_max_prefixes_restart: HashMap<IpAddr, u16>,
    /// Active max-prefix idle-hold deadlines, keyed by peer address.
    ///
    /// Inserted when a max-prefix CEASE is sent and `max_prefixes_restart > 0`.
    /// The session stays stopped until the deadline, when the event loop sends
    /// it [`SessionCommand::Start`] (RFC 4271 §8.1.3 `IdleHoldTimer_Expires`).
    pub(crate) max_prefix_idle: HashMap<IpAddr, Instant>,
    /// Peers stopped by a max-prefix CEASE with no `max_prefixes_restart`.
    ///
    /// Nothing starts these sessions again; only removing the peer (or
    /// restarting the daemon) clears the entry. Held in memory only.
    pub(crate) max_prefix_latched: HashSet<IpAddr>,
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
    /// RFC 7999 §3.3: each session's BLACKHOLE agreement and authorized prefix
    /// scope. A peer without an entry, or whose entry is denied (the default),
    /// has every BLACKHOLE-tagged announcement refused with no FIB effect.
    pub(crate) blackhole_sessions: HashMap<IpAddr, PeerBlackhole>,
    /// RFC 7999: which peers hold an authorized blackhole for which prefix —
    /// the single record of the kernel null routes this daemon asked for.
    pub(crate) blackholes: BlackholeBooks,
    /// Next-hop oracle consulted on every IPv4 best-path recompute (RFC 4271 §9.1
    /// steps 1 & 8). Defaults to `AlwaysReachable`; replaced with `DaemonOracle`
    /// once `KernelFib` is initialised at startup.
    oracle_v4: Arc<dyn NextHopOracle + Send + Sync>,
    /// Next-hop oracle for IPv6 best-path recompute.
    oracle_v6: Arc<dyn NextHopOracle + Send + Sync>,
}

impl DaemonState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        local_as: u32,
        local_bgp_id: Ipv4Addr,
        local_ipv6: Option<Ipv6Addr>,
        cluster_id: Option<u32>,
        confederation_id: Option<u32>,
        peers: &[config::PeerConfig],
        update_senders: HashMap<IpAddr, mpsc::Sender<UpdateMessage>>,
        config_capabilities: Vec<Capability>,
    ) -> Self {
        let rr_clients: HashSet<IpAddr> = peers
            .iter()
            .filter(|p| p.is_rr_client && p.remote_as == local_as)
            .map(|p| p.address)
            .collect();
        let next_hop_self_peers: HashSet<IpAddr> = peers
            .iter()
            .filter(|p| p.next_hop_self)
            .map(|p| p.address)
            .collect();
        let cluster_id = cluster_id.unwrap_or_else(|| u32::from_be_bytes(local_bgp_id.octets()));
        let is_rr = !rr_clients.is_empty();

        // Computed once (rather than inline in each closure below) so the
        // iBGP-guard warning in `effective_role` fires at most once per peer,
        // not once per policy map built from it.
        let peer_roles: HashMap<IpAddr, Role> = peers
            .iter()
            .filter_map(|p| effective_role(p, local_as).map(|r| (p.address, r)))
            .collect();

        let blackhole_sessions: HashMap<IpAddr, PeerBlackhole> = peers
            .iter()
            .map(|p| {
                (
                    p.address,
                    peer_blackhole(p, peer_roles.get(&p.address).copied()),
                )
            })
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

        // A peer's `confederation_member` flag only takes effect when the
        // daemon itself has a `confederation_id` configured — mirrors
        // `effective_confederation_member`'s graceful degradation, without
        // repeating its warning (already logged at session-spawn time,
        // where the full `PeerConfig`/`DaemonConfig` are both in scope).
        let confed_member =
            |p: &config::PeerConfig| p.confederation_member && confederation_id.is_some();

        let peer_config_types = peers
            .iter()
            .map(|p| {
                (
                    p.address,
                    config_peer_type(local_as, p.remote_as, confed_member(p)),
                )
            })
            .collect();

        let (adj_ribs_out, adj_ribs_out_v6) = {
            let mut v4 = HashMap::new();
            let mut v6 = HashMap::new();
            for p in peers {
                let pt = config_peer_type(local_as, p.remote_as, confed_member(p));
                let (aro_v4, aro_v6) = make_adj_ribs_out_pair(
                    PeerId::from(p.address),
                    pt,
                    is_rr.then_some(cluster_id),
                );
                v4.insert(p.address, aro_v4);
                v6.insert(p.address, aro_v6);
            }
            (v4, v6)
        };

        let peer_remote_as = peers.iter().map(|p| (p.address, p.remote_as)).collect();

        let shutdown_messages: HashMap<IpAddr, String> = peers
            .iter()
            .filter_map(|p| p.shutdown_message.as_ref().map(|m| (p.address, m.clone())))
            .collect();

        let peer_max_prefixes_v4: HashMap<IpAddr, u32> = peers
            .iter()
            .filter_map(|p| p.max_prefixes_v4.map(|n| (p.address, n)))
            .collect();

        let peer_max_prefixes_v6: HashMap<IpAddr, u32> = peers
            .iter()
            .filter_map(|p| p.max_prefixes_v6.map(|n| (p.address, n)))
            .collect();

        let peer_max_prefixes_restart: HashMap<IpAddr, u16> = peers
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
            confederation_id,
            peer_bgp_ids: HashMap::new(),
            eor_received: HashSet::new(),
            eor_received_v6: HashSet::new(),
            gr_capable_peers: HashMap::new(),
            gr_advertised_peers: HashSet::new(),
            gr_peer_restarting: HashSet::new(),
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
            mrai: MraiTracker::new(),
            mrai_v6: MraiTracker::new(),
            stalled_peers: Vec::new(),
            pending_decisions: HashMap::new(),
            pending_decisions_v6: HashMap::new(),
            pending_removal: HashSet::new(),
            gr: GracefulRestartState::new(),
            selection_deferral: SelectionDeferral::disabled(),
            shutdown_messages,
            peer_max_prefixes_v4,
            peer_max_prefixes_v6,
            peer_max_prefixes_restart,
            max_prefix_idle: HashMap::new(),
            max_prefix_latched: HashSet::new(),
            route_tx,
            peer_tx,
            fib_manager: None,
            rpki: None,
            blackhole_sessions,
            blackholes: BlackholeBooks::default(),
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
        let local_as = Asn::new(self.rib.local_as);
        for policy in self.import_policies.values_mut() {
            policy.add_term(pathvector_policy::Term::new(
                pathvector_policy::RoaValidityCondition::<Ipv4Addr>::new(
                    rtr.clone(),
                    pathvector_rpki::RoaValidity::Invalid,
                    local_as,
                ),
                pathvector_policy::Reject,
            ));
        }
        for policy in self.import_policies_v6.values_mut() {
            policy.add_term(pathvector_policy::Term::new(
                pathvector_policy::RoaValidityCondition::<Ipv6Addr>::new(
                    rtr.clone(),
                    pathvector_rpki::RoaValidity::Invalid,
                    local_as,
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

/// Resolves whether `peer` should be classified as a confederation
/// Member-AS (RFC 5065), or `false` if confederation membership must not
/// apply to this session.
///
/// Requires `confederation_id` to be configured — a peer with
/// `confederation_member = true` under an unconfigured confederation is
/// treated as a plain eBGP peer. Warns once (rather than failing startup)
/// so a config typo doesn't silently disable a peer, matching
/// [`effective_role`]'s graceful-degradation pattern. Takes the resolved
/// `confederation_id` scalar (rather than the whole `DaemonConfig`) to
/// match `effective_role`'s existing `local_as: u32` convention — callers
/// may only have `SpawnConfig`'s copy of it in scope, not the full config.
fn effective_confederation_member(
    peer: &config::PeerConfig,
    confederation_id: Option<u32>,
) -> bool {
    if !peer.confederation_member {
        return false;
    }
    if confederation_id.is_none() {
        tracing::warn!(
            peer = %peer.address,
            "confederation_member is configured but daemon.confederation_id is unset; \
             ignoring confederation membership for this peer"
        );
        return false;
    }
    true
}

/// The BLACKHOLE agreement a peer's configuration describes (RFC 7999 §3.3):
/// denied unless `blackhole_authorized_prefixes` is set. A session with an
/// RFC 9234 role keeps leak detection in force for blackhole requests.
fn peer_blackhole(peer: &config::PeerConfig, role: Option<Role>) -> PeerBlackhole {
    PeerBlackhole::from_config(
        peer.blackhole_authorized_prefixes.as_ref(),
        role.map(|r| (r, Asn::new(peer.remote_as))),
    )
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
            // The supervisor recovers from netlink loss on its own and
            // reports through the status channel; it returns only if no
            // netlink socket can be opened at all.
            tokio::spawn(crate_fib::log_fib_status(kernel_fib.status()));
            tokio::spawn(async move {
                if let Err(e) = kernel_fib.spawn().await {
                    tracing::error!(
                        "kernel FIB tracking unavailable: {e} — next-hop reachability will \
                         not reflect the kernel routing table"
                    );
                }
            });
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
        guard.selection_deferral =
            SelectionDeferral::new(daemon_start, cfg.daemon.selection_deferral_time);
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
    if let Some(port) = metrics_port {
        match crate::metrics::install(port) {
            Ok(()) => {
                // Pre-register every statically-configured peer so a peer
                // that never reaches Established (misconfigured, unreachable)
                // is still visible as "down" rather than having no metrics
                // series at all — see metrics.rs's `register_peer` doc comment.
                for peer in &cfg.peers {
                    crate::metrics::register_peer(peer.address);
                }
                // Same reasoning for the global Loc-RIB gauges: update_rib_sizes
                // is only called from event-driven sites (post-Established,
                // post-flush), so a daemon with zero established peers would
                // otherwise show no Loc-RIB size at all instead of a real 0.
                crate::metrics::update_rib_sizes(0, 0, &HashMap::new());
                // Same reasoning again for self-originated routes: only
                // touched by origination.rs's event-driven functions, so a
                // daemon that has not yet originated anything would
                // otherwise show no series at all instead of a real 0.
                crate::metrics::update_originated_routes(0, 0);
                // Same reasoning again for the kernel FIB gauge: only touched
                // by fib::process_batch's event-driven success arms, so a
                // daemon that has not yet written anything to the kernel
                // would otherwise show no series at all instead of a real 0.
                crate::metrics::init_fib_routes_installed();
            }
            Err(e) => {
                tracing::warn!(
                    port,
                    error = %e,
                    "metrics endpoint unavailable — running without Prometheus export"
                );
            }
        }
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

    // Spawn the BGP TCP listeners for inbound connections (RFC 4271 §6.8).
    // Two independent listeners (IPv4 and IPv6) rather than one dual-stack
    // socket — see run_bgp_listener's doc comment for why. Each family's
    // bind failure is independent, so e.g. an environment with IPv6 disabled
    // still gets a working IPv4 listener (dial-only for v6 in that case).
    {
        let incoming = Arc::clone(&incoming_senders);
        let md5 = Arc::clone(&md5_passwords);
        let bind_addr_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bgp_port);
        tokio::spawn(async move {
            run_bgp_listener(bind_addr_v4, incoming, md5).await;
        });
    }
    {
        let incoming = Arc::clone(&incoming_senders);
        let md5 = Arc::clone(&md5_passwords);
        let bind_addr_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bgp_port);
        tokio::spawn(async move {
            run_bgp_listener(bind_addr_v6, incoming, md5).await;
        });
    }

    // Spawn the command processor that handles AddPeer / RemovePeer at runtime.
    {
        let state_cmd = Arc::clone(&state);
        let stop_cmd = Arc::clone(&stop_senders);
        let incoming_cmd = Arc::clone(&incoming_senders);
        let keys_cmd = Arc::clone(&md5_passwords);
        let peer_store = cfg
            .sidecar_path
            .as_ref()
            .map(|p| Arc::new(config::DynamicPeerStore::new(p.clone())));
        let proc_handle = tokio::spawn(run_command_processor(
            cmd_rx,
            state_cmd,
            stop_cmd,
            incoming_cmd,
            keys_cmd,
            event_tx,
            spawn_fn,
            SpawnConfig {
                local_as,
                local_bgp_id,
                hold_time,
                graceful_restart_time: cfg.daemon.graceful_restart_time,
                configured_restarting: cfg.daemon.restarting,
                confederation_id: cfg.daemon.confederation_id,
                startup_instant: daemon_start, // R-bit expires after graceful_restart_time secs
                md5_enforcement: cfg.daemon.tcp_md5_enforcement.into(),
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
        let mut guard = crate::lock_timing::write_timed(state, "rpki_install").await;
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
            crate::lock_timing::write_timed(state, "rpki_reeval")
                .await
                .reevaluate_all_import_policies();
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
                crate::lock_timing::write_timed(&reeval_state, "rpki_reeval")
                    .await
                    .reevaluate_all_import_policies();
            }
        });
    }
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
///   the per-peer forwarding tasks, and a sender for it.
/// - The stop-sender map so the event loop can close a session whose outbound
///   channel overflowed.
/// - The incoming-sender map the BGP listeners use to hand inbound
///   connections to sessions.
/// - The TCP MD5 key table for inbound connections, holding every static
///   peer's key. No listener is bound yet; each installs its family's keys
///   when it binds, before it listens.
///
/// Extracted from `run_with()` so it can be driven in tests by supplying a
/// mock `spawn_fn` — no real TCP sockets needed.
pub(crate) async fn build_daemon<H, F>(
    cfg: &config::Config,
    spawn_fn: F,
) -> (
    Arc<RwLock<DaemonState>>,
    mpsc::Receiver<(IpAddr, SessionEvent)>,
    mpsc::Sender<(IpAddr, SessionEvent)>, // kept alive for AddPeer forwarding
    Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    Md5Keys, // RFC 2385 keys for inbound connections
)
where
    H: SessionHandle,
    F: Fn(SessionConfig) -> H,
{
    let local_as = cfg.daemon.local_as;
    let local_bgp_id = cfg.daemon.bgp_id;

    let (event_tx, event_rx) = mpsc::channel::<(IpAddr, SessionEvent)>(256);
    let mut update_senders: HashMap<IpAddr, mpsc::Sender<UpdateMessage>> = HashMap::new();
    // stop_senders: shared with the command processor so AddPeer/RemovePeer can
    // insert/remove without touching the event loop directly.
    let stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // incoming_senders: shared with the BGP listener so AddPeer immediately
    // accepts inbound connections from newly configured peers.
    let incoming_senders: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // md5_passwords: TCP MD5 keys for inbound connections. The listeners
    // install them on their sockets when they bind, before listening.
    let md5_passwords: Md5Keys = Arc::new(ListenerKeys::default());
    let md5_enforcement = Md5Enforcement::from(cfg.daemon.tcp_md5_enforcement);
    warn_if_md5_best_effort(md5_enforcement, &cfg.peers);

    // Capture startup instant here; used to expire the R-bit window per-session.
    let startup_instant = std::time::Instant::now();

    for peer in &cfg.peers {
        let confed_member = effective_confederation_member(peer, cfg.daemon.confederation_id);
        let peer_type = config_peer_type(local_as, peer.remote_as, confed_member);
        let public_as = effective_session_as(local_as, cfg.daemon.confederation_id, peer_type);
        // Recompute capabilities for each session so the R-bit correctly reflects
        // elapsed time since startup (RFC 4724 §3: R-bit must be cleared after restart).
        let capabilities = build_local_capabilities(
            public_as,
            cfg.daemon.graceful_restart_time,
            cfg.daemon.restarting
                && cfg.daemon.graceful_restart_time > 0
                && startup_instant.elapsed()
                    < std::time::Duration::from_secs(u64::from(cfg.daemon.graceful_restart_time)),
            effective_role(peer, local_as),
        );
        let session_cfg = SessionConfig {
            local_as,
            public_as,
            local_bgp_id,
            hold_time: peer.hold_time.unwrap_or(cfg.daemon.hold_time),
            capabilities,
            required_capabilities: vec![],
            peer_as: Some(peer.remote_as),
            confederation_member: confed_member,
            peer_addr: SocketAddr::new(peer.address, peer.port),
            tcp_md5: session_tcp_md5(peer, md5_enforcement),
            connect_retry_time: peer
                .connect_retry_time
                .map_or(DEFAULT_CONNECT_RETRY_TIME, |s| {
                    std::time::Duration::from_secs(u64::from(s))
                }),
            // RFC 9687 §6 RECOMMENDS enabling it without configuration.
            send_hold_time: SendHoldTime::RECOMMENDED,
        };

        // The listener key is configured before the peer can appear in
        // incoming_senders.
        if let Some(auth) = session_tcp_md5(peer, md5_enforcement) {
            set_listener_key(&md5_passwords, peer.address, auth);
        }

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
            .insert(peer.address, handle.incoming_sender());
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
        cfg.daemon.confederation_id,
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

/// A [`SessionCommand::SetCapabilities`] owed to a session whose teardown has
/// just been processed.
///
/// Built under the state write lock and sent after it is released, so the lock
/// is never held across the channel send.
#[must_use = "send the capability refresh once the state lock is released"]
struct CapabilityRefresh {
    session: mpsc::Sender<SessionCommand>,
    capabilities: Vec<Capability>,
}

impl CapabilityRefresh {
    async fn send(self) {
        let _ = self
            .session
            .send(SessionCommand::SetCapabilities(self.capabilities))
            .await;
    }
}

/// Handles one [`SessionEvent::Terminated`].
///
/// This is the only handler for that event: `run_event_loop` calls it both for
/// the event that starts a batch and for events coalesced behind it, which used
/// to be two copies that drifted apart (GH #105, GH #148).
///
/// Returns the capability refresh the session needs before its next OPEN, or
/// `None` if the peer was being removed (or has no command channel).
fn handle_session_terminated(
    s: &mut DaemonState,
    peer_ip: IpAddr,
    termination_reason: TerminationReason,
    stop_senders: &Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>,
) -> Option<CapabilityRefresh> {
    let is_removed = s.pending_removal.remove(&peer_ip);
    // Capture identity fields while they are still in the RIB.  on_terminated
    // clears session-level state (peer_types, hold_times, etc.); remove_peer
    // clears everything including peer_remote_as.  Both run below.
    let removal_identity = if is_removed {
        s.rib
            .peer_remote_as
            .get(&peer_ip)
            .copied()
            .map(|remote_as| (remote_as, s.rib.local_as))
    } else {
        None
    };
    // Recorded before `on_terminated` consumes the reason.
    crate::metrics::on_session_terminated(peer_ip, &termination_reason);
    // For removal, suppress the intermediate Changed(None) broadcast — the
    // explicit Removed event below is the authoritative notification.
    s.on_terminated(peer_ip, termination_reason, !is_removed);

    if is_removed {
        // Permanent removal: erase all per-peer state so the peer no longer
        // appears in gRPC responses and remove the stop sender so no further
        // commands can be sent to this session.
        s.remove_peer(peer_ip);
        stop_senders.lock().unwrap().remove(&peer_ip);
        // Broadcast a Removed event carrying the last-known remote_as and
        // local_as so watch_peers subscribers can identify the removed peer
        // without re-reading a snapshot that no longer contains it.
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
        return None;
    }

    // RFC 4724 §4.2: when re-establishing a session, the Restart State (R) bit
    // "MUST NOT be set unless the Receiving Speaker has restarted". The session
    // may still hold the R=1/F=0 set it was spawned with after our restart, so
    // replace it: this teardown was not a restart of ours, and F=0 would make
    // the peer delete the routes it retained for us.
    let gr_time = s
        .config_capabilities
        .iter()
        .find_map(|c| {
            if let Capability::GracefulRestart { restart_time, .. } = c {
                Some(*restart_time)
            } else {
                None
            }
        })
        .unwrap_or(0);
    // RFC 5065 §4: the FourByteAsn capability must carry the same AS number as
    // `my_as` — the Confederation Identifier for `External` peers, the
    // Member-AS Number otherwise.  `peer_config_types` survives disconnects
    // (only cleared on permanent removal), so it reflects this peer's static
    // classification here.
    let peer_type = s
        .peer_config_types
        .get(&peer_ip)
        .copied()
        .unwrap_or(PeerType::External);
    let public_as = effective_session_as(s.rib.local_as, s.rib.confederation_id, peer_type);
    let capabilities = build_local_capabilities(
        public_as,
        gr_time,
        false,
        s.rib.peer_roles.get(&peer_ip).copied(),
    );
    let session = stop_senders.lock().unwrap().get(&peer_ip).cloned()?;
    Some(CapabilityRefresh {
        session,
        capabilities,
    })
}

/// Stops a session that must not come back by itself
/// ([`SessionCommand::Notification`]), with a Cease of the given subcode.
fn hold_down(subcode: CeaseError) -> SessionCommand {
    SessionCommand::Notification(NotificationMessage {
        error: NotificationError::Cease(subcode),
        data: vec![],
    })
}

/// The command for a NOTIFICATION that `on_route_update` asks for.
///
/// After a maximum-prefix CEASE the session stays stopped: the daemon starts it
/// again itself if `max_prefixes_restart` is set, and otherwise only an
/// operator does. Any other (an UPDATE error) reconnects by itself.
fn route_reset(notification: NotificationMessage) -> SessionCommand {
    if notification.error == NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached) {
        SessionCommand::Notification(notification)
    } else {
        SessionCommand::AutomaticStop(notification)
    }
}

/// A reset of a session that should come back by itself
/// ([`SessionCommand::AutomaticStop`]), with a Cease of the given subcode.
fn automatic_stop(subcode: CeaseError) -> SessionCommand {
    SessionCommand::AutomaticStop(NotificationMessage {
        error: NotificationError::Cease(subcode),
        data: vec![],
    })
}

pub(crate) async fn run_event_loop(
    mut event_rx: mpsc::Receiver<(IpAddr, SessionEvent)>,
    state: Arc<RwLock<DaemonState>>,
    stop_senders: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
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
                // `event_batch` covers the whole lock hold: the triggering
                // event plus every event coalesced by the drain loop below.
                let mut s = crate::lock_timing::write_timed(&state, "event_batch").await;
                match event {
                    SessionEvent::Established(info) => {
                        // A peer held down after a max-prefix CEASE is not
                        // registered, even if its session got as far as
                        // Established before the stop reached it. Skipping
                        // `on_established` leaves the session unregistered, so
                        // `on_route_update` ignores any UPDATE already queued.
                        if s.is_max_prefix_held(peer_ip) {
                            tracing::info!(
                                peer = %peer_ip,
                                "held down after max-prefix — rejecting session"
                            );
                            drop(s);
                            let tx = stop_senders.lock().unwrap().get(&peer_ip).cloned();
                            if let Some(tx) = tx {
                                let _ = tx.send(hold_down(CeaseError::ConnectionRejected)).await;
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
                        // Snapshot RIB sizes after the full-table dump so
                        // adj_rib_out reflects the session bring-up immediately.
                        crate::metrics::update_rib_sizes(
                            s.rib.loc_rib.len(),
                            s.rib.loc_rib_v6.len(),
                            &s.rib.prefixes_advertised,
                        );
                    }
                    SessionEvent::Terminated(termination_reason) => {
                        let refresh = handle_session_terminated(
                            &mut s,
                            peer_ip,
                            termination_reason,
                            &stop_senders,
                        );
                        // This arm skips the end-of-batch gauge refresh below, so
                        // refresh the RIB-size gauges here: the peer's routes have
                        // just been flushed (GH #105).
                        crate::metrics::update_rib_sizes(
                            s.rib.loc_rib.len(),
                            s.rib.loc_rib_v6.len(),
                            &s.rib.prefixes_advertised,
                        );
                        // Drop the write guard before awaiting so we don't hold the
                        // lock while the channel send blocks, then skip the coalescing
                        // loop (no pending_decisions were touched in Terminated path).
                        drop(s);
                        if let Some(refresh) = refresh {
                            refresh.send().await;
                        }
                        continue;
                    }
                    SessionEvent::RouteUpdate(msg) => {
                        let notify_err = s.on_route_update(peer_ip, msg);
                        let adj_in = s.rib.prefixes_received.get(&peer_ip).copied().unwrap_or(0);
                        crate::metrics::on_route_update(peer_ip, adj_in);
                        // handle_update returns Some(NotificationMessage) only for
                        // conditions RFC 7606 still classifies as session-reset-worthy
                        // (e.g. duplicate MP_REACH/MP_UNREACH_NLRI — Malformed Attribute
                        // List). A missing well-known mandatory attribute is normally
                        // NOT one of them: RFC 7606 §3(d) requires treat-as-withdraw
                        // instead, and handle_update returns None for that case. The
                        // exception is RFC 7606 §5.2 "Missing NLRI": an UPDATE with path
                        // attributes other than MP_UNREACH_NLRI but no reachable NLRI at
                        // all can't be confidently treated-as-withdraw (there's nothing
                        // reliable to withdraw), so a missing-mandatory-attribute error
                        // in that specific shape still resets the session here.
                        if let Some(err) = notify_err {
                            // Flush pending decisions for other peers before
                            // tearing this one down so they don't starve.
                            s.flush_pending();
                            let stalled = s.take_stalled_peers();
                            drop(s);
                            let tx = stop_senders.lock().unwrap().get(&peer_ip).cloned();
                            if let Some(tx) = tx {
                                let _ = tx.send(route_reset(err)).await;
                            }
                            // Process any stalled peers before next iteration.
                            for peer in stalled {
                                let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                                if let Some(tx) = tx {
                                    let _ = tx.send(automatic_stop(CeaseError::OutOfResources)).await;
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
                // The drain loop has two ways out: the channel is empty, or a
                // coalesced UPDATE needs a NOTIFICATION. Both fall through to
                // the code after the loop, so what the batch owes is sent from
                // one place. Leave the loop only with `break`: skipping that
                // code drops commands the batch has already promised.
                //
                // Peers that reconnected while held down after a max-prefix
                // CEASE; their stop is sent after the drain loop alongside the
                // stalled peers' resets
                // to avoid dropping and re-acquiring the write lock mid-iteration.
                let mut idle_hold_rejected: Vec<IpAddr> = Vec::new();
                // Owed by coalesced `Terminated` events.
                let mut capability_refreshes: Vec<CapabilityRefresh> = Vec::new();
                // Set when a coalesced UPDATE ends the batch early.
                let mut notification: Option<(IpAddr, NotificationMessage)> = None;

                // PR-1: the drain loop has no cap, so batch size is the main
                // driver of `event_batch` lock-hold time. Counted here
                // (primary event + each coalesced one) and recorded once the
                // channel is empty; the NOTIFICATION paths skip it.
                let mut batch_events: u32 = 1;

                while let Ok((extra_ip, extra_event)) = event_rx.try_recv() {
                    batch_events += 1;
                    match extra_event {
                        SessionEvent::Established(info) => {
                            // Same max-prefix guard as the primary Established arm.
                            if s.is_max_prefix_held(extra_ip) {
                                tracing::info!(
                                    peer = %extra_ip,
                                    "held down after max-prefix — rejecting session (coalesced)"
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
                            // Same hook as the first-event arm: coalescing must
                            // not change what gets recorded (GH #105).
                            crate::metrics::on_session_established(extra_ip);
                        }
                        SessionEvent::Terminated(termination_reason) => {
                            capability_refreshes.extend(handle_session_terminated(
                                &mut s,
                                extra_ip,
                                termination_reason,
                                &stop_senders,
                            ));
                        }
                        SessionEvent::RouteUpdate(msg) => {
                            // See the primary RouteUpdate arm above: this only
                            // fires for the session-reset-worthy conditions RFC
                            // 7606 still calls for (not a missing mandatory
                            // attribute, which is now treat-as-withdraw and
                            // returns None here).
                            let notify_err = s.on_route_update(extra_ip, msg);
                            // Counted per UPDATE and the Adj-RIB-In gauge set from
                            // live state, exactly as in the first-event arm; both
                            // used to be skipped for coalesced events (GH #105).
                            let adj_in = s
                                .rib
                                .prefixes_received
                                .get(&extra_ip)
                                .copied()
                                .unwrap_or(0);
                            crate::metrics::on_route_update(extra_ip, adj_in);
                            if let Some(err) = notify_err {
                                notification = Some((extra_ip, err));
                                break;
                            }
                        }
                    }
                }
                // After an early exit the channel may not be empty, so the
                // batch size is not recorded.
                if notification.is_none() {
                    metrics::histogram!("pathvectord_event_loop_batch_events")
                        .record(f64::from(batch_events));
                }
                // Flush all accumulated outbound decisions. On the early exit
                // this keeps other peers from starving behind the teardown.
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

                // Before any reset below: a session being reset still needs
                // the new set for its next OPEN.
                for refresh in capability_refreshes {
                    refresh.send().await;
                }

                // Before the other resets, so a session that is also stalled
                // still reports why it is being reset.
                if let Some((peer, err)) = notification {
                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(route_reset(err)).await;
                    }
                }

                for peer in stalled {
                    tracing::error!(
                        peer = %peer,
                        "closing session: outbound UPDATE channel overflowed; \
                         session will re-establish and perform a fresh full-table dump"
                    );
                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(automatic_stop(CeaseError::OutOfResources)).await;
                    }
                }

                for peer in idle_hold_rejected {
                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(hold_down(CeaseError::ConnectionRejected)).await;
                    }
                }
            }

            Ok(()) = fib_changed => {
                let mut s = crate::lock_timing::write_timed(&state, "fib_change").await;
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
                        let _ = tx.send(automatic_stop(CeaseError::OutOfResources)).await;
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
                let expired: Vec<IpAddr> = {
                    let mut s = crate::lock_timing::write_timed(&state, "gr_deadline").await;
                    let expired = s.gr.drain_expired(now);
                    for peer_ip in &expired {
                        s.on_gr_deadline_expired(*peer_ip);
                    }
                    expired
                };
                if !expired.is_empty() {
                    let stalled = crate::lock_timing::write_timed(&state, "gr_deadline")
                        .await
                        .take_stalled_peers();
                    for peer in stalled {
                        tracing::error!(
                            peer = %peer,
                            "closing session: outbound UPDATE channel overflowed during GR deadline flush"
                        );
                        let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(automatic_stop(CeaseError::OutOfResources)).await;
                        }
                    }
                }
            }

            // RFC 4724 §4.1 — Selection_Deferral_Timer.  Fires once, at
            // whichever family still hasn't released by the deadline (path
            // (b) — the wait-set-satisfied path (a) is driven reactively by
            // `recompute_selection_deferral` on EOR receipt / establishment /
            // permanent removal, not by this timer). `pending_deadline()`
            // returns `None` once both families are released, or when the
            // feature is disabled, so this branch is dormant in the common
            // case.
            () = async {
                let deadline = state.read().await.selection_deferral.pending_deadline();
                match deadline {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None    => std::future::pending::<()>().await,
                }
            } => {
                let mut s = crate::lock_timing::write_timed(&state, "selection_deferral").await;
                tracing::warn!(
                    "RFC 4724 §4.1: selection-deferral timer expired — \
                     releasing any still-deferred address family unconditionally"
                );
                s.force_release_selection_deferral();
                s.flush_pending();
                let stalled = s.take_stalled_peers();
                drop(s);

                for peer in stalled {
                    tracing::error!(
                        peer = %peer,
                        "closing session: outbound UPDATE channel overflowed during \
                         selection-deferral timer flush"
                    );
                    let tx = stop_senders.lock().unwrap().get(&peer).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(automatic_stop(CeaseError::OutOfResources)).await;
                    }
                }
            }

            // Max-prefix idle-hold expiry timer.  When no
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
                let mut s = crate::lock_timing::write_timed(&state, "max_prefix_idle").await;
                let expired: Vec<IpAddr> = s
                    .max_prefix_idle
                    .iter()
                    .filter(|(_, deadline)| *deadline <= &now)
                    .map(|(ip, _)| *ip)
                    .collect();
                for peer_ip in expired {
                    s.max_prefix_idle.remove(&peer_ip);
                    // A peer being removed has been sent its stop already.
                    if s.pending_removal.contains(&peer_ip) {
                        continue;
                    }
                    let session = stop_senders.lock().unwrap().get(&peer_ip).cloned();
                    let Some(session) = session else { continue };
                    // Sent without releasing the state lock, so a concurrent
                    // `RemovePeer` cannot queue its stop ahead of this start.
                    // That rules out waiting for room in the channel.
                    if let Err(TrySendError::Full(_)) = session.try_send(SessionCommand::Start) {
                        s.max_prefix_idle
                            .insert(peer_ip, now + std::time::Duration::from_millis(100));
                        continue;
                    }
                    tracing::info!(
                        peer = %peer_ip,
                        "max-prefix idle-hold expired — restarting session"
                    );
                }
            }

            _ = mrai_timer.tick() => {
                let mut s = crate::lock_timing::write_timed(&state, "mrai").await;
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
                            let _ = tx.send(automatic_stop(CeaseError::OutOfResources)).await;
                        }
                    }
                }
            }
        }
    }
}
