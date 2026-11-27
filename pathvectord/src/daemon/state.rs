//! [`DaemonState`]: the routing state the daemon's use cases operate on.
//!
//! Construction lives here. The behaviour is in sibling modules, one
//! `impl DaemonState` block per concern (session lifecycle, route processing,
//! policy changes, origination, Graceful Restart, FIB notifications).

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};

use pathvector_policy::Policy;
use pathvector_rib::{
    AdjRibIn, AdjRibOut, LocRib, PeerId, Route,
    oracle::{AlwaysReachable, NextHopOracle},
};
use pathvector_session::message::{Capability, UpdateMessage};
use pathvector_types::{Asn, PeerType, Role};
use tokio::sync::{broadcast, mpsc};

use super::{
    RibSnapshot,
    blackhole::{BlackholeBooks, PeerBlackhole},
    deferral::SelectionDeferral,
    gr::GracefulRestartState,
    peering::{
        base_export_policy, config_peer_type, effective_role, import_policy_pair,
        install_rov_import_term, make_adj_ribs_out_pair, peer_blackhole,
    },
    route::MraiTracker,
};
use crate::outbound::{PrefixDecision, PrefixDecisionV6};
use crate::{config, fib as crate_fib, proto};
use crate_fib::ApplyFibChange;

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
    /// Set to [`MAX_LEN_EXTENDED`](pathvector_session::message::MAX_LEN_EXTENDED) (65535) when both sides negotiated
    /// `Capability::ExtendedMessage`; otherwise [`MAX_LEN`](pathvector_session::message::MAX_LEN) (4096).
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
    /// and resets each affected session ([`SessionCommand::AutomaticStop`](pathvector_session::transport::SessionCommand::AutomaticStop)) so it
    /// re-establishes and performs a clean full-table dump.
    ///
    /// [`take_stalled_peers`]: DaemonState::take_stalled_peers
    pub(super) stalled_peers: Vec<IpAddr>,
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
    /// Peers that have been removed via [`DaemonCommand::RemovePeer`](super::DaemonCommand::RemovePeer) but whose
    /// session has not yet sent `Retired`.
    ///
    /// While a peer is in this set, `Terminated` opens no restart window and
    /// `AddPeer` for its address is ignored. When `Retired` arrives, the event
    /// loop calls [`DaemonState::remove_peer`] to erase all per-peer state.
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
    /// it [`SessionCommand::Start`](pathvector_session::transport::SessionCommand::Start) (RFC 4271 §8.1.3 `IdleHoldTimer_Expires`).
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
    /// Set when import policy rejects RPKI-Invalid routes
    /// (`reject_invalid = true`), so `add_peer` gives a new peer the same term.
    /// `None` in monitoring-only mode, even though `rpki` is set then.
    pub(super) rov_reject: Option<pathvector_rpki::RtrHandle>,
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
    pub(super) oracle_v4: Arc<dyn NextHopOracle + Send + Sync>,
    /// Next-hop oracle for IPv6 best-path recompute.
    pub(super) oracle_v6: Arc<dyn NextHopOracle + Send + Sync>,
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

        let (import_policies, import_policies_v6) = peers
            .iter()
            .map(|p| {
                let role = peer_roles.get(&p.address).copied();
                let (v4, v6) = import_policy_pair(p, local_as, role, None);
                ((p.address, v4), (p.address, v6))
            })
            .unzip();

        let export_policies = peers
            .iter()
            .map(|p| {
                let role = peer_roles.get(&p.address).copied();
                let policy = base_export_policy(p.export_default, local_as, p.remote_as, role);
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
                let role = peer_roles.get(&p.address).copied();
                let policy = base_export_policy(p.export_default, local_as, p.remote_as, role);
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
            rov_reject: None,
            blackhole_sessions,
            blackholes: BlackholeBooks::default(),
            oracle_v4: Arc::new(AlwaysReachable),
            oracle_v6: Arc::new(AlwaysReachable),
        }
    }

    /// Turns on RFC 6811 reject-Invalid: appends the term to every configured
    /// peer's IPv4 and IPv6 import policy, and records `rtr` so peers added
    /// later get it too.
    ///
    /// Called once, right after the RTR client is spawned — `DaemonState::new`
    /// itself takes no RPKI parameter, since the RTR handle isn't available
    /// until after construction and threading it through would touch this
    /// struct's many existing test call sites.
    pub(crate) fn install_rpki_import_terms(&mut self, rtr: &pathvector_rpki::RtrHandle) {
        let local_as = Asn::new(self.rib.local_as);
        for policy in self.import_policies.values_mut() {
            install_rov_import_term(policy, rtr, local_as);
        }
        for policy in self.import_policies_v6.values_mut() {
            install_rov_import_term(policy, rtr, local_as);
        }
        self.rov_reject = Some(rtr.clone());
    }
}
