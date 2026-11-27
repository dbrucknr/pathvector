//! [`RibSnapshot`]: the read-heavy half of the daemon's routing state.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use pathvector_rib::LocRib;
use pathvector_types::{Nlri, PeerType, Role};

/// Immutable-ish snapshot of the read-heavy routing state.
///
/// Stored inside `DaemonState` as an `Arc<RibSnapshot>`. The event loop
/// mutates it via [`Arc::make_mut`](std::sync::Arc::make_mut) (zero-cost when no readers hold a clone;
/// a full deep copy of both Loc-RIBs when one does). Handlers that must walk
/// the table (`list_routes`, `watch_routes`, ...) clone the `Arc` in O(1) and
/// release the outer `RwLock`; that clone is the price of a slow scan.
/// Handlers that only need per-peer facts (`list_peers`, `get_peer`,
/// `watch_peers`) must not take that clone: they read the counters through
/// [`peer_stats`](super::peer_stats) under the read guard, which costs O(peers) and never
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
    pub(super) fn reflector_cluster_id(&self) -> Option<u32> {
        (!self.rr_clients.is_empty()).then_some(self.cluster_id)
    }
}
