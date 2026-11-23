//! Kernel FIB integration via Linux netlink (`RTM_NEWROUTE` / `RTM_DELROUTE`).
//!
//! # Design
//!
//! Three components cooperate to provide live next-hop reachability to the BGP
//! decision process:
//!
//! - [`FibSnapshot`] — an in-memory copy of the **IGP / kernel routing table**
//!   for one or both address families. Cheap to query under a shared `RwLock`.
//! - [`KernelFib`] — drives the snapshot: dumps the initial kernel FIB on
//!   startup and then applies `RTM_NEWROUTE` / `RTM_DELROUTE` netlink events as
//!   they arrive. Signals change via a `watch` channel so the daemon can
//!   re-evaluate best-paths whose next-hops were affected.
//! - [`KernelOracle`] — a thin wrapper that consumers can hold to query
//!   the snapshot; see `pathvectord::fib` for the `NextHopOracle` impl.
//!
//! # BGP route exclusion
//!
//! Routes tagged `RTPROT_BGP` (protocol 186) are **excluded** from
//! [`FibSnapshot`].  This matches the approach used by BIRD (`krt.c`
//! protocol-tag filter) and FRR/Zebra (`rtm_protocol` skip in
//! `kernel_netlink.c`).  The reasons are:
//!
//! 1. **No feedback loop** — every route `FibWriter` installs generates a
//!    `RTM_NEWROUTE` multicast event.  Including it in the snapshot would fire
//!    `change_tx`, waking the event loop and triggering a full `recompute_all`
//!    scan over the Loc-RIB — for every single FIB install.
//!
//! 2. **Semantic correctness** — the oracle answers "is there an IGP/kernel
//!    path to this next-hop?"  BGP routes are *destinations* we compute from,
//!    not the IGP paths we use to *reach* BGP next-hops.  Recursive next-hop
//!    resolution (a BGP route whose next-hop is itself reachable only via
//!    another BGP route) is a distinct, explicitly opt-in feature not yet
//!    implemented here.
//!
//! Recursive next-hop resolution (tracked in TODO.md) is explicitly not
//! implemented — see TODO.md § "Recursive next-hop resolution".
//!
//! # Platform behaviour
//!
//! On Linux the implementation uses `rtnetlink` for the initial route dump and
//! a raw `NETLINK_ROUTE` multicast socket for ongoing change events.
//!
//! On non-Linux platforms (macOS, used for development) the module compiles but
//! [`KernelFib::spawn`] is a no-op. The snapshot stays empty and the
//! daemon falls back to `AlwaysReachable`.
//!
//! # Startup sequence
//!
//! To avoid a race between the initial dump and arriving change events:
//!
//! 1. Open the multicast socket and subscribe to route groups **first**.
//! 2. Dump the current kernel FIB into the snapshot.
//! 3. Apply any events that arrived during or after the dump (idempotent).
//!
//! This guarantees the snapshot is always at least as fresh as the kernel
//! table at the time the dump completed.

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, RwLock},
};

use tokio::sync::watch;

// ── Platform-specific FibWriter ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::FibWriter;

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub use stub::FibWriter;

// ── FibWrite trait ────────────────────────────────────────────────────────────

/// Capability to write routes into the kernel FIB.
///
/// Implemented by [`FibWriter`] on every supported platform. Callers that
/// accept `impl FibWrite` (or `W: FibWrite`) receive static dispatch —
/// the compiler monomorphises the call site and the vtable is never needed.
///
/// Async methods return `impl Future<Output = io::Result<()>> + Send + '_`
/// so that callers inside `tokio::spawn` blocks can `.await` them safely.
/// The `'_` lifetime ties the returned future to `&self`, which is necessary
/// for implementations (like the Linux backend) that borrow internal handles
/// across the await point.
pub trait FibWrite {
    /// Install or replace an IPv4 prefix route via `gateway`.
    fn install_v4(
        &self,
        dst: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Remove an IPv4 prefix route.
    fn withdraw_v4(
        &self,
        dst: Ipv4Addr,
        prefix_len: u8,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Install or replace an IPv6 prefix route via `gateway`.
    fn install_v6(
        &self,
        dst: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Remove an IPv6 prefix route.
    fn withdraw_v6(
        &self,
        dst: Ipv6Addr,
        prefix_len: u8,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Install a kernel blackhole (null) route for an IPv4 prefix (RFC 7999).
    ///
    /// Uses `RTN_BLACKHOLE` — the kernel silently drops all matching packets.
    /// No gateway is needed. `NLM_F_REPLACE` makes this idempotent.
    fn install_blackhole_v4(
        &self,
        dst: Ipv4Addr,
        prefix_len: u8,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Remove a kernel blackhole route for an IPv4 prefix.
    fn withdraw_blackhole_v4(
        &self,
        dst: Ipv4Addr,
        prefix_len: u8,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Install a kernel blackhole (null) route for an IPv6 prefix (RFC 7999).
    fn install_blackhole_v6(
        &self,
        dst: Ipv6Addr,
        prefix_len: u8,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Remove a kernel blackhole route for an IPv6 prefix.
    fn withdraw_blackhole_v6(
        &self,
        dst: Ipv6Addr,
        prefix_len: u8,
    ) -> impl Future<Output = io::Result<()>> + Send + '_;
}

// ── FibSnapshot ──────────────────────────────────────────────────────────────

mod route;
pub(crate) use route::RouteList;
pub use route::{
    FibLookup, Ipv4Prefix, Ipv6Prefix, KernelRouteV4, KernelRouteV6, MultipathLeg, NextHopPath,
    NextHopV4, NextHopV6, PrefixError, RejectKind, RouteKind, RoutePreference, RouteSlotV4,
    RouteSlotV6, TableId,
};

/// Returns `true` if `addr` is a link-local IPv6 address (`fe80::/10`).
///
/// Link-local addresses are always on-link and are not stored in the main
/// routing table, so they must be handled explicitly rather than via LPM.
fn is_link_local_v6(addr: Ipv6Addr) -> bool {
    let o = addr.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// In-memory copy of the kernel routing table.
///
/// Updated by [`KernelFib`] under a write lock; read concurrently by
/// [`KernelOracle`] instances in the decision process.
///
/// # Route identity
///
/// A destination prefix does **not** identify a kernel route: Linux keeps
/// several routes per prefix, distinguished by table, priority (metric),
/// IPv4 TOS, IPv6 source prefix and next hop. The snapshot stores each route
/// under its full kernel identity ([`KernelRouteV4`], [`KernelRouteV6`]), so
/// adding a backup route never overwrites the primary and deleting one route
/// leaves the others in place. See the `route` module docs for the kernel
/// source this follows.
///
/// # Lookup
///
/// Reachability queries use longest-prefix match. Among the routes for the
/// longest matching prefix, the one with the lowest priority wins, as in the
/// kernel. IPv4 routes with a non-zero TOS and IPv6 routes with a source
/// prefix are kept but never selected, because a best-effort lookup from an
/// unspecified source cannot match them.
///
/// The selected route's [`RouteKind`] then decides the outcome
/// ([`FibLookup`]). Only a unicast route makes the destination reachable; its
/// priority is returned as the IGP metric for the RFC 4271 §9.1.2.2 step 8
/// tiebreaker. A `blackhole`, `unreachable`, `prohibit` or `throw` route
/// makes every destination it covers unreachable, even when a shorter unicast
/// route also covers them, because the kernel does not fall back to a shorter
/// prefix once a negative route is selected. See the `route` module docs for
/// the kernel source and for how `throw` is treated.
#[derive(Debug, Default, Clone)]
pub struct FibSnapshot {
    pub(crate) v4: RouteList<KernelRouteV4>,
    pub(crate) v6: RouteList<KernelRouteV6>,
}

impl FibSnapshot {
    /// Creates an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every IPv4 route in the snapshot, in kernel order within each slot.
    pub fn routes_v4(&self) -> impl Iterator<Item = &KernelRouteV4> {
        self.v4.iter()
    }

    /// Every IPv6 route in the snapshot, in kernel order within each slot.
    pub fn routes_v6(&self) -> impl Iterator<Item = &KernelRouteV6> {
        self.v6.iter()
    }

    /// How the kernel's lookup for best-effort IPv4 traffic to `addr` ends.
    #[must_use]
    pub fn lookup_v4(&self, addr: Ipv4Addr) -> FibLookup<'_, KernelRouteV4> {
        self.v4.resolve(addr)
    }

    /// How the kernel's lookup for IPv6 traffic to `addr` from an unspecified
    /// source ends. Link-local addresses are not special-cased here.
    #[must_use]
    pub fn lookup_v6(&self, addr: Ipv6Addr) -> FibLookup<'_, KernelRouteV6> {
        self.v6.resolve(addr)
    }

    /// The unicast IPv4 route the kernel would forward best-effort traffic to
    /// `addr` along, or `None` if the lookup ends in no route or a negative
    /// route.
    #[must_use]
    pub fn route_to_v4(&self, addr: Ipv4Addr) -> Option<&KernelRouteV4> {
        self.lookup_v4(addr).forwarding()
    }

    /// The unicast IPv6 route the kernel would forward traffic to `addr` from
    /// an unspecified source along, or `None` if the lookup ends in no route
    /// or a negative route. Link-local addresses are not special-cased here.
    #[must_use]
    pub fn route_to_v6(&self, addr: Ipv6Addr) -> Option<&KernelRouteV6> {
        self.lookup_v6(addr).forwarding()
    }

    /// Returns `true` if the lookup for `addr` ends in a unicast IPv4 route.
    #[must_use]
    pub fn is_v4_reachable(&self, addr: Ipv4Addr) -> bool {
        self.lookup_v4(addr).is_reachable()
    }

    /// Returns the priority of the unicast IPv4 route the kernel would use for
    /// `addr`, or `None` if `addr` is not reachable.
    #[must_use]
    pub fn igp_metric_v4(&self, addr: Ipv4Addr) -> Option<u32> {
        self.route_to_v4(addr).map(|r| r.slot.priority)
    }

    /// Returns `true` if the lookup for `addr` ends in a unicast IPv6 route.
    ///
    /// A link-local address (`fe80::/10`) that no route covers is considered
    /// reachable: it is on-link by definition, and this lookup has no output
    /// interface to find the per-interface `fe80::/64` route with. The
    /// fallback applies only when the lookup finds **no** route. A negative
    /// route that covers the address is honoured like anywhere else, since the
    /// kernel rejects that traffic too (`RTM_GETROUTE` for an address beneath
    /// a `prohibit` route answers `EACCES`).
    #[must_use]
    pub fn is_v6_reachable(&self, addr: Ipv6Addr) -> bool {
        match self.lookup_v6(addr) {
            FibLookup::Forward(_) => true,
            FibLookup::Reject { .. } | FibLookup::Throw(_) => false,
            FibLookup::NoRoute => is_link_local_v6(addr),
        }
    }

    /// Returns the priority of the unicast IPv6 route the kernel would use for
    /// `addr`, or `None` if `addr` is not reachable through a route.
    #[must_use]
    pub fn igp_metric_v6(&self, addr: Ipv6Addr) -> Option<u32> {
        self.route_to_v6(addr).map(|r| r.slot.priority)
    }
}

// ── KernelOracle ─────────────────────────────────────────────────────────────

/// A handle into a [`FibSnapshot`] for next-hop reachability queries.
///
/// Cheap to clone — shares the `Arc<RwLock<FibSnapshot>>` with
/// [`KernelFib`]. The daemon wraps this in its `NextHopOracle` impl.
///
/// See `pathvectord::fib::KernelOracle` for the `NextHopOracle` impl.
#[derive(Clone)]
pub struct KernelOracle {
    pub(crate) snapshot: Arc<RwLock<FibSnapshot>>,
}

impl KernelOracle {
    /// Returns `true` if `addr` is reachable according to the live snapshot.
    ///
    /// # Panics
    ///
    /// Panics if the `FibSnapshot` `RwLock` is poisoned (another thread panicked
    /// while holding the write lock — an unrecoverable state).
    #[must_use]
    pub fn is_v4_reachable(&self, addr: Ipv4Addr) -> bool {
        self.snapshot
            .read()
            .expect("FibSnapshot RwLock poisoned")
            .is_v4_reachable(addr)
    }

    /// Returns the IGP metric for `addr`, if known.
    ///
    /// # Panics
    ///
    /// Panics if the `FibSnapshot` `RwLock` is poisoned.
    #[must_use]
    pub fn igp_metric_v4(&self, addr: Ipv4Addr) -> Option<u32> {
        self.snapshot
            .read()
            .expect("FibSnapshot RwLock poisoned")
            .igp_metric_v4(addr)
    }

    /// Returns `true` if `addr` is reachable according to the live snapshot.
    ///
    /// # Panics
    ///
    /// Panics if the `FibSnapshot` `RwLock` is poisoned.
    #[must_use]
    pub fn is_v6_reachable(&self, addr: Ipv6Addr) -> bool {
        self.snapshot
            .read()
            .expect("FibSnapshot RwLock poisoned")
            .is_v6_reachable(addr)
    }

    /// Returns the IGP metric for `addr`, if known.
    ///
    /// # Panics
    ///
    /// Panics if the `FibSnapshot` `RwLock` is poisoned.
    #[must_use]
    pub fn igp_metric_v6(&self, addr: Ipv6Addr) -> Option<u32> {
        self.snapshot
            .read()
            .expect("FibSnapshot RwLock poisoned")
            .igp_metric_v6(addr)
    }
}

// ── KernelFib ────────────────────────────────────────────────────────────────

/// Routing table to track.
///
/// `254` is `RT_TABLE_MAIN` — the default kernel routing table populated by
/// connected routes, static routes, and BGP-installed routes. `0` means all
/// tables (useful for debugging; not recommended for production).
pub const RT_TABLE_MAIN: u32 = 254;

/// Background subscriber that keeps a [`FibSnapshot`] current via netlink.
///
/// # Usage
///
/// ```ignore
/// let (fib, change_rx) = KernelFib::new(RT_TABLE_MAIN);
/// let oracle = fib.oracle();              // share with decision process
/// tokio::spawn(fib.spawn());             // starts the event loop
/// // change_rx fires whenever the FIB changes
/// ```
pub struct KernelFib {
    pub(crate) snapshot: Arc<RwLock<FibSnapshot>>,
    pub(crate) change_tx: watch::Sender<()>,
    pub(crate) table: u32,
}

impl KernelFib {
    /// Creates a `KernelFib` for the given routing `table`.
    ///
    /// Returns the `KernelFib` and a `watch::Receiver` that fires whenever the
    /// FIB snapshot changes. The receiver can be cloned and shared with any
    /// component that needs to react to FIB changes (e.g. the BGP decision
    /// process to re-evaluate next-hop reachability).
    ///
    /// Call [`oracle`][`KernelFib::oracle`] to obtain a [`KernelOracle`] before
    /// calling [`spawn`][`KernelFib::spawn`] (spawning consumes `self`).
    #[must_use]
    pub fn new(table: u32) -> (Self, watch::Receiver<()>) {
        let snapshot = Arc::new(RwLock::new(FibSnapshot::new()));
        let (tx, rx) = watch::channel(());
        (
            KernelFib {
                snapshot,
                change_tx: tx,
                table,
            },
            rx,
        )
    }

    /// Returns a [`KernelOracle`] backed by this FIB's live snapshot.
    ///
    /// Create all oracles before calling `spawn`, since `spawn` consumes `self`.
    #[must_use]
    pub fn oracle(&self) -> KernelOracle {
        KernelOracle {
            snapshot: self.snapshot.clone(),
        }
    }

    /// Returns a direct handle to the shared snapshot (for testing).
    #[must_use]
    pub fn snapshot(&self) -> Arc<RwLock<FibSnapshot>> {
        self.snapshot.clone()
    }

    /// Starts the netlink event loop.
    ///
    /// On Linux: dumps the current kernel FIB, then processes `RTM_NEWROUTE`
    /// and `RTM_DELROUTE` events indefinitely, updating the snapshot and
    /// notifying watchers on each change.
    ///
    /// On non-Linux: returns immediately (no-op stub for development builds).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the initial netlink connection or route dump fails.
    /// After the dump succeeds, errors on individual route-change events are
    /// logged and skipped rather than terminating the loop.
    // async is needed for the Linux branch (which awaits the route dump and event
    // loop). On non-Linux builds the body has no await points; the allow keeps
    // the API surface uniform across platforms.
    #[allow(clippy::unused_async)]
    pub async fn spawn(self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            linux::run(self.snapshot, self.change_tx, self.table).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self.snapshot, self.change_tx, self.table);
            Ok(())
        }
    }

    /// Returns all `RTPROT_BGP` routes currently in the kernel table as
    /// `(network, prefix_len)` pairs.
    ///
    /// These are routes installed by a previous daemon run that are now stale.
    /// The caller is responsible for issuing the corresponding withdrawals via
    /// `FibWriter` before the BGP event loop starts.
    ///
    /// On non-Linux platforms always returns `([], [])`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the netlink dump fails (Linux only).
    #[allow(clippy::unused_async)]
    pub async fn stale_bgp_routes(&self) -> io::Result<(Vec<(Ipv4Addr, u8)>, Vec<(Ipv6Addr, u8)>)> {
        #[cfg(target_os = "linux")]
        {
            let (conn, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(conn);
            let v4 = linux::dump_stale_bgp_v4(&handle, self.table).await?;
            let v6 = linux::dump_stale_bgp_v6(&handle, self.table).await?;
            Ok((v4, v6))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok((vec![], vec![]))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A unicast route in the main table with no TOS, source or gateway.
    pub(crate) fn r4(network: &str, prefix_len: u8, metric: u32) -> KernelRouteV4 {
        KernelRouteV4 {
            slot: RouteSlotV4 {
                table: TableId::MAIN,
                dst: Ipv4Prefix::new(network.parse().unwrap(), prefix_len).unwrap(),
                tos: 0,
                priority: metric,
            },
            kind: RouteKind::Unicast,
            protocol: 3, // RTPROT_BOOT, what `ip route add` uses
            scope: 0,
            prefsrc: None,
            next_hop: NextHopV4::Path(NextHopPath {
                gateway: None,
                oif: None,
            }),
        }
    }

    /// IPv6 counterpart of [`r4`].
    pub(crate) fn r6(network: &str, prefix_len: u8, metric: u32) -> KernelRouteV6 {
        KernelRouteV6 {
            slot: RouteSlotV6 {
                table: TableId::MAIN,
                dst: Ipv6Prefix::new(network.parse().unwrap(), prefix_len).unwrap(),
                src: Ipv6Prefix::DEFAULT,
                priority: metric,
            },
            kind: RouteKind::Unicast,
            protocol: 3,
            preference: RoutePreference::Medium,
            next_hop: NextHopV6::Path(NextHopPath {
                gateway: None,
                oif: None,
            }),
        }
    }

    fn snap_with_v4(entries: &[(&str, u8, u32)]) -> FibSnapshot {
        let mut snap = FibSnapshot::new();
        for &(network, prefix_len, metric) in entries {
            snap.v4.insert_back(r4(network, prefix_len, metric));
        }
        snap
    }

    fn snap_with_v6(entries: &[(&str, u8, u32)]) -> FibSnapshot {
        let mut snap = FibSnapshot::new();
        for &(network, prefix_len, metric) in entries {
            snap.v6.insert_back(r6(network, prefix_len, metric));
        }
        snap
    }

    // ── FibSnapshot reachability ──────────────────────────────────────────────

    #[test]
    fn empty_snapshot_nothing_reachable() {
        let snap = FibSnapshot::new();
        assert!(!snap.is_v4_reachable("192.0.2.1".parse().unwrap()));
        assert!(!snap.is_v6_reachable("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn exact_host_route_matches() {
        let snap = snap_with_v4(&[("192.0.2.1", 32, 10)]);
        assert!(snap.is_v4_reachable("192.0.2.1".parse().unwrap()));
        assert!(!snap.is_v4_reachable("192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn subnet_route_matches_all_hosts_in_range() {
        let snap = snap_with_v4(&[("10.0.0.0", 8, 100)]);
        assert!(snap.is_v4_reachable("10.1.2.3".parse().unwrap()));
        assert!(snap.is_v4_reachable("10.255.255.255".parse().unwrap()));
        assert!(!snap.is_v4_reachable("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn default_route_matches_everything() {
        let snap = snap_with_v4(&[("0.0.0.0", 0, 200)]);
        assert!(snap.is_v4_reachable("1.2.3.4".parse().unwrap()));
        assert!(snap.is_v4_reachable("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn longest_prefix_wins() {
        // /8 with metric 100, /24 with metric 50 — /24 is more specific
        let snap = snap_with_v4(&[("10.0.0.0", 8, 100), ("10.20.30.0", 24, 50)]);
        // Address in the /24 subnet → metric 50 (the more-specific route)
        assert_eq!(snap.igp_metric_v4("10.20.30.5".parse().unwrap()), Some(50));
        // Address in /8 but outside /24 → metric 100
        assert_eq!(snap.igp_metric_v4("10.99.0.1".parse().unwrap()), Some(100));
    }

    #[test]
    fn same_prefix_lowest_priority_wins_whatever_the_load_order() {
        // Issue #56. fib_table_lookup walks a leaf's aliases in ascending
        // priority and uses the first, so metric 10 must win over 100 no
        // matter which order the routes were dumped or added in.
        for entries in [
            [("198.51.100.0", 24, 10), ("198.51.100.0", 24, 100)],
            [("198.51.100.0", 24, 100), ("198.51.100.0", 24, 10)],
        ] {
            let snap = snap_with_v4(&entries);
            assert_eq!(snap.routes_v4().count(), 2, "both routes are kept");
            assert_eq!(
                snap.igp_metric_v4("198.51.100.7".parse().unwrap()),
                Some(10)
            );
            let route = snap.route_to_v4("198.51.100.7".parse().unwrap()).unwrap();
            assert_eq!(route.slot.dst.to_string(), "198.51.100.0/24");
        }
        for entries in [
            [("2001:db8:1::", 64, 10), ("2001:db8:1::", 64, 100)],
            [("2001:db8:1::", 64, 100), ("2001:db8:1::", 64, 10)],
        ] {
            let snap = snap_with_v6(&entries);
            assert_eq!(snap.routes_v6().count(), 2);
            assert_eq!(
                snap.igp_metric_v6("2001:db8:1::7".parse().unwrap()),
                Some(10)
            );
            assert!(snap.route_to_v6("2001:db8:2::1".parse().unwrap()).is_none());
        }
    }

    #[test]
    fn no_match_returns_none_metric() {
        let snap = snap_with_v4(&[("192.168.0.0", 16, 10)]);
        assert_eq!(snap.igp_metric_v4("10.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn ipv6_subnet_matches() {
        let snap = snap_with_v6(&[("2001:db8::", 32, 5)]);
        assert!(snap.is_v6_reachable("2001:db8::1".parse().unwrap()));
        assert!(!snap.is_v6_reachable("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_default_route_matches_everything() {
        let snap = snap_with_v6(&[("::", 0, 1)]);
        assert!(snap.is_v6_reachable("::1".parse().unwrap()));
        assert!(snap.is_v6_reachable("2001:db8::1".parse().unwrap()));
    }

    // ── FibSnapshot IPv6 reachability ─────────────────────────────────────────

    #[test]
    fn ipv6_link_local_without_a_route_is_reachable() {
        // fe80::/10 addresses are on-link — reachable even with an empty snapshot.
        let snap = FibSnapshot::new();
        assert!(snap.is_v6_reachable("fe80::1".parse().unwrap()));
        assert!(snap.is_v6_reachable("fe80::dead:beef".parse().unwrap()));
        // febf:: is still in fe80::/10 (second byte & 0xc0 == 0x80)
        assert!(snap.is_v6_reachable("febf::1".parse().unwrap()));
        // fec0:: is NOT link-local (second byte 0xc0 & 0xc0 == 0xc0 ≠ 0x80)
        assert!(!snap.is_v6_reachable("fec0::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_non_link_local_needs_route() {
        let snap = FibSnapshot::new();
        // 2001:db8:: is not link-local; needs a route.
        assert!(!snap.is_v6_reachable("2001:db8::1".parse().unwrap()));
        let snap = snap_with_v6(&[("2001:db8::", 32, 10)]);
        assert!(snap.is_v6_reachable("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn igp_metric_v6_returns_metric_of_covering_route() {
        let snap = snap_with_v6(&[("2001:db8::", 32, 100), ("2001:db8:1::", 48, 20)]);
        // /48 is more specific → metric 20
        assert_eq!(
            snap.igp_metric_v6("2001:db8:1::1".parse().unwrap()),
            Some(20)
        );
        // In /32 but outside /48 → metric 100
        assert_eq!(
            snap.igp_metric_v6("2001:db8:2::1".parse().unwrap()),
            Some(100)
        );
        // Completely uncovered
        assert_eq!(snap.igp_metric_v6("2001:db9::1".parse().unwrap()), None);
    }

    // ── Negative routes (issue #57) ──────────────────────────────────────────
    //
    // ip-route(8): blackhole, unreachable and prohibit destinations "are
    // unreachable"; a selected throw route ends the lookup in the table
    // "pretending that no route was found". fib_table_lookup returns the
    // selected alias's fib_props error without backtracking, and
    // fib6_table_lookup backtracks only when the node yields no route, so a
    // negative route hides every shorter route that also covers the address.

    const NEGATIVE_KINDS: [RouteKind; 4] = [
        RouteKind::Reject(RejectKind::Blackhole),
        RouteKind::Reject(RejectKind::Unreachable),
        RouteKind::Reject(RejectKind::Prohibit),
        RouteKind::Throw,
    ];

    fn neg4(network: &str, prefix_len: u8, metric: u32, kind: RouteKind) -> KernelRouteV4 {
        KernelRouteV4 {
            kind,
            ..r4(network, prefix_len, metric)
        }
    }

    /// A negative IPv6 route as the kernel reports it: on the loopback device
    /// (ifindex 1), which also keeps it distinct from [`r6`]'s device-less
    /// unicast route under `rt6_duplicate_nexthop`.
    fn neg6(network: &str, prefix_len: u8, metric: u32, kind: RouteKind) -> KernelRouteV6 {
        KernelRouteV6 {
            kind,
            next_hop: NextHopV6::Path(NextHopPath {
                gateway: None,
                oif: std::num::NonZeroU32::new(1),
            }),
            ..r6(network, prefix_len, metric)
        }
    }

    /// The lookup outcome must name the negative route and its kind.
    fn assert_negative<R: std::fmt::Debug + PartialEq>(
        got: FibLookup<'_, R>,
        route: &R,
        kind: RouteKind,
    ) {
        match (got, kind) {
            (FibLookup::Reject { route: r, kind: k }, RouteKind::Reject(want)) => {
                assert_eq!(r, route);
                assert_eq!(k, want);
            }
            (FibLookup::Throw(r), RouteKind::Throw) => assert_eq!(r, route),
            (other, _) => panic!("expected {kind:?} via {route:?}, got {other:?}"),
        }
    }

    #[test]
    fn ipv4_negative_route_beneath_a_covering_route_is_unreachable_until_removed() {
        let covered: Ipv4Addr = "10.1.2.3".parse().unwrap();
        let elsewhere: Ipv4Addr = "10.2.0.1".parse().unwrap();
        for kind in NEGATIVE_KINDS {
            let neg = neg4("10.1.0.0", 16, 1024, kind);
            let mut snap = snap_with_v4(&[("0.0.0.0", 0, 0)]);
            assert!(snap.v4.insert_back(neg.clone()));

            assert!(
                !snap.is_v4_reachable(covered),
                "{kind:?} must not fall through"
            );
            assert_eq!(snap.igp_metric_v4(covered), None, "{kind:?}");
            assert_eq!(snap.route_to_v4(covered), None, "{kind:?}");
            assert_negative(snap.lookup_v4(covered), &neg, kind);
            // Outside the negative prefix the default route still forwards.
            assert_eq!(snap.igp_metric_v4(elsewhere), Some(0), "{kind:?}");

            assert!(snap.v4.remove(&neg));
            assert!(snap.is_v4_reachable(covered), "{kind:?} removed");
            assert_eq!(snap.igp_metric_v4(covered), Some(0));
        }
    }

    #[test]
    fn ipv6_negative_route_beneath_a_covering_route_is_unreachable_until_removed() {
        let covered: Ipv6Addr = "2001:db8:1::3".parse().unwrap();
        let elsewhere: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
        for kind in NEGATIVE_KINDS {
            let neg = neg6("2001:db8:1::", 48, 1024, kind);
            let mut snap = snap_with_v6(&[("::", 0, 1)]);
            assert!(snap.v6.insert_back(neg.clone()));

            assert!(
                !snap.is_v6_reachable(covered),
                "{kind:?} must not fall through"
            );
            assert_eq!(snap.igp_metric_v6(covered), None, "{kind:?}");
            assert_eq!(snap.route_to_v6(covered), None, "{kind:?}");
            assert_negative(snap.lookup_v6(covered), &neg, kind);
            assert_eq!(snap.igp_metric_v6(elsewhere), Some(1), "{kind:?}");

            assert!(snap.v6.remove(&neg));
            assert!(snap.is_v6_reachable(covered), "{kind:?} removed");
            assert_eq!(snap.igp_metric_v6(covered), Some(1));
        }
    }

    #[test]
    fn negative_and_unicast_routes_for_one_prefix_compete_on_priority() {
        // fib_table_lookup walks a leaf's aliases in ascending priority and
        // stops at the first one, whatever its type; IPv6 nodes are sorted by
        // metric the same way.
        let addr4: Ipv4Addr = "198.51.100.7".parse().unwrap();
        let addr6: Ipv6Addr = "2001:db8:1::7".parse().unwrap();
        for kind in NEGATIVE_KINDS {
            let mut snap = snap_with_v4(&[("198.51.100.0", 24, 100)]);
            snap.v4.insert_back(neg4("198.51.100.0", 24, 10, kind));
            snap.v6.insert_back(r6("2001:db8:1::", 64, 100));
            snap.v6.insert_back(neg6("2001:db8:1::", 64, 10, kind));
            assert!(!snap.is_v4_reachable(addr4), "{kind:?} at metric 10 wins");
            assert!(!snap.is_v6_reachable(addr6), "{kind:?} at metric 10 wins");

            let mut snap = snap_with_v4(&[("198.51.100.0", 24, 10)]);
            snap.v4.insert_back(neg4("198.51.100.0", 24, 100, kind));
            snap.v6.insert_back(r6("2001:db8:1::", 64, 10));
            snap.v6.insert_back(neg6("2001:db8:1::", 64, 100, kind));
            assert_eq!(snap.igp_metric_v4(addr4), Some(10), "{kind:?} at 100 loses");
            assert_eq!(snap.igp_metric_v6(addr6), Some(10), "{kind:?} at 100 loses");
        }
    }

    #[test]
    fn a_longer_unicast_route_inside_a_negative_prefix_still_forwards() {
        // Longest prefix first: the negative route only decides for addresses
        // where it is the longest match.
        for kind in NEGATIVE_KINDS {
            let mut snap = snap_with_v4(&[("10.1.0.0", 16, 50)]);
            snap.v4.insert_back(neg4("10.0.0.0", 8, 0, kind));
            assert_eq!(snap.igp_metric_v4("10.1.9.9".parse().unwrap()), Some(50));
            assert!(!snap.is_v4_reachable("10.2.9.9".parse().unwrap()));

            let mut snap = snap_with_v6(&[("2001:db8:1::", 48, 50)]);
            snap.v6.insert_back(neg6("2001:db8::", 32, 0, kind));
            assert_eq!(
                snap.igp_metric_v6("2001:db8:1::9".parse().unwrap()),
                Some(50)
            );
            assert!(!snap.is_v6_reachable("2001:db8:2::9".parse().unwrap()));
        }
    }

    #[test]
    fn ipv6_negative_route_over_link_local_space_is_honoured() {
        // The link-local fallback is for "no route", not for a route that
        // rejects: RTM_GETROUTE for an address beneath a prohibit route
        // answers EACCES (checked against the kernel in kernel_fib_netns.rs).
        let covered: Ipv6Addr = "fe80:1234::1".parse().unwrap();
        let other: Ipv6Addr = "fe80::1".parse().unwrap();
        for kind in NEGATIVE_KINDS {
            let neg = neg6("fe80:1234::", 64, 100, kind);
            let mut snap = FibSnapshot::new();
            snap.v6.insert_back(neg.clone());
            assert!(!snap.is_v6_reachable(covered), "{kind:?}");
            assert_negative(snap.lookup_v6(covered), &neg, kind);
            assert!(
                snap.is_v6_reachable(other),
                "{kind:?}: uncovered link-local"
            );

            let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
            let oracle = fib.oracle();
            fib.snapshot.write().unwrap().v6.insert_back(neg.clone());
            assert!(
                !oracle.is_v6_reachable(covered),
                "{kind:?} via KernelOracle"
            );
            assert!(oracle.is_v6_reachable(other));
            fib.snapshot.write().unwrap().v6.remove(&neg);
            assert!(
                oracle.is_v6_reachable(covered),
                "{kind:?} removed: fallback again"
            );
        }
    }

    #[test]
    fn ipv6_route_preference_ranks_routes_of_one_metric() {
        // rt6_score_route adds IPV6_DECODE_PREF(pref) << 2 ("1:low,2:med,
        // 3:high") and find_match keeps only a strictly better score, so a
        // higher preference beats list order within the lowest-metric group,
        // whatever the route types.
        let addr: Ipv6Addr = "2001:db8:1::7".parse().unwrap();
        let blackhole = RouteKind::Reject(RejectKind::Blackhole);
        let with_pref = |mut r: KernelRouteV6, preference| {
            r.preference = preference;
            r
        };
        // Negative routes are always medium: ip6_route_info_create overwrites
        // their fib6_flags, dropping RTF_PREF.
        let cases = [
            // (first, second, reachable)
            (
                neg6("2001:db8:1::", 64, 100, blackhole),
                with_pref(r6("2001:db8:1::", 64, 100), RoutePreference::High),
                true,
            ),
            (
                with_pref(r6("2001:db8:1::", 64, 100), RoutePreference::Low),
                neg6("2001:db8:1::", 64, 100, blackhole),
                false,
            ),
            // Equal preference: list order (the earlier route).
            (
                neg6("2001:db8:1::", 64, 100, blackhole),
                r6("2001:db8:1::", 64, 100),
                false,
            ),
            (
                r6("2001:db8:1::", 64, 100),
                neg6("2001:db8:1::", 64, 100, blackhole),
                true,
            ),
            // A lower metric beats any preference: preference only ranks
            // routes within one metric group.
            (
                neg6("2001:db8:1::", 64, 10, blackhole),
                with_pref(r6("2001:db8:1::", 64, 100), RoutePreference::High),
                false,
            ),
        ];
        for (first, second, reachable) in cases {
            let mut snap = FibSnapshot::new();
            snap.v6.insert_back(first.clone());
            snap.v6.insert_back(second.clone());
            assert_eq!(
                snap.is_v6_reachable(addr),
                reachable,
                "{first:?} then {second:?}"
            );
        }
    }

    #[test]
    fn kernel_oracle_reports_a_negative_route_as_unreachable() {
        let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
        let oracle = fib.oracle();
        {
            let mut snap = fib.snapshot.write().unwrap();
            snap.v4.insert_back(r4("0.0.0.0", 0, 0));
            snap.v4.insert_back(neg4(
                "192.0.2.0",
                24,
                0,
                RouteKind::Reject(RejectKind::Blackhole),
            ));
            snap.v6.insert_back(r6("::", 0, 1));
            snap.v6.insert_back(neg6(
                "2001:db8::",
                32,
                1,
                RouteKind::Reject(RejectKind::Prohibit),
            ));
        }
        assert!(!oracle.is_v4_reachable("192.0.2.1".parse().unwrap()));
        assert_eq!(oracle.igp_metric_v4("192.0.2.1".parse().unwrap()), None);
        assert!(oracle.is_v4_reachable("198.51.100.1".parse().unwrap()));
        assert!(!oracle.is_v6_reachable("2001:db8::1".parse().unwrap()));
        assert_eq!(oracle.igp_metric_v6("2001:db8::1".parse().unwrap()), None);
        assert!(oracle.is_v6_reachable("2001:db9::1".parse().unwrap()));
    }

    // ── KernelOracle ─────────────────────────────────────────────────────────

    #[test]
    fn kernel_oracle_v4_reachability_and_metric() {
        let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
        let oracle = fib.oracle();

        assert!(!oracle.is_v4_reachable("10.0.0.1".parse().unwrap()));
        assert_eq!(oracle.igp_metric_v4("10.0.0.1".parse().unwrap()), None);

        fib.snapshot
            .write()
            .unwrap()
            .v4
            .insert_back(r4("10.0.0.0", 8, 42));

        assert!(oracle.is_v4_reachable("10.1.2.3".parse().unwrap()));
        assert_eq!(oracle.igp_metric_v4("10.1.2.3".parse().unwrap()), Some(42));
        assert_eq!(oracle.igp_metric_v4("11.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn kernel_oracle_v6_reachability_and_metric() {
        let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
        let oracle = fib.oracle();

        // Link-local is always reachable even without a route.
        assert!(oracle.is_v6_reachable("fe80::1".parse().unwrap()));
        assert!(!oracle.is_v6_reachable("2001:db8::1".parse().unwrap()));
        assert_eq!(oracle.igp_metric_v6("2001:db8::1".parse().unwrap()), None);

        fib.snapshot
            .write()
            .unwrap()
            .v6
            .insert_back(r6("2001:db8::", 32, 7));

        assert!(oracle.is_v6_reachable("2001:db8::1".parse().unwrap()));
        assert_eq!(
            oracle.igp_metric_v6("2001:db8::1".parse().unwrap()),
            Some(7)
        );
        assert_eq!(oracle.igp_metric_v6("2001:db9::1".parse().unwrap()), None);
    }

    // ── KernelFib::stale_bgp_routes (non-Linux stub) ─────────────────────────

    #[tokio::test]
    async fn stale_bgp_routes_returns_empty_on_non_linux() {
        let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
        let (v4, v6) = fib.stale_bgp_routes().await.expect("stub must not fail");
        // On non-Linux platforms (including macOS CI), the stub always returns [].
        // On Linux this test still compiles but would require a real netlink handle —
        // the assertion holds: an empty kernel produces empty stale lists.
        assert!(
            v4.is_empty() || cfg!(target_os = "linux"),
            "non-Linux stub must return empty v4"
        );
        assert!(
            v6.is_empty() || cfg!(target_os = "linux"),
            "non-Linux stub must return empty v6"
        );
    }

    // ── KernelFib construction and spawn ─────────────────────────────────────

    #[test]
    fn kernel_fib_new_snapshot_is_empty() {
        let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
        let snap = fib.snapshot().read().unwrap().clone();
        assert!(snap.v4.is_empty());
        assert!(snap.v6.is_empty());
    }

    #[tokio::test]
    async fn spawn_succeeds_on_non_linux() {
        // On non-Linux (macOS) spawn() is a no-op that returns Ok(()) immediately.
        // On Linux this would block indefinitely; the cfg guard prevents that.
        #[cfg(not(target_os = "linux"))]
        {
            let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
            fib.spawn().await.expect("spawn must succeed on non-Linux");
        }
    }

    #[test]
    fn kernel_oracle_queries_live_snapshot() {
        let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
        let oracle = fib.oracle();

        // Empty → nothing reachable
        assert!(!oracle.is_v4_reachable("10.0.0.1".parse().unwrap()));

        // Inject a route directly
        {
            let mut snap = fib.snapshot.write().unwrap();
            snap.v4.insert_back(r4("10.0.0.0", 8, 10));
        }

        // Oracle now sees the injected route
        assert!(oracle.is_v4_reachable("10.1.2.3".parse().unwrap()));
        assert_eq!(oracle.igp_metric_v4("10.1.2.3".parse().unwrap()), Some(10));
    }

    #[test]
    fn change_receiver_fires_when_snapshot_written() {
        let (fib, rx) = KernelFib::new(RT_TABLE_MAIN);
        // Initially unchanged.
        assert!(!rx.has_changed().unwrap());

        // Simulate what the event loop does: write to snapshot and send.
        fib.snapshot
            .write()
            .unwrap()
            .v4
            .insert_back(r4("192.168.1.0", 24, 20));
        let _ = fib.change_tx.send(());

        assert!(rx.has_changed().unwrap());
    }
}
