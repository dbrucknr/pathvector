//! Kernel FIB integration via Linux netlink (`RTM_NEWROUTE` / `RTM_DELROUTE`).
//!
//! # Design
//!
//! Three components cooperate to provide live next-hop reachability to the BGP
//! decision process:
//!
//! - [`FibSnapshot`] — an in-memory copy of the kernel routing table for one
//!   or both address families. Cheap to query under a shared `RwLock`.
//! - [`KernelFib`] — drives the snapshot: dumps the initial kernel FIB on
//!   startup and then applies `RTM_NEWROUTE` / `RTM_DELROUTE` netlink events as
//!   they arrive. Signals change via a `watch` channel so the daemon can
//!   re-evaluate best-paths whose next-hops were affected.
//! - [`KernelOracle`] — a thin wrapper that consumers can hold to query
//!   the snapshot; see `pathvectord::fib` for the `NextHopOracle` impl.
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
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, RwLock},
};

use tokio::sync::watch;

// ── FibSnapshot ──────────────────────────────────────────────────────────────

/// An entry in the FIB snapshot: (network address, prefix length, metric).
///
/// Metric corresponds to the Linux route priority (lower = preferred). Used to
/// implement RFC 4271 §9.1.2.2 step 8 (prefer lower IGP metric).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibEntry4 {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub metric: u32,
}

/// IPv6 equivalent of [`FibEntry4`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FibEntry6 {
    pub network: Ipv6Addr,
    pub prefix_len: u8,
    pub metric: u32,
}

/// In-memory copy of the kernel routing table.
///
/// Updated atomically by [`KernelFib`] under a write lock; read concurrently
/// by [`KernelOracle`] instances in the decision process.
///
/// Reachability queries use longest-prefix match (LPM): a next-hop is
/// considered reachable if any route in the snapshot covers it. The metric of
/// the covering route is returned for the step-8 tiebreaker.
#[derive(Debug, Default, Clone)]
pub struct FibSnapshot {
    pub(crate) v4: Vec<FibEntry4>,
    pub(crate) v6: Vec<FibEntry6>,
}

impl FibSnapshot {
    /// Creates an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `addr` is covered by any IPv4 route in the snapshot.
    #[must_use]
    pub fn is_v4_reachable(&self, addr: Ipv4Addr) -> bool {
        self.lpm_v4(addr).is_some()
    }

    /// Returns the metric of the most-specific IPv4 route covering `addr`.
    #[must_use]
    pub fn igp_metric_v4(&self, addr: Ipv4Addr) -> Option<u32> {
        self.lpm_v4(addr).map(|e| e.metric)
    }

    /// Returns `true` if `addr` is covered by any IPv6 route in the snapshot.
    #[must_use]
    pub fn is_v6_reachable(&self, addr: Ipv6Addr) -> bool {
        self.lpm_v6(addr).is_some()
    }

    /// Returns the metric of the most-specific IPv6 route covering `addr`.
    #[must_use]
    pub fn igp_metric_v6(&self, addr: Ipv6Addr) -> Option<u32> {
        self.lpm_v6(addr).map(|e| e.metric)
    }

    /// Longest-prefix match over IPv4 entries.
    fn lpm_v4(&self, addr: Ipv4Addr) -> Option<&FibEntry4> {
        let addr_u32 = u32::from(addr);
        self.v4
            .iter()
            .filter(|e| {
                if e.prefix_len == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(u32::from(e.prefix_len));
                (u32::from(e.network) >> shift) == (addr_u32 >> shift)
            })
            .max_by_key(|e| e.prefix_len)
    }

    /// Longest-prefix match over IPv6 entries.
    fn lpm_v6(&self, addr: Ipv6Addr) -> Option<&FibEntry6> {
        let addr_u128 = u128::from(addr);
        self.v6
            .iter()
            .filter(|e| {
                if e.prefix_len == 0 {
                    return true;
                }
                let shift = 128u32.saturating_sub(u32::from(e.prefix_len));
                (u128::from(e.network) >> shift) == (addr_u128 >> shift)
            })
            .max_by_key(|e| e.prefix_len)
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
            // No-op on macOS / other dev platforms.
            // The daemon keeps AlwaysReachable as the oracle.
            let _ = (self.snapshot, self.change_tx, self.table);
            Ok(())
        }
    }
}

// ── FibWriter ────────────────────────────────────────────────────────────────

/// Writes BGP-learned routes into the kernel FIB via netlink.
///
/// On Linux, a `RTM_NEWROUTE` (with `NLM_F_REPLACE`) installs or replaces a
/// route; `RTM_DELROUTE` removes it. All routes are tagged with
/// `RTPROT_BGP` so they are distinguishable from static or IGP routes.
///
/// On non-Linux platforms all methods are no-ops, preserving the API surface
/// so `pathvectord` can use `FibWriter` unconditionally.
#[cfg(target_os = "linux")]
pub struct FibWriter {
    handle: rtnetlink::Handle,
    table: u32,
    metric: u32,
}

#[cfg(not(target_os = "linux"))]
pub struct FibWriter;

#[cfg(target_os = "linux")]
impl FibWriter {
    /// Opens a netlink connection and returns a `FibWriter` for `table` / `metric`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the netlink socket cannot be created.
    pub fn new(table: u32, metric: u32) -> std::io::Result<Self> {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(conn);
        Ok(Self {
            handle,
            table,
            metric,
        })
    }

    /// Install (or replace) an IPv4 prefix route via `gateway`.
    ///
    /// Uses `NLM_F_REPLACE` so duplicate announcements from BGP are idempotent.
    pub async fn install_v4(
        &self,
        dst: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> std::io::Result<()> {
        linux::install_route_v4(
            &self.handle,
            dst,
            prefix_len,
            gateway,
            self.table,
            self.metric,
        )
        .await
    }

    /// Remove an IPv4 prefix route from the kernel FIB.
    pub async fn withdraw_v4(&self, dst: Ipv4Addr, prefix_len: u8) -> std::io::Result<()> {
        linux::withdraw_route_v4(&self.handle, dst, prefix_len, self.table).await
    }

    /// Install (or replace) an IPv6 prefix route via `gateway`.
    pub async fn install_v6(
        &self,
        dst: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
    ) -> std::io::Result<()> {
        linux::install_route_v6(
            &self.handle,
            dst,
            prefix_len,
            gateway,
            self.table,
            self.metric,
        )
        .await
    }

    /// Remove an IPv6 prefix route from the kernel FIB.
    pub async fn withdraw_v6(&self, dst: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
        linux::withdraw_route_v6(&self.handle, dst, prefix_len, self.table).await
    }
}

#[cfg(not(target_os = "linux"))]
impl FibWriter {
    /// No-op on non-Linux platforms; accepts the same arguments so call sites
    /// need no `#[cfg]` gates.
    ///
    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    pub fn new(_table: u32, _metric: u32) -> std::io::Result<Self> {
        Ok(Self)
    }

    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    #[allow(clippy::unused_async)]
    pub async fn install_v4(
        &self,
        _dst: Ipv4Addr,
        _prefix_len: u8,
        _gateway: Ipv4Addr,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    #[allow(clippy::unused_async)]
    pub async fn withdraw_v4(&self, _dst: Ipv4Addr, _prefix_len: u8) -> std::io::Result<()> {
        Ok(())
    }

    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    #[allow(clippy::unused_async)]
    pub async fn install_v6(
        &self,
        _dst: Ipv6Addr,
        _prefix_len: u8,
        _gateway: Ipv6Addr,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    #[allow(clippy::unused_async)]
    pub async fn withdraw_v6(&self, _dst: Ipv6Addr, _prefix_len: u8) -> std::io::Result<()> {
        Ok(())
    }
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr},
        sync::{Arc, RwLock},
    };

    use futures::{StreamExt, TryStreamExt};
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_route::{
        AddressFamily, RouteNetlinkMessage,
        route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteType},
    };
    use rtnetlink::{IpVersion, RouteMessageBuilder, multicast::MulticastGroup};
    use tokio::sync::watch;

    use super::{FibEntry4, FibEntry6, FibSnapshot};

    pub async fn run(
        snapshot: Arc<RwLock<FibSnapshot>>,
        change_tx: watch::Sender<()>,
        table: u32,
    ) -> io::Result<()> {
        // Step 1 — Open a multicast connection subscribed to route change groups
        // BEFORE the dump so no events are missed during the window between dump
        // completion and subscription start. Events arriving during the dump are
        // idempotent (insert of an already-known prefix is a no-op update).
        let (conn, handle, mut events) = rtnetlink::new_multicast_connection(&[
            MulticastGroup::Ipv4Route,
            MulticastGroup::Ipv6Route,
        ])?;
        tokio::spawn(conn);

        // Step 2 — Populate snapshot from current kernel FIB.
        {
            let mut snap = snapshot.write().expect("FibSnapshot poisoned");

            let mut v4 = handle.route().get(IpVersion::V4).execute();
            while let Some(msg) = v4
                .try_next()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            {
                if let Some(entry) = parse_v4(&msg, table) {
                    snap.v4.push(entry);
                }
            }

            let mut v6 = handle.route().get(IpVersion::V6).execute();
            while let Some(msg) = v6
                .try_next()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            {
                if let Some(entry) = parse_v6(&msg, table) {
                    snap.v6.push(entry);
                }
            }
        }

        // Notify watchers: initial FIB loaded.
        let _ = change_tx.send(());

        // Step 3 — Apply incremental changes delivered by the multicast connection.
        while let Some((msg, _addr)) = events.next().await {
            match msg.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                    apply_new(
                        &mut snapshot.write().expect("FibSnapshot poisoned"),
                        &route,
                        table,
                    );
                    let _ = change_tx.send(());
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route)) => {
                    apply_del(
                        &mut snapshot.write().expect("FibSnapshot poisoned"),
                        &route,
                        table,
                    );
                    let _ = change_tx.send(());
                }
                _ => {}
            }
        }

        Ok(())
    }

    // ── Route parsing helpers ─────────────────────────────────────────────────

    /// Returns the routing table this message belongs to.
    ///
    /// Linux stores the table ID in `header.table` for IDs ≤ 255. Routes in
    /// tables with IDs > 255 carry an `RTA_TABLE` attribute that overrides the
    /// header field. We check the attribute first.
    fn route_table(msg: &RouteMessage) -> u32 {
        msg.attributes
            .iter()
            .find_map(|a| {
                if let RouteAttribute::Table(t) = a {
                    Some(*t)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| u32::from(msg.header.table))
    }

    fn in_table(msg: &RouteMessage, table: u32) -> bool {
        table == 0 || route_table(msg) == table
    }

    /// Parse an IPv4 unicast route. Returns `None` for non-unicast types,
    /// wrong-table routes, or routes with no parseable destination.
    fn parse_v4(msg: &RouteMessage, table: u32) -> Option<FibEntry4> {
        if msg.header.kind != RouteType::Unicast {
            return None;
        }
        if !in_table(msg, table) {
            return None;
        }

        let prefix_len = msg.header.destination_prefix_length;

        // Default route (0.0.0.0/0) may carry no Destination attribute.
        let network = msg
            .attributes
            .iter()
            .find_map(|a| {
                if let RouteAttribute::Destination(RouteAddress::Inet(v4)) = a {
                    Some(*v4)
                } else {
                    None
                }
            })
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        let metric = metric_of(msg);

        Some(FibEntry4 {
            network,
            prefix_len,
            metric,
        })
    }

    /// Parse an IPv6 unicast route.
    fn parse_v6(msg: &RouteMessage, table: u32) -> Option<FibEntry6> {
        if msg.header.kind != RouteType::Unicast {
            return None;
        }
        if !in_table(msg, table) {
            return None;
        }

        let prefix_len = msg.header.destination_prefix_length;

        let network = msg
            .attributes
            .iter()
            .find_map(|a| {
                if let RouteAttribute::Destination(RouteAddress::Inet6(v6)) = a {
                    Some(*v6)
                } else {
                    None
                }
            })
            .unwrap_or(Ipv6Addr::UNSPECIFIED);

        let metric = metric_of(msg);

        Some(FibEntry6 {
            network,
            prefix_len,
            metric,
        })
    }

    fn metric_of(msg: &RouteMessage) -> u32 {
        msg.attributes
            .iter()
            .find_map(|a| {
                if let RouteAttribute::Priority(m) = a {
                    Some(*m)
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    // ── Snapshot mutation ─────────────────────────────────────────────────────

    fn apply_new(snap: &mut FibSnapshot, msg: &RouteMessage, table: u32) {
        match msg.header.address_family {
            AddressFamily::Inet => {
                if let Some(entry) = parse_v4(msg, table) {
                    if let Some(slot) = snap
                        .v4
                        .iter_mut()
                        .find(|e| e.network == entry.network && e.prefix_len == entry.prefix_len)
                    {
                        *slot = entry;
                    } else {
                        snap.v4.push(entry);
                    }
                }
            }
            AddressFamily::Inet6 => {
                if let Some(entry) = parse_v6(msg, table) {
                    if let Some(slot) = snap
                        .v6
                        .iter_mut()
                        .find(|e| e.network == entry.network && e.prefix_len == entry.prefix_len)
                    {
                        *slot = entry;
                    } else {
                        snap.v6.push(entry);
                    }
                }
            }
            _ => {}
        }
    }

    fn apply_del(snap: &mut FibSnapshot, msg: &RouteMessage, table: u32) {
        if !in_table(msg, table) {
            return;
        }
        match msg.header.address_family {
            AddressFamily::Inet => {
                let prefix_len = msg.header.destination_prefix_length;
                let network = msg
                    .attributes
                    .iter()
                    .find_map(|a| {
                        if let RouteAttribute::Destination(RouteAddress::Inet(v4)) = a {
                            Some(*v4)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
                snap.v4
                    .retain(|e| !(e.network == network && e.prefix_len == prefix_len));
            }
            AddressFamily::Inet6 => {
                let prefix_len = msg.header.destination_prefix_length;
                let network = msg
                    .attributes
                    .iter()
                    .find_map(|a| {
                        if let RouteAttribute::Destination(RouteAddress::Inet6(v6)) = a {
                            Some(*v6)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(Ipv6Addr::UNSPECIFIED);
                snap.v6
                    .retain(|e| !(e.network == network && e.prefix_len == prefix_len));
            }
            _ => {}
        }
    }

    /// Install (or replace) an IPv4 route tagged RTPROT_BGP.
    pub(super) async fn install_route_v4(
        handle: &rtnetlink::Handle,
        dst: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        table: u32,
        metric: u32,
    ) -> io::Result<()> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dst, prefix_len)
            .gateway(gateway)
            .table_id(table)
            .priority(metric)
            .protocol(RouteProtocol::Bgp)
            .build();
        handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Install (or replace) an IPv6 route tagged RTPROT_BGP.
    pub(super) async fn install_route_v6(
        handle: &rtnetlink::Handle,
        dst: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
        table: u32,
        metric: u32,
    ) -> io::Result<()> {
        let msg = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(dst, prefix_len)
            .gateway(gateway)
            .table_id(table)
            .priority(metric)
            .protocol(RouteProtocol::Bgp)
            .build();
        handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Remove an IPv6 route from the kernel FIB.
    ///
    /// Returns `Ok(())` if the route was deleted or was already absent (ESRCH).
    pub(super) async fn withdraw_route_v6(
        handle: &rtnetlink::Handle,
        dst: Ipv6Addr,
        prefix_len: u8,
        table: u32,
    ) -> io::Result<()> {
        let msg = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(dst, prefix_len)
            .table_id(table)
            .build();
        match handle.route().del(msg).execute().await {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(ref e))
                if e.code.map_or(false, |c| c.get() == -3) =>
            {
                Ok(())
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }

    /// Remove an IPv4 route from the kernel FIB.
    ///
    /// Returns `Ok(())` if the route was deleted **or was already absent**
    /// (errno `ESRCH`/3). The kernel returns `ESRCH` when the route does not
    /// exist, which is the expected outcome on a clean daemon shutdown (routes
    /// are withdrawn from Loc-RIB before the kernel is updated) and on restart
    /// when a previous run has already cleaned up.
    pub(super) async fn withdraw_route_v4(
        handle: &rtnetlink::Handle,
        dst: Ipv4Addr,
        prefix_len: u8,
        table: u32,
    ) -> io::Result<()> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dst, prefix_len)
            .table_id(table)
            .build();
        match handle.route().del(msg).execute().await {
            Ok(()) => Ok(()),
            // ESRCH (3): route already absent — treat as success.
            Err(rtnetlink::Error::NetlinkError(ref e))
                if e.code.map_or(false, |c| c.get() == -3) =>
            {
                Ok(())
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_with_v4(entries: &[(Ipv4Addr, u8, u32)]) -> FibSnapshot {
        FibSnapshot {
            v4: entries
                .iter()
                .map(|&(network, prefix_len, metric)| FibEntry4 {
                    network,
                    prefix_len,
                    metric,
                })
                .collect(),
            v6: vec![],
        }
    }

    fn snap_with_v6(entries: &[(Ipv6Addr, u8, u32)]) -> FibSnapshot {
        FibSnapshot {
            v4: vec![],
            v6: entries
                .iter()
                .map(|&(network, prefix_len, metric)| FibEntry6 {
                    network,
                    prefix_len,
                    metric,
                })
                .collect(),
        }
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
        let snap = snap_with_v4(&[("192.0.2.1".parse().unwrap(), 32, 10)]);
        assert!(snap.is_v4_reachable("192.0.2.1".parse().unwrap()));
        assert!(!snap.is_v4_reachable("192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn subnet_route_matches_all_hosts_in_range() {
        let snap = snap_with_v4(&[("10.0.0.0".parse().unwrap(), 8, 100)]);
        assert!(snap.is_v4_reachable("10.1.2.3".parse().unwrap()));
        assert!(snap.is_v4_reachable("10.255.255.255".parse().unwrap()));
        assert!(!snap.is_v4_reachable("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn default_route_matches_everything() {
        let snap = snap_with_v4(&[("0.0.0.0".parse().unwrap(), 0, 200)]);
        assert!(snap.is_v4_reachable("1.2.3.4".parse().unwrap()));
        assert!(snap.is_v4_reachable("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn longest_prefix_wins() {
        // /8 with metric 100, /24 with metric 50 — /24 is more specific
        let snap = snap_with_v4(&[
            ("10.0.0.0".parse().unwrap(), 8, 100),
            ("10.20.30.0".parse().unwrap(), 24, 50),
        ]);
        // Address in the /24 subnet → metric 50 (the more-specific route)
        assert_eq!(snap.igp_metric_v4("10.20.30.5".parse().unwrap()), Some(50));
        // Address in /8 but outside /24 → metric 100
        assert_eq!(snap.igp_metric_v4("10.99.0.1".parse().unwrap()), Some(100));
    }

    #[test]
    fn no_match_returns_none_metric() {
        let snap = snap_with_v4(&[("192.168.0.0".parse().unwrap(), 16, 10)]);
        assert_eq!(snap.igp_metric_v4("10.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn ipv6_subnet_matches() {
        let snap = snap_with_v6(&[("2001:db8::".parse().unwrap(), 32, 5)]);
        assert!(snap.is_v6_reachable("2001:db8::1".parse().unwrap()));
        assert!(!snap.is_v6_reachable("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_default_route_matches_everything() {
        let snap = snap_with_v6(&[(Ipv6Addr::UNSPECIFIED, 0, 1)]);
        assert!(snap.is_v6_reachable("::1".parse().unwrap()));
        assert!(snap.is_v6_reachable("2001:db8::1".parse().unwrap()));
    }

    // ── KernelFib construction ────────────────────────────────────────────────

    #[test]
    fn kernel_fib_new_snapshot_is_empty() {
        let (fib, _rx) = KernelFib::new(RT_TABLE_MAIN);
        let snap = fib.snapshot().read().unwrap().clone();
        assert!(snap.v4.is_empty());
        assert!(snap.v6.is_empty());
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
            snap.v4.push(FibEntry4 {
                network: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
                metric: 10,
            });
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
        fib.snapshot.write().unwrap().v4.push(FibEntry4 {
            network: "192.168.1.0".parse().unwrap(),
            prefix_len: 24,
            metric: 20,
        });
        let _ = fib.change_tx.send(());

        assert!(rx.has_changed().unwrap());
    }
}
