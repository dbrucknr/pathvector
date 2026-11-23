//! Linux [`FibWriter`]: installs and withdraws BGP-learned routes via rtnetlink.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    sync::{Arc, RwLock},
};

use futures::{FutureExt, StreamExt, TryStreamExt};
use netlink_packet_core::{NLM_F_APPEND, NLM_F_REPLACE, NetlinkMessage, NetlinkPayload, Nla};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteNextHop, RouteProtocol,
        RouteScope, RouteType, RouteVia,
    },
};
use rtnetlink::{MulticastGroup, RouteMessageBuilder, sys::AsyncSocket};
use tokio::sync::watch;

use super::{
    FibSnapshot, FibWrite, Ipv4Prefix, Ipv6Prefix, KernelRouteV4, KernelRouteV6, MultipathLeg,
    NextHopPath, NextHopV4, NextHopV6, Position, RoutePreference, RouteSlotV4, RouteSlotV6,
    TableId,
};

// ── FibWriter ─────────────────────────────────────────────────────────────────

/// Writes BGP-learned routes into the kernel FIB via rtnetlink.
///
/// A `RTM_NEWROUTE` (with `NLM_F_REPLACE`) installs or replaces a route;
/// `RTM_DELROUTE` removes it. All routes are tagged with `RTPROT_BGP` so they
/// are distinguishable from static or IGP routes.
pub struct FibWriter {
    handle: rtnetlink::Handle,
    table: u32,
    metric: u32,
}

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
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the netlink call fails.
    pub async fn install_v4(
        &self,
        dst: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> std::io::Result<()> {
        install_route_v4(
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
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the netlink call fails.
    pub async fn withdraw_v4(&self, dst: Ipv4Addr, prefix_len: u8) -> std::io::Result<()> {
        withdraw_route_v4(&self.handle, dst, prefix_len, self.table, self.metric).await
    }

    /// Install (or replace) an IPv6 prefix route via `gateway`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the netlink call fails.
    pub async fn install_v6(
        &self,
        dst: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
    ) -> std::io::Result<()> {
        install_route_v6(
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
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the netlink call fails.
    pub async fn withdraw_v6(&self, dst: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
        withdraw_route_v6(&self.handle, dst, prefix_len, self.table, self.metric).await
    }
}

impl FibWrite for FibWriter {
    async fn install_v4(&self, dst: Ipv4Addr, prefix_len: u8, gateway: Ipv4Addr) -> io::Result<()> {
        self.install_v4(dst, prefix_len, gateway).await
    }

    async fn withdraw_v4(&self, dst: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
        self.withdraw_v4(dst, prefix_len).await
    }

    async fn install_v6(&self, dst: Ipv6Addr, prefix_len: u8, gateway: Ipv6Addr) -> io::Result<()> {
        self.install_v6(dst, prefix_len, gateway).await
    }

    async fn withdraw_v6(&self, dst: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
        self.withdraw_v6(dst, prefix_len).await
    }

    async fn install_blackhole_v4(&self, dst: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
        install_blackhole_v4(&self.handle, dst, prefix_len, self.table, self.metric).await
    }

    async fn withdraw_blackhole_v4(&self, dst: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
        withdraw_blackhole_route_v4(&self.handle, dst, prefix_len, self.table, self.metric).await
    }

    async fn install_blackhole_v6(&self, dst: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
        install_blackhole_v6(&self.handle, dst, prefix_len, self.table, self.metric).await
    }

    async fn withdraw_blackhole_v6(&self, dst: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
        withdraw_blackhole_route_v6(&self.handle, dst, prefix_len, self.table, self.metric).await
    }
}

// ── KernelFib event loop ──────────────────────────────────────────────────────

pub(super) async fn run(
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

    // A second connection re-reads IPv6 sibling sets (see `reread_sets`).
    // NETLINK_GET_STRICT_CHK (Linux 4.20+) makes the kernel apply the dump's
    // table and device filters (`ip_valid_fib_dump_req`); without it the
    // dump is unfiltered, which costs more but gives the same result,
    // because the sets are picked out by slot here.
    let (mut reread_conn, reread_handle, _) = rtnetlink::new_connection()?;
    let _ = reread_conn
        .socket_mut()
        .socket_ref()
        .set_netlink_get_strict_chk(true);
    tokio::spawn(reread_conn);

    // Step 2 — Populate snapshot from current kernel FIB.
    //
    // Build into a local snapshot while awaiting so the RwLockWriteGuard is
    // never held across an await point (std::sync::RwLockWriteGuard is !Send).
    // The dump lists each slot's routes in kernel order, so appending them
    // reproduces that order.
    let mut fresh = FibSnapshot::new();
    let mut stream = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute();
    while let Some(msg) = stream.try_next().await.map_err(io::Error::other)? {
        apply_dumped(&mut fresh, &msg, table);
    }

    let mut stream = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute();
    while let Some(msg) = stream.try_next().await.map_err(io::Error::other)? {
        apply_dumped(&mut fresh, &msg, table);
    }

    *snapshot.write().expect("FibSnapshot poisoned") = fresh;

    // Notify watchers: initial FIB loaded.
    let _ = change_tx.send(());

    // Step 3 — Apply incremental changes delivered by the multicast connection.
    //
    // `change_tx` fires only when the snapshot actually changes.  BGP routes
    // (RTPROT_BGP) are excluded from the snapshot entirely — they represent
    // destinations we reach *via* BGP, not the IGP paths used to reach BGP
    // next-hops.  Including them would create a feedback loop: every route we
    // install via `FibWriter` would trigger a `change_tx`, waking the event
    // loop and causing a spurious full `recompute_all` scan over the Loc-RIB.
    //
    // This matches the approach used by BIRD (krt.c protocol-tag filter) and
    // FRR/Zebra (rtm_protocol == RTPROT_ZEBRA skip) — both daemon suites filter
    // self-installed routes before deciding whether to re-run the decision
    // process.
    //
    // The netlink header flags matter: NLM_F_REPLACE means the kernel replaced
    // an existing route without sending RTM_DELROUTE for it, and NLM_F_APPEND
    // says where in its slot an IPv4 route was inserted.
    //
    // Events already queued are applied together before any re-read, so a
    // burst of deletes costs one dump per table and device.
    while let Some(event) = events.next().await {
        let mut changed = false;
        let mut reread = HashSet::new();
        let mut next = Some(event);
        while let Some((msg, _addr)) = next {
            changed |= apply_event(&snapshot, msg, table, &mut reread);
            next = events.next().now_or_never().flatten();
        }
        if !reread.is_empty() {
            changed |= reread_sets(&reread_handle, &snapshot, reread).await;
        }
        if changed {
            let _ = change_tx.send(());
        }
    }

    Ok(())
}

/// Applies one multicast route event. An IPv6 delete that leaves a route with
/// an inferred protocol in its slot adds the slot to `reread`.
fn apply_event(
    snapshot: &RwLock<FibSnapshot>,
    msg: NetlinkMessage<RouteNetlinkMessage>,
    table: u32,
    reread: &mut HashSet<RouteSlotV6>,
) -> bool {
    let flags = msg.header.flags;
    let mut snap = snapshot.write().expect("FibSnapshot poisoned");
    match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
            apply_new(&mut snap, &route, flags, table)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route)) => {
            let changed = apply_del(&mut snap, &route, table);
            reread.extend(slot_to_reread(&snap, &route, table));
            changed
        }
        _ => false,
    }
}

// ── Re-reading IPv6 sibling sets ──────────────────────────────────────────────
//
// An IPv6 ECMP sibling's protocol is reported only when a message describes
// that sibling, and a dump describes a set only through its first sibling
// (`fib6_dump_node`: "no need to dump the sibling routes again"). The other
// siblings carry an inferred protocol (see the `route` module docs).
//
// A delete changes what the kernel describes: once the first sibling is gone
// the next one heads the set, and a lone remaining route is described in
// full. So after a delete that leaves an inferred route in its slot, the set
// is read back and applied with `RouteMirror::redescribe`.
//
// No request can target one prefix:
// - A strict-checked dump rejects a prefix (`ip_valid_fib_dump_req`:
//   `rtm_dst_len || rtm_src_len || rtm_tos || rtm_scope` is "Invalid values
//   in header for FIB dump request"); it filters only by table, protocol,
//   type and device, and `rt6_dump_route` tests the protocol of the described
//   route alone.
// - `RTM_GETROUTE` with `RTM_F_FIB_MATCH` runs a full policy lookup for an
//   address, and `fib6_select_path` picks the sibling by multipath hash
//   (`match = sibling`), which `rt6_fill_node` then describes. It cannot ask
//   for a given table, metric or sibling.
//
// So the re-read is a dump filtered by table and by the device of the
// inferred route (`fib6_info_uses_dev` matches a set through any sibling),
// and the wanted sets are picked out by slot.

/// The slot to re-read after an IPv6 `RTM_DELROUTE` has been applied: the
/// deleted route's slot, if a route whose protocol is inferred remains there.
fn slot_to_reread(snap: &FibSnapshot, msg: &RouteMessage, table: u32) -> Option<RouteSlotV6> {
    if !in_table(msg, table) || msg.header.address_family != AddressFamily::Inet6 {
        return None;
    }
    let slot = decode_v6(msg).first()?.slot;
    snap.v6.first_inferred(&slot).map(|_| slot)
}

/// A re-read dump: one routing table, optionally only routes using a device.
type DumpFilter = (TableId, Option<NonZeroU32>);

/// Groups the slots that still hold an inferred route by the dump that will
/// re-read them. Slots settled by later events in the same burst are dropped.
fn reread_groups(
    snap: &FibSnapshot,
    slots: HashSet<RouteSlotV6>,
) -> HashMap<DumpFilter, HashSet<RouteSlotV6>> {
    let mut groups: HashMap<DumpFilter, HashSet<RouteSlotV6>> = HashMap::new();
    for slot in slots {
        let Some(route) = snap.v6.first_inferred(&slot) else {
            continue;
        };
        let oif = match route.next_hop {
            NextHopV6::Path(p) => p.oif,
            NextHopV6::Object(_) => None,
        };
        groups.entry((slot.table, oif)).or_default().insert(slot);
    }
    groups
}

/// An `RTM_GETROUTE` dump request for IPv6 routes in `table`, limited to
/// routes using `oif` if given. The header obeys `ip_valid_fib_dump_req`:
/// zero prefix lengths, TOS and scope, and no protocol or type filter.
fn reread_request(table: TableId, oif: Option<NonZeroU32>) -> RouteMessage {
    let mut msg = RouteMessage::default();
    msg.header.address_family = AddressFamily::Inet6;
    msg.header.table = RouteHeader::RT_TABLE_UNSPEC;
    msg.header.protocol = RouteProtocol::Unspec;
    msg.header.kind = RouteType::Unspec;
    msg.header.scope = RouteScope::Universe;
    msg.attributes.push(RouteAttribute::Table(table.get()));
    if let Some(oif) = oif {
        msg.attributes.push(RouteAttribute::Oif(oif.get()));
    }
    msg
}

/// The routes of a dumped message, if it describes a set in one of `slots`.
fn wanted_set(msg: &RouteMessage, slots: &HashSet<RouteSlotV6>) -> Option<Vec<KernelRouteV6>> {
    if msg.header.address_family != AddressFamily::Inet6 {
        return None;
    }
    let set = decode_v6(msg);
    slots.contains(&set.first()?.slot).then_some(set)
}

/// Dumps the IPv6 routes `filter` selects and returns the sets in `slots`.
async fn dump_sets(
    handle: &rtnetlink::Handle,
    (table, oif): DumpFilter,
    slots: &HashSet<RouteSlotV6>,
) -> io::Result<Vec<Vec<KernelRouteV6>>> {
    let mut stream = handle.route().get(reread_request(table, oif)).execute();
    let mut sets = Vec::new();
    while let Some(msg) = stream.try_next().await.map_err(io::Error::other)? {
        sets.extend(wanted_set(&msg, slots));
    }
    Ok(sets)
}

/// Re-reads the sibling sets in `slots` and applies them. The snapshot lock is
/// not held while the kernel is read. If a dump fails, its slots keep their
/// inferred protocols until a later delete re-reads them.
///
/// Returns `true` if the tracked routes changed.
async fn reread_sets(
    handle: &rtnetlink::Handle,
    snapshot: &RwLock<FibSnapshot>,
    slots: HashSet<RouteSlotV6>,
) -> bool {
    let groups = reread_groups(&snapshot.read().expect("FibSnapshot poisoned"), slots);
    let mut changed = false;
    for (filter, slots) in groups {
        let Ok(sets) = dump_sets(handle, filter, &slots).await else {
            continue;
        };
        let mut snap = snapshot.write().expect("FibSnapshot poisoned");
        for set in sets {
            changed |= snap.v6.redescribe(set);
        }
    }
    changed
}

// ── Stale BGP route dump ──────────────────────────────────────────────────────

/// Returns `(network, prefix_len)` for every `RTPROT_BGP` IPv4 route in `table`.
///
/// This is the inverse of the snapshot's tracking rule: it selects *only* BGP-protocol routes,
/// which were installed by a previous daemon run and are now stale.
pub(super) async fn dump_stale_bgp_v4(
    handle: &rtnetlink::Handle,
    table: u32,
) -> io::Result<Vec<(Ipv4Addr, u8)>> {
    let mut out = Vec::new();
    let mut stream = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute();
    while let Some(msg) = stream.try_next().await.map_err(io::Error::other)? {
        if !is_bgp_route(&msg) || !in_table(&msg, table) {
            continue;
        }
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
        out.push((network, prefix_len));
    }
    Ok(out)
}

/// Returns `(network, prefix_len)` for every `RTPROT_BGP` IPv6 route in `table`.
pub(super) async fn dump_stale_bgp_v6(
    handle: &rtnetlink::Handle,
    table: u32,
) -> io::Result<Vec<(Ipv6Addr, u8)>> {
    let mut out = Vec::new();
    let mut stream = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute();
    while let Some(msg) = stream.try_next().await.map_err(io::Error::other)? {
        if !is_bgp_route(&msg) || !in_table(&msg, table) {
            continue;
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
        out.push((network, prefix_len));
    }
    Ok(out)
}

// ── Route parsing helpers ─────────────────────────────────────────────────────

/// Returns `true` if this route was installed by our own BGP daemon.
///
/// `RTPROT_BGP` (186) is the Linux protocol tag we set on every route written
/// by [`FibWriter`].  These routes must be excluded from [`FibSnapshot`] because:
///
/// 1. **Feedback loop** — if we include them, every `FibWriter` install fires
///    `change_tx`, waking the event loop and triggering a full `recompute_all`
///    scan with no benefit.
///
/// 2. **Semantic correctness** — the oracle answers "is there an IGP/kernel
///    path to this next-hop?"  BGP routes represent *destinations* we are
///    advertising, not the IGP paths we use to *reach* BGP next-hops.
///    Counting a BGP route as evidence of next-hop reachability conflates the
///    two RIBs; recursive next-hop resolution is a distinct, opt-in feature.
fn is_bgp_route(msg: &RouteMessage) -> bool {
    msg.header.protocol == RouteProtocol::Bgp
}

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

// ── Decoding: netlink message → kernel route identity ─────────────────────────

/// `RTA_NH_ID` in `<linux/rtnetlink.h>`. netlink-packet-route 0.30 has no
/// variant for it, so it arrives as `RouteAttribute::Other`.
const RTA_NH_ID: u16 = 30;

fn destination_v4(msg: &RouteMessage) -> Ipv4Addr {
    // A default route may carry no RTA_DST.
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Destination(RouteAddress::Inet(v4)) => Some(*v4),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn destination_v6(msg: &RouteMessage) -> Ipv6Addr {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Destination(RouteAddress::Inet6(v6)) => Some(*v6),
            _ => None,
        })
        .unwrap_or(Ipv6Addr::UNSPECIFIED)
}

fn source_v6(msg: &RouteMessage) -> Ipv6Addr {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Source(RouteAddress::Inet6(v6)) => Some(*v6),
            _ => None,
        })
        .unwrap_or(Ipv6Addr::UNSPECIFIED)
}

fn prefsrc_v4(msg: &RouteMessage) -> Option<Ipv4Addr> {
    msg.attributes.iter().find_map(|a| match a {
        RouteAttribute::PrefSource(RouteAddress::Inet(v4)) => Some(*v4),
        _ => None,
    })
}

fn nexthop_object(msg: &RouteMessage) -> Option<u32> {
    msg.attributes.iter().find_map(|a| match a {
        RouteAttribute::Other(nla) if nla.kind() == RTA_NH_ID && nla.value_len() == 4 => {
            let mut value = [0u8; 4];
            nla.emit_value(&mut value);
            // nla_put_u32 writes host byte order.
            Some(u32::from_ne_bytes(value))
        }
        _ => None,
    })
}

fn multipath(msg: &RouteMessage) -> Option<&[RouteNextHop]> {
    msg.attributes.iter().find_map(|a| match a {
        RouteAttribute::MultiPath(legs) => Some(legs.as_slice()),
        _ => None,
    })
}

/// A gateway (`RTA_GATEWAY`, or `RTA_VIA` for a cross-family gateway) and an
/// output interface, taken from a route's or a multipath leg's attributes.
fn path(attributes: &[RouteAttribute], oif: Option<u32>) -> NextHopPath {
    let gateway = attributes.iter().find_map(|a| match a {
        RouteAttribute::Gateway(RouteAddress::Inet(v4))
        | RouteAttribute::Via(RouteVia::Inet(v4)) => Some(IpAddr::V4(*v4)),
        RouteAttribute::Gateway(RouteAddress::Inet6(v6))
        | RouteAttribute::Via(RouteVia::Inet6(v6)) => Some(IpAddr::V6(*v6)),
        _ => None,
    });
    let oif = oif.or_else(|| {
        attributes.iter().find_map(|a| match a {
            RouteAttribute::Oif(i) => Some(*i),
            _ => None,
        })
    });
    NextHopPath {
        gateway,
        oif: oif.and_then(NonZeroU32::new),
    }
}

/// Decodes an IPv4 route into its kernel identity.
///
/// Returns `None` for a table of 0 or a destination the kernel would itself
/// reject (`fib_valid_key_len`); neither occurs in a kernel-generated message.
fn decode_v4(msg: &RouteMessage) -> Option<KernelRouteV4> {
    let slot = RouteSlotV4 {
        table: TableId::new(route_table(msg))?,
        dst: Ipv4Prefix::new(destination_v4(msg), msg.header.destination_prefix_length).ok()?,
        tos: msg.header.tos,
        priority: metric_of(msg),
    };
    let next_hop = if let Some(id) = nexthop_object(msg) {
        NextHopV4::Object(id)
    } else if let Some(legs) = multipath(msg) {
        // One IPv4 alias, several legs: added and deleted as a unit.
        NextHopV4::Multipath(
            legs.iter()
                .map(|leg| MultipathLeg {
                    path: path(&leg.attributes, Some(leg.interface_index)),
                    hops: leg.hops,
                })
                .collect(),
        )
    } else {
        NextHopV4::Path(path(&msg.attributes, None))
    };
    Some(KernelRouteV4 {
        slot,
        kind: u8::from(msg.header.kind),
        protocol: u8::from(msg.header.protocol),
        scope: u8::from(msg.header.scope),
        prefsrc: prefsrc_v4(msg),
        next_hop,
    })
}

/// Decodes an IPv6 route message into one route per ECMP sibling.
///
/// The kernel stores each IPv6 ECMP sibling as its own `fib6_info` but reports
/// a sibling set as one message with `RTA_MULTIPATH` (`rt6_fill_node`), in
/// notifications and in dumps alike (`fib6_dump_node` dumps a set once). It
/// deletes siblings one at a time, or all at once with one `RTA_MULTIPATH`
/// message. Splitting the message makes these line up. A route using a
/// nexthop object is never split.
///
/// Every returned route carries the header's type and protocol, but only the
/// first one is the route the header describes; see [`apply_new`] for how the
/// others are treated.
///
/// Returns an empty `Vec` for a table of 0 or a non-canonical prefix.
fn decode_v6(msg: &RouteMessage) -> Vec<KernelRouteV6> {
    let Some(table) = TableId::new(route_table(msg)) else {
        return Vec::new();
    };
    let Ok(dst) = Ipv6Prefix::new(destination_v6(msg), msg.header.destination_prefix_length) else {
        return Vec::new();
    };
    let Ok(src) = Ipv6Prefix::new(source_v6(msg), msg.header.source_prefix_length) else {
        return Vec::new();
    };
    let slot = RouteSlotV6 {
        table,
        dst,
        src,
        priority: metric_of(msg),
    };
    let protocol = u8::from(msg.header.protocol);
    let kind = u8::from(msg.header.kind);
    // RTA_PREF, like type and protocol, belongs to the route the header
    // describes, and an unreported leg takes it from that sibling the same
    // way its protocol is inferred. Legs created by the same request share it
    // (ip6_route_multipath_add builds every leg from one fib6_config); for a
    // leg of another origin it is a best guess, which only matters when the
    // set competes with another route of its metric.
    let preference = preference_v6(msg);
    let route = |next_hop| KernelRouteV6 {
        slot,
        kind,
        protocol,
        protocol_inferred: false,
        preference,
        next_hop,
    };
    if let Some(id) = nexthop_object(msg) {
        vec![route(NextHopV6::Object(id))]
    } else if let Some(legs) = multipath(msg) {
        legs.iter()
            .map(|leg| {
                route(NextHopV6::Path(path(
                    &leg.attributes,
                    Some(leg.interface_index),
                )))
            })
            .collect()
    } else {
        vec![route(NextHopV6::Path(path(&msg.attributes, None)))]
    }
}

/// `RTA_PREF`, normalised as the kernel stores it; absent means medium
/// (`IPV6_EXTRACT_PREF(0)`).
fn preference_v6(msg: &RouteMessage) -> RoutePreference {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Preference(p) => Some(RoutePreference::from_rta_pref(u8::from(*p))),
            _ => None,
        })
        .unwrap_or_default()
}

fn metric_of(msg: &RouteMessage) -> u32 {
    // IPv4 omits RTA_PRIORITY when the priority is 0 (fib_dump_info).
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

// ── Snapshot mutation ─────────────────────────────────────────────────────────

/// Adds a route from the initial dump. Dumps list routes in kernel order, so
/// each route goes to the end of its slot.
///
/// An IPv6 dump message describes its first leg only. `fib6_dump_node` never
/// dumps the other siblings separately, so their protocol is inferred from
/// the first (see the `route` module docs) until a message reports it.
fn apply_dumped(snap: &mut FibSnapshot, msg: &RouteMessage, table: u32) -> bool {
    if !in_table(msg, table) {
        return false;
    }
    match msg.header.address_family {
        AddressFamily::Inet => decode_v4(msg).is_some_and(|r| snap.v4.insert(r, Position::Back)),
        AddressFamily::Inet6 => {
            let mut legs = decode_v6(msg).into_iter();
            let Some(first) = legs.next() else {
                return false;
            };
            let mut changed = snap.v6.upsert(first, Position::Back);
            for leg in legs {
                changed |= snap.v6.insert(protocol_inferred(leg), Position::Back);
            }
            changed
        }
        _ => false,
    }
}

/// Applies a `RTM_NEWROUTE` notification whose netlink header carried `flags`.
///
/// Returns `true` if the tracked routes changed. Every route is mirrored, so
/// that replacements displace the right one, but untracked routes (BGP, and
/// types other than unicast and the negative types) never count as a change.
///
/// - `NLM_F_REPLACE`: the kernel replaced an existing route in place and sent
///   no `RTM_DELROUTE` for it (`fib_table_insert`, `fib6_add_rt2node`).
/// - IPv4 without `NLM_F_REPLACE`: inserted at the end of its slot with
///   `NLM_F_APPEND`, otherwise at the front (`fib_table_insert`).
/// - IPv6 without `NLM_F_REPLACE`: always at the end of its slot
///   (`fib6_add_rt2node`).
///
/// For IPv6 the header describes the first `RTA_MULTIPATH` leg. Without
/// `NLM_F_APPEND`, every leg not yet mirrored comes from the same request
/// (`ip6_route_multipath_add` reports its first new route), so it shares the
/// header's protocol. With `NLM_F_APPEND`, `ip6_route_mpath_notify` reports
/// the set's *first* sibling instead, which may be an older route of another
/// protocol, so new legs get that protocol as an inference. Legs already
/// mirrored keep what is known about them.
///
/// A route that is already mirrored is not added again, so replaying an event
/// that the initial dump already reflected is harmless.
fn apply_new(snap: &mut FibSnapshot, msg: &RouteMessage, flags: u16, table: u32) -> bool {
    if !in_table(msg, table) {
        return false;
    }
    let replace = flags & NLM_F_REPLACE != 0;
    let append = flags & NLM_F_APPEND != 0;
    match msg.header.address_family {
        AddressFamily::Inet => {
            let Some(route) = decode_v4(msg) else {
                return false;
            };
            if replace {
                snap.v4.replace(route)
            } else if append {
                snap.v4.insert(route, Position::Back)
            } else {
                snap.v4.insert(route, Position::Front)
            }
        }
        AddressFamily::Inet6 => {
            let mut legs = decode_v6(msg).into_iter();
            let Some(first) = legs.next() else {
                return false;
            };
            let mut changed = if replace {
                snap.v6.replace(first)
            } else {
                snap.v6.upsert(first, Position::Back)
            };
            for leg in legs {
                let leg = if append { protocol_inferred(leg) } else { leg };
                changed |= snap.v6.insert(leg, Position::Back);
            }
            changed
        }
        _ => false,
    }
}

/// An IPv6 ECMP leg whose message describes another sibling: its protocol is
/// not in the message, so the described sibling's protocol (already on the
/// leg from the header) is marked as an inference.
fn protocol_inferred(mut leg: KernelRouteV6) -> KernelRouteV6 {
    leg.protocol_inferred = true;
    leg
}

/// Applies a `RTM_DELROUTE` notification.
///
/// The kernel reports the identity of the route it removed, so exactly that
/// route is removed here and other routes for the same prefix remain. This
/// applies to BGP routes too: a BGP leg can share an ECMP set with a static one.
/// Returns `true` if the tracked routes changed.
fn apply_del(snap: &mut FibSnapshot, msg: &RouteMessage, table: u32) -> bool {
    if !in_table(msg, table) {
        return false;
    }
    match msg.header.address_family {
        AddressFamily::Inet => decode_v4(msg).is_some_and(|r| snap.v4.remove(&r)),
        AddressFamily::Inet6 => decode_v6(msg)
            .iter()
            .fold(false, |changed, r| snap.v6.remove(r) | changed),
        _ => false,
    }
}

// ── Route write helpers ───────────────────────────────────────────────────────

/// Install (or replace) an IPv4 route tagged `RTPROT_BGP`.
async fn install_route_v4(
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
        .map_err(io::Error::other)
}

/// Install (or replace) an IPv6 route tagged `RTPROT_BGP`.
async fn install_route_v6(
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
        .map_err(io::Error::other)
}

/// Install (or replace) an IPv4 blackhole route tagged `RTPROT_BGP`.
///
/// Uses `RTN_BLACKHOLE` — the kernel silently drops all matching packets.
/// No gateway attribute is set; the route type alone governs forwarding.
async fn install_blackhole_v4(
    handle: &rtnetlink::Handle,
    dst: Ipv4Addr,
    prefix_len: u8,
    table: u32,
    metric: u32,
) -> io::Result<()> {
    let mut msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .priority(metric)
        .protocol(RouteProtocol::Bgp)
        .build();
    msg.header.kind = RouteType::BlackHole;
    handle
        .route()
        .add(msg)
        .replace()
        .execute()
        .await
        .map_err(io::Error::other)
}

/// Install (or replace) an IPv6 blackhole route tagged `RTPROT_BGP`.
async fn install_blackhole_v6(
    handle: &rtnetlink::Handle,
    dst: Ipv6Addr,
    prefix_len: u8,
    table: u32,
    metric: u32,
) -> io::Result<()> {
    let mut msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .priority(metric)
        .protocol(RouteProtocol::Bgp)
        .build();
    msg.header.kind = RouteType::BlackHole;
    handle
        .route()
        .add(msg)
        .replace()
        .execute()
        .await
        .map_err(io::Error::other)
}

/// Remove an IPv4 blackhole route (`RTN_BLACKHOLE`) from the kernel FIB.
///
/// The route type must be specified in the `RTM_DELROUTE` message; using
/// `RTN_UNSPEC` (the builder default) causes the kernel to return ESRCH for
/// a blackhole route even when the prefix, table, metric, and protocol match.
async fn withdraw_blackhole_route_v4(
    handle: &rtnetlink::Handle,
    dst: Ipv4Addr,
    prefix_len: u8,
    table: u32,
    metric: u32,
) -> io::Result<()> {
    let mut msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .priority(metric)
        .protocol(RouteProtocol::Bgp)
        .build();
    msg.header.kind = RouteType::BlackHole;
    match handle.route().del(msg).execute().await {
        Ok(()) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(ref e)) if e.code.is_some_and(|c| c.get() == -3) => {
            Ok(())
        }
        Err(e) => Err(io::Error::other(e)),
    }
}

/// Remove an IPv6 blackhole route (`RTN_BLACKHOLE`) from the kernel FIB.
async fn withdraw_blackhole_route_v6(
    handle: &rtnetlink::Handle,
    dst: Ipv6Addr,
    prefix_len: u8,
    table: u32,
    metric: u32,
) -> io::Result<()> {
    let mut msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .priority(metric)
        .protocol(RouteProtocol::Bgp)
        .build();
    msg.header.kind = RouteType::BlackHole;
    match handle.route().del(msg).execute().await {
        Ok(()) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(ref e)) if e.code.is_some_and(|c| c.get() == -3) => {
            Ok(())
        }
        Err(e) => Err(io::Error::other(e)),
    }
}

/// Remove an IPv4 route from the kernel FIB.
///
/// Returns `Ok(())` if the route was deleted **or was already absent**
/// (errno `ESRCH`/3). The kernel returns `ESRCH` when the route does not
/// exist, which is the expected outcome on a clean daemon shutdown (routes
/// are withdrawn from Loc-RIB before the kernel is updated) and on restart
/// when a previous run has already cleaned up.
async fn withdraw_route_v4(
    handle: &rtnetlink::Handle,
    dst: Ipv4Addr,
    prefix_len: u8,
    table: u32,
    metric: u32,
) -> io::Result<()> {
    let msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .priority(metric)
        .protocol(RouteProtocol::Bgp)
        .build();
    match handle.route().del(msg).execute().await {
        Ok(()) => Ok(()),
        // ESRCH (3): route already absent — treat as success.
        Err(rtnetlink::Error::NetlinkError(ref e)) if e.code.is_some_and(|c| c.get() == -3) => {
            Ok(())
        }
        Err(e) => Err(io::Error::other(e)),
    }
}

/// Remove an IPv6 route from the kernel FIB.
///
/// Returns `Ok(())` if the route was deleted or was already absent (ESRCH).
async fn withdraw_route_v6(
    handle: &rtnetlink::Handle,
    dst: Ipv6Addr,
    prefix_len: u8,
    table: u32,
    metric: u32,
) -> io::Result<()> {
    let msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .priority(metric)
        .protocol(RouteProtocol::Bgp)
        .build();
    match handle.route().del(msg).execute().await {
        Ok(()) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(ref e)) if e.code.is_some_and(|c| c.get() == -3) => {
            Ok(())
        }
        Err(e) => Err(io::Error::other(e)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use netlink_packet_route::{
        AddressFamily,
        route::{
            RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteType,
        },
    };

    use super::*;
    use crate::fib::{RejectKind, RouteKind};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn igp_v4_msg(network: &str, prefix_len: u8, metric: u32, table: u32) -> RouteMessage {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.kind = RouteType::Unicast;
        msg.header.protocol = RouteProtocol::Ospf;
        msg.header.destination_prefix_length = prefix_len;
        msg.header.table = u8::try_from(table).unwrap_or(RouteHeader::RT_TABLE_MAIN);
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(
                network.parse().unwrap(),
            )));
        msg.attributes.push(RouteAttribute::Priority(metric));
        msg
    }

    fn bgp_v4_msg(network: &str, prefix_len: u8, table: u32) -> RouteMessage {
        let mut msg = igp_v4_msg(network, prefix_len, 20, table);
        msg.header.protocol = RouteProtocol::Bgp;
        msg
    }

    fn igp_v6_msg(network: &str, prefix_len: u8, metric: u32, table: u32) -> RouteMessage {
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet6;
        msg.header.kind = RouteType::Unicast;
        msg.header.protocol = RouteProtocol::Ospf;
        msg.header.destination_prefix_length = prefix_len;
        msg.header.table = u8::try_from(table).unwrap_or(RouteHeader::RT_TABLE_MAIN);
        msg.attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(
                network.parse().unwrap(),
            )));
        msg.attributes.push(RouteAttribute::Priority(metric));
        msg
    }

    fn bgp_v6_msg(network: &str, prefix_len: u8, table: u32) -> RouteMessage {
        let mut msg = igp_v6_msg(network, prefix_len, 20, table);
        msg.header.protocol = RouteProtocol::Bgp;
        msg
    }

    // ── is_bgp_route ─────────────────────────────────────────────────────────

    #[test]
    fn bgp_route_identified_correctly() {
        assert!(is_bgp_route(&bgp_v4_msg("10.0.0.0", 8, 254)));
    }

    #[test]
    fn ospf_route_not_identified_as_bgp() {
        assert!(!is_bgp_route(&igp_v4_msg("10.0.0.0", 8, 100, 254)));
    }

    // ── withdraw message shape ────────────────────────────────────────────────
    //
    // RTM_DELROUTE matches on (dst, prefix_len, tos, priority, table).
    // Omitting priority means the kernel cannot find the installed route and
    // silently returns an error. These tests assert that the RouteMessageBuilder
    // output for withdrawals carries a Priority attribute matching the installed
    // metric, so a future edit cannot accidentally drop it.

    #[test]
    fn withdraw_v4_message_carries_priority_and_bgp_protocol() {
        let metric: u32 = 20;
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix("10.0.0.0".parse().unwrap(), 24)
            .table_id(254)
            .priority(metric)
            .protocol(RouteProtocol::Bgp)
            .build();
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Priority(m) if *m == metric)),
            "RTM_DELROUTE must include priority({metric}) to match the installed route"
        );
        assert_eq!(
            msg.header.protocol,
            RouteProtocol::Bgp,
            "RTM_DELROUTE must use RTPROT_BGP — the kernel rejects if protocol mismatches the installed route"
        );
    }

    #[test]
    fn withdraw_v6_message_carries_priority_and_bgp_protocol() {
        let metric: u32 = 20;
        let msg = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix("2001:db8::".parse().unwrap(), 32)
            .table_id(254)
            .priority(metric)
            .protocol(RouteProtocol::Bgp)
            .build();
        assert!(
            msg.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Priority(m) if *m == metric)),
            "RTM_DELROUTE (v6) must include priority({metric}) to match the installed route"
        );
        assert_eq!(
            msg.header.protocol,
            RouteProtocol::Bgp,
            "RTM_DELROUTE (v6) must use RTPROT_BGP — the kernel rejects if protocol mismatches the installed route"
        );
    }

    // ── install_blackhole_v4/v6 — message shape ───────────────────────────────

    #[test]
    fn install_blackhole_v4_message_has_blackhole_type_and_bgp_protocol() {
        let mut msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix("192.0.2.0".parse().unwrap(), 24)
            .table_id(254)
            .priority(20)
            .protocol(RouteProtocol::Bgp)
            .build();
        msg.header.kind = RouteType::BlackHole;
        assert_eq!(
            msg.header.kind,
            RouteType::BlackHole,
            "blackhole route must use RTN_BLACKHOLE"
        );
        assert_eq!(
            msg.header.protocol,
            RouteProtocol::Bgp,
            "blackhole route must be tagged RTPROT_BGP for correct withdrawal"
        );
        // No gateway attribute.
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Gateway(_))),
            "blackhole route must have no gateway"
        );
    }

    #[test]
    fn install_blackhole_v6_message_has_blackhole_type_and_bgp_protocol() {
        let mut msg = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix("2001:db8::".parse().unwrap(), 32)
            .table_id(254)
            .priority(20)
            .protocol(RouteProtocol::Bgp)
            .build();
        msg.header.kind = RouteType::BlackHole;
        assert_eq!(
            msg.header.kind,
            RouteType::BlackHole,
            "IPv6 blackhole route must use RTN_BLACKHOLE"
        );
        assert_eq!(
            msg.header.protocol,
            RouteProtocol::Bgp,
            "IPv6 blackhole route must be tagged RTPROT_BGP"
        );
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Gateway(_))),
            "IPv6 blackhole route must have no gateway"
        );
    }

    // ── withdraw_blackhole_route_v4/v6 — message shape ───────────────────────

    #[test]
    fn withdraw_blackhole_v4_message_has_blackhole_type_and_bgp_protocol() {
        // RTM_DELROUTE for a blackhole route must carry RTN_BLACKHOLE. The
        // kernel matches on route type for deletion — sending RTN_UNSPEC (the
        // builder default) returns ESRCH, which we treat as success, causing
        // the kernel null route to persist silently.
        let mut msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix("192.0.2.0".parse().unwrap(), 24)
            .table_id(254)
            .priority(20)
            .protocol(RouteProtocol::Bgp)
            .build();
        msg.header.kind = RouteType::BlackHole;
        assert_eq!(
            msg.header.kind,
            RouteType::BlackHole,
            "RTM_DELROUTE for a blackhole route must use RTN_BLACKHOLE, not RTN_UNSPEC"
        );
        assert_eq!(
            msg.header.protocol,
            RouteProtocol::Bgp,
            "RTM_DELROUTE must carry RTPROT_BGP to match the installed route"
        );
    }

    #[test]
    fn withdraw_blackhole_v6_message_has_blackhole_type_and_bgp_protocol() {
        let mut msg = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix("2001:db8::".parse().unwrap(), 32)
            .table_id(254)
            .priority(20)
            .protocol(RouteProtocol::Bgp)
            .build();
        msg.header.kind = RouteType::BlackHole;
        assert_eq!(
            msg.header.kind,
            RouteType::BlackHole,
            "IPv6 RTM_DELROUTE for a blackhole route must use RTN_BLACKHOLE"
        );
        assert_eq!(
            msg.header.protocol,
            RouteProtocol::Bgp,
            "IPv6 RTM_DELROUTE must carry RTPROT_BGP"
        );
    }

    // ── Fixtures for the identity tests ──────────────────────────────────────
    //
    // Notification flags as the kernel sets them on the RTM_NEWROUTE it
    // multicasts (fib_table_insert / fib6_add_rt2node):
    // - a new route in an empty slot: NLM_F_EXCL | NLM_F_CREATE;
    // - `ip route append` into an occupied IPv4 slot: NLM_F_CREATE | NLM_F_APPEND;
    // - `ip route replace` of an existing route: NLM_F_REPLACE.
    const CREATE: u16 = netlink_packet_core::NLM_F_EXCL | netlink_packet_core::NLM_F_CREATE;
    const APPEND: u16 = netlink_packet_core::NLM_F_CREATE | NLM_F_APPEND;
    const REPLACE: u16 = NLM_F_REPLACE;

    fn with_gateway(mut msg: RouteMessage, gateway: &str) -> RouteMessage {
        let addr = match gateway.parse::<IpAddr>().unwrap() {
            IpAddr::V4(v4) => RouteAddress::Inet(v4),
            IpAddr::V6(v6) => RouteAddress::Inet6(v6),
        };
        msg.attributes.push(RouteAttribute::Gateway(addr));
        msg
    }

    fn with_oif(mut msg: RouteMessage, oif: u32) -> RouteMessage {
        msg.attributes.push(RouteAttribute::Oif(oif));
        msg
    }

    /// An IPv6 message for an ECMP sibling set, as `rt6_fill_node` encodes it.
    fn ecmp_v6_msg(
        network: &str,
        prefix_len: u8,
        metric: u32,
        legs: &[(&str, u32)],
    ) -> RouteMessage {
        let mut msg = igp_v6_msg(network, prefix_len, metric, 254);
        let legs = legs
            .iter()
            .map(|&(gw, oif)| {
                let mut leg = RouteNextHop::default();
                leg.interface_index = oif;
                leg.attributes
                    .push(RouteAttribute::Gateway(RouteAddress::Inet6(
                        gw.parse().unwrap(),
                    )));
                leg
            })
            .collect();
        msg.attributes.push(RouteAttribute::MultiPath(legs));
        msg
    }

    /// The negative route types, in `ip-route(8)` order.
    const NEGATIVE_TYPES: [RouteType; 4] = [
        RouteType::BlackHole,
        RouteType::Unreachable,
        RouteType::Prohibit,
        RouteType::Throw,
    ];

    /// A negative IPv4 route as the kernel reports it: `ip route add
    /// blackhole ...` uses `RTPROT_BOOT` and universe scope, and the kernel
    /// refuses a gateway or device for these types (`fib_create_info`).
    fn negative_v4_msg(
        network: &str,
        prefix_len: u8,
        metric: u32,
        kind: RouteType,
    ) -> RouteMessage {
        let mut msg = igp_v4_msg(network, prefix_len, metric, 254);
        msg.header.kind = kind;
        msg.header.protocol = RouteProtocol::Boot;
        msg
    }

    /// A negative IPv6 route as the kernel reports it: on the loopback device
    /// (`fib6_nh_init` holds `net->loopback_dev`), which is ifindex 1.
    fn negative_v6_msg(
        network: &str,
        prefix_len: u8,
        metric: u32,
        kind: RouteType,
    ) -> RouteMessage {
        let mut msg = with_oif(igp_v6_msg(network, prefix_len, metric, 254), 1);
        msg.header.kind = kind;
        msg.header.protocol = RouteProtocol::Boot;
        msg
    }

    fn metric_v4(snap: &FibSnapshot, addr: &str) -> Option<u32> {
        snap.igp_metric_v4(addr.parse().unwrap())
    }

    fn metric_v6(snap: &FibSnapshot, addr: &str) -> Option<u32> {
        snap.igp_metric_v6(addr.parse().unwrap())
    }

    // ── Tracking policy ──────────────────────────────────────────────────────

    #[test]
    fn unicast_and_negative_routes_are_tracked_bgp_and_local_types_are_not() {
        assert!(
            !decode_v4(&bgp_v4_msg("10.0.0.0", 8, 254))
                .unwrap()
                .is_tracked()
        );
        assert!(!decode_v6(&bgp_v6_msg("2001:db8::", 32, 254))[0].is_tracked());
        assert!(
            decode_v4(&igp_v4_msg("10.0.0.0", 8, 100, 254))
                .unwrap()
                .is_tracked()
        );
        // Issue #57: a negative route decides reachability for what it covers.
        for kind in NEGATIVE_TYPES {
            let v4 = negative_v4_msg("10.0.0.0", 8, 100, kind);
            assert!(decode_v4(&v4).unwrap().is_tracked(), "{kind:?}");
            let v6 = negative_v6_msg("2001:db8::", 32, 100, kind);
            assert!(decode_v6(&v6)[0].is_tracked(), "{kind:?}");
            // FibWriter's own RFC 7999 blackholes stay excluded like every
            // other BGP route.
            let mut bgp = v4;
            bgp.header.protocol = RouteProtocol::Bgp;
            assert!(!decode_v4(&bgp).unwrap().is_tracked(), "BGP {kind:?}");
        }
        for kind in [
            RouteType::Local,
            RouteType::Broadcast,
            RouteType::Anycast,
            RouteType::Multicast,
            RouteType::Nat,
            RouteType::Unspec,
        ] {
            let mut msg = igp_v4_msg("10.0.0.0", 8, 100, 254);
            msg.header.kind = kind;
            assert!(!decode_v4(&msg).unwrap().is_tracked(), "{kind:?}");
            let mut snap = FibSnapshot::new();
            assert!(!apply_new(&mut snap, &msg, CREATE, 254), "{kind:?}");
        }
    }

    #[test]
    fn apply_new_bgp_route_returns_false_and_leaves_snapshot_empty() {
        let mut snap = FibSnapshot::new();
        assert!(!apply_new(
            &mut snap,
            &bgp_v4_msg("10.0.0.0", 8, 254),
            CREATE,
            254
        ));
        assert!(!apply_new(
            &mut snap,
            &bgp_v6_msg("2001:db8::", 32, 254),
            CREATE,
            254
        ));
        // Mirrored for slot bookkeeping, but never used or reported.
        assert_eq!(snap.routes_v4().count() + snap.routes_v6().count(), 0);
        assert_eq!(snap.igp_metric_v4("10.1.1.1".parse().unwrap()), None);
        assert_eq!(snap.igp_metric_v6("2001:db8::1".parse().unwrap()), None);
    }

    #[test]
    fn apply_new_rejects_route_in_wrong_table() {
        let mut snap = FibSnapshot::new();
        assert!(!apply_new(
            &mut snap,
            &igp_v4_msg("10.0.0.0", 8, 100, 200),
            CREATE,
            254
        ));
        assert!(!apply_new(
            &mut snap,
            &igp_v6_msg("2001:db8::", 32, 100, 200),
            CREATE,
            254
        ));
        assert!(snap.v4.is_empty() && snap.v6.is_empty());
    }

    #[test]
    fn apply_del_bgp_route_returns_false() {
        let mut snap = FibSnapshot::new();
        apply_new(&mut snap, &igp_v4_msg("10.0.0.0", 8, 20, 254), CREATE, 254);
        let mut del = igp_v4_msg("10.0.0.0", 8, 20, 254);
        del.header.protocol = RouteProtocol::Bgp;
        assert!(
            !apply_del(&mut snap, &del, 254),
            "BGP DelRoute must not signal change"
        );
        assert_eq!(snap.v4.len(), 1);
    }

    // ── Decoding ─────────────────────────────────────────────────────────────

    #[test]
    fn decode_v4_reads_every_identity_field() {
        let mut msg = with_oif(
            with_gateway(igp_v4_msg("10.1.0.0", 16, 30, 254), "192.0.2.1"),
            7,
        );
        msg.header.tos = 0x10;
        msg.attributes
            .push(RouteAttribute::PrefSource(RouteAddress::Inet(
                "192.0.2.9".parse().unwrap(),
            )));
        let r = decode_v4(&msg).unwrap();
        assert_eq!(r.kind, u8::from(RouteType::Unicast));
        assert_eq!(r.slot.table, TableId::MAIN);
        assert_eq!(r.slot.dst.to_string(), "10.1.0.0/16");
        assert_eq!(r.slot.tos, 0x10);
        assert_eq!(r.slot.priority, 30);
        assert_eq!(r.protocol, u8::from(RouteProtocol::Ospf));
        assert_eq!(r.prefsrc, Some("192.0.2.9".parse().unwrap()));
        assert_eq!(
            r.next_hop,
            NextHopV4::Path(NextHopPath {
                gateway: Some("192.0.2.1".parse().unwrap()),
                oif: NonZeroU32::new(7),
            })
        );
    }

    #[test]
    fn decode_v4_default_route_without_destination_is_zero_prefix() {
        // fib_dump_info omits RTA_DST when the prefix length is 0.
        let mut msg = RouteMessage::default();
        msg.header.address_family = AddressFamily::Inet;
        msg.header.kind = RouteType::Unicast;
        msg.header.table = 254;
        let r = decode_v4(&msg).unwrap();
        assert_eq!(r.slot.dst, Ipv4Prefix::DEFAULT);
        assert_eq!(r.slot.priority, 0, "absent RTA_PRIORITY means priority 0");
    }

    #[test]
    fn decode_rejects_unspecified_table_and_host_bits() {
        let mut msg = igp_v4_msg("10.0.0.0", 8, 1, 254);
        msg.header.table = 0;
        assert!(
            decode_v4(&msg).is_none(),
            "RT_TABLE_UNSPEC is not a real table"
        );
        // fib_valid_key_len: "Invalid prefix for given prefix length".
        assert!(decode_v4(&igp_v4_msg("10.0.0.1", 8, 1, 254)).is_none());
        assert_eq!(
            decode_v6(&igp_v6_msg("2001:db8::1", 32, 1, 254)),
            Vec::new()
        );
    }

    #[test]
    fn route_table_uses_rta_table_attribute_when_present() {
        let mut msg = igp_v4_msg("10.0.0.0", 8, 100, 254);
        // Table IDs > 255 are stored in RTA_TABLE, not the header byte.
        msg.attributes.push(RouteAttribute::Table(300));
        assert_eq!(route_table(&msg), 300);
        assert_eq!(decode_v4(&msg).unwrap().slot.table.get(), 300);
    }

    #[test]
    fn route_table_falls_back_to_header_when_no_attribute() {
        let msg = igp_v4_msg("10.0.0.0", 8, 100, 254);
        assert_eq!(route_table(&msg), 254);
    }

    #[test]
    fn in_table_zero_matches_any_table() {
        let msg = igp_v4_msg("10.0.0.0", 8, 100, 200);
        assert!(
            in_table(&msg, 0),
            "table 0 must match routes from any table"
        );
    }

    #[test]
    fn decode_reads_nexthop_object_id() {
        // RTA_NH_ID is a host-order u32 (nla_put_u32 in rt6_fill_node /
        // fib_dump_info).
        let nh = RouteAttribute::Other(netlink_packet_core::DefaultNla::new(
            RTA_NH_ID,
            42u32.to_ne_bytes().to_vec(),
        ));
        let mut v4 = igp_v4_msg("10.0.0.0", 8, 1, 254);
        v4.attributes.push(nh.clone());
        assert_eq!(decode_v4(&v4).unwrap().next_hop, NextHopV4::Object(42));

        // Even if compat mode adds RTA_MULTIPATH, a nexthop-object route is one
        // route and is not split.
        let mut v6 = ecmp_v6_msg("2001:db8::", 32, 1, &[("fe80::1", 2), ("fe80::2", 3)]);
        v6.attributes.push(nh);
        let routes = decode_v6(&v6);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, NextHopV6::Object(42));
    }

    #[test]
    fn decode_v4_keeps_multipath_legs_together() {
        // An IPv4 multipath route is one fib_alias; it must stay one route.
        let mut msg = igp_v4_msg("10.0.0.0", 8, 1, 254);
        let legs = ["192.0.2.1", "192.0.2.2"]
            .iter()
            .zip([2u32, 3])
            .map(|(gw, oif)| {
                let mut leg = RouteNextHop::default();
                leg.interface_index = oif;
                leg.hops = 1;
                leg.attributes
                    .push(RouteAttribute::Gateway(RouteAddress::Inet(
                        gw.parse().unwrap(),
                    )));
                leg
            })
            .collect();
        msg.attributes.push(RouteAttribute::MultiPath(legs));
        let NextHopV4::Multipath(legs) = decode_v4(&msg).unwrap().next_hop else {
            panic!("expected multipath");
        };
        assert_eq!(legs.len(), 2);
        assert_eq!(legs[1].path.oif, NonZeroU32::new(3));
        assert_eq!(legs[1].hops, 1);
    }

    #[test]
    fn decode_v6_splits_ecmp_siblings_and_reads_source_prefix() {
        let msg = ecmp_v6_msg("2001:db8::", 32, 5, &[("fe80::1", 2), ("fe80::2", 3)]);
        let routes = decode_v6(&msg);
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .all(|r| r.slot.priority == 5 && r.qualifies_for_ecmp())
        );

        let mut sourced = igp_v6_msg("2001:db8::", 32, 5, 254);
        sourced.header.source_prefix_length = 48;
        sourced
            .attributes
            .push(RouteAttribute::Source(RouteAddress::Inet6(
                "2001:db8:1::".parse().unwrap(),
            )));
        assert_eq!(
            decode_v6(&sourced)[0].slot.src.to_string(),
            "2001:db8:1::/48"
        );
    }

    // ── Issue #56 acceptance: same prefix, metrics 10 and 100 ────────────────
    //
    // fib_table_insert groups IPv4 aliases by "[prefix,dscp,priority]" and
    // fib6_add_rt2node groups IPv6 routes by metric, so two routes for one
    // prefix with different priorities are two kernel routes. The lookup takes
    // the lowest priority (fib_table_lookup walks aliases in ascending
    // priority; fib6 nodes are sorted by metric). fib_table_delete and
    // fib6_del remove exactly one route and report it in RTM_DELROUTE.

    fn same_prefix_lifecycle(
        primary: &RouteMessage,
        backup: &RouteMessage,
        metric: impl Fn(&FibSnapshot) -> Option<u32>,
    ) {
        for (first, second) in [(primary, backup), (backup, primary)] {
            let mut snap = FibSnapshot::new();
            assert!(apply_new(&mut snap, first, CREATE, 254));
            assert!(
                apply_new(&mut snap, second, CREATE, 254),
                "a second priority for the same prefix is a new route"
            );
            assert_eq!(
                metric(&snap),
                Some(10),
                "lowest priority wins in either order"
            );

            let mut backup_gone = snap.clone();
            assert!(apply_del(&mut backup_gone, backup, 254));
            assert_eq!(
                metric(&backup_gone),
                Some(10),
                "deleting the backup keeps the primary"
            );

            let mut primary_gone = snap.clone();
            assert!(apply_del(&mut primary_gone, primary, 254));
            assert_eq!(
                metric(&primary_gone),
                Some(100),
                "deleting the primary falls back"
            );

            assert!(apply_del(&mut primary_gone, backup, 254));
            assert_eq!(metric(&primary_gone), None);
        }
    }

    #[test]
    fn ipv4_same_prefix_different_metrics_are_distinct_routes() {
        same_prefix_lifecycle(
            &igp_v4_msg("198.51.100.0", 24, 10, 254),
            &igp_v4_msg("198.51.100.0", 24, 100, 254),
            |s| metric_v4(s, "198.51.100.7"),
        );
    }

    #[test]
    fn ipv6_same_prefix_different_metrics_are_distinct_routes() {
        same_prefix_lifecycle(
            &igp_v6_msg("2001:db8:1::", 64, 10, 254),
            &igp_v6_msg("2001:db8:1::", 64, 100, 254),
            |s| metric_v6(s, "2001:db8:1::7"),
        );
    }

    #[test]
    fn initial_dump_matches_incremental_state_in_any_order() {
        let msgs = [
            igp_v4_msg("198.51.100.0", 24, 100, 254),
            igp_v4_msg("198.51.100.0", 24, 10, 254),
            igp_v6_msg("2001:db8:1::", 64, 100, 254),
            igp_v6_msg("2001:db8:1::", 64, 10, 254),
        ];
        let mut incremental = FibSnapshot::new();
        for m in &msgs {
            apply_new(&mut incremental, m, CREATE, 254);
        }
        for order in [[0, 1, 2, 3], [1, 0, 3, 2]] {
            let mut dumped = FibSnapshot::new();
            for i in order {
                apply_dumped(&mut dumped, &msgs[i], 254);
            }
            assert_eq!(metric_v4(&dumped, "198.51.100.7"), Some(10));
            assert_eq!(metric_v6(&dumped, "2001:db8:1::7"), Some(10));
            assert_eq!(dumped.v4.len(), incremental.v4.len());
            assert_eq!(dumped.v6.len(), incremental.v6.len());
            // Events that arrived during the dump are replayed afterwards; the
            // replay must not change anything.
            for m in &msgs {
                assert!(!apply_new(&mut dumped, m, CREATE, 254));
            }
        }
    }

    #[test]
    fn duplicate_notification_is_not_a_change() {
        let mut snap = FibSnapshot::new();
        let msg = igp_v4_msg("192.168.0.0", 24, 10, 254);
        assert!(apply_new(&mut snap, &msg, CREATE, 254));
        assert!(!apply_new(&mut snap, &msg, CREATE, 254));
        let msg6 = igp_v6_msg("2001:db8::", 32, 50, 254);
        assert!(apply_new(&mut snap, &msg6, CREATE, 254));
        assert!(!apply_new(&mut snap, &msg6, CREATE, 254));
        assert_eq!((snap.v4.len(), snap.v6.len()), (1, 1));
    }

    #[test]
    fn delete_of_absent_route_is_not_a_change() {
        let mut snap = FibSnapshot::new();
        apply_new(
            &mut snap,
            &igp_v4_msg("192.168.0.0", 24, 10, 254),
            CREATE,
            254,
        );
        // Same prefix, different priority: a different route, so nothing goes.
        assert!(!apply_del(
            &mut snap,
            &igp_v4_msg("192.168.0.0", 24, 20, 254),
            254
        ));
        assert!(!apply_del(
            &mut snap,
            &igp_v6_msg("2001:db8::", 32, 0, 254),
            254
        ));
        assert_eq!(snap.v4.len(), 1);
    }

    // ── Other identity selectors ─────────────────────────────────────────────

    #[test]
    fn same_prefix_in_two_tables_are_distinct_when_tracking_all_tables() {
        let mut snap = FibSnapshot::new();
        let main = igp_v4_msg("10.0.0.0", 8, 10, 254);
        let other = igp_v4_msg("10.0.0.0", 8, 10, 100);
        assert!(apply_new(&mut snap, &main, CREATE, 0));
        assert!(apply_new(&mut snap, &other, CREATE, 0));
        assert_eq!(snap.v4.len(), 2);
        assert!(apply_del(&mut snap, &main, 0));
        assert_eq!(
            metric_v4(&snap, "10.1.1.1"),
            Some(10),
            "table 100's route remains"
        );
    }

    #[test]
    fn tos_route_neither_overwrites_nor_serves_best_effort_lookups() {
        // fib_table_lookup: `if (fa->fa_dscp && !fib_dscp_masked_match(...))
        // continue;` — a DSCP-specific alias does not match other traffic.
        let mut snap = FibSnapshot::new();
        let plain = igp_v4_msg("10.0.0.0", 8, 50, 254);
        let mut tos = igp_v4_msg("10.0.0.0", 8, 5, 254);
        tos.header.tos = 0x10;
        apply_new(&mut snap, &plain, CREATE, 254);
        assert!(apply_new(&mut snap, &tos, CREATE, 254));
        assert_eq!(metric_v4(&snap, "10.1.1.1"), Some(50));
        assert!(apply_del(&mut snap, &tos, 254));
        assert_eq!(metric_v4(&snap, "10.1.1.1"), Some(50));
        assert!(apply_del(&mut snap, &plain, 254));
        assert!(
            !apply_new(&mut FibSnapshot::new(), &tos, CREATE, 1),
            "wrong table"
        );
        apply_new(&mut snap, &tos, CREATE, 254);
        assert_eq!(
            metric_v4(&snap, "10.1.1.1"),
            None,
            "only a TOS route: no best-effort route"
        );
    }

    #[test]
    fn appended_ipv4_aliases_in_one_slot_are_deleted_individually() {
        // `ip route append`: same [prefix, dscp, priority], different next hop.
        let mut snap = FibSnapshot::new();
        let a = with_gateway(igp_v4_msg("10.0.0.0", 8, 10, 254), "192.0.2.1");
        let b = with_gateway(igp_v4_msg("10.0.0.0", 8, 10, 254), "192.0.2.2");
        assert!(apply_new(&mut snap, &a, CREATE, 254));
        assert!(apply_new(&mut snap, &b, APPEND, 254));
        assert!(apply_del(&mut snap, &a, 254));
        assert_eq!(
            metric_v4(&snap, "10.1.1.1"),
            Some(10),
            "b is still installed"
        );
    }

    // ── NLM_F_REPLACE ────────────────────────────────────────────────────────

    #[test]
    fn ipv4_replace_swaps_the_slots_first_alias_without_a_delete() {
        let mut snap = FibSnapshot::new();
        let old = with_gateway(igp_v4_msg("10.0.0.0", 8, 10, 254), "192.0.2.1");
        let new = with_gateway(igp_v4_msg("10.0.0.0", 8, 10, 254), "192.0.2.2");
        apply_new(&mut snap, &old, CREATE, 254);
        assert!(apply_new(&mut snap, &new, REPLACE, 254));
        assert_eq!(snap.v4.len(), 1);
        assert!(!apply_del(&mut snap, &old, 254), "the old alias is gone");
        assert!(apply_del(&mut snap, &new, 254));
    }

    #[test]
    fn bgp_replacing_an_igp_route_removes_it_from_the_snapshot() {
        // FibWriter installs with NLM_F_REPLACE. With the same prefix and
        // priority as an IGP route, the kernel replaces the IGP alias; the
        // only notification is RTM_NEWROUTE for the BGP route.
        let mut snap = FibSnapshot::new();
        apply_new(&mut snap, &igp_v4_msg("10.0.0.0", 8, 20, 254), CREATE, 254);
        apply_new(
            &mut snap,
            &igp_v6_msg("2001:db8::", 32, 20, 254),
            CREATE,
            254,
        );
        assert!(apply_new(
            &mut snap,
            &bgp_v4_msg("10.0.0.0", 8, 254),
            REPLACE,
            254
        ));
        assert!(apply_new(
            &mut snap,
            &bgp_v6_msg("2001:db8::", 32, 254),
            REPLACE,
            254
        ));
        assert_eq!(snap.routes_v4().count() + snap.routes_v6().count(), 0);
    }

    // ── PR #122 review: untracked routes in the same slot / ECMP set ─────────

    #[test]
    fn replacing_a_leading_bgp_alias_keeps_the_static_alias_behind_it() {
        // Kernel slot order [BGP via .1, static dev]. fib_table_insert with
        // NLM_F_REPLACE swaps `fa_first` — the BGP alias — and leaves the
        // static alias in place.
        let bgp1 = with_oif(
            with_gateway(bgp_v4_msg("198.18.1.0", 24, 254), "192.0.2.1"),
            2,
        );
        let bgp2 = with_oif(
            with_gateway(bgp_v4_msg("198.18.1.0", 24, 254), "192.0.2.2"),
            2,
        );
        let mut static_route = with_oif(igp_v4_msg("198.18.1.0", 24, 20, 254), 2);
        static_route.header.protocol = RouteProtocol::Static;

        // Through the initial dump (kernel order) ...
        let mut dumped = FibSnapshot::new();
        apply_dumped(&mut dumped, &bgp1, 254);
        apply_dumped(&mut dumped, &static_route, 254);
        // ... and incrementally: static first, then BGP prepended
        // (NLM_F_CREATE without NLM_F_APPEND goes to the front).
        let mut incremental = FibSnapshot::new();
        apply_new(&mut incremental, &static_route, CREATE, 254);
        assert!(!apply_new(
            &mut incremental,
            &bgp1,
            netlink_packet_core::NLM_F_CREATE,
            254
        ));

        for snap in [&mut dumped, &mut incremental] {
            assert_eq!(metric_v4(snap, "198.18.1.7"), Some(20));
            assert!(
                !apply_new(snap, &bgp2, REPLACE, 254),
                "only the BGP alias was replaced"
            );
            assert_eq!(
                metric_v4(snap, "198.18.1.7"),
                Some(20),
                "static alias survives"
            );
            assert!(!apply_del(snap, &bgp1, 254), "the old BGP alias is gone");
            assert!(
                !apply_del(snap, &bgp2, 254),
                "untracked: no change signalled"
            );
            assert!(apply_del(snap, &static_route, 254));
            assert_eq!(metric_v4(snap, "198.18.1.7"), None);
        }
    }

    /// A one-leg IPv6 message (`RTM_DELROUTE` of one sibling, or a single add).
    fn v6_leg(prefix: &str, gw: &str, protocol: RouteProtocol) -> RouteMessage {
        let mut msg = with_oif(with_gateway(igp_v6_msg(prefix, 64, 10, 254), gw), 2);
        msg.header.protocol = protocol;
        msg
    }

    /// The single dump message for an ECMP set: `fib6_dump_node` dumps the set
    /// once, headed by its first sibling, then skips the other siblings.
    fn v6_set_dump(prefix: &str, first: RouteProtocol, legs: &[&str]) -> RouteMessage {
        let legs: Vec<_> = legs.iter().map(|gw| (*gw, 2)).collect();
        let mut msg = ecmp_v6_msg(prefix, 64, 10, &legs);
        msg.header.protocol = first;
        msg
    }

    #[test]
    fn dumped_static_ecmp_set_keeps_the_surviving_sibling() {
        // PR #122 review round 2: both siblings are static, but the dump
        // describes only the first. Deleting it must leave the second usable.
        let mut snap = FibSnapshot::new();
        apply_dumped(
            &mut snap,
            &v6_set_dump(
                "2001:db8:200::",
                RouteProtocol::Static,
                &["fe80::1", "fe80::2"],
            ),
            254,
        );
        assert_eq!(snap.routes_v6().count(), 2);
        assert!(apply_del(
            &mut snap,
            &v6_leg("2001:db8:200::", "fe80::1", RouteProtocol::Static),
            254
        ));
        assert_eq!(metric_v6(&snap, "2001:db8:200::1"), Some(10));
        assert!(apply_del(
            &mut snap,
            &v6_leg("2001:db8:200::", "fe80::2", RouteProtocol::Static),
            254
        ));
        assert_eq!(metric_v6(&snap, "2001:db8:200::1"), None);
    }

    #[test]
    fn dumped_all_bgp_ecmp_set_is_not_igp_reachability() {
        // PR #122 review round 3: two BGP siblings and nothing else. Live
        // events report each BGP route, so the running snapshot has no path;
        // a restart's dump must agree.
        let mut live = FibSnapshot::new();
        apply_new(
            &mut live,
            &v6_leg("2001:db8:203::", "fe80::1", RouteProtocol::Bgp),
            APPEND,
            254,
        );
        let second = v6_set_dump(
            "2001:db8:203::",
            RouteProtocol::Bgp,
            &["fe80::2", "fe80::1"],
        );
        apply_new(&mut live, &second, APPEND, 254);
        assert_eq!(metric_v6(&live, "2001:db8:203::1"), None);

        let mut dumped = FibSnapshot::new();
        apply_dumped(
            &mut dumped,
            &v6_set_dump(
                "2001:db8:203::",
                RouteProtocol::Bgp,
                &["fe80::1", "fe80::2"],
            ),
            254,
        );
        assert_eq!(
            metric_v6(&dumped, "2001:db8:203::1"),
            None,
            "dump agrees with live"
        );
        assert_eq!(dumped.v6.len(), 2, "both siblings mirrored");
    }

    #[test]
    fn dumped_mixed_ecmp_set_headed_by_bgp_follows_the_documented_inference() {
        // The dump message for a BGP-first static+BGP set is the same as for
        // an all-BGP set, so the static sibling is inferred to be BGP. That is
        // the documented cost of keeping all-BGP sets out (see the `route`
        // module docs). A later message reporting the static route fixes it.
        let mut snap = FibSnapshot::new();
        apply_dumped(
            &mut snap,
            &v6_set_dump(
                "2001:db8:202::",
                RouteProtocol::Bgp,
                &["fe80::1", "fe80::2"],
            ),
            254,
        );
        assert_eq!(metric_v6(&snap, "2001:db8:202::1"), None);
        let reported = v6_leg("2001:db8:202::", "fe80::2", RouteProtocol::Static);
        assert!(apply_new(&mut snap, &reported, REPLACE, 254));
        assert_eq!(metric_v6(&snap, "2001:db8:202::1"), Some(10));
        assert!(apply_del(&mut snap, &reported, 254));
        assert!(!apply_del(
            &mut snap,
            &v6_leg("2001:db8:202::", "fe80::1", RouteProtocol::Bgp),
            254
        ));
        assert_eq!(snap.v6.len(), 0);
    }

    #[test]
    fn dumped_mixed_ecmp_set_headed_by_static_clears_after_both_deletes() {
        // Review round 1: the BGP sibling's protocol is not in the dump, so it
        // is inferred to be static (the documented mixed-set limit) and counts
        // until deleted; its delete must be applied.
        let mut snap = FibSnapshot::new();
        apply_dumped(
            &mut snap,
            &v6_set_dump(
                "2001:db8:99::",
                RouteProtocol::Static,
                &["fe80::1", "fe80::2"],
            ),
            254,
        );
        assert_eq!(metric_v6(&snap, "2001:db8:99::1"), Some(10));
        assert!(apply_del(
            &mut snap,
            &v6_leg("2001:db8:99::", "fe80::1", RouteProtocol::Static),
            254
        ));
        assert!(apply_del(
            &mut snap,
            &v6_leg("2001:db8:99::", "fe80::2", RouteProtocol::Bgp),
            254
        ));
        assert_eq!(metric_v6(&snap, "2001:db8:99::1"), None);
        assert_eq!(snap.v6.len(), 0);
    }

    #[test]
    fn incremental_mixed_ecmp_set_knows_each_siblings_protocol() {
        // Single-route appends: each RTM_NEWROUTE is headed by the route it
        // adds (fib6_add_rt2node → inet6_rt_notify(rt)), so protocols are known.
        let mut snap = FibSnapshot::new();
        apply_new(
            &mut snap,
            &v6_leg("2001:db8:99::", "fe80::1", RouteProtocol::Static),
            APPEND,
            254,
        );
        let mut bgp_added =
            v6_set_dump("2001:db8:99::", RouteProtocol::Bgp, &["fe80::2", "fe80::1"]);
        bgp_added.header.protocol = RouteProtocol::Bgp;
        assert!(!apply_new(&mut snap, &bgp_added, APPEND, 254));
        assert_eq!(
            snap.routes_v6().count(),
            1,
            "only the static sibling is tracked"
        );
        assert!(apply_del(
            &mut snap,
            &v6_leg("2001:db8:99::", "fe80::1", RouteProtocol::Static),
            254
        ));
        assert_eq!(
            metric_v6(&snap, "2001:db8:99::1"),
            None,
            "the remaining sibling is BGP"
        );
        assert!(!apply_del(
            &mut snap,
            &v6_leg("2001:db8:99::", "fe80::2", RouteProtocol::Bgp),
            254
        ));
        assert_eq!(snap.v6.len(), 0);
    }

    // ── Re-reading a set after a delete ──────────────────────────────────────
    //
    // fib6_dump_node describes a set through its first sibling; after that
    // sibling is deleted a dump describes the next one, and a lone route in
    // full (rt6_fill_node with no siblings emits no RTA_MULTIPATH).

    fn slot_of(msg: &RouteMessage) -> RouteSlotV6 {
        decode_v6(msg)[0].slot
    }

    /// Applies an RTM_DELROUTE the way the event loop does.
    fn delete_event(snap: &mut FibSnapshot, msg: &RouteMessage) -> HashSet<RouteSlotV6> {
        let lock = RwLock::new(std::mem::take(snap));
        let mut reread = HashSet::new();
        apply_event(
            &lock,
            NetlinkMessage::from(RouteNetlinkMessage::DelRoute(msg.clone())),
            254,
            &mut reread,
        );
        *snap = lock.into_inner().unwrap();
        reread
    }

    /// Applies the kernel's answer to a re-read the way `reread_sets` does.
    fn reread_answer(
        snap: &mut FibSnapshot,
        slots: HashSet<RouteSlotV6>,
        dump: &[RouteMessage],
    ) -> bool {
        let mut changed = false;
        for (filter, slots) in reread_groups(snap, slots) {
            assert_eq!(filter.0, TableId::MAIN);
            for set in dump.iter().filter_map(|m| wanted_set(m, &slots)) {
                changed |= snap.v6.redescribe(set);
            }
        }
        changed
    }

    #[test]
    fn deleting_the_described_bgp_sibling_rereads_and_restores_the_static_path() {
        let prefix = "2001:db8:202::";
        let mut snap = FibSnapshot::new();
        apply_dumped(
            &mut snap,
            &v6_set_dump(prefix, RouteProtocol::Bgp, &["fe80::1", "fe80::2"]),
            254,
        );
        let bgp = v6_leg(prefix, "fe80::1", RouteProtocol::Bgp);
        let reread = delete_event(&mut snap, &bgp);
        assert_eq!(reread, HashSet::from([slot_of(&bgp)]));
        assert_eq!(
            metric_v6(&snap, "2001:db8:202::1"),
            None,
            "before the re-read"
        );

        // The dump now holds the static route on its own, among others.
        let unrelated = v6_leg("2001:db8:300::", "fe80::2", RouteProtocol::Static);
        let lone_static = v6_leg(prefix, "fe80::2", RouteProtocol::Static);
        assert!(reread_answer(&mut snap, reread, &[unrelated, lone_static]));
        assert_eq!(metric_v6(&snap, "2001:db8:202::1"), Some(10));
        assert_eq!(
            snap.routes_v6().count(),
            1,
            "the unrelated route is not added"
        );
    }

    #[test]
    fn deleting_the_described_static_sibling_rereads_and_drops_the_bgp_path() {
        let prefix = "2001:db8:99::";
        let mut snap = FibSnapshot::new();
        apply_dumped(
            &mut snap,
            &v6_set_dump(prefix, RouteProtocol::Static, &["fe80::1", "fe80::2"]),
            254,
        );
        let reread = delete_event(&mut snap, &v6_leg(prefix, "fe80::1", RouteProtocol::Static));
        assert_eq!(
            metric_v6(&snap, "2001:db8:99::1"),
            Some(10),
            "inferred static"
        );
        let lone_bgp = v6_leg(prefix, "fe80::2", RouteProtocol::Bgp);
        assert!(reread_answer(&mut snap, reread, &[lone_bgp]));
        assert_eq!(metric_v6(&snap, "2001:db8:99::1"), None);
        assert_eq!(snap.v6.len(), 1, "still mirrored, as BGP");
    }

    #[test]
    fn reread_of_a_larger_set_settles_its_new_first_sibling() {
        // [B, S, S] dumped: both static siblings are inferred BGP. After B is
        // deleted the kernel describes the first static route and lists the
        // other under its protocol.
        let prefix = "2001:db8:210::";
        let mut snap = FibSnapshot::new();
        apply_dumped(
            &mut snap,
            &v6_set_dump(
                prefix,
                RouteProtocol::Bgp,
                &["fe80::1", "fe80::2", "fe80::3"],
            ),
            254,
        );
        let reread = delete_event(&mut snap, &v6_leg(prefix, "fe80::1", RouteProtocol::Bgp));
        let answer = v6_set_dump(prefix, RouteProtocol::Static, &["fe80::2", "fe80::3"]);
        assert!(reread_answer(&mut snap, reread, &[answer]));
        let got: Vec<_> = snap.routes_v6().map(|r| r.protocol_inferred).collect();
        assert_eq!(got, [false, true], "the third is still a guess");
        assert_eq!(metric_v6(&snap, "2001:db8:210::1"), Some(10));
    }

    #[test]
    fn deletes_that_leave_no_inferred_route_are_not_reread() {
        let prefix = "2001:db8:211::";
        // A set created by one request: every leg's protocol is known.
        let mut created = FibSnapshot::new();
        apply_new(
            &mut created,
            &v6_set_dump(prefix, RouteProtocol::Static, &["fe80::1", "fe80::2"]),
            CREATE,
            254,
        );
        let first = v6_leg(prefix, "fe80::1", RouteProtocol::Static);
        assert!(delete_event(&mut created, &first).is_empty());

        // Deleting the inferred leg leaves only the described one.
        let mut dumped = FibSnapshot::new();
        let set = v6_set_dump(prefix, RouteProtocol::Bgp, &["fe80::1", "fe80::2"]);
        apply_dumped(&mut dumped, &set, 254);
        let mut other = dumped.clone();
        assert!(
            delete_event(
                &mut dumped,
                &v6_leg(prefix, "fe80::2", RouteProtocol::Static)
            )
            .is_empty()
        );
        // Deleting the whole set in one message leaves nothing.
        assert!(delete_event(&mut other, &set).is_empty());
        assert!(other.v6.is_empty());

        // IPv4, and routes in a table we do not track, never are.
        let mut snap = FibSnapshot::new();
        let v4 = igp_v4_msg("10.0.0.0", 8, 10, 254);
        apply_new(&mut snap, &v4, CREATE, 254);
        assert!(delete_event(&mut snap, &v4).is_empty());
        assert_eq!(
            slot_to_reread(
                &FibSnapshot::new(),
                &igp_v6_msg("2001:db8::", 32, 10, 200),
                254
            ),
            None
        );
    }

    #[test]
    fn reread_groups_by_table_and_device_and_skips_settled_slots() {
        let mut snap = FibSnapshot::new();
        let mut on_oif = |prefix: &str, oif: u32, table: u32| {
            let mut msg = v6_set_dump(prefix, RouteProtocol::Bgp, &["fe80::1", "fe80::2"]);
            if let Some(RouteAttribute::MultiPath(legs)) = msg
                .attributes
                .iter_mut()
                .find(|a| matches!(a, RouteAttribute::MultiPath(_)))
            {
                for leg in legs {
                    leg.interface_index = oif;
                }
            }
            msg.attributes.push(RouteAttribute::Table(table));
            apply_dumped(&mut snap, &msg, 0);
            slot_of(&msg)
        };
        let a = on_oif("2001:db8:1::", 2, 254);
        let b = on_oif("2001:db8:2::", 2, 254);
        let c = on_oif("2001:db8:3::", 3, 254);
        let d = on_oif("2001:db8:4::", 2, 300);
        let settled = on_oif("2001:db8:5::", 2, 254);
        let reported = KernelRouteV6 {
            protocol_inferred: false,
            ..snap.v6.first_inferred(&settled).unwrap().clone()
        };
        snap.v6.upsert(reported, Position::Back);

        let groups = reread_groups(&snap, HashSet::from([a, b, c, d, settled]));
        let main = TableId::MAIN;
        let other = TableId::new(300).unwrap();
        let oif = |i| NonZeroU32::new(i);
        assert_eq!(
            groups,
            HashMap::from([
                ((main, oif(2)), HashSet::from([a, b])),
                ((main, oif(3)), HashSet::from([c])),
                ((other, oif(2)), HashSet::from([d])),
            ])
        );
    }

    #[test]
    fn reread_request_obeys_the_strict_dump_rules() {
        // ip_valid_fib_dump_req rejects a nonzero rtm_dst_len, rtm_src_len,
        // rtm_tos or rtm_scope and accepts only RTA_TABLE and RTA_OIF; a
        // nonzero rtm_protocol or rtm_type would filter by the described
        // route's protocol or type. Without RTA_DST rtnetlink sends
        // NLM_F_DUMP.
        let msg = reread_request(TableId::new(300).unwrap(), NonZeroU32::new(7));
        assert_eq!(msg.header.address_family, AddressFamily::Inet6);
        assert_eq!(
            (
                msg.header.destination_prefix_length,
                msg.header.source_prefix_length,
                msg.header.tos,
                u8::from(msg.header.scope),
                u8::from(msg.header.protocol),
                u8::from(msg.header.kind),
                msg.header.table,
            ),
            (0, 0, 0, 0, 0, 0, 0)
        );
        assert!(msg.header.flags.is_empty());
        assert_eq!(
            msg.attributes,
            [RouteAttribute::Table(300), RouteAttribute::Oif(7)]
        );
        let any_device = reread_request(TableId::MAIN, None);
        assert_eq!(any_device.attributes, [RouteAttribute::Table(254)]);
    }

    #[test]
    fn multipath_append_legs_infer_the_described_siblings_protocol() {
        // ip6_route_mpath_notify reports the set's *first* sibling for an
        // NLM_F_APPEND multipath add, so the header says nothing about the
        // appended legs.
        let mut snap = FibSnapshot::new();
        let a = with_oif(
            with_gateway(igp_v6_msg("2001:db8::", 32, 10, 254), "fe80::1"),
            2,
        );
        apply_new(&mut snap, &a, CREATE, 254);
        let appended = ecmp_v6_msg("2001:db8::", 32, 10, &[("fe80::1", 2), ("fe80::2", 2)]);
        assert!(apply_new(&mut snap, &appended, APPEND, 254));
        let inferred: Vec<_> = snap.routes_v6().map(|r| r.protocol_inferred).collect();
        assert!(inferred.contains(&true) && inferred.contains(&false));
        assert!(
            snap.routes_v6()
                .all(|r| r.protocol == u8::from(RouteProtocol::Ospf))
        );
        assert!(apply_del(&mut snap, &a, 254));
        assert_eq!(
            metric_v6(&snap, "2001:db8::1"),
            Some(10),
            "appended leg still a path"
        );
    }

    #[test]
    fn multipath_create_legs_share_the_header_protocol() {
        // Without NLM_F_APPEND, ip6_route_multipath_add reports its first new
        // route, and every leg not yet seen comes from the same request.
        let mut snap = FibSnapshot::new();
        let set = ecmp_v6_msg("2001:db8::", 32, 10, &[("fe80::1", 2), ("fe80::2", 3)]);
        assert!(apply_new(&mut snap, &set, CREATE, 254));
        assert_eq!(snap.routes_v6().count(), 2);
        let a = with_oif(
            with_gateway(igp_v6_msg("2001:db8::", 32, 10, 254), "fe80::1"),
            2,
        );
        assert!(apply_del(&mut snap, &a, 254));
        assert_eq!(metric_v6(&snap, "2001:db8::1"), Some(10));
    }

    #[test]
    fn ipv6_ecmp_sibling_add_and_delete_track_each_sibling() {
        // Appending sibling B to A: one RTM_NEWROUTE listing [B, A]. Deleting
        // B alone: RTM_DELROUTE for B only (fib6_del_route clears the sibling
        // count before inet6_rt_notify).
        let mut snap = FibSnapshot::new();
        let a = with_oif(
            with_gateway(igp_v6_msg("2001:db8::", 32, 10, 254), "fe80::1"),
            2,
        );
        let b = with_oif(
            with_gateway(igp_v6_msg("2001:db8::", 32, 10, 254), "fe80::2"),
            3,
        );
        let both = ecmp_v6_msg("2001:db8::", 32, 10, &[("fe80::2", 3), ("fe80::1", 2)]);
        assert!(apply_new(&mut snap, &a, CREATE, 254));
        assert!(apply_new(&mut snap, &both, APPEND, 254));
        assert_eq!(snap.v6.len(), 2);
        assert!(apply_del(&mut snap, &b, 254));
        assert_eq!(
            metric_v6(&snap, "2001:db8::1"),
            Some(10),
            "sibling A survives"
        );
        assert!(apply_del(&mut snap, &a, 254));
        assert_eq!(metric_v6(&snap, "2001:db8::1"), None);
    }

    #[test]
    fn ipv6_delete_all_siblings_in_one_message() {
        // __ip6_del_rt_siblings with fc_delete_all_nh sends one RTM_DELROUTE
        // listing every sibling.
        let mut snap = FibSnapshot::new();
        let both = ecmp_v6_msg("2001:db8::", 32, 10, &[("fe80::1", 2), ("fe80::2", 3)]);
        apply_new(&mut snap, &both, CREATE, 254);
        assert!(apply_del(&mut snap, &both, 254));
        assert!(snap.v6.is_empty());
    }

    #[test]
    fn ipv6_replace_of_ecmp_set_removes_every_sibling() {
        // fib6_add_rt2node: "Replacing an ECMP route, remove all siblings".
        let mut snap = FibSnapshot::new();
        apply_new(
            &mut snap,
            &ecmp_v6_msg("2001:db8::", 32, 10, &[("fe80::1", 2), ("fe80::2", 3)]),
            CREATE,
            254,
        );
        let c = with_oif(
            with_gateway(igp_v6_msg("2001:db8::", 32, 10, 254), "fe80::3"),
            4,
        );
        assert!(apply_new(&mut snap, &c, REPLACE, 254));
        assert_eq!(snap.v6.len(), 1);
        assert!(apply_del(&mut snap, &c, 254));
        assert!(snap.v6.is_empty());
    }

    #[test]
    fn ipv6_replace_leaves_other_metrics_alone() {
        let mut snap = FibSnapshot::new();
        apply_new(
            &mut snap,
            &igp_v6_msg("2001:db8::", 32, 10, 254),
            CREATE,
            254,
        );
        apply_new(
            &mut snap,
            &igp_v6_msg("2001:db8::", 32, 100, 254),
            CREATE,
            254,
        );
        let replacement = with_oif(igp_v6_msg("2001:db8::", 32, 100, 254), 9);
        assert!(apply_new(&mut snap, &replacement, REPLACE, 254));
        assert_eq!(snap.v6.len(), 2);
        assert_eq!(metric_v6(&snap, "2001:db8::1"), Some(10));
    }

    // ── Issue #57 acceptance: negative routes beneath a covering route ───────
    //
    // ip-route(8): blackhole/unreachable/prohibit destinations "are
    // unreachable"; a selected throw route terminates the lookup in the table
    // "pretending that no route was found". fib_table_lookup returns the
    // selected alias's fib_props error without backtracking to the covering
    // route; fib6_table_lookup likewise backtracks only when no route of the
    // node is selected.

    #[test]
    fn decode_reads_the_route_type() {
        let cases = [
            (
                RouteType::BlackHole,
                RouteKind::Reject(RejectKind::Blackhole),
            ),
            (
                RouteType::Unreachable,
                RouteKind::Reject(RejectKind::Unreachable),
            ),
            (RouteType::Prohibit, RouteKind::Reject(RejectKind::Prohibit)),
            (RouteType::Throw, RouteKind::Throw),
        ];
        for (rtm_type, kind) in cases {
            let v4 = decode_v4(&negative_v4_msg("10.0.0.0", 8, 5, rtm_type)).unwrap();
            assert_eq!(v4.route_kind(), Some(kind));
            assert_eq!(
                v4.next_hop,
                NextHopV4::Path(NextHopPath {
                    gateway: None,
                    oif: None
                })
            );
            let v6 = decode_v6(&negative_v6_msg("2001:db8::", 32, 5, rtm_type));
            assert_eq!(v6.len(), 1);
            assert_eq!(v6[0].route_kind(), Some(kind));
            assert!(!v6[0].qualifies_for_ecmp());
        }
        assert_eq!(
            decode_v4(&igp_v4_msg("10.0.0.0", 8, 5, 254))
                .unwrap()
                .route_kind(),
            Some(RouteKind::Unicast)
        );
    }

    /// Covering unicast route, then each negative route beneath it, then the
    /// negative route's deletion, through the same entry points the event
    /// loop uses.
    fn negative_lifecycle(
        covering: &RouteMessage,
        negative: impl Fn(RouteType) -> RouteMessage,
        reachable: impl Fn(&FibSnapshot) -> bool,
        outside: impl Fn(&FibSnapshot) -> bool,
    ) {
        for kind in NEGATIVE_TYPES {
            let mut snap = FibSnapshot::new();
            assert!(apply_new(&mut snap, covering, CREATE, 254));
            assert!(reachable(&snap), "covered by the unicast route");

            let neg = negative(kind);
            assert!(
                apply_new(&mut snap, &neg, CREATE, 254),
                "{kind:?} is tracked"
            );
            assert!(
                !reachable(&snap),
                "{kind:?} beneath a covering route: unreachable"
            );
            assert!(outside(&snap), "{kind:?} only affects what it covers");

            assert!(apply_del(&mut snap, &neg, 254), "{kind:?} deleted");
            assert!(reachable(&snap), "{kind:?} deleted: reachability recovers");

            // The initial dump gives the same answer as the events.
            let mut dumped = FibSnapshot::new();
            apply_dumped(&mut dumped, &neg, 254);
            apply_dumped(&mut dumped, covering, 254);
            assert!(!reachable(&dumped), "{kind:?} from the dump");
        }
    }

    #[test]
    fn ipv4_negative_route_beneath_a_covering_route_is_unreachable() {
        negative_lifecycle(
            &with_gateway(igp_v4_msg("0.0.0.0", 0, 0, 254), "192.0.2.1"),
            |kind| negative_v4_msg("10.1.0.0", 16, 0, kind),
            |s| s.is_v4_reachable("10.1.2.3".parse().unwrap()),
            |s| s.igp_metric_v4("10.2.0.1".parse().unwrap()) == Some(0),
        );
    }

    #[test]
    fn ipv6_negative_route_beneath_a_covering_route_is_unreachable() {
        negative_lifecycle(
            &with_oif(with_gateway(igp_v6_msg("::", 0, 1024, 254), "fe80::1"), 2),
            |kind| negative_v6_msg("2001:db8:1::", 48, 1024, kind),
            |s| s.is_v6_reachable("2001:db8:1::3".parse().unwrap()),
            |s| s.igp_metric_v6("2001:db8:2::1".parse().unwrap()) == Some(1024),
        );
    }

    #[test]
    fn replacing_a_unicast_route_with_a_negative_one_is_followed() {
        // `ip route replace blackhole <prefix> metric <m>`: one RTM_NEWROUTE
        // with NLM_F_REPLACE and no RTM_DELROUTE for the unicast route.
        for kind in NEGATIVE_TYPES {
            let mut snap = FibSnapshot::new();
            apply_new(&mut snap, &igp_v4_msg("0.0.0.0", 0, 0, 254), CREATE, 254);
            apply_new(&mut snap, &igp_v4_msg("10.0.0.0", 8, 10, 254), CREATE, 254);
            let neg = negative_v4_msg("10.0.0.0", 8, 10, kind);
            assert!(apply_new(&mut snap, &neg, REPLACE, 254));
            assert_eq!(snap.v4.len(), 2, "{kind:?} took the unicast alias's place");
            assert_eq!(metric_v4(&snap, "10.1.1.1"), None, "{kind:?}");

            let mut snap = FibSnapshot::new();
            let gw = with_oif(
                with_gateway(igp_v6_msg("2001:db8::", 32, 10, 254), "fe80::1"),
                2,
            );
            apply_new(&mut snap, &gw, CREATE, 254);
            assert!(apply_new(
                &mut snap,
                &negative_v6_msg("2001:db8::", 32, 10, kind),
                REPLACE,
                254
            ));
            assert_eq!(snap.v6.len(), 1, "{kind:?}");
            assert_eq!(metric_v6(&snap, "2001:db8::1"), None, "{kind:?}");
        }
    }

    fn with_pref(
        mut msg: RouteMessage,
        pref: netlink_packet_route::route::RoutePreference,
    ) -> RouteMessage {
        msg.attributes.push(RouteAttribute::Preference(pref));
        msg
    }

    #[test]
    fn decode_v6_reads_route_preference() {
        use netlink_packet_route::route::RoutePreference as Pref;
        let plain = igp_v6_msg("2001:db8::", 32, 5, 254);
        assert_eq!(decode_v6(&plain)[0].preference, RoutePreference::Medium);
        for (wire, want) in [
            (Pref::High, RoutePreference::High),
            (Pref::Low, RoutePreference::Low),
            (Pref::Medium, RoutePreference::Medium),
            (Pref::Invalid, RoutePreference::Medium),
        ] {
            let msg = with_pref(igp_v6_msg("2001:db8::", 32, 5, 254), wire);
            assert_eq!(decode_v6(&msg)[0].preference, want, "{wire:?}");
        }
    }

    #[test]
    fn ipv6_high_preference_unicast_beats_an_earlier_negative_route_of_its_metric() {
        // Codex's reproduction on PR #123: blackhole fd59::/64 metric 100, then
        // a device route for the same prefix and metric appended with
        // RTA_PREF=high. rt6_score_route ranks the unicast route higher, so
        // RTM_GETROUTE succeeds; the snapshot must agree.
        use netlink_packet_route::route::RoutePreference as Pref;
        for kind in NEGATIVE_TYPES {
            let mut snap = FibSnapshot::new();
            assert!(apply_new(
                &mut snap,
                &negative_v6_msg("fd59::", 64, 100, kind),
                CREATE,
                254
            ));
            let uni = with_pref(with_oif(igp_v6_msg("fd59::", 64, 100, 254), 2), Pref::High);
            assert!(apply_new(&mut snap, &uni, APPEND, 254));
            assert!(snap.is_v6_reachable("fd59::1".parse().unwrap()), "{kind:?}");
            assert_eq!(metric_v6(&snap, "fd59::1"), Some(100));

            // A low-preference unicast route loses to a later negative route,
            // which the kernel always reports as medium.
            let mut snap = FibSnapshot::new();
            let low = with_pref(with_oif(igp_v6_msg("fd59::", 64, 100, 254), 2), Pref::Low);
            apply_new(&mut snap, &low, CREATE, 254);
            assert!(apply_new(
                &mut snap,
                &negative_v6_msg("fd59::", 64, 100, kind),
                APPEND,
                254
            ));
            assert!(
                !snap.is_v6_reachable("fd59::1".parse().unwrap()),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn negative_route_in_another_table_is_ignored() {
        let mut snap = FibSnapshot::new();
        apply_new(&mut snap, &igp_v4_msg("0.0.0.0", 0, 0, 254), CREATE, 254);
        let mut other = negative_v4_msg("10.0.0.0", 8, 0, RouteType::Unreachable);
        other.header.table = 100;
        assert!(!apply_new(&mut snap, &other, CREATE, 254));
        assert_eq!(metric_v4(&snap, "10.1.1.1"), Some(0));
    }

    #[test]
    fn untracked_replace_still_needs_a_valid_slot() {
        // A local route (not mirrored) replacing into an empty slot changes
        // nothing; a malformed one is ignored.
        let mut snap = FibSnapshot::new();
        let mut local = igp_v4_msg("10.0.0.0", 8, 0, 254);
        local.header.kind = RouteType::Local;
        assert!(!apply_new(&mut snap, &local, REPLACE, 254));
        let mut local6 = igp_v6_msg("2001:db8::", 32, 0, 254);
        local6.header.kind = RouteType::Local;
        assert!(!apply_new(&mut snap, &local6, REPLACE, 254));
        assert!(!apply_new(
            &mut snap,
            &igp_v4_msg("10.0.0.1", 8, 0, 254),
            REPLACE,
            254
        ));
        assert!(!apply_new(
            &mut snap,
            &igp_v6_msg("2001:db8::1", 32, 0, 254),
            REPLACE,
            254
        ));
    }

    // ── dump_stale_bgp filter logic ───────────────────────────────────────────
    //
    // dump_stale_bgp_v4/v6 call is_bgp_route() + in_table() to decide whether
    // to include each route. We test those predicates directly here (the live
    // netlink dump is integration-only and requires a real Linux kernel).

    #[test]
    fn dump_stale_v4_includes_bgp_route_in_matching_table() {
        let msg = bgp_v4_msg("10.0.0.0", 8, 254);
        assert!(is_bgp_route(&msg) && in_table(&msg, 254));
    }

    #[test]
    fn dump_stale_v4_excludes_igp_route() {
        let msg = igp_v4_msg("10.0.0.0", 8, 100, 254);
        assert!(!is_bgp_route(&msg));
    }

    #[test]
    fn dump_stale_v4_excludes_bgp_route_in_wrong_table() {
        let msg = bgp_v4_msg("10.0.0.0", 8, 200);
        assert!(is_bgp_route(&msg) && !in_table(&msg, 254));
    }

    #[test]
    fn dump_stale_v6_includes_bgp_route_in_matching_table() {
        let msg = bgp_v6_msg("2001:db8::", 32, 254);
        assert!(is_bgp_route(&msg) && in_table(&msg, 254));
    }

    #[test]
    fn dump_stale_v6_excludes_igp_route() {
        let msg = igp_v6_msg("2001:db8::", 32, 100, 254);
        assert!(!is_bgp_route(&msg));
    }
}
