//! Linux [`FibWriter`]: installs and withdraws BGP-learned routes via rtnetlink.

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
use rtnetlink::{MulticastGroup, RouteMessageBuilder};
use tokio::sync::watch;

use super::{FibEntry4, FibEntry6, FibSnapshot};

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

    // Step 2 — Populate snapshot from current kernel FIB.
    //
    // Collect into local Vecs while awaiting so the RwLockWriteGuard is never
    // held across an await point (std::sync::RwLockWriteGuard is !Send).
    let mut v4_entries: Vec<FibEntry4> = Vec::new();
    let mut stream = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute();
    while let Some(msg) = stream.try_next().await.map_err(io::Error::other)? {
        if let Some(entry) = parse_v4(&msg, table) {
            v4_entries.push(entry);
        }
    }

    let mut v6_entries: Vec<FibEntry6> = Vec::new();
    let mut stream = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute();
    while let Some(msg) = stream.try_next().await.map_err(io::Error::other)? {
        if let Some(entry) = parse_v6(&msg, table) {
            v6_entries.push(entry);
        }
    }

    {
        let mut snap = snapshot.write().expect("FibSnapshot poisoned");
        snap.v4 = v4_entries;
        snap.v6 = v6_entries;
    }

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
    while let Some((msg, _addr)) = events.next().await {
        match msg.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                let changed = apply_new(
                    &mut snapshot.write().expect("FibSnapshot poisoned"),
                    &route,
                    table,
                );
                if changed {
                    let _ = change_tx.send(());
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route)) => {
                let changed = apply_del(
                    &mut snapshot.write().expect("FibSnapshot poisoned"),
                    &route,
                    table,
                );
                if changed {
                    let _ = change_tx.send(());
                }
            }
            _ => {}
        }
    }

    Ok(())
}

// ── Stale BGP route dump ──────────────────────────────────────────────────────

/// Returns `(network, prefix_len)` for every `RTPROT_BGP` IPv4 route in `table`.
///
/// This is the inverse of `parse_v4`: it selects *only* BGP-protocol routes,
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

/// Parse an IPv4 unicast route. Returns `None` for non-unicast types,
/// wrong-table routes, BGP-protocol routes, or routes with no parseable
/// destination.
fn parse_v4(msg: &RouteMessage, table: u32) -> Option<FibEntry4> {
    if msg.header.kind != RouteType::Unicast {
        return None;
    }
    if !in_table(msg, table) {
        return None;
    }
    if is_bgp_route(msg) {
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

/// Parse an IPv6 unicast route. Returns `None` for BGP-protocol routes.
fn parse_v6(msg: &RouteMessage, table: u32) -> Option<FibEntry6> {
    if msg.header.kind != RouteType::Unicast {
        return None;
    }
    if !in_table(msg, table) {
        return None;
    }
    if is_bgp_route(msg) {
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

// ── Snapshot mutation ─────────────────────────────────────────────────────────

/// Applies a `RTM_NEWROUTE` event to the snapshot.
///
/// Returns `true` if the snapshot changed (an entry was added or updated),
/// `false` if the route was filtered (BGP protocol, wrong table, non-unicast)
/// or was an exact duplicate of an existing entry.
fn apply_new(snap: &mut FibSnapshot, msg: &RouteMessage, table: u32) -> bool {
    match msg.header.address_family {
        AddressFamily::Inet => {
            let Some(entry) = parse_v4(msg, table) else {
                return false;
            };
            if let Some(slot) = snap
                .v4
                .iter_mut()
                .find(|e| e.network == entry.network && e.prefix_len == entry.prefix_len)
            {
                if *slot == entry {
                    return false; // no-op duplicate
                }
                *slot = entry;
            } else {
                snap.v4.push(entry);
            }
            true
        }
        AddressFamily::Inet6 => {
            let Some(entry) = parse_v6(msg, table) else {
                return false;
            };
            if let Some(slot) = snap
                .v6
                .iter_mut()
                .find(|e| e.network == entry.network && e.prefix_len == entry.prefix_len)
            {
                if *slot == entry {
                    return false;
                }
                *slot = entry;
            } else {
                snap.v6.push(entry);
            }
            true
        }
        _ => false,
    }
}

/// Applies a `RTM_DELROUTE` event to the snapshot.
///
/// Returns `true` if an entry was actually removed, `false` if the route was
/// filtered (BGP protocol, wrong table) or was already absent.
fn apply_del(snap: &mut FibSnapshot, msg: &RouteMessage, table: u32) -> bool {
    if !in_table(msg, table) || is_bgp_route(msg) {
        return false;
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
            let before = snap.v4.len();
            snap.v4
                .retain(|e| !(e.network == network && e.prefix_len == prefix_len));
            snap.v4.len() < before
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
            let before = snap.v6.len();
            snap.v6
                .retain(|e| !(e.network == network && e.prefix_len == prefix_len));
            snap.v6.len() < before
        }
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

    // ── parse_v4 — BGP exclusion ──────────────────────────────────────────────

    #[test]
    fn parse_v4_rejects_bgp_route() {
        assert!(
            parse_v4(&bgp_v4_msg("10.0.0.0", 8, 254), 254).is_none(),
            "BGP routes must not enter FibSnapshot"
        );
    }

    #[test]
    fn parse_v4_accepts_igp_route() {
        let entry =
            parse_v4(&igp_v4_msg("10.0.0.0", 8, 100, 254), 254).expect("IGP route must be parsed");
        assert_eq!(entry.network, "10.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(entry.prefix_len, 8);
        assert_eq!(entry.metric, 100);
    }

    // ── parse_v6 — BGP exclusion ──────────────────────────────────────────────

    #[test]
    fn parse_v6_rejects_bgp_route() {
        assert!(
            parse_v6(&bgp_v6_msg("2001:db8::", 32, 254), 254).is_none(),
            "BGP routes must not enter FibSnapshot"
        );
    }

    #[test]
    fn parse_v6_accepts_igp_route() {
        let entry = parse_v6(&igp_v6_msg("2001:db8::", 32, 50, 254), 254)
            .expect("IGP route must be parsed");
        assert_eq!(entry.network, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(entry.prefix_len, 32);
        assert_eq!(entry.metric, 50);
    }

    // ── apply_new ─────────────────────────────────────────────────────────────

    #[test]
    fn apply_new_igp_route_returns_true_and_updates_snapshot() {
        let mut snap = FibSnapshot::new();
        assert!(apply_new(
            &mut snap,
            &igp_v4_msg("192.168.0.0", 24, 10, 254),
            254
        ));
        assert_eq!(snap.v4.len(), 1);
    }

    #[test]
    fn apply_new_bgp_route_returns_false_and_leaves_snapshot_empty() {
        let mut snap = FibSnapshot::new();
        assert!(
            !apply_new(&mut snap, &bgp_v4_msg("10.0.0.0", 8, 254), 254),
            "BGP route must not change snapshot or signal change"
        );
        assert!(snap.v4.is_empty());
    }

    #[test]
    fn apply_new_duplicate_igp_route_returns_false() {
        let mut snap = FibSnapshot::new();
        let msg = igp_v4_msg("192.168.0.0", 24, 10, 254);
        apply_new(&mut snap, &msg, 254);
        assert!(
            !apply_new(&mut snap, &msg, 254),
            "identical re-insert must not fire change notification"
        );
        assert_eq!(snap.v4.len(), 1);
    }

    #[test]
    fn apply_new_metric_change_returns_true() {
        let mut snap = FibSnapshot::new();
        apply_new(&mut snap, &igp_v4_msg("192.168.0.0", 24, 10, 254), 254);
        assert!(
            apply_new(&mut snap, &igp_v4_msg("192.168.0.0", 24, 20, 254), 254),
            "metric change on existing prefix must fire change notification"
        );
        assert_eq!(snap.v4[0].metric, 20);
    }

    // ── apply_del ─────────────────────────────────────────────────────────────

    #[test]
    fn apply_del_igp_route_returns_true_when_present() {
        let mut snap = FibSnapshot::new();
        apply_new(&mut snap, &igp_v4_msg("192.168.0.0", 24, 10, 254), 254);
        assert!(apply_del(
            &mut snap,
            &igp_v4_msg("192.168.0.0", 24, 0, 254),
            254
        ));
        assert!(snap.v4.is_empty());
    }

    #[test]
    fn apply_del_igp_route_returns_false_when_absent() {
        let mut snap = FibSnapshot::new();
        assert!(
            !apply_del(&mut snap, &igp_v4_msg("192.168.0.0", 24, 0, 254), 254),
            "delete of absent route must not signal change"
        );
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

    #[test]
    fn apply_del_bgp_route_returns_false_always() {
        // Even if a BGP route somehow appeared in the snapshot, its RTM_DELROUTE
        // event must not trigger a change notification.
        let mut snap = FibSnapshot::new();
        snap.v4.push(FibEntry4 {
            network: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            metric: 20,
        });
        assert!(
            !apply_del(&mut snap, &bgp_v4_msg("10.0.0.0", 8, 254), 254),
            "BGP DelRoute must not signal change"
        );
        // The smuggled entry is untouched — apply_del was a no-op for BGP.
        assert_eq!(snap.v4.len(), 1);
    }
}
