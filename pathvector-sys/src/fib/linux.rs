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
use rtnetlink::{IpVersion, RouteMessageBuilder, multicast::MulticastGroup};
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
        withdraw_route_v4(&self.handle, dst, prefix_len, self.table).await
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
        withdraw_route_v6(&self.handle, dst, prefix_len, self.table).await
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

// ── Route parsing helpers ─────────────────────────────────────────────────────

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

// ── Snapshot mutation ─────────────────────────────────────────────────────────

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

// ── Route write helpers ───────────────────────────────────────────────────────

/// Install (or replace) an IPv4 route tagged RTPROT_BGP.
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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// Install (or replace) an IPv6 route tagged RTPROT_BGP.
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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
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
) -> io::Result<()> {
    let msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .build();
    match handle.route().del(msg).execute().await {
        Ok(()) => Ok(()),
        // ESRCH (3): route already absent — treat as success.
        Err(rtnetlink::Error::NetlinkError(ref e)) if e.code.map_or(false, |c| c.get() == -3) => {
            Ok(())
        }
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
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
) -> io::Result<()> {
    let msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, prefix_len)
        .table_id(table)
        .build();
    match handle.route().del(msg).execute().await {
        Ok(()) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(ref e)) if e.code.map_or(false, |c| c.get() == -3) => {
            Ok(())
        }
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}
