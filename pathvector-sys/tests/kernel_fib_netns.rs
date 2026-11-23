//! Live-kernel checks for issue #56: routes with the same prefix but different
//! priorities are separate kernel routes, and the snapshot must keep both.
//!
//! These tests add and delete real routes, so they are `#[ignore]`d and must
//! run inside a **disposable network namespace** with `CAP_NET_ADMIN`:
//!
//! ```text
//! cargo test -p pathvector-sys --test kernel_fib_netns --no-run
//! sudo unshare --net -- <test binary> --ignored
//! ```
//!
//! A Docker container has its own namespace, so
//! `docker run --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 ...`
//! works too (use `--network none`). As a guard, each test refuses to run if
//! any interface other than `lo` and the ones these tests create is up. A
//! fresh namespace has only `lo` and the kernel's fallback tunnel devices
//! (`tunl0`, `sit0`, ...), which start down; a host namespace has up NICs.
//!
//! What the kernel does here is described in `net/ipv4/fib_trie.c`
//! (`fib_table_insert` keys aliases by "[prefix,dscp,priority]") and
//! `net/ipv6/ip6_fib.c` (`fib6_add_rt2node` keeps one route per metric for a
//! given next hop).

#![cfg(target_os = "linux")]

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkFlags},
    route::{RouteMessage, RouteProtocol, RouteScope},
};
use pathvector_sys::{FibSnapshot, KernelFib, RT_TABLE_MAIN};
use rtnetlink::{Handle, LinkDummy, RouteMessageBuilder};

const OWN_LINK_PREFIX: &str = "pv56";

fn connect() -> Handle {
    let (conn, handle, _) = rtnetlink::new_connection().expect("netlink socket");
    tokio::spawn(conn);
    handle
}

/// Panics if any interface other than `lo` and ours is administratively up.
async fn assert_disposable_namespace(handle: &Handle) {
    let links: Vec<_> = handle
        .link()
        .get()
        .execute()
        .try_collect()
        .await
        .expect("link dump");
    for link in links {
        let name = link
            .attributes
            .iter()
            .find_map(|a| match a {
                LinkAttribute::IfName(n) => Some(n.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let up = link.header.flags.contains(LinkFlags::Up);
        assert!(
            name == "lo" || name.starts_with(OWN_LINK_PREFIX) || !up,
            "refusing to modify routes: interface {name:?} is up, which suggests this \
             is not a disposable network namespace (run under `unshare --net`)"
        );
    }
}

/// Creates an up dummy interface and returns its index.
async fn dummy(handle: &Handle, name: &str) -> u32 {
    assert!(name.starts_with(OWN_LINK_PREFIX));
    assert_disposable_namespace(handle).await;
    handle
        .link()
        .add(LinkDummy::new(name).up().build())
        .execute()
        .await
        .expect("create dummy link (needs CAP_NET_ADMIN)");
    let link = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await
        .expect("link lookup")
        .expect("link exists");
    link.header.index
}

async fn add_v4(handle: &Handle, dst: Ipv4Addr, len: u8, oif: u32, metric: u32) {
    let msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, len)
        .output_interface(oif)
        .scope(RouteScope::Link)
        .priority(metric)
        .build();
    handle
        .route()
        .add(msg)
        .execute()
        .await
        .expect("add IPv4 route");
}

async fn del_v4(handle: &Handle, dst: Ipv4Addr, len: u8, oif: u32, metric: u32) {
    let msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, len)
        .output_interface(oif)
        .scope(RouteScope::Link)
        .priority(metric)
        .build();
    handle
        .route()
        .del(msg)
        .execute()
        .await
        .expect("delete IPv4 route");
}

async fn add_v6(handle: &Handle, dst: Ipv6Addr, len: u8, oif: u32, metric: u32) {
    let msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, len)
        .output_interface(oif)
        .priority(metric)
        .build();
    handle
        .route()
        .add(msg)
        .execute()
        .await
        .expect("add IPv6 route");
}

async fn del_v6(handle: &Handle, dst: Ipv6Addr, len: u8, oif: u32, metric: u32) {
    let msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, len)
        .output_interface(oif)
        .priority(metric)
        .build();
    handle
        .route()
        .del(msg)
        .execute()
        .await
        .expect("delete IPv6 route");
}

/// Waits until `probe` holds for the snapshot, or panics after 5 s.
async fn eventually(
    snap: &Arc<RwLock<FibSnapshot>>,
    what: &str,
    probe: impl Fn(&FibSnapshot) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if probe(&snap.read().unwrap()) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Starts a `KernelFib` on the main table and waits for its initial dump.
async fn start_fib() -> (Arc<RwLock<FibSnapshot>>, tokio::task::JoinHandle<()>) {
    let (fib, mut changes) = KernelFib::new(RT_TABLE_MAIN);
    let snap = fib.snapshot();
    let task = tokio::spawn(async move {
        fib.spawn().await.expect("KernelFib event loop");
    });
    tokio::time::timeout(Duration::from_secs(5), changes.changed())
        .await
        .expect("initial dump within 5 s")
        .expect("change channel open");
    (snap, task)
}

fn count_v4(s: &FibSnapshot, dst: Ipv4Addr) -> usize {
    s.routes_v4().filter(|r| r.slot.dst.addr() == dst).count()
}

fn count_v6(s: &FibSnapshot, dst: Ipv6Addr) -> usize {
    s.routes_v6().filter(|r| r.slot.dst.addr() == dst).count()
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn ipv4_incremental_updates_keep_both_priorities() {
    let handle = connect();
    let oif = dummy(&handle, "pv56a").await;
    let (snap, task) = start_fib().await;
    let dst: Ipv4Addr = "198.51.100.0".parse().unwrap();
    let probe: Ipv4Addr = "198.51.100.7".parse().unwrap();
    let metric = |s: &FibSnapshot| s.igp_metric_v4(probe);

    for (first, second) in [(10, 100), (100, 10)] {
        add_v4(&handle, dst, 24, oif, first).await;
        add_v4(&handle, dst, 24, oif, second).await;
        eventually(&snap, "both routes present", |s| count_v4(s, dst) == 2).await;
        assert_eq!(
            metric(&snap.read().unwrap()),
            Some(10),
            "added {first} then {second}"
        );

        // Delete the backup: the primary must survive.
        del_v4(&handle, dst, 24, oif, 100).await;
        eventually(&snap, "backup removed", |s| count_v4(s, dst) == 1).await;
        assert_eq!(metric(&snap.read().unwrap()), Some(10));

        // Put it back, delete the primary: fall back to the backup.
        add_v4(&handle, dst, 24, oif, 100).await;
        eventually(&snap, "backup re-added", |s| count_v4(s, dst) == 2).await;
        del_v4(&handle, dst, 24, oif, 10).await;
        eventually(&snap, "primary removed", |s| count_v4(s, dst) == 1).await;
        assert_eq!(metric(&snap.read().unwrap()), Some(100));

        del_v4(&handle, dst, 24, oif, 100).await;
        eventually(&snap, "all removed", |s| count_v4(s, dst) == 0).await;
        assert_eq!(metric(&snap.read().unwrap()), None);
    }
    task.abort();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn ipv6_incremental_updates_keep_both_priorities() {
    let handle = connect();
    let oif = dummy(&handle, "pv56b").await;
    let (snap, task) = start_fib().await;
    let dst: Ipv6Addr = "2001:db8:56::".parse().unwrap();
    let probe: Ipv6Addr = "2001:db8:56::7".parse().unwrap();
    let metric = |s: &FibSnapshot| s.igp_metric_v6(probe);

    for (first, second) in [(10, 100), (100, 10)] {
        add_v6(&handle, dst, 64, oif, first).await;
        add_v6(&handle, dst, 64, oif, second).await;
        eventually(&snap, "both routes present", |s| count_v6(s, dst) == 2).await;
        assert_eq!(
            metric(&snap.read().unwrap()),
            Some(10),
            "added {first} then {second}"
        );

        del_v6(&handle, dst, 64, oif, 100).await;
        eventually(&snap, "backup removed", |s| count_v6(s, dst) == 1).await;
        assert_eq!(metric(&snap.read().unwrap()), Some(10));

        add_v6(&handle, dst, 64, oif, 100).await;
        eventually(&snap, "backup re-added", |s| count_v6(s, dst) == 2).await;
        del_v6(&handle, dst, 64, oif, 10).await;
        eventually(&snap, "primary removed", |s| count_v6(s, dst) == 1).await;
        assert_eq!(metric(&snap.read().unwrap()), Some(100));

        del_v6(&handle, dst, 64, oif, 100).await;
        eventually(&snap, "all removed", |s| count_v6(s, dst) == 0).await;
        assert_eq!(metric(&snap.read().unwrap()), None);
    }
    task.abort();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn initial_dump_keeps_both_priorities() {
    let handle = connect();
    let oif = dummy(&handle, "pv56c").await;
    let dst4: Ipv4Addr = "203.0.113.0".parse().unwrap();
    let dst6: Ipv6Addr = "2001:db8:57::".parse().unwrap();
    // The kernel orders these by priority whatever the insertion order.
    add_v4(&handle, dst4, 24, oif, 100).await;
    add_v4(&handle, dst4, 24, oif, 10).await;
    add_v6(&handle, dst6, 64, oif, 100).await;
    add_v6(&handle, dst6, 64, oif, 10).await;

    let (snap, task) = start_fib().await;
    {
        let s = snap.read().unwrap();
        assert_eq!(count_v4(&s, dst4), 2);
        assert_eq!(count_v6(&s, dst6), 2);
        assert_eq!(s.igp_metric_v4("203.0.113.9".parse().unwrap()), Some(10));
        assert_eq!(s.igp_metric_v6("2001:db8:57::9".parse().unwrap()), Some(10));
    }

    // The dumped state and later events agree: deleting the primary leaves
    // the backup.
    del_v4(&handle, dst4, 24, oif, 10).await;
    del_v6(&handle, dst6, 64, oif, 10).await;
    eventually(&snap, "primaries removed", |s| {
        count_v4(s, dst4) == 1 && count_v6(s, dst6) == 1
    })
    .await;
    let s = snap.read().unwrap();
    assert_eq!(s.igp_metric_v4("203.0.113.9".parse().unwrap()), Some(100));
    assert_eq!(
        s.igp_metric_v6("2001:db8:57::9".parse().unwrap()),
        Some(100)
    );
    drop(s);
    task.abort();
}

// ── PR #122 review: untracked routes sharing a slot or ECMP set ──────────────

/// Sends `RTM_NEWROUTE` with exactly `flags` (rtnetlink's builder only offers
/// EXCL or REPLACE) and panics if the kernel rejects it.
async fn new_route_with_flags(handle: &Handle, route: RouteMessage, flags: u16) {
    let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(route));
    req.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    let mut responses = handle.clone().request(req).expect("send RTM_NEWROUTE");
    while let Some(msg) = responses.next().await {
        if let NetlinkPayload::Error(e) = msg.payload {
            assert!(e.code.is_none(), "kernel rejected RTM_NEWROUTE: {e:?}");
        }
    }
}

fn v6_via(dst: Ipv6Addr, gw: &str, oif: u32, protocol: RouteProtocol) -> RouteMessage {
    RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, 64)
        .gateway(gw.parse().unwrap())
        .output_interface(oif)
        .priority(10)
        .protocol(protocol)
        .build()
}

fn v4_route(dst: Ipv4Addr, gw: Option<&str>, oif: u32, protocol: RouteProtocol) -> RouteMessage {
    let mut b = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst, 24)
        .output_interface(oif)
        .priority(10)
        .protocol(protocol);
    b = match gw {
        Some(gw) => b.gateway(gw.parse().unwrap()),
        None => b.scope(RouteScope::Link),
    };
    b.build()
}

async fn del(handle: &Handle, route: RouteMessage) {
    handle
        .route()
        .del(route)
        .execute()
        .await
        .expect("delete route");
}

/// Adds a marker route and waits for it, so every earlier event has been
/// applied (the kernel delivers notifications in order).
async fn barrier_v4(handle: &Handle, snap: &Arc<RwLock<FibSnapshot>>, oif: u32, dst: Ipv4Addr) {
    add_v4(handle, dst, 24, oif, 1).await;
    eventually(snap, "marker route", |s| count_v4(s, dst) == 1).await;
}

async fn barrier_v6(handle: &Handle, snap: &Arc<RwLock<FibSnapshot>>, oif: u32, dst: Ipv6Addr) {
    add_v6(handle, dst, 64, oif, 1).await;
    eventually(snap, "marker route", |s| count_v6(s, dst) == 1).await;
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn mixed_protocol_ipv6_ecmp_leaves_nothing_after_both_deletes() {
    // A static and a BGP route appended into one ECMP set. rt6_fill_node
    // reports a set under one route's protocol, so the BGP leg must not be
    // taken for static by incremental events, and its delete must apply.
    let handle = connect();
    let oif = dummy(&handle, "pv56d").await;
    let dump_dst: Ipv6Addr = "2001:db8:99::".parse().unwrap();
    let live_dst: Ipv6Addr = "2001:db8:9a::".parse().unwrap();
    let append = NLM_F_CREATE | NLM_F_APPEND;

    // Present before the initial dump.
    new_route_with_flags(
        &handle,
        v6_via(dump_dst, "fe80::1", oif, RouteProtocol::Static),
        append,
    )
    .await;
    new_route_with_flags(
        &handle,
        v6_via(dump_dst, "fe80::2", oif, RouteProtocol::Bgp),
        append,
    )
    .await;
    let (snap, task) = start_fib().await;
    // And added while running.
    new_route_with_flags(
        &handle,
        v6_via(live_dst, "fe80::1", oif, RouteProtocol::Static),
        append,
    )
    .await;
    new_route_with_flags(
        &handle,
        v6_via(live_dst, "fe80::2", oif, RouteProtocol::Bgp),
        append,
    )
    .await;
    barrier_v6(&handle, &snap, oif, "2001:db8:98::".parse().unwrap()).await;

    // fib6_dump_node dumps the set once, headed by the static route, so the
    // BGP leg's protocol is unknown after the dump and it counts as a path.
    // Single-route appends are each headed by the route they add, so the
    // incremental BGP leg is known and not counted.
    for (dst, probe, counted) in [
        (dump_dst, "2001:db8:99::1", 2),
        (live_dst, "2001:db8:9a::1", 1),
    ] {
        let probe: Ipv6Addr = probe.parse().unwrap();
        {
            let s = snap.read().unwrap();
            assert_eq!(count_v6(&s, dst), counted);
            assert_eq!(s.igp_metric_v6(probe), Some(10));
        }
        del(&handle, v6_via(dst, "fe80::1", oif, RouteProtocol::Static)).await;
        del(&handle, v6_via(dst, "fe80::2", oif, RouteProtocol::Bgp)).await;
    }
    barrier_v6(&handle, &snap, oif, "2001:db8:97::".parse().unwrap()).await;
    let s = snap.read().unwrap();
    assert_eq!(s.igp_metric_v6("2001:db8:99::1".parse().unwrap()), None);
    assert_eq!(s.igp_metric_v6("2001:db8:9a::1".parse().unwrap()), None);
    drop(s);
    task.abort();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn replacing_a_leading_bgp_alias_keeps_the_static_alias() {
    // Slot order [BGP, static] (BGP prepended with NLM_F_CREATE only). An
    // NLM_F_REPLACE of BGP replaces `fa_first`, the BGP alias.
    let handle = connect();
    let oif = dummy(&handle, "pv56e").await;
    handle
        .address()
        .add(oif, "192.0.2.100".parse().unwrap(), 24)
        .execute()
        .await
        .expect("address for the BGP gateways");
    let dump_dst: Ipv4Addr = "198.18.1.0".parse().unwrap();
    let live_dst: Ipv4Addr = "198.18.3.0".parse().unwrap();

    let setup = |dst| {
        let handle = handle.clone();
        async move {
            add_static_then_prepend_bgp(&handle, dst, oif).await;
        }
    };
    setup(dump_dst).await;
    let (snap, task) = start_fib().await;
    setup(live_dst).await;
    barrier_v4(&handle, &snap, oif, "198.18.2.0".parse().unwrap()).await;

    for dst in [dump_dst, live_dst] {
        let replacement = v4_route(dst, Some("192.0.2.2"), oif, RouteProtocol::Bgp);
        handle
            .route()
            .add(replacement)
            .replace()
            .execute()
            .await
            .expect("replace the BGP alias");
    }
    barrier_v4(&handle, &snap, oif, "198.18.4.0".parse().unwrap()).await;

    // The kernel still has both aliases; the static one must still count.
    let s = snap.read().unwrap();
    assert_eq!(s.igp_metric_v4("198.18.1.7".parse().unwrap()), Some(10));
    assert_eq!(s.igp_metric_v4("198.18.3.7".parse().unwrap()), Some(10));
    drop(s);
    task.abort();
}

async fn add_static_then_prepend_bgp(handle: &Handle, dst: Ipv4Addr, oif: u32) {
    handle
        .route()
        .add(v4_route(dst, None, oif, RouteProtocol::Static))
        .execute()
        .await
        .expect("static alias");
    new_route_with_flags(
        handle,
        v4_route(dst, Some("192.0.2.1"), oif, RouteProtocol::Bgp),
        NLM_F_CREATE,
    )
    .await;
}

// ── PR #122 review round 2: dumps report an ECMP set once ────────────────────

/// Two metric-10 routes for `dst` via `fe80::1` then `fe80::2`, appended into one
/// ECMP set.
async fn ecmp_pair(handle: &Handle, dst: Ipv6Addr, oif: u32, protocols: [RouteProtocol; 2]) {
    for (gw, protocol) in ["fe80::1", "fe80::2"].into_iter().zip(protocols) {
        new_route_with_flags(
            handle,
            v6_via(dst, gw, oif, protocol),
            NLM_F_CREATE | NLM_F_APPEND,
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn dumped_static_ecmp_set_keeps_the_surviving_sibling() {
    // fib6_dump_node dumps the set once and skips the second sibling, so its
    // protocol is never reported. It must still count once the first goes.
    let handle = connect();
    let oif = dummy(&handle, "pv56f").await;
    let dst: Ipv6Addr = "2001:db8:200::".parse().unwrap();
    let probe: Ipv6Addr = "2001:db8:200::1".parse().unwrap();
    ecmp_pair(
        &handle,
        dst,
        oif,
        [RouteProtocol::Static, RouteProtocol::Static],
    )
    .await;

    let (snap, task) = start_fib().await;
    assert_eq!(snap.read().unwrap().igp_metric_v6(probe), Some(10));
    del(&handle, v6_via(dst, "fe80::1", oif, RouteProtocol::Static)).await;
    barrier_v6(&handle, &snap, oif, "2001:db8:201::".parse().unwrap()).await;
    assert_eq!(
        snap.read().unwrap().igp_metric_v6(probe),
        Some(10),
        "the static route via fe80::2 is still in the kernel"
    );
    del(&handle, v6_via(dst, "fe80::2", oif, RouteProtocol::Static)).await;
    barrier_v6(&handle, &snap, oif, "2001:db8:203::".parse().unwrap()).await;
    assert_eq!(snap.read().unwrap().igp_metric_v6(probe), None);
    task.abort();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn dumped_ecmp_set_headed_by_bgp_keeps_the_static_sibling() {
    // BGP added first heads the dump; the static sibling behind it must count.
    let handle = connect();
    let oif = dummy(&handle, "pv56g").await;
    let dst: Ipv6Addr = "2001:db8:202::".parse().unwrap();
    let probe: Ipv6Addr = "2001:db8:202::1".parse().unwrap();
    ecmp_pair(
        &handle,
        dst,
        oif,
        [RouteProtocol::Bgp, RouteProtocol::Static],
    )
    .await;

    let (snap, task) = start_fib().await;
    assert_eq!(
        snap.read().unwrap().igp_metric_v6(probe),
        Some(10),
        "static sibling usable right after the dump"
    );
    del(&handle, v6_via(dst, "fe80::1", oif, RouteProtocol::Bgp)).await;
    barrier_v6(&handle, &snap, oif, "2001:db8:204::".parse().unwrap()).await;
    assert_eq!(snap.read().unwrap().igp_metric_v6(probe), Some(10));
    del(&handle, v6_via(dst, "fe80::2", oif, RouteProtocol::Static)).await;
    barrier_v6(&handle, &snap, oif, "2001:db8:205::".parse().unwrap()).await;
    assert_eq!(snap.read().unwrap().igp_metric_v6(probe), None);
    task.abort();
}
