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

use futures::TryStreamExt;
use netlink_packet_route::{
    link::{LinkAttribute, LinkFlags},
    route::RouteScope,
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
