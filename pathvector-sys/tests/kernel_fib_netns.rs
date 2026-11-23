//! Live-kernel checks for the FIB snapshot:
//!
//! - issue #56: routes with the same prefix but different priorities are
//!   separate kernel routes, and the snapshot must keep both;
//! - issue #57: a negative route (blackhole, unreachable, prohibit, throw)
//!   beneath a covering unicast route makes the covered destinations
//!   unreachable. These tests compare the oracle with the kernel's own lookup
//!   (`RTM_GETROUTE` for one destination, which is what `ip route get` sends).
//!
//! The tests run in parallel in one namespace, so each uses its own prefixes
//! and interfaces (prefixed `pvtest`), and none adds a real default route.
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
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
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
    route::{RouteAttribute, RouteMessage, RoutePreference, RouteProtocol, RouteScope, RouteType},
};
use pathvector_sys::{
    FibSnapshot, KernelFib, RT_TABLE_MAIN,
    fib::{FibLookup, RejectKind},
};
use rtnetlink::{Handle, LinkDummy, RouteMessageBuilder};

/// Every interface these tests create starts with this.
const OWN_LINK_PREFIX: &str = "pvtest";

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
    let oif = dummy(&handle, "pvtest56a").await;
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
    let oif = dummy(&handle, "pvtest56b").await;
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
    let oif = dummy(&handle, "pvtest56c").await;
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
    // reports each with the other as an RTA_MULTIPATH leg under its own
    // protocol, so the BGP leg must not be taken for static.
    let handle = connect();
    let oif = dummy(&handle, "pvtest56d").await;
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

    for (dst, probe) in [(dump_dst, "2001:db8:99::1"), (live_dst, "2001:db8:9a::1")] {
        let probe: Ipv6Addr = probe.parse().unwrap();
        {
            let s = snap.read().unwrap();
            assert_eq!(count_v6(&s, dst), 1, "only the static sibling is tracked");
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
    let oif = dummy(&handle, "pvtest56e").await;
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

// ── Issue #57: negative routes, compared with the kernel's own lookup ────────

/// The negative route types, in `ip-route(8)` order.
const NEGATIVE_TYPES: [RouteType; 4] = [
    RouteType::BlackHole,
    RouteType::Unreachable,
    RouteType::Prohibit,
    RouteType::Throw,
];

/// What a lookup ends in: `Ok` for a forwarding route, `Err(errno)` otherwise.
type Verdict = Result<(), i32>;

/// The kernel's verdict for `dst`: an `RTM_GETROUTE` request for that one
/// destination (no `NLM_F_DUMP`), as `ip route get` sends it. The kernel runs
/// its full output lookup, policy rules included (`inet_rtm_getroute`,
/// `inet6_rtm_getroute`), and answers with the route or the lookup's error.
async fn kernel_verdict(handle: &Handle, dst: IpAddr) -> Verdict {
    let msg = match dst {
        IpAddr::V4(a) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(a, 32)
            .build(),
        IpAddr::V6(a) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(a, 128)
            .build(),
    };
    match handle.route().get(msg).execute().try_next().await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => panic!("RTM_GETROUTE for {dst} returned nothing"),
        Err(rtnetlink::Error::NetlinkError(e)) => {
            Err(-e.code.expect("netlink error carries an errno").get())
        }
        Err(e) => panic!("RTM_GETROUTE for {dst}: {e}"),
    }
}

/// The verdict the snapshot predicts. The errors are the ones `ip-route(8)`
/// says local senders get, which are the `fib_props` / `fib6_prop` errors:
/// blackhole `EINVAL`, unreachable `EHOSTUNREACH`, prohibit `EACCES`. A throw
/// ends the table lookup with `-EAGAIN`, which the rule walk treats as "no
/// route here"; with no later table holding a route, `__fib_lookup` turns the
/// final `-ESRCH` into `-ENETUNREACH` (IPv6 returns `ip6_null_entry`, whose
/// error is also `-ENETUNREACH`), exactly as when there is no route at all.
fn oracle_verdict<R>(lookup: FibLookup<'_, R>) -> Verdict {
    match lookup {
        FibLookup::Forward(_) => Ok(()),
        FibLookup::Reject { kind, .. } => Err(match kind {
            RejectKind::Blackhole => libc::EINVAL,
            RejectKind::Unreachable => libc::EHOSTUNREACH,
            RejectKind::Prohibit => libc::EACCES,
        }),
        FibLookup::Throw(_) | FibLookup::NoRoute => Err(libc::ENETUNREACH),
    }
}

fn snapshot_verdict(s: &FibSnapshot, dst: IpAddr) -> Verdict {
    match dst {
        IpAddr::V4(a) => oracle_verdict(s.lookup_v4(a)),
        IpAddr::V6(a) => oracle_verdict(s.lookup_v6(a)),
    }
}

fn reachable(s: &FibSnapshot, dst: IpAddr) -> bool {
    match dst {
        IpAddr::V4(a) => s.is_v4_reachable(a),
        IpAddr::V6(a) => s.is_v6_reachable(a),
    }
}

/// Asserts that the snapshot and the kernel agree on every probe, and that
/// both give `expected`.
async fn assert_agrees(
    handle: &Handle,
    snap: &Arc<RwLock<FibSnapshot>>,
    probes: &[(IpAddr, Verdict)],
    context: &str,
) {
    for &(dst, expected) in probes {
        let kernel = kernel_verdict(handle, dst).await;
        let (oracle, is_reachable) = {
            let s = snap.read().unwrap();
            (snapshot_verdict(&s, dst), reachable(&s, dst))
        };
        assert_eq!(kernel, expected, "{context}: kernel verdict for {dst}");
        assert_eq!(oracle, kernel, "{context}: oracle vs kernel for {dst}");
        assert_eq!(
            is_reachable,
            kernel.is_ok(),
            "{context}: is_reachable for {dst}"
        );
    }
}

/// The expected errno for traffic covered by a negative route of `kind`.
fn rejected_with(kind: RouteType) -> Verdict {
    Err(match kind {
        RouteType::BlackHole => libc::EINVAL,
        RouteType::Unreachable => libc::EHOSTUNREACH,
        RouteType::Prohibit => libc::EACCES,
        RouteType::Throw => libc::ENETUNREACH,
        other => panic!("{other:?} is not a negative type"),
    })
}

/// A negative route message. No gateway or device: `fib_create_info` refuses
/// them for these types ("Gateway, device and multipath can not be specified
/// for this route type").
fn negative_msg(dst: IpAddr, len: u8, kind: RouteType, metric: u32) -> RouteMessage {
    match dst {
        IpAddr::V4(a) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(a, len)
            .kind(kind)
            .priority(metric)
            .build(),
        IpAddr::V6(a) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(a, len)
            .kind(kind)
            .priority(metric)
            .build(),
    }
}

async fn add_negative(handle: &Handle, dst: IpAddr, len: u8, kind: RouteType, metric: u32) {
    handle
        .route()
        .add(negative_msg(dst, len, kind, metric))
        .execute()
        .await
        .unwrap_or_else(|e| panic!("add {kind:?} {dst}/{len}: {e}"));
}

/// `ip route replace <kind> ...`: `NLM_F_REPLACE`, so the kernel swaps the
/// slot's route in place and sends no `RTM_DELROUTE` for the old one.
async fn replace_with_negative(
    handle: &Handle,
    dst: IpAddr,
    len: u8,
    kind: RouteType,
    metric: u32,
) {
    handle
        .route()
        .add(negative_msg(dst, len, kind, metric))
        .replace()
        .execute()
        .await
        .unwrap_or_else(|e| panic!("replace with {kind:?} {dst}/{len}: {e}"));
}

async fn del_negative(handle: &Handle, dst: IpAddr, len: u8, kind: RouteType, metric: u32) {
    handle
        .route()
        .del(negative_msg(dst, len, kind, metric))
        .execute()
        .await
        .unwrap_or_else(|e| panic!("delete {kind:?} {dst}/{len}: {e}"));
}

/// Adds a unicast device route.
async fn add_unicast(handle: &Handle, dst: IpAddr, len: u8, oif: u32, metric: u32) {
    match dst {
        IpAddr::V4(a) => add_v4(handle, a, len, oif, metric).await,
        IpAddr::V6(a) => add_v6(handle, a, len, oif, metric).await,
    }
}

async fn del_unicast(handle: &Handle, dst: IpAddr, len: u8, oif: u32, metric: u32) {
    match dst {
        IpAddr::V4(a) => del_v4(handle, a, len, oif, metric).await,
        IpAddr::V6(a) => del_v6(handle, a, len, oif, metric).await,
    }
}

/// Number of snapshot routes for `dst` (any length, any type).
fn count(s: &FibSnapshot, dst: IpAddr) -> usize {
    match dst {
        IpAddr::V4(a) => count_v4(s, a),
        IpAddr::V6(a) => count_v6(s, a),
    }
}

/// One family's addresses for the negative-route lifecycle.
///
/// The tests in this file run in parallel in one namespace, so each uses its
/// own prefixes; only [`initial_dump_of_negative_routes_agrees_with_the_kernel`]
/// adds a real default route, and every covering route here is more specific
/// than it.
struct Plan {
    /// The covering unicast route.
    covering: IpAddr,
    covering_len: u8,
    covering_metric: u32,
    negative: IpAddr,
    negative_len: u8,
    /// Inside the negative prefix.
    covered: IpAddr,
    /// Outside the negative prefix, so only the default covers it.
    outside: IpAddr,
}

/// The issue #57 acceptance sequence for one family, against the kernel:
/// a covering unicast route; each negative type beneath it makes the covered
/// address unreachable; deleting it restores reachability; replacing a
/// unicast route for the same prefix with a negative one does the same.
async fn negative_lifecycle(handle: &Handle, oif: u32, plan: &Plan) {
    let Plan {
        covering,
        covering_len,
        covering_metric,
        negative,
        negative_len: len,
        covered,
        outside,
    } = *plan;
    add_unicast(handle, covering, covering_len, oif, covering_metric).await;
    let (snap, task) = start_fib().await;
    assert_agrees(
        handle,
        &snap,
        &[(covered, Ok(())), (outside, Ok(()))],
        "covering route only",
    )
    .await;

    for kind in NEGATIVE_TYPES {
        let metric = 50;
        add_negative(handle, negative, len, kind, metric).await;
        eventually(&snap, "negative route tracked", |s| count(s, negative) == 1).await;
        assert_agrees(
            handle,
            &snap,
            &[(covered, rejected_with(kind)), (outside, Ok(()))],
            &format!("{kind:?} beneath the covering route"),
        )
        .await;

        del_negative(handle, negative, len, kind, metric).await;
        eventually(&snap, "negative route removed", |s| count(s, negative) == 0).await;
        assert_agrees(
            handle,
            &snap,
            &[(covered, Ok(())), (outside, Ok(()))],
            &format!("{kind:?} deleted"),
        )
        .await;

        // A unicast route for the prefix, then `ip route replace <kind>`.
        add_unicast(handle, negative, len, oif, metric).await;
        eventually(&snap, "unicast route tracked", |s| count(s, negative) == 1).await;
        replace_with_negative(handle, negative, len, kind, metric).await;
        eventually(&snap, "replaced by the negative route", |s| {
            !reachable(s, covered)
        })
        .await;
        assert_eq!(
            count(&snap.read().unwrap(), negative),
            1,
            "{kind:?} replaced"
        );
        assert_agrees(
            handle,
            &snap,
            &[(covered, rejected_with(kind)), (outside, Ok(()))],
            &format!("unicast replaced by {kind:?}"),
        )
        .await;
        del_negative(handle, negative, len, kind, metric).await;
        eventually(&snap, "replacement removed", |s| count(s, negative) == 0).await;
    }

    del_unicast(handle, covering, covering_len, oif, covering_metric).await;
    task.abort();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn ipv4_negative_routes_beneath_a_covering_route_agree_with_the_kernel() {
    let handle = connect();
    let oif = dummy(&handle, "pvtest57a").await;
    let plan = Plan {
        covering: "100.64.0.0".parse().unwrap(),
        covering_len: 10,
        covering_metric: 0,
        negative: "100.64.57.0".parse().unwrap(),
        negative_len: 24,
        covered: "100.64.57.7".parse().unwrap(),
        outside: "100.65.0.7".parse().unwrap(),
    };
    negative_lifecycle(&handle, oif, &plan).await;
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn ipv6_negative_routes_beneath_a_covering_route_agree_with_the_kernel() {
    let handle = connect();
    let oif = dummy(&handle, "pvtest57b").await;
    let plan = Plan {
        covering: "fd57::".parse().unwrap(),
        covering_len: 16,
        covering_metric: 1024,
        negative: "fd57:1::".parse().unwrap(),
        negative_len: 48,
        covered: "fd57:1::7".parse().unwrap(),
        outside: "fd57:2::7".parse().unwrap(),
    };
    negative_lifecycle(&handle, oif, &plan).await;
}

/// The initial dump: negative routes already present when the snapshot is
/// built, in several arrangements, all checked against the kernel.
///
/// The covering routes are `172.16.0.0/15` and `fd58::/16` rather than a
/// default route, because the other tests in this file run in parallel in the
/// same namespace and expect their own probes to be uncovered once they
/// delete their routes.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn initial_dump_of_negative_routes_agrees_with_the_kernel() {
    let handle = connect();
    let oif = dummy(&handle, "pvtest57c").await;
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    add_unicast(&handle, ip("172.16.0.0"), 15, oif, 0).await;
    add_unicast(&handle, ip("fd58::"), 16, oif, 1024).await;

    let mut probes = Vec::new();
    // One negative route per type beneath the covering route.
    for (i, kind) in NEGATIVE_TYPES.into_iter().enumerate() {
        add_negative(&handle, ip(&format!("172.16.{i}.0")), 24, kind, 0).await;
        add_negative(&handle, ip(&format!("fd58:{i}::")), 48, kind, 1024).await;
        probes.push((ip(&format!("172.16.{i}.1")), rejected_with(kind)));
        probes.push((ip(&format!("fd58:{i}::1")), rejected_with(kind)));
    }

    // Same prefix, negative at the lower metric: the negative route wins.
    add_unicast(&handle, ip("172.17.2.0"), 24, oif, 100).await;
    add_negative(&handle, ip("172.17.2.0"), 24, RouteType::BlackHole, 10).await;
    probes.push((ip("172.17.2.1"), rejected_with(RouteType::BlackHole)));
    add_unicast(&handle, ip("fd58:100::"), 48, oif, 100).await;
    add_negative(&handle, ip("fd58:100::"), 48, RouteType::Prohibit, 10).await;
    probes.push((ip("fd58:100::1"), rejected_with(RouteType::Prohibit)));

    // Same prefix, negative at the higher metric: the unicast route wins.
    add_unicast(&handle, ip("172.17.3.0"), 24, oif, 10).await;
    add_negative(&handle, ip("172.17.3.0"), 24, RouteType::Unreachable, 100).await;
    probes.push((ip("172.17.3.1"), Ok(())));
    add_unicast(&handle, ip("fd58:101::"), 48, oif, 10).await;
    add_negative(&handle, ip("fd58:101::"), 48, RouteType::Unreachable, 100).await;
    probes.push((ip("fd58:101::1"), Ok(())));

    // A longer unicast route inside a negative prefix still forwards.
    add_negative(&handle, ip("172.17.128.0"), 17, RouteType::Throw, 0).await;
    add_unicast(&handle, ip("172.17.129.0"), 24, oif, 0).await;
    probes.push((ip("172.17.129.1"), Ok(())));
    probes.push((ip("172.17.130.1"), rejected_with(RouteType::Throw)));
    add_negative(&handle, ip("fd58:200::"), 24, RouteType::Throw, 1024).await;
    add_unicast(&handle, ip("fd58:201::"), 32, oif, 1024).await;
    probes.push((ip("fd58:201::1"), Ok(())));
    probes.push((ip("fd58:202::1"), rejected_with(RouteType::Throw)));

    // Outside every negative route the covering route forwards.
    probes.push((ip("172.17.0.1"), Ok(())));
    probes.push((ip("fd58:ffff::1"), Ok(())));

    let (snap, task) = start_fib().await;
    assert_agrees(&handle, &snap, &probes, "initial dump").await;
    task.abort();
}

// ── PR #123 review: IPv6 route preference and link-local space ───────────────

/// `ip -6 route append`: `NLM_F_CREATE | NLM_F_APPEND` without `NLM_F_EXCL`,
/// which `fib6_add_rt2node` would answer with `-EEXIST` for a second route of
/// the same metric.
async fn append(handle: &Handle, msg: RouteMessage) {
    new_route_with_flags(handle, msg, NLM_F_CREATE | NLM_F_APPEND).await;
}

fn unicast_v6_msg(dst: Ipv6Addr, len: u8, oif: u32, metric: u32) -> RouteMessage {
    RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, len)
        .output_interface(oif)
        .priority(metric)
        .build()
}

fn with_pref(mut msg: RouteMessage, pref: RoutePreference) -> RouteMessage {
    msg.attributes.push(RouteAttribute::Preference(pref));
    msg
}

/// Within one metric group IPv6 ranks routes by router preference
/// (`rt6_score_route`: `m |= IPV6_DECODE_PREF(...) << 2`; `find_match` keeps a
/// strictly better score) before list order, for negative and unicast routes
/// alike. Negative routes are always medium: `ip6_route_info_create`
/// overwrites a reject route's `fib6_flags`, dropping `RTF_PREF`.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn ipv6_route_preference_between_negative_and_unicast_agrees_with_the_kernel() {
    let handle = connect();
    let oif = dummy(&handle, "pvtest57d").await;
    let (snap, task) = start_fib().await;
    let ip6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();

    // Blackhole first, then a high-preference device route: the device route
    // wins although it comes second (Codex's reproduction).
    add_negative(&handle, ip("fd59::"), 64, RouteType::BlackHole, 100).await;
    append(
        &handle,
        with_pref(
            unicast_v6_msg(ip6("fd59::"), 64, oif, 100),
            RoutePreference::High,
        ),
    )
    .await;
    // A low-preference device route first, then a prohibit route: the
    // prohibit route wins, being medium.
    append(
        &handle,
        with_pref(
            unicast_v6_msg(ip6("fd59:1::"), 64, oif, 100),
            RoutePreference::Low,
        ),
    )
    .await;
    append(
        &handle,
        negative_msg(ip("fd59:1::"), 64, RouteType::Prohibit, 100),
    )
    .await;
    // An RTA_PREF on a negative route is dropped (ip6_route_info_create
    // overwrites its fib6_flags): a "low" unreachable route ahead of a medium
    // device route still wins by list order ...
    append(
        &handle,
        with_pref(
            negative_msg(ip("fd59:2::"), 64, RouteType::Unreachable, 100),
            RoutePreference::Low,
        ),
    )
    .await;
    append(&handle, unicast_v6_msg(ip6("fd59:2::"), 64, oif, 100)).await;
    // ... and a "high" blackhole behind a device route still loses by it.
    add_unicast(&handle, ip("fd59:3::"), 64, oif, 100).await;
    append(
        &handle,
        with_pref(
            negative_msg(ip("fd59:3::"), 64, RouteType::BlackHole, 100),
            RoutePreference::High,
        ),
    )
    .await;

    let probes = [
        (ip("fd59::1"), Ok(())),
        (ip("fd59:1::1"), rejected_with(RouteType::Prohibit)),
        (ip("fd59:2::1"), rejected_with(RouteType::Unreachable)),
        (ip("fd59:3::1"), Ok(())),
    ];
    eventually(&snap, "all eight routes tracked", |s| {
        ["fd59::", "fd59:1::", "fd59:2::", "fd59:3::"]
            .iter()
            .all(|p| count_v6(s, ip6(p)) == 2)
    })
    .await;
    assert_agrees(&handle, &snap, &probes, "incremental").await;
    task.abort();

    // The initial dump carries RTA_PREF too.
    let (dumped, task) = start_fib().await;
    assert_agrees(&handle, &dumped, &probes, "initial dump").await;
    task.abort();
}

/// The link-local fallback in `is_v6_reachable` applies only when no route
/// covers the address: a negative route over link-local space is honoured,
/// as the kernel honours it.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn negative_route_over_link_local_space_agrees_with_the_kernel() {
    let handle = connect();
    let _oif = dummy(&handle, "pvtest57e").await;
    let (snap, task) = start_fib().await;
    let net: IpAddr = "fe80:57::".parse().unwrap();
    let probe: IpAddr = "fe80:57::1".parse().unwrap();
    for kind in NEGATIVE_TYPES {
        add_negative(&handle, net, 64, kind, 100).await;
        eventually(&snap, "negative route tracked", |s| count(s, net) == 1).await;
        assert_agrees(
            &handle,
            &snap,
            &[(probe, rejected_with(kind))],
            &format!("{kind:?} over link-local space"),
        )
        .await;

        del_negative(&handle, net, 64, kind, 100).await;
        eventually(&snap, "negative route removed", |s| count(s, net) == 0).await;
        // With no route at all the oracle falls back to "on-link"; the kernel
        // has no route without an output interface. This is the documented
        // fallback, not a kernel comparison.
        assert!(reachable(&snap.read().unwrap(), probe), "{kind:?} removed");
    }
    task.abort();
}
