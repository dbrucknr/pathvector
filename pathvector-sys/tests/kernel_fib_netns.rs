//! Live-kernel checks for the FIB snapshot:
//!
//! - issue #56: routes with the same prefix but different priorities are
//!   separate kernel routes, and the snapshot must keep both;
//! - issue #57: a negative route (blackhole, unreachable, prohibit, throw)
//!   beneath a covering unicast route makes the covered destinations
//!   unreachable. These tests compare the oracle with the kernel's own lookup
//!   (`RTM_GETROUTE` for one destination, which is what `ip route get` sends);
//! - issue #59: when the kernel drops notifications because the socket's
//!   receive buffer is full (`ENOBUFS`, netlink(7)), the snapshot reports the
//!   loss and resynchronizes until it agrees with a fresh dump.
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
//! (`fib_table_insert` keys aliases by "[prefix,dscp,priority]";
//! `fib_table_lookup` returns the selected alias's `fib_props` error) and
//! `net/ipv6/ip6_fib.c` (`fib6_add_rt2node` keeps one route per metric for a
//! given next hop), with `net/ipv6/route.c` (`fib6_prop`) for IPv6 errors.

#![cfg(target_os = "linux")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use futures::TryStreamExt;
use netlink_packet_route::route::RouteMessage;
use netlink_packet_route::{
    link::{LinkAttribute, LinkFlags},
    route::{RouteScope, RouteType},
};
use pathvector_sys::{
    FibSnapshot, KernelFib, RT_TABLE_MAIN,
    fib::{FibLookup, FibStatus, KernelFibBuilder, RejectKind, ResyncBackoff},
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

/// Starts a `KernelFib` on the main table and waits until it is ready.
async fn start_fib() -> (Arc<RwLock<FibSnapshot>>, tokio::task::JoinHandle<()>) {
    let (snap, _, task) = start_built_fib(KernelFib::builder(RT_TABLE_MAIN)).await;
    (snap, task)
}

/// Starts a configured `KernelFib` and waits until it is ready.
async fn start_built_fib(
    builder: KernelFibBuilder,
) -> (
    Arc<RwLock<FibSnapshot>>,
    tokio::sync::watch::Receiver<FibStatus>,
    tokio::task::JoinHandle<()>,
) {
    let (fib, mut changes) = builder.build();
    let snap = fib.snapshot();
    let mut status = fib.status();
    let task = tokio::spawn(async move {
        let err = fib.spawn().await.expect_err("only returns on failure");
        panic!("KernelFib could not open a netlink socket: {err}");
    });
    tokio::time::timeout(Duration::from_secs(5), changes.changed())
        .await
        .expect("initial dump within 5 s")
        .expect("change channel open");
    wait_status(&mut status, "ready", |s| s.health().is_ready()).await;
    (snap, status, task)
}

/// Waits until `pred` holds for the status, or panics after 30 s.
async fn wait_status(
    status: &mut tokio::sync::watch::Receiver<FibStatus>,
    what: &str,
    pred: impl FnMut(&FibStatus) -> bool,
) -> FibStatus {
    let waited = tokio::time::timeout(Duration::from_secs(30), async {
        *status.wait_for(pred).await.expect("status channel open")
    })
    .await;
    waited.unwrap_or_else(|_| panic!("timed out waiting for {what}: {:?}", *status.borrow()))
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
/// The covering routes are `198.18.0.0/15` and `fd58::/16` rather than a
/// default route, because the other tests in this file run in parallel in the
/// same namespace and expect their own probes to be uncovered once they
/// delete their routes.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn initial_dump_of_negative_routes_agrees_with_the_kernel() {
    let handle = connect();
    let oif = dummy(&handle, "pvtest57c").await;
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    add_unicast(&handle, ip("198.18.0.0"), 15, oif, 0).await;
    add_unicast(&handle, ip("fd58::"), 16, oif, 1024).await;

    let mut probes = Vec::new();
    // One negative route per type beneath the covering route.
    for (i, kind) in NEGATIVE_TYPES.into_iter().enumerate() {
        add_negative(&handle, ip(&format!("198.18.{i}.0")), 24, kind, 0).await;
        add_negative(&handle, ip(&format!("fd58:{i}::")), 48, kind, 1024).await;
        probes.push((ip(&format!("198.18.{i}.1")), rejected_with(kind)));
        probes.push((ip(&format!("fd58:{i}::1")), rejected_with(kind)));
    }

    // Same prefix, negative at the lower metric: the negative route wins.
    add_unicast(&handle, ip("198.19.2.0"), 24, oif, 100).await;
    add_negative(&handle, ip("198.19.2.0"), 24, RouteType::BlackHole, 10).await;
    probes.push((ip("198.19.2.1"), rejected_with(RouteType::BlackHole)));
    add_unicast(&handle, ip("fd58:100::"), 48, oif, 100).await;
    add_negative(&handle, ip("fd58:100::"), 48, RouteType::Prohibit, 10).await;
    probes.push((ip("fd58:100::1"), rejected_with(RouteType::Prohibit)));

    // Same prefix, negative at the higher metric: the unicast route wins.
    add_unicast(&handle, ip("198.19.3.0"), 24, oif, 10).await;
    add_negative(&handle, ip("198.19.3.0"), 24, RouteType::Unreachable, 100).await;
    probes.push((ip("198.19.3.1"), Ok(())));
    add_unicast(&handle, ip("fd58:101::"), 48, oif, 10).await;
    add_negative(&handle, ip("fd58:101::"), 48, RouteType::Unreachable, 100).await;
    probes.push((ip("fd58:101::1"), Ok(())));

    // A longer unicast route inside a negative prefix still forwards.
    add_negative(&handle, ip("198.19.128.0"), 17, RouteType::Throw, 0).await;
    add_unicast(&handle, ip("198.19.129.0"), 24, oif, 0).await;
    probes.push((ip("198.19.129.1"), Ok(())));
    probes.push((ip("198.19.130.1"), rejected_with(RouteType::Throw)));
    add_negative(&handle, ip("fd58:200::"), 24, RouteType::Throw, 1024).await;
    add_unicast(&handle, ip("fd58:201::"), 32, oif, 1024).await;
    probes.push((ip("fd58:201::1"), Ok(())));
    probes.push((ip("fd58:202::1"), rejected_with(RouteType::Throw)));

    // Outside every negative route the covering route forwards.
    probes.push((ip("198.19.0.1"), Ok(())));
    probes.push((ip("fd58:ffff::1"), Ok(())));

    let (snap, task) = start_fib().await;
    assert_agrees(&handle, &snap, &probes, "initial dump").await;
    task.abort();
}

// ── Issue #59: recovery after notification loss ──────────────────────────────

/// The snapshot's routes inside `10.59.0.0/16`, the prefix the loss test uses
/// (no other test in this file touches it).
fn routes_in_10_59(s: &FibSnapshot) -> Vec<pathvector_sys::fib::KernelRouteV4> {
    s.routes_v4()
        .filter(|r| {
            let o = r.slot.dst.addr().octets();
            o[0] == 10 && o[1] == 59
        })
        .cloned()
        .collect()
}

/// netlink(7): "The kernel can't send a netlink message if the socket buffer
/// is full: the message will be dropped [...] It is up to the application to
/// detect when this happens (via the `ENOBUFS` error returned by recvmsg(2))
/// and resynchronize."
///
/// The test's runtime is single-threaded, so while it blocks on another
/// thread that adds 1000 routes, the `KernelFib` connection task cannot read
/// its socket. A 1000-route burst does not fit in the (deliberately small)
/// receive buffer, so the kernel drops notifications and reports `ENOBUFS`
/// once the reader comes back. The snapshot must count the loss, recover
/// without help, and then hold exactly what a fresh dump holds.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace; see module docs"]
async fn notifications_lost_to_enobufs_are_recovered_by_a_resync() {
    const ROUTES: u16 = 1000;
    let handle = connect();
    let oif = dummy(&handle, "pvtest59a").await;
    let backoff =
        ResyncBackoff::new(Duration::from_millis(20), Duration::from_millis(500)).unwrap();
    let (snap, mut status, task) = start_built_fib(
        KernelFib::builder(RT_TABLE_MAIN)
            .resync_backoff(backoff)
            .receive_buffer(NonZeroU32::new(32 * 1024).unwrap()),
    )
    .await;
    let before = *status.borrow();
    assert_eq!(routes_in_10_59(&snap.read().unwrap()), []);

    // Block this runtime (and so the connection task) while routes are added.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let writer = connect();
            for i in 0..ROUTES {
                let [hi, lo] = i.to_be_bytes();
                add_v4(&writer, Ipv4Addr::new(10, 59, hi, lo), 32, oif, 0).await;
            }
        });
    })
    .join()
    .expect("route writer thread");

    // `losses` counts overruns and connection losses; the connection
    // stays up here, so this is the ENOBUFS.
    wait_status(&mut status, "the loss to be detected", |s| {
        s.losses() > before.losses()
    })
    .await;
    let ready = wait_status(&mut status, "recovery", |s| {
        s.health().is_ready() && s.resyncs() > before.resyncs()
    })
    .await;
    assert!(ready.resyncs() > before.resyncs(), "recovered by a redump");

    // Agreement with a fresh dump, which never saw the loss.
    let recovered = routes_in_10_59(&snap.read().unwrap());
    assert_eq!(recovered.len(), usize::from(ROUTES), "every route is known");
    let (fresh, _, fresh_task) = start_built_fib(KernelFib::builder(RT_TABLE_MAIN)).await;
    assert_eq!(recovered, routes_in_10_59(&fresh.read().unwrap()));
    fresh_task.abort();
    task.abort();
}
