//! Supervisor tests against a scripted fake kernel.
//!
//! The fake keeps the "true" routing table and delivers a notification for
//! every change that actually changes it (the kernel rejects a duplicate add
//! with `EEXIST` and a delete of an absent route with `ESRCH`, and notifies
//! neither). Faults are injected the ways netlink(7), the kernel dump code and
//! `netlink-proto` 0.12 say they surface (see the module docs of
//! `supervisor.rs`):
//!
//! - a full receive buffer starts a congestion episode: one `Overrun`
//!   (`ENOBUFS`), then every notification is dropped until the reader has
//!   read the queue to the end (`netlink_overrun`, `netlink_broadcast_deliver`
//!   and `netlink_rcv_wake` in `net/netlink/af_netlink.c`);
//! - a terminated connection ends the feed;
//! - a dump can fail with an errno, stop without `NLMSG_DONE`, carry
//!   `NLM_F_DUMP_INTR`, race a change, or (like `fib6_dump_table` restarting
//!   after a tree change) skip an unchanged route while a change is notified.
//!
//! Time is paused (`start_paused`), so every backoff is exact and the tests
//! run instantly. The property is checked at quiescent points: when no task
//! can run, a feed has been read to the end, so a `Ready` status must mean the
//! snapshot equals the fake kernel's table.

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use proptest::prelude::*;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};

use super::*;
use crate::fib::{
    FibSnapshot, Ipv4Prefix, Ipv6Prefix, KernelRouteV4, KernelRouteV6, NextHopPath, NextHopV4,
    NextHopV6, RouteKind, RouteSlotV4, RouteSlotV6, TableId,
    health::{DegradedCause, FibStatus, ResyncBackoff, SnapshotHealth},
};

// ── Routes ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Route {
    V4(KernelRouteV4),
    V6(KernelRouteV6),
}

fn v4(network: &str, len: u8, metric: u32) -> Route {
    Route::V4(KernelRouteV4 {
        slot: RouteSlotV4 {
            table: TableId::MAIN,
            dst: Ipv4Prefix::new(network.parse().unwrap(), len).unwrap(),
            tos: 0,
            priority: metric,
        },
        kind: RouteKind::Unicast,
        protocol: 3,
        scope: 0,
        prefsrc: None,
        next_hop: NextHopV4::Path(NextHopPath {
            gateway: None,
            oif: None,
        }),
    })
}

fn v6(network: &str, len: u8, metric: u32) -> Route {
    Route::V6(KernelRouteV6 {
        slot: RouteSlotV6 {
            table: TableId::MAIN,
            dst: Ipv6Prefix::new(network.parse().unwrap(), len).unwrap(),
            src: Ipv6Prefix::DEFAULT,
            priority: metric,
        },
        kind: RouteKind::Unicast,
        protocol: 3,
        next_hop: NextHopV6::Path(NextHopPath {
            gateway: None,
            oif: None,
        }),
    })
}

/// A small universe of distinct routes, both families, some sharing a prefix.
fn universe() -> Vec<Route> {
    vec![
        v4("10.0.0.0", 8, 100),
        v4("10.1.0.0", 16, 10),
        v4("10.1.0.0", 16, 20),
        v4("192.0.2.0", 24, 0),
        v6("2001:db8::", 32, 1024),
        v6("2001:db8:1::", 48, 10),
        v6("2001:db8:1::", 48, 20),
        v6("fd00::", 8, 1),
    ]
}

#[derive(Debug, Clone)]
enum Change {
    Add(Route),
    Del(Route),
}

impl Change {
    fn route(&self) -> &Route {
        match self {
            Self::Add(r) | Self::Del(r) => r,
        }
    }
}

impl RouteUpdate for Change {
    fn family(&self) -> Family {
        match self.route() {
            Route::V4(_) => Family::V4,
            Route::V6(_) => Family::V6,
        }
    }

    fn apply(&self, s: &mut FibSnapshot) -> bool {
        match self {
            Self::Add(Route::V4(r)) => s.v4.insert_back(r.clone()),
            Self::Add(Route::V6(r)) => s.v6.insert_back(r.clone()),
            Self::Del(Route::V4(r)) => s.v4.remove(r),
            Self::Del(Route::V6(r)) => s.v6.remove(r),
        }
    }
}

// ── Fake kernel ───────────────────────────────────────────────────────────────

/// What one dump request does.
#[derive(Debug)]
enum DumpAct {
    Normal,
    /// The kernel answers with this errno.
    Fail(i32),
    /// Half the routes, then the connection ends without `NLMSG_DONE`.
    Truncate,
    /// The kernel sets `NLM_F_DUMP_INTR`; nothing is actually missed.
    FlagInterrupted,
    /// The table changes while the dump runs; the dump shows the result.
    ChangeDuring(Change),
    /// The table changes while the dump runs and, if it really changed, the
    /// dump skips the first other route of the family it is dumping.
    SkipDuring(Change),
    /// The table changes while the dump runs, but its notification is
    /// dropped (`ENOBUFS`).
    OverrunDuring(Change),
    /// Waits for the sender before answering.
    Gate(oneshot::Receiver<()>),
}

struct FeedSlot {
    tx: Option<mpsc::UnboundedSender<Notification<Change>>>,
    /// Notifications that will find the receive buffer full.
    dropping: usize,
    /// `NETLINK_S_CONGESTED`: every notification is dropped until the reader
    /// empties the queue.
    congested: bool,
}

#[derive(Default)]
struct Kernel {
    truth: FibSnapshot,
    feeds: Vec<FeedSlot>,
    /// Errno for each of the next connection attempts, which fail.
    connect_failures: VecDeque<i32>,
    dump_script: VecDeque<DumpAct>,
    connect_times: Vec<Instant>,
    dump_times: Vec<Instant>,
}

impl Kernel {
    /// Changes the table and notifies every live socket, unless the change is
    /// a no-op.
    fn change(&mut self, change: &Change) -> bool {
        if !change.apply(&mut self.truth) {
            return false;
        }
        for slot in &mut self.feeds {
            let Some(tx) = &slot.tx else { continue };
            if slot.dropping > 0 || slot.congested {
                slot.dropping = slot.dropping.saturating_sub(1);
                if !slot.congested {
                    slot.congested = true;
                    let _ = tx.send(Notification::Overrun);
                }
            } else {
                let _ = tx.send(Notification::Route(change.clone()));
            }
        }
        true
    }

    /// `netlink_rcv_wake`: a read that leaves the queue empty ends congestion.
    fn read_to_end(&mut self, id: usize) {
        self.feeds[id].congested = false;
    }

    fn copy(&self, family: Family, into: &mut FibSnapshot, skip: Option<&Route>) {
        match family {
            Family::V4 => {
                for r in self.truth.v4.iter() {
                    if skip != Some(&Route::V4(r.clone())) {
                        into.v4.insert_back(r.clone());
                    }
                }
            }
            Family::V6 => {
                for r in self.truth.v6.iter() {
                    if skip != Some(&Route::V6(r.clone())) {
                        into.v6.insert_back(r.clone());
                    }
                }
            }
        }
    }

    fn routes(&self, family: Family) -> Vec<Route> {
        match family {
            Family::V4 => self.truth.v4.iter().cloned().map(Route::V4).collect(),
            Family::V6 => self.truth.v6.iter().cloned().map(Route::V6).collect(),
        }
    }
}

#[derive(Clone, Default)]
struct FakeKernel(Arc<Mutex<Kernel>>);

impl FakeKernel {
    fn with(routes: &[Route]) -> Self {
        let k = Self::default();
        for r in routes {
            k.change(&Change::Add(r.clone()));
        }
        k
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Kernel> {
        self.0.lock().unwrap()
    }

    fn change(&self, change: &Change) -> bool {
        self.lock().change(change)
    }

    fn add(&self, r: &Route) -> bool {
        self.change(&Change::Add(r.clone()))
    }

    fn del(&self, r: &Route) -> bool {
        self.change(&Change::Del(r.clone()))
    }

    /// The next `n` notifications to every live socket are dropped.
    fn lose_next(&self, n: usize) {
        for slot in &mut self.lock().feeds {
            slot.dropping += n;
        }
    }

    /// Every live connection ends.
    fn terminate(&self) {
        for slot in &mut self.lock().feeds {
            slot.tx = None;
        }
    }

    fn fail_connects(&self, errnos: &[i32]) {
        self.lock().connect_failures.extend(errnos);
    }

    fn script(&self, act: DumpAct) {
        self.lock().dump_script.push_back(act);
    }

    fn truth(&self) -> FibSnapshot {
        self.lock().truth.clone()
    }

    fn connects(&self) -> usize {
        self.lock().connect_times.len()
    }

    fn dumps(&self) -> usize {
        self.lock().dump_times.len()
    }
}

struct FakeSource(FakeKernel);

impl RouteSource for FakeSource {
    type Feed = FakeFeed;

    fn connect(&mut self) -> io::Result<FakeFeed> {
        let mut k = self.0.lock();
        k.connect_times.push(Instant::now());
        if let Some(errno) = k.connect_failures.pop_front() {
            return Err(io::Error::from_raw_os_error(errno));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        k.feeds.push(FeedSlot {
            tx: Some(tx),
            dropping: 0,
            congested: false,
        });
        Ok(FakeFeed {
            id: k.feeds.len() - 1,
            rx,
            kernel: self.0.clone(),
        })
    }
}

struct FakeFeed {
    id: usize,
    rx: mpsc::UnboundedReceiver<Notification<Change>>,
    kernel: FakeKernel,
}

impl RouteFeed for FakeFeed {
    type Update = Change;

    async fn next(&mut self) -> Option<Notification<Change>> {
        let n = self.rx.recv().await;
        if self.rx.is_empty() {
            self.kernel.lock().read_to_end(self.id);
        }
        n
    }

    fn try_next(&mut self) -> Received<Change> {
        let received = match self.rx.try_recv() {
            Ok(n) => Received::Notification(n),
            Err(mpsc::error::TryRecvError::Empty) => Received::Empty,
            Err(mpsc::error::TryRecvError::Disconnected) => Received::Closed,
        };
        if self.rx.is_empty() {
            self.kernel.lock().read_to_end(self.id);
        }
        received
    }

    async fn dump(
        &mut self,
        family: Family,
        into: &mut FibSnapshot,
    ) -> Result<DumpReport, DumpError> {
        let act = {
            let mut k = self.kernel.lock();
            k.dump_times.push(Instant::now());
            k.dump_script.pop_front().unwrap_or(DumpAct::Normal)
        };
        let act = match act {
            DumpAct::Gate(rx) => {
                let _ = rx.await;
                DumpAct::Normal
            }
            other => other,
        };
        let mut k = self.kernel.lock();
        if k.feeds[self.id].tx.is_none() {
            return Err(DumpError::ConnectionLost);
        }
        let mut report = DumpReport::default();
        match act {
            DumpAct::Normal | DumpAct::Gate(_) => k.copy(family, into, None),
            DumpAct::Fail(errno) => {
                return Err(DumpError::Failed(io::Error::from_raw_os_error(errno)));
            }
            DumpAct::Truncate => {
                let routes = k.routes(family);
                for r in &routes[..routes.len() / 2] {
                    Change::Add(r.clone()).apply(into);
                }
                k.feeds[self.id].tx = None;
                return Err(DumpError::ConnectionLost);
            }
            DumpAct::FlagInterrupted => {
                k.copy(family, into, None);
                report.interrupted = true;
            }
            DumpAct::ChangeDuring(c) => {
                k.change(&c);
                k.copy(family, into, None);
            }
            DumpAct::SkipDuring(c) => {
                // Only a change to the tree being walked restarts the walk.
                let skip = if k.change(&c) && c.family() == family {
                    k.routes(family).into_iter().find(|r| r != c.route())
                } else {
                    None
                };
                k.copy(family, into, skip.as_ref());
            }
            DumpAct::OverrunDuring(c) => {
                k.feeds[self.id].dropping += 1;
                k.change(&c);
                k.copy(family, into, None);
            }
        }
        Ok(report)
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

fn backoff() -> ResyncBackoff {
    ResyncBackoff::new(Duration::from_millis(10), Duration::from_secs(1)).unwrap()
}

struct Harness {
    kernel: FakeKernel,
    snapshot: Arc<RwLock<FibSnapshot>>,
    status: watch::Receiver<FibStatus>,
    changes: watch::Receiver<()>,
    task: JoinHandle<io::Error>,
}

impl Harness {
    fn start(kernel: &FakeKernel) -> Self {
        let (shared, changes, status) = Shared::new();
        let snapshot = shared.snapshot.clone();
        let task = tokio::spawn(supervise(FakeSource(kernel.clone()), shared, backoff()));
        Self {
            kernel: kernel.clone(),
            snapshot,
            status,
            changes,
            task,
        }
    }

    /// Starts and waits for the initial dump.
    async fn ready(kernel: &FakeKernel) -> Self {
        let mut h = Self::start(kernel);
        h.wait_ready().await;
        h
    }

    fn status(&self) -> FibStatus {
        *self.status.borrow()
    }

    fn health(&self) -> SnapshotHealth {
        self.status().health()
    }

    fn snapshot(&self) -> FibSnapshot {
        self.snapshot.read().unwrap().clone()
    }

    fn agrees(&self) -> bool {
        self.snapshot() == self.kernel.truth()
    }

    async fn wait_for(&mut self, what: &str, pred: impl FnMut(&FibStatus) -> bool) -> FibStatus {
        let status = tokio::time::timeout(Duration::from_secs(600), self.status.wait_for(pred))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("status channel open");
        *status
    }

    async fn wait_ready(&mut self) -> FibStatus {
        self.wait_for("Ready", |s| s.health().is_ready()).await
    }

    async fn wait_degraded(&mut self, cause: DegradedCause) -> FibStatus {
        self.wait_for(&format!("Degraded({cause:?})"), |s| {
            s.health().degraded_cause() == Some(cause)
        })
        .await
    }

    /// Lets every task run to quiescence and virtual time pass.
    async fn quiesce(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn reachable(s: &FibSnapshot, addr: &str) -> bool {
    match addr.parse().unwrap() {
        std::net::IpAddr::V4(a) => s.is_v4_reachable(a),
        std::net::IpAddr::V6(a) => s.is_v6_reachable(a),
    }
}

const ENOMEM: i32 = 12;
const EBUSY: i32 = 16;
const EMFILE: i32 = 24;

// ── Initial population ────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn initial_dump_mirrors_the_kernel_and_reports_ready() {
    let kernel = FakeKernel::with(&universe()[..6]);
    let mut h = Harness::start(&kernel);
    let status = h.wait_ready().await;
    assert!(h.agrees());
    assert_eq!((status.resyncs(), status.losses()), (1, 0));
    assert_eq!(kernel.dumps(), 2, "one dump per family");
    assert!(
        h.changes.has_changed().unwrap(),
        "watchers learn of the dump"
    );
}

#[tokio::test(start_paused = true)]
async fn health_is_starting_and_the_snapshot_empty_until_the_first_dump() {
    let kernel = FakeKernel::with(&universe());
    let (gate, gated) = oneshot::channel();
    kernel.script(DumpAct::Gate(gated));
    let mut h = Harness::start(&kernel);
    h.quiesce(Duration::from_secs(5)).await;
    assert_eq!(h.health(), SnapshotHealth::Starting);
    assert_eq!(h.snapshot(), FibSnapshot::new());
    gate.send(()).unwrap();
    h.wait_ready().await;
    assert!(h.agrees());
}

#[tokio::test(start_paused = true)]
async fn an_empty_kernel_table_is_still_announced_once() {
    let mut h = Harness::start(&FakeKernel::default());
    h.wait_ready().await;
    assert!(h.changes.has_changed().unwrap());
}

#[tokio::test(start_paused = true)]
async fn notifications_after_the_dump_are_applied() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[..2]);
    let h = Harness::ready(&kernel).await;
    kernel.add(&routes[4]);
    kernel.del(&routes[0]);
    h.quiesce(Duration::from_millis(1)).await;
    assert!(h.agrees());
    assert!(h.health().is_ready());
    assert_eq!(h.status().resyncs(), 1, "no redump for ordinary changes");
}

// ── Notification loss (ENOBUFS) ───────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn lost_notification_degrades_then_a_resync_restores_agreement() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[..1]);
    let mut h = Harness::ready(&kernel).await;

    kernel.lose_next(1);
    kernel.add(&routes[3]); // 192.0.2.0/24, dropped
    let status = h.wait_degraded(DegradedCause::NotificationsLost).await;
    assert_eq!(status.losses(), 1);
    // Stale but flagged: the old snapshot still answers.
    let s = h.snapshot();
    assert!(
        !reachable(&s, "192.0.2.1"),
        "the dropped add is not known yet"
    );
    assert!(reachable(&s, "10.9.9.9"), "known routes still answer");

    let status = h.wait_ready().await;
    assert!(h.agrees());
    assert!(reachable(&h.snapshot(), "192.0.2.1"));
    assert_eq!((status.resyncs(), status.losses()), (2, 1));
    assert_eq!(kernel.connects(), 1, "an overrun keeps the connection");
}

#[tokio::test(start_paused = true)]
async fn a_burst_of_overruns_costs_one_resync() {
    let routes = universe();
    let kernel = FakeKernel::with(&[]);
    let mut h = Harness::ready(&kernel).await;
    let dumps = kernel.dumps();

    // Three separate congestion episodes, each ended by the reader, all
    // within the first backoff delay.
    for r in &routes[..3] {
        kernel.lose_next(1);
        kernel.add(r); // dropped: ENOBUFS
        h.quiesce(Duration::from_millis(1)).await;
    }
    h.wait_degraded(DegradedCause::NotificationsLost).await;
    let status = h.wait_ready().await;
    assert!(h.agrees());
    assert_eq!(kernel.dumps() - dumps, 2, "a single resync (two dumps)");
    assert_eq!((status.resyncs(), status.losses()), (2, 3));
}

#[tokio::test(start_paused = true)]
async fn notifications_received_while_waiting_to_resync_are_applied() {
    let routes = universe();
    let kernel = FakeKernel::with(&[]);
    let mut h = Harness::ready(&kernel).await;
    let (gate, gated) = oneshot::channel();

    kernel.lose_next(1);
    kernel.add(&routes[0]); // dropped
    kernel.script(DumpAct::Gate(gated));
    h.wait_degraded(DegradedCause::NotificationsLost).await;
    kernel.add(&routes[3]); // delivered during the backoff wait
    h.quiesce(Duration::from_millis(1)).await;
    assert!(reachable(&h.snapshot(), "192.0.2.1"));
    assert!(!h.health().is_ready());
    gate.send(()).unwrap();
    h.wait_ready().await;
    assert!(h.agrees());
}

#[tokio::test(start_paused = true)]
async fn lookups_during_a_resync_answer_from_the_previous_snapshot() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[..4]);
    let mut h = Harness::ready(&kernel).await;
    let before = h.snapshot();
    let (gate, gated) = oneshot::channel();
    kernel.script(DumpAct::Gate(gated));

    kernel.lose_next(1);
    kernel.del(&routes[3]); // dropped
    h.wait_degraded(DegradedCause::NotificationsLost).await;
    h.quiesce(Duration::from_secs(5)).await; // the resync is now blocked on the gate
    assert_eq!(h.snapshot(), before, "never empty or partial mid-resync");
    gate.send(()).unwrap();
    h.wait_ready().await;
    assert!(h.agrees());
    assert!(!reachable(&h.snapshot(), "192.0.2.1"));
}

// ── Connection loss ───────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn connection_termination_reconnects_and_resyncs() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[..4]);
    let mut h = Harness::ready(&kernel).await;

    kernel.terminate();
    kernel.del(&routes[0]); // nobody is listening
    kernel.add(&routes[5]);
    let status = h.wait_degraded(DegradedCause::ConnectionLost).await;
    assert_eq!(status.losses(), 1);
    let status = h.wait_ready().await;
    assert!(h.agrees());
    assert_eq!(kernel.connects(), 2);
    assert_eq!((status.resyncs(), status.losses()), (2, 1));
}

#[tokio::test(start_paused = true)]
async fn reconnect_failures_back_off_exponentially_up_to_the_cap() {
    let kernel = FakeKernel::with(&universe()[..2]);
    let mut h = Harness::ready(&kernel).await;
    kernel.fail_connects(&[EMFILE; 9]);
    let lost_at = Instant::now();
    kernel.terminate();

    h.wait_for("ConnectFailed", |s| {
        matches!(
            s.health().degraded_cause(),
            Some(DegradedCause::ConnectFailed(f)) if f.errno() == Some(EMFILE)
        )
    })
    .await;
    h.wait_ready().await;
    assert!(h.agrees());

    let times = kernel.lock().connect_times.clone();
    assert_eq!(times.len(), 1 + 10, "initial + 9 failures + 1 success");
    let mut previous = lost_at;
    let gaps: Vec<u128> = times[1..]
        .iter()
        .map(|&t| {
            let gap = t - previous;
            previous = t;
            gap.as_millis()
        })
        .collect();
    assert_eq!(
        gaps,
        [10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000],
        "initial · 2ⁿ, capped at the maximum"
    );
}

#[tokio::test(start_paused = true)]
async fn the_first_connect_failure_is_returned_to_the_caller() {
    let kernel = FakeKernel::default();
    kernel.fail_connects(&[ENOMEM]);
    let (shared, _changes, status) = Shared::new();
    let err = supervise(FakeSource(kernel.clone()), shared, backoff()).await;
    assert_eq!(err.raw_os_error(), Some(ENOMEM));
    assert!(matches!(
        status.borrow().health().degraded_cause(),
        Some(DegradedCause::ConnectFailed(f)) if f.errno() == Some(ENOMEM)
    ));
    assert_eq!(kernel.connects(), 1, "no retry");
}

// ── Dump failures ─────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn a_failed_dump_degrades_and_retries_on_a_new_connection() {
    let kernel = FakeKernel::with(&universe());
    kernel.script(DumpAct::Fail(EBUSY));
    let mut h = Harness::start(&kernel);
    h.wait_for("DumpFailed", |s| {
        matches!(
            s.health().degraded_cause(),
            Some(DegradedCause::DumpFailed(f)) if f.errno() == Some(EBUSY)
        )
    })
    .await;
    assert_eq!(h.snapshot(), FibSnapshot::new(), "nothing installed");
    h.wait_ready().await;
    assert!(h.agrees());
    assert_eq!(kernel.connects(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_dump_cut_short_is_never_installed() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[..4]);
    let mut h = Harness::ready(&kernel).await;
    let before = h.snapshot();
    let (gate, gated) = oneshot::channel();
    kernel.script(DumpAct::Truncate);
    kernel.script(DumpAct::Gate(gated));

    kernel.lose_next(1);
    kernel.add(&routes[4]); // dropped: triggers the resync
    h.wait_degraded(DegradedCause::ConnectionLost).await;
    assert_eq!(h.snapshot(), before, "the half dump was discarded");
    gate.send(()).unwrap();
    h.wait_ready().await;
    assert!(h.agrees());
    assert_eq!(kernel.connects(), 2);
}

#[tokio::test(start_paused = true)]
async fn an_interrupted_dump_is_installed_but_repeated() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[..3]);
    kernel.script(DumpAct::FlagInterrupted);
    let mut h = Harness::start(&kernel);
    let status = h.wait_degraded(DegradedCause::DumpInconsistent).await;
    assert_eq!(status.resyncs(), 1, "the fresh snapshot is installed");
    assert!(h.agrees());
    let status = h.wait_ready().await;
    assert_eq!((status.resyncs(), status.losses()), (2, 0));
    assert_eq!(kernel.dumps(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_change_during_a_dump_of_that_family_forces_a_redump() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[4..6]);
    kernel.script(DumpAct::Normal);
    kernel.script(DumpAct::ChangeDuring(Change::Add(routes[6].clone())));
    let mut h = Harness::start(&kernel);
    h.wait_degraded(DegradedCause::DumpInconsistent).await;
    h.wait_ready().await;
    assert!(h.agrees());
    assert_eq!(h.status().resyncs(), 2);
}

/// `fib6_dump_table` restarts at the root after a tree change and skips the
/// number of routes already sent, so an unchanged route can go missing. The
/// only trace is the notification for the change; it must force a redump.
#[tokio::test(start_paused = true)]
async fn a_dump_that_skips_an_unchanged_route_is_caught_and_repeated() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[4..7]);
    kernel.script(DumpAct::Normal);
    kernel.script(DumpAct::SkipDuring(Change::Del(routes[4].clone())));
    let mut h = Harness::start(&kernel);
    h.wait_degraded(DegradedCause::DumpInconsistent).await;
    assert!(!h.agrees(), "the skipped route is missing, and flagged");
    h.wait_ready().await;
    assert!(h.agrees());
}

#[tokio::test(start_paused = true)]
async fn changes_to_the_other_family_during_a_dump_are_not_inconsistencies() {
    let routes = universe();
    let kernel = FakeKernel::with(&[routes[0].clone(), routes[4].clone()]);
    // An IPv6 change during the IPv4 dump: the IPv6 dump will show it.
    kernel.script(DumpAct::ChangeDuring(Change::Add(routes[5].clone())));
    // An IPv4 change during the IPv6 dump: newer than the IPv4 dump, so it
    // must be applied on top of it.
    kernel.script(DumpAct::ChangeDuring(Change::Add(routes[3].clone())));
    let mut h = Harness::start(&kernel);
    let status = h.wait_ready().await;
    assert!(h.agrees());
    assert_eq!(status.resyncs(), 1, "both dumps were clean");
}

#[tokio::test(start_paused = true)]
async fn an_overrun_during_a_dump_abandons_the_attempt() {
    let routes = universe();
    let kernel = FakeKernel::with(&routes[..2]);
    kernel.script(DumpAct::OverrunDuring(Change::Add(routes[3].clone())));
    let mut h = Harness::start(&kernel);
    let status = h.wait_degraded(DegradedCause::NotificationsLost).await;
    assert_eq!(
        (status.resyncs(), status.losses()),
        (0, 1),
        "nothing installed"
    );
    assert_eq!(kernel.dumps(), 1, "the IPv6 dump is not even attempted");
    h.wait_ready().await;
    assert!(h.agrees());
}

// ── Pacing ────────────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn losses_right_after_recovery_escalate_and_a_quiet_period_resets() {
    let routes = universe();
    let kernel = FakeKernel::with(&[]);
    let mut h = Harness::ready(&kernel).await;

    let mut waits = Vec::new();
    for r in &routes[..4] {
        let dumps = kernel.dumps();
        let lost_at = Instant::now();
        kernel.lose_next(1);
        kernel.add(r);
        h.wait_degraded(DegradedCause::NotificationsLost).await;
        h.wait_ready().await;
        waits.push((kernel.lock().dump_times[dumps] - lost_at).as_millis());
    }
    assert_eq!(waits, [10, 20, 40, 80], "back-to-back losses back off");

    // Ready for longer than the cap: the next loss starts over.
    h.quiesce(Duration::from_secs(2)).await;
    let dumps = kernel.dumps();
    let lost_at = Instant::now();
    kernel.lose_next(1);
    kernel.add(&routes[4]);
    h.wait_degraded(DegradedCause::NotificationsLost).await;
    h.wait_ready().await;
    assert_eq!((kernel.lock().dump_times[dumps] - lost_at).as_millis(), 10);
    assert!(h.agrees());
}

// ── Model check ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Op {
    /// Toggle a route of the universe (add if absent, else delete).
    Toggle(usize),
    /// Drop the next `n` notifications.
    Lose(usize),
    Terminate,
    FailConnects(usize),
    Dump(Fault),
    /// Let `n` ms of virtual time pass.
    Wait(u64),
}

#[derive(Debug, Clone)]
enum Fault {
    Fail,
    Truncate,
    Interrupted,
    ChangeDuring(usize),
    SkipDuring(usize),
    OverrunDuring(usize),
}

fn toggle(kernel: &FakeKernel, i: usize) -> Change {
    let r = universe()[i].clone();
    let present = match &r {
        Route::V4(x) => kernel.lock().truth.v4.contains(x),
        Route::V6(x) => kernel.lock().truth.v6.contains(x),
    };
    if present {
        Change::Del(r)
    } else {
        Change::Add(r)
    }
}

fn op() -> impl Strategy<Value = Op> {
    let n = universe().len();
    let fault = prop_oneof![
        Just(Fault::Fail),
        Just(Fault::Truncate),
        Just(Fault::Interrupted),
        (0..n).prop_map(Fault::ChangeDuring),
        (0..n).prop_map(Fault::SkipDuring),
        (0..n).prop_map(Fault::OverrunDuring),
    ];
    prop_oneof![
        6 => (0..n).prop_map(Op::Toggle),
        2 => (1..4usize).prop_map(Op::Lose),
        1 => Just(Op::Terminate),
        1 => (1..4usize).prop_map(Op::FailConnects),
        2 => fault.prop_map(Op::Dump),
        3 => (0..200u64).prop_map(Op::Wait),
    ]
}

/// At a quiescent point every delivered notification has been applied, so
/// `Ready` must mean the snapshot equals the kernel's table.
fn check_ready_means_agreement(h: &Harness, step: &str) {
    if h.health().is_ready() {
        assert!(
            h.agrees(),
            "Ready but the snapshot differs from the kernel after {step}"
        );
    }
}

async fn run_model(initial: Vec<usize>, ops: Vec<Op>) {
    let routes = universe();
    let kernel = FakeKernel::with(
        &initial
            .iter()
            .map(|&i| routes[i].clone())
            .collect::<Vec<_>>(),
    );
    let mut h = Harness::ready(&kernel).await;
    for (step, op) in ops.iter().enumerate() {
        match op {
            Op::Toggle(i) => {
                kernel.change(&toggle(&kernel, *i));
            }
            Op::Lose(n) => kernel.lose_next(*n),
            Op::Terminate => kernel.terminate(),
            Op::FailConnects(n) => kernel.fail_connects(&vec![EMFILE; *n]),
            Op::Dump(fault) => kernel.script(match fault {
                Fault::Fail => DumpAct::Fail(EBUSY),
                Fault::Truncate => DumpAct::Truncate,
                Fault::Interrupted => DumpAct::FlagInterrupted,
                Fault::ChangeDuring(i) => DumpAct::ChangeDuring(toggle(&kernel, *i)),
                Fault::SkipDuring(i) => DumpAct::SkipDuring(toggle(&kernel, *i)),
                Fault::OverrunDuring(i) => DumpAct::OverrunDuring(toggle(&kernel, *i)),
            }),
            Op::Wait(ms) => h.quiesce(Duration::from_millis(*ms)).await,
        }
        h.quiesce(Duration::from_millis(1)).await;
        check_ready_means_agreement(&h, &format!("step {step} ({op:?})"));
    }

    // Faults are finite, so the supervisor must converge. A scripted fault
    // only fires on a dump, and a dump only happens after a loss, so force
    // one to flush any leftover script entries.
    for _ in 0..16 {
        if kernel.lock().dump_script.is_empty() && kernel.lock().connect_failures.is_empty() {
            break;
        }
        kernel.terminate();
        h.quiesce(Duration::from_secs(60)).await;
    }
    h.wait_ready().await;
    assert!(
        h.agrees(),
        "after recovery the snapshot equals a fresh dump"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any sequence of route changes and faults: whenever the supervisor
    /// says Ready the snapshot equals the kernel's table, and once the faults
    /// stop it always gets back to Ready.
    #[test]
    fn any_history_of_changes_and_faults_converges_to_the_kernel_table(
        initial in proptest::sample::subsequence((0..universe().len()).collect::<Vec<_>>(), 0..=8),
        ops in proptest::collection::vec(op(), 0..40),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(run_model(initial, ops));
    }
}
