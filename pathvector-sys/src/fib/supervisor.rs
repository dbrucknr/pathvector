//! Keeps the [`FibSnapshot`] in step with the kernel across notification
//! loss, connection loss and inconsistent dumps.
//!
//! This is the platform-independent half of the snapshot's life cycle. It
//! talks to the kernel only through the [`RouteSource`] / [`RouteFeed`] port;
//! the Linux netlink adapter lives in `linux.rs`, and the tests drive the same
//! code with a scripted fake (`supervisor/tests.rs`).
//!
//! # What can go wrong, and how each is detected
//!
//! The governing texts are netlink(7), the kernel's netlink and route-dump
//! code, and the pinned `netlink-proto` 0.12 crate.
//!
//! - **Dropped notifications.** netlink(7): "The kernel can't send a netlink
//!   message if the socket buffer is full: the message will be dropped [...]
//!   It is up to the application to detect when this happens (via the
//!   `ENOBUFS` error returned by recvmsg(2)) and resynchronize." In
//!   `netlink-proto` 0.12 (`framed.rs`) an `ENOBUFS` from the socket becomes a
//!   synthetic `NLMSG_OVERRUN` message with sequence number 0, which no request
//!   uses, so it reaches the multicast channel; the adapter reports it as
//!   [`Notification::Overrun`]. The kernel reports this once per congestion
//!   episode (`net/netlink/af_netlink.c`): `netlink_overrun` sets `ENOBUFS`
//!   only when it sets `NETLINK_S_CONGESTED`, `netlink_broadcast_deliver` then
//!   drops *every* notification while that bit is set, and `netlink_rcv_wake`
//!   clears it only when a read leaves the queue empty. `sock_error` is
//!   checked before the queue (`__skb_try_recv_datagram`), so the `ENOBUFS`
//!   arrives ahead of anything already queued.
//! - **Connection loss.** Any other receive error, a send error or an
//!   undecodable datagram makes `netlink-proto`'s `Connection` future finish,
//!   which drops the sender of the multicast channel: the feed ends
//!   ([`RouteFeed::next`] returns `None`).
//! - **A dump cut short.** A request's response channel is also closed when
//!   the connection finishes, so a dump that loses its connection simply stops.
//!   The adapter therefore treats a dump as complete only when its
//!   `NLMSG_DONE` arrives ([`DumpError::ConnectionLost`] otherwise).
//! - **A dump that misses routes.** The kernel marks a dump
//!   `NLM_F_DUMP_INTR` ("Dump was inconsistent due to sequence change",
//!   `include/uapi/linux/netlink.h`) only for dumpers that record a generation
//!   number via `nl_dump_check_consistent`. The IPv4 and IPv6 route dumpers
//!   (`inet_dump_fib`, `inet6_dump_fib`) do not, so route dumps never carry
//!   the flag. Yet they can skip routes when the table changes between two
//!   dump chunks: `fib6_dump_table` restarts from the root "if the tree
//!   changed" and skips as many routes as it had already sent, which drops an
//!   unchanged route when an earlier one was deleted; `fib_table_dump`
//!   resumes by key and alias index, with the same hazard inside one leaf.
//!   Any such change also sends a notification for that family to our socket,
//!   which is subscribed before the dump starts. So a dump of family F counts
//!   as inconsistent if it carries `NLM_F_DUMP_INTR` **or** any F
//!   notification arrives while it runs, and it is repeated.
//!   (`iproute2`'s `rtnl_dump_filter_l` only prints "Dump was interrupted and
//!   may be inconsistent."; a daemon has to do better.)
//! - **A dump that stops.** `netlink_dump` returns `-ENOBUFS` when it cannot
//!   allocate or charge the next chunk, leaving the dump running
//!   (`cb_running` stays set); `netlink_recvmsg` reports that through
//!   `sk_err`, which `netlink-proto` turns into the same overrun message, and
//!   retries the dump only after it has *received* a queued message. On a
//!   socket with nothing else queued the dump never resumes. So the
//!   supervisor reads notifications while a dump runs, treats an overrun
//!   then as fatal for the dump, and also gives each dump a deadline
//!   ([`DumpTimeout`]). An abandoned dump is still running in the kernel, and
//!   `__netlink_dump_start` answers a new dump on that socket with `EBUSY`,
//!   so abandoning one always replaces the connection.
//!
//! # Recovery
//!
//! After any of these the health becomes [`SnapshotHealth::Degraded`] and the
//! supervisor resynchronizes with [`ResyncBackoff`] delays:
//!
//! 1. Notifications already received are applied to the live snapshot. They
//!    were read before the dump requests are sent, so the dumps will reflect
//!    them too.
//! 2. Each family is dumped into a fresh snapshot, IPv4 then IPv6, while
//!    notifications keep being read. Those that arrive during a family's dump
//!    are applied to the fresh snapshot once that dump completes (replaying a change the dump
//!    already shows is harmless: see `apply_new`). Notifications for a family
//!    not dumped yet are left out of the fresh snapshot, since its dump will
//!    show them. Every notification is also applied to the live snapshot, in
//!    case this attempt is abandoned.
//! 3. An overrun at any point abandons the attempt and nothing is installed:
//!    changes made while the socket was congested were dropped without a
//!    trace, and while a dump runs `netlink_recvmsg` queues the next dump
//!    chunk before `netlink_rcv_wake` looks at the queue, so the episode can
//!    last through the rest of the dump. The next attempt starts after a
//!    delay during which the queue is read to the end, which ends the
//!    episode, so that attempt's dumps are covered by fresh notifications.
//!    If the overrun (or the deadline) catches a dump still running, the
//!    connection is replaced as well.
//! 4. Otherwise the fresh snapshot replaces the old one in a single move under
//!    the write lock; the old one is freed after the lock is released, so
//!    lookups are never blocked for longer than that move.
//! 5. If the dumps were consistent the health becomes
//!    [`Ready`](SnapshotHealth::Ready); otherwise it stays degraded and the
//!    supervisor tries again after the next delay. An inconsistent snapshot is
//!    still installed: it is newer than the one it replaces, and every
//!    notification since its dump has been applied.
//!
//! An overrun with no dump running keeps the same connection:
//! `netlink-proto` notes that after `ENOBUFS` "contents of the socket's
//! internal buffer is still valid". A connection loss, a failed dump or an
//! abandoned dump drops the connection (its task is aborted with it) and opens
//! a new one.
//!
//! Between attempts the supervisor keeps applying the notifications it does
//! receive, so a degraded snapshot drifts no further than necessary, and
//! further overruns fold into the pending resynchronization instead of
//! triggering one dump each.

use std::{
    future::Future,
    io, mem,
    sync::{Arc, RwLock},
    time::Duration,
};

use tokio::{
    sync::watch,
    task::coop,
    time::{self, Instant},
};

use super::{
    FibSnapshot,
    health::{DegradedCause, DumpTimeout, FibStatus, IoFailure, ResyncBackoff, SnapshotHealth},
};

// ── Port ──────────────────────────────────────────────────────────────────────

/// An address family the snapshot mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    V4,
    V6,
}

/// One route notification, decoded far enough to be applied to a snapshot.
pub(crate) trait RouteUpdate: Send + 'static {
    /// The family whose table changed. Counts for dump consistency even when
    /// [`apply`](Self::apply) changes nothing (a route in another table or one
    /// installed by BGP still means the kernel's table moved under the dump).
    fn family(&self) -> Family;

    /// Applies the change; returns `true` if the snapshot changed.
    fn apply(&self, snapshot: &mut FibSnapshot) -> bool;
}

/// What a feed delivers.
#[derive(Debug)]
pub(crate) enum Notification<U> {
    /// A route was added, replaced or deleted.
    Route(U),
    /// The kernel dropped notifications for this socket (`ENOBUFS`).
    Overrun,
}

/// The result of polling a feed without waiting.
#[derive(Debug)]
pub(crate) enum Received<U> {
    Notification(Notification<U>),
    /// Nothing has been received yet.
    Empty,
    /// The connection has ended and everything it received has been read.
    Closed,
}

/// A complete dump of one family.
#[derive(Debug, Default)]
pub(crate) struct DumpReport {
    /// The family's routes, in kernel order (the other family is empty).
    pub(crate) routes: FibSnapshot,
    /// The kernel set `NLM_F_DUMP_INTR` on one of the dump's messages.
    pub(crate) interrupted: bool,
}

/// Why a dump did not complete.
#[derive(Debug)]
pub(crate) enum DumpError {
    /// The kernel answered with an error.
    Failed(io::Error),
    /// The connection ended before the dump's `NLMSG_DONE`.
    ConnectionLost,
}

/// One live connection: a stream of route notifications plus the ability to
/// dump the kernel's routes over the same socket, so that notifications and
/// dump replies are ordered with respect to each other.
pub(crate) trait RouteFeed: Send {
    type Update: RouteUpdate;

    /// The next notification, or `None` once the connection has ended.
    ///
    /// Must be cancel safe: the supervisor races it against a timer.
    fn next(&mut self) -> impl Future<Output = Option<Notification<Self::Update>>> + Send;

    /// A notification that has already been received, without waiting.
    fn try_next(&mut self) -> Received<Self::Update>;

    /// Requests a dump of every route of `family`. The returned future does
    /// not borrow the feed, so notifications can be read while it runs, and
    /// succeeds only if the kernel ends the dump with `NLMSG_DONE`. Dropping
    /// it before then leaves the dump running in the kernel; the feed must
    /// not be asked for another dump afterwards.
    fn dump(
        &mut self,
        family: Family,
    ) -> impl Future<Output = Result<DumpReport, DumpError>> + Send + 'static;
}

/// Opens connections subscribed to IPv4 and IPv6 route notifications.
pub(crate) trait RouteSource: Send {
    type Feed: RouteFeed;

    /// Opens a socket and subscribes it to route notifications.
    ///
    /// # Errors
    ///
    /// The socket could not be opened, bound or configured.
    fn connect(&mut self) -> io::Result<Self::Feed>;
}

// ── Shared state ──────────────────────────────────────────────────────────────

/// What the supervisor publishes: the snapshot, a change signal, and the
/// status.
#[derive(Clone)]
pub(crate) struct Shared {
    pub(crate) snapshot: Arc<RwLock<FibSnapshot>>,
    pub(crate) change_tx: watch::Sender<()>,
    pub(crate) status_tx: watch::Sender<FibStatus>,
}

impl Shared {
    /// An empty snapshot in the [`Starting`](SnapshotHealth::Starting) state,
    /// with receivers for the change signal and the status.
    pub(crate) fn new() -> (Self, watch::Receiver<()>, watch::Receiver<FibStatus>) {
        let (change_tx, change_rx) = watch::channel(());
        let (status_tx, status_rx) = watch::channel(FibStatus::STARTING);
        let shared = Self {
            snapshot: Arc::new(RwLock::new(FibSnapshot::new())),
            change_tx,
            status_tx,
        };
        (shared, change_rx, status_rx)
    }

    /// Applies one notification to the live snapshot.
    fn apply(&self, update: &impl RouteUpdate) {
        let changed = update.apply(&mut self.snapshot.write().expect("FibSnapshot poisoned"));
        if changed {
            let _ = self.change_tx.send(());
        }
    }

    /// Replaces the live snapshot with a freshly dumped one.
    ///
    /// The comparison runs under a read lock (this task is the only writer),
    /// the swap is a move under the write lock, and the old snapshot is freed
    /// after the lock is released.
    fn install(&self, fresh: FibSnapshot) {
        let first = self.status_tx.borrow().resyncs == 0;
        let changed = first || *self.snapshot.read().expect("FibSnapshot poisoned") != fresh;
        let old = mem::replace(
            &mut *self.snapshot.write().expect("FibSnapshot poisoned"),
            fresh,
        );
        drop(old);
        self.status_tx.send_modify(|s| s.resyncs += 1);
        if changed {
            let _ = self.change_tx.send(());
        }
    }

    fn degrade(&self, cause: DegradedCause) {
        let now = wall_clock();
        self.status_tx.send_modify(|s| {
            if cause.is_loss() {
                s.losses += 1;
            }
            s.health = match s.health {
                SnapshotHealth::Degraded {
                    since, attempts, ..
                } => SnapshotHealth::Degraded {
                    since,
                    cause,
                    attempts,
                },
                SnapshotHealth::Starting | SnapshotHealth::Ready { .. } => {
                    SnapshotHealth::Degraded {
                        since: now,
                        cause,
                        attempts: 0,
                    }
                }
            };
        });
    }

    fn begin_attempt(&self) {
        self.status_tx.send_if_modified(|s| match &mut s.health {
            SnapshotHealth::Degraded { attempts, .. } => {
                *attempts = attempts.saturating_add(1);
                true
            }
            _ => false,
        });
    }

    fn ready(&self) {
        let since = wall_clock();
        self.status_tx
            .send_modify(|s| s.health = SnapshotHealth::Ready { since });
    }
}

/// `std` time that follows tokio's clock, so paused-time tests stay coherent.
fn wall_clock() -> std::time::Instant {
    Instant::now().into_std()
}

// ── Retry pacing ──────────────────────────────────────────────────────────────

/// The position in a [`ResyncBackoff`] sequence.
struct Retry {
    policy: ResyncBackoff,
    attempt: u32,
    ready_at: Option<Instant>,
}

impl Retry {
    fn new(policy: ResyncBackoff) -> Self {
        Self {
            policy,
            attempt: 0,
            ready_at: None,
        }
    }

    /// The delay before the next attempt. The sequence restarts only if the
    /// snapshot had been ready for at least the maximum delay.
    fn next_delay(&mut self) -> Duration {
        if self
            .ready_at
            .take()
            .is_some_and(|t| t.elapsed() >= self.policy.max())
        {
            self.attempt = 0;
        }
        let delay = self.policy.delay(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        delay
    }

    fn ready(&mut self) {
        self.ready_at = Some(Instant::now());
    }
}

// ── Supervisor ────────────────────────────────────────────────────────────────

/// Timing for [`supervise`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pacing {
    pub(crate) backoff: ResyncBackoff,
    pub(crate) dump_timeout: DumpTimeout,
}

/// Runs until dropped, keeping `shared` in step with the kernel.
///
/// Returns only if the very first [`RouteSource::connect`] fails: that means
/// this process cannot use netlink at all (for example a sandbox that forbids
/// the socket), which retrying will not fix. Every later failure is retried
/// with backoff delays and reported through the status.
pub(crate) async fn supervise<S: RouteSource>(
    mut source: S,
    shared: Shared,
    pacing: Pacing,
) -> io::Error {
    let mut feed = match source.connect() {
        Ok(feed) => feed,
        Err(e) => {
            shared.degrade(DegradedCause::ConnectFailed(IoFailure::from(&e)));
            return e;
        }
    };
    let mut retry = Retry::new(pacing.backoff);
    loop {
        run_connection(feed, &shared, &mut retry, pacing.dump_timeout).await;
        feed = reconnect(&mut source, &shared, &mut retry).await;
    }
}

/// Opens a new connection, waiting before every attempt.
async fn reconnect<S: RouteSource>(source: &mut S, shared: &Shared, retry: &mut Retry) -> S::Feed {
    loop {
        time::sleep(retry.next_delay()).await;
        match source.connect() {
            Ok(feed) => return feed,
            Err(e) => shared.degrade(DegradedCause::ConnectFailed(IoFailure::from(&e))),
        }
    }
}

/// Resynchronizes and then follows notifications on one connection, until
/// the connection is lost or must be replaced. Dropping `feed` on return
/// closes the connection.
async fn run_connection<F: RouteFeed>(
    mut feed: F,
    shared: &Shared,
    retry: &mut Retry,
    dump_timeout: DumpTimeout,
) {
    loop {
        shared.begin_attempt();
        match resync(&mut feed, shared, dump_timeout).await {
            Attempt::Ready => {
                shared.ready();
                retry.ready();
            }
            Attempt::Retry(cause) => {
                shared.degrade(cause);
                if settle(&mut feed, shared, retry.next_delay()).await.is_err() {
                    shared.degrade(DegradedCause::ConnectionLost);
                    return;
                }
                continue;
            }
            Attempt::Reconnect(cause) => {
                shared.degrade(cause);
                return;
            }
        }

        // The snapshot mirrors the kernel; keep it that way.
        loop {
            match feed.next().await {
                Some(Notification::Route(update)) => {
                    shared.apply(&update);
                    coop::consume_budget().await;
                }
                Some(Notification::Overrun) => {
                    shared.degrade(DegradedCause::NotificationsLost);
                    if settle(&mut feed, shared, retry.next_delay()).await.is_err() {
                        shared.degrade(DegradedCause::ConnectionLost);
                        return;
                    }
                    break;
                }
                None => {
                    shared.degrade(DegradedCause::ConnectionLost);
                    return;
                }
            }
        }
    }
}

/// The feed ended.
struct Closed;

/// Waits `delay` while still applying notifications to the live snapshot.
async fn settle<F: RouteFeed>(
    feed: &mut F,
    shared: &Shared,
    delay: Duration,
) -> Result<(), Closed> {
    let deadline = time::sleep(delay);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => return Ok(()),
            notification = feed.next() => match notification {
                Some(Notification::Route(update)) => shared.apply(&update),
                Some(Notification::Overrun) => shared.degrade(DegradedCause::NotificationsLost),
                None => return Err(Closed),
            },
        }
        coop::consume_budget().await;
    }
}

/// How a resynchronization attempt ended.
#[derive(Debug)]
enum Attempt {
    /// A consistent fresh snapshot was installed.
    Ready,
    /// Try again on the same connection: an overrun abandoned the attempt
    /// after its dumps had finished (nothing installed), or the installed
    /// snapshot may miss routes.
    Retry(DegradedCause),
    /// The connection must be replaced: it ended, a dump failed, or a dump
    /// was abandoned while still running in the kernel (nothing installed).
    Reconnect(DegradedCause),
}

impl From<DumpError> for Attempt {
    fn from(e: DumpError) -> Self {
        Self::Reconnect(match e {
            DumpError::Failed(e) => DegradedCause::DumpFailed(IoFailure::from(&e)),
            DumpError::ConnectionLost => DegradedCause::ConnectionLost,
        })
    }
}

/// The most notifications one drain of already-received notifications reads.
/// A connection task on another thread can keep refilling the channel, so an
/// unbounded drain might never end.
const DRAIN_LIMIT: usize = 65_536;

/// Dumps both families into a fresh snapshot and installs it.
async fn resync<F: RouteFeed>(feed: &mut F, shared: &Shared, dump_timeout: DumpTimeout) -> Attempt {
    // Step 1: everything received so far predates the dump requests. Past
    // the cap the rest is read during the IPv4 dump, where an IPv4 change
    // counts against consistency: conservative, never wrong.
    for _ in 0..DRAIN_LIMIT {
        match feed.try_next() {
            Received::Notification(Notification::Route(update)) => shared.apply(&update),
            Received::Notification(Notification::Overrun) => {
                return Attempt::Retry(DegradedCause::NotificationsLost);
            }
            Received::Empty => break,
            Received::Closed => return Attempt::Reconnect(DegradedCause::ConnectionLost),
        }
    }

    let mut fresh = FibSnapshot::new();
    let mut consistent = true;
    // Step 2: IPv4, then IPv6.
    for family in [Family::V4, Family::V6] {
        // Notifications that arrive while the dump runs, in order.
        let mut during = Vec::new();
        let dump = feed.dump(family);
        let deadline_at = Instant::now() + dump_timeout.get();
        let deadline = time::sleep_until(deadline_at);
        tokio::pin!(dump, deadline);
        let report = loop {
            // Checked against the clock too: a timer is only marked as fired
            // when the runtime services its time driver, which a busy loop
            // can postpone.
            if Instant::now() >= deadline_at {
                return Attempt::Reconnect(DegradedCause::DumpStalled);
            }
            tokio::select! {
                // The dump and the deadline are polled before every
                // notification, so a queue that never empties cannot hold
                // them back (tokio's select "Fairness" docs). An overrun
                // queued before NLMSG_DONE is still seen before anything is
                // installed: the drain below reads it.
                biased;
                result = &mut dump => match result {
                    Ok(report) => break report,
                    Err(e) => return e.into(),
                },
                () = &mut deadline => return Attempt::Reconnect(DegradedCause::DumpStalled),
                notification = feed.next() => match notification {
                    Some(Notification::Route(update)) => {
                        shared.apply(&update);
                        during.push(update);
                    }
                    // Step 3: the dump may also have stopped for good.
                    Some(Notification::Overrun) => {
                        return Attempt::Reconnect(DegradedCause::NotificationsLost);
                    }
                    None => return Attempt::Reconnect(DegradedCause::ConnectionLost),
                },
            }
            // The feed's channel does not take part in tokio's cooperative
            // budget; without this a busy channel never yields the thread,
            // and on a current-thread runtime the deadline's timer never
            // fires.
            coop::consume_budget().await;
        };
        consistent &= !report.interrupted;
        match family {
            Family::V4 => fresh.v4 = report.routes.v4,
            Family::V6 => fresh.v6 = report.routes.v6,
        }

        // With IPv4 dumped first, an IPv4 notification is always newer than
        // the IPv4 dump, while an IPv6 one is newer than the IPv6 dump only
        // once that dump is done.
        let dumped = |f: Family| f == Family::V4 || family == Family::V6;
        let mut replay = |update: &F::Update, consistent: &mut bool| {
            let f = update.family();
            *consistent &= f != family;
            if dumped(f) {
                update.apply(&mut fresh);
            }
        };
        for update in &during {
            replay(update, &mut consistent);
        }
        // A capped drain cannot tell what is left from what arrived during
        // the dump, so stopping at the cap counts as inconsistent; the rest
        // is applied after the install, in order.
        let mut drained = 0;
        loop {
            if drained == DRAIN_LIMIT {
                consistent = false;
                break;
            }
            drained += 1;
            match feed.try_next() {
                Received::Empty => break,
                Received::Closed => return Attempt::Reconnect(DegradedCause::ConnectionLost),
                // Step 3, with the dump already finished.
                Received::Notification(Notification::Overrun) => {
                    return Attempt::Retry(DegradedCause::NotificationsLost);
                }
                Received::Notification(Notification::Route(update)) => {
                    replay(&update, &mut consistent);
                    shared.apply(&update);
                }
            }
        }
    }

    // Steps 4 and 5.
    shared.install(fresh);
    if consistent {
        Attempt::Ready
    } else {
        Attempt::Retry(DegradedCause::DumpInconsistent)
    }
}

#[cfg(test)]
mod tests;
