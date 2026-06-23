//! FIB integration for pathvectord.
//!
//! Two components:
//!
//! - [`DaemonOracle`] — wraps [`pathvector_sys::KernelOracle`] and implements
//!   [`NextHopOracle`] so the BGP decision process (RFC 4271 §9.1 steps 1 & 8)
//!   can consult the live kernel FIB for next-hop reachability and IGP metrics.
//!
//! - [`FibManager`] — consumes [`BestPathChange`] values from the event loop
//!   and forwards them to a background task that issues `RTM_NEWROUTE` /
//!   `RTM_DELROUTE` netlink calls.
//!
//! # Deduplication
//!
//! Rather than a bounded channel (which silently drops updates when full),
//! `FibManager` maintains a `HashMap<Nlri, PendingOp>` for each address
//! family, protected by a `std::sync::Mutex`. Every `apply_v4/v6` call
//! overwrites the entry for that NLRI — only the *latest desired state* per
//! prefix is kept. A [`tokio::sync::Notify`] signals the background writer
//! that work is pending.
//!
//! This eliminates silent drops during full-table convergence and naturally
//! coalesces rapid best-path oscillations (e.g., from FIB re-evaluation) into
//! a single kernel operation per prefix.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use pathvector_rib::{BestPathChange, oracle::NextHopOracle};
use pathvector_sys::{FibWrite, KernelOracle as SysOracle};
use pathvector_types::{NextHop, Nlri};
use tokio::sync::Notify;

// ── DaemonOracle ─────────────────────────────────────────────────────────────

/// Implements [`NextHopOracle`] by querying the in-process [`FibSnapshot`].
///
/// [`FibSnapshot`]: pathvector_sys::FibSnapshot
// Constructed only on Linux (where KernelFib::spawn() populates the snapshot);
// tests on all platforms use it directly.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct DaemonOracle(pub(crate) SysOracle);

impl NextHopOracle for DaemonOracle {
    fn is_reachable(&self, next_hop: &NextHop) -> bool {
        match next_hop {
            NextHop::V4(addr) => self.0.is_v4_reachable(*addr),
            NextHop::V6(addr) => self.0.is_v6_reachable(*addr),
            NextHop::V6WithLinkLocal { global, link_local } => {
                // RFC 4760 §3: the link-local is included so the receiver can
                // forward even when the global address isn't reachable via the
                // main routing table (e.g. speaker has no global IPv6, or the
                // global is a loopback like ::1 that only exists in table local).
                // Prefer the global when it's reachable; fall back to link-local.
                if !global.is_unspecified() && self.0.is_v6_reachable(*global) {
                    true
                } else {
                    self.0.is_v6_reachable(*link_local)
                }
            }
        }
    }

    fn igp_metric(&self, next_hop: &NextHop) -> Option<u32> {
        match next_hop {
            NextHop::V4(addr) => self.0.igp_metric_v4(*addr),
            NextHop::V6(addr) => self.0.igp_metric_v6(*addr),
            NextHop::V6WithLinkLocal { global, link_local } => {
                if !global.is_unspecified() && self.0.igp_metric_v6(*global).is_some() {
                    self.0.igp_metric_v6(*global)
                } else {
                    self.0.igp_metric_v6(*link_local)
                }
            }
        }
    }
}

// ── FibManager ───────────────────────────────────────────────────────────────

/// The desired kernel state for an IPv4 prefix.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PendingV4 {
    Install {
        gateway: Ipv4Addr,
    },
    /// RFC 7999: program a kernel null route (`RTN_BLACKHOLE`) for this prefix.
    Blackhole,
    Withdraw,
}

/// The desired kernel state for an IPv6 prefix.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PendingV6 {
    Install {
        gateway: Ipv6Addr,
    },
    /// RFC 7999: program a kernel null route (`RTN_BLACKHOLE`) for this prefix.
    Blackhole,
    Withdraw,
}

/// Abstraction over FIB change application, enabling kernel-free unit testing.
///
/// The production implementation is [`FibManager`].  Tests can inject a
/// `RecordingFib` (defined in the test module) that records calls without
/// touching the kernel — same pattern as [`pathvector_rib::oracle::NextHopOracle`].
pub(crate) trait ApplyFibChange: Send + Sync {
    fn apply_v4(&self, change: BestPathChange<Ipv4Addr>);
    fn apply_v6(&self, change: BestPathChange<Ipv6Addr>);
    /// Program a kernel null route for an IPv4 BLACKHOLE prefix (RFC 7999).
    fn apply_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>);
    /// Remove the kernel null route for an IPv4 BLACKHOLE prefix.
    fn withdraw_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>);
    /// Program a kernel null route for an IPv6 BLACKHOLE prefix (RFC 7999).
    fn apply_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>);
    /// Remove the kernel null route for an IPv6 BLACKHOLE prefix.
    fn withdraw_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>);
}

/// Serialises FIB mutations from the BGP event loop to a background writer task.
///
/// `apply_v4/v6` are non-blocking: they overwrite the pending entry for the
/// given NLRI and signal the writer via a [`Notify`]. The writer drains both
/// maps in one batch per wakeup and issues the actual netlink calls.
///
/// Because each NLRI has exactly one pending slot, rapid best-path oscillations
/// are automatically coalesced — the kernel always converges to the correct
/// final state without intermediate churn, and no updates are ever dropped.
pub(crate) struct FibManager {
    pending_v4: Arc<Mutex<HashMap<Nlri<Ipv4Addr>, PendingV4>>>,
    pending_v6: Arc<Mutex<HashMap<Nlri<Ipv6Addr>, PendingV6>>>,
    notify: Arc<Notify>,
}

impl FibManager {
    pub(crate) fn new<W: FibWrite + Send + Sync + 'static>(writer: W) -> Self {
        let pending_v4 = Arc::new(Mutex::new(HashMap::new()));
        let pending_v6 = Arc::new(Mutex::new(HashMap::new()));
        let notify = Arc::new(Notify::new());
        spawn_writer(
            writer,
            Arc::clone(&pending_v4),
            Arc::clone(&pending_v6),
            Arc::clone(&notify),
        );
        Self {
            pending_v4,
            pending_v6,
            notify,
        }
    }

    /// Snapshot the pending IPv4 map — used only in tests.
    #[cfg(test)]
    pub(crate) fn pending_v4_snapshot(&self) -> HashMap<Nlri<Ipv4Addr>, PendingV4> {
        self.pending_v4.lock().unwrap().clone()
    }

    /// Snapshot the pending IPv6 map — used only in tests.
    #[cfg(test)]
    pub(crate) fn pending_v6_snapshot(&self) -> HashMap<Nlri<Ipv6Addr>, PendingV6> {
        self.pending_v6.lock().unwrap().clone()
    }
}

impl ApplyFibChange for FibManager {
    /// Record the desired FIB state for the prefix in `change`.
    ///
    /// For `Announced`: records `Install { gateway }`. For `Withdrawn`: records
    /// `Withdraw`. For `Unchanged`: no-op. Routes with no usable IPv4 next-hop
    /// are silently skipped.
    ///
    /// If a pending entry already exists for this NLRI, it is overwritten —
    /// only the latest desired state is retained.
    fn apply_v4(&self, change: BestPathChange<Ipv4Addr>) {
        let (nlri, op) = match change {
            BestPathChange::Announced(nlri, route) => {
                let Some(NextHop::V4(gateway)) = route.next_hop else {
                    return;
                };
                (nlri, PendingV4::Install { gateway })
            }
            BestPathChange::Withdrawn(nlri) => (nlri, PendingV4::Withdraw),
            BestPathChange::Unchanged => return,
        };
        self.pending_v4.lock().unwrap().insert(nlri, op);
        self.notify.notify_one();
    }

    /// Record the desired FIB state for the IPv6 prefix in `change`.
    ///
    /// Routes with no usable IPv6 global next-hop are silently skipped.
    fn apply_v6(&self, change: BestPathChange<Ipv6Addr>) {
        let (nlri, op) = match change {
            BestPathChange::Announced(nlri, route) => {
                let gateway = match route.next_hop {
                    Some(NextHop::V6(gw)) => gw,
                    Some(NextHop::V6WithLinkLocal { global, .. }) => global,
                    _ => return,
                };
                (nlri, PendingV6::Install { gateway })
            }
            BestPathChange::Withdrawn(nlri) => (nlri, PendingV6::Withdraw),
            BestPathChange::Unchanged => return,
        };
        self.pending_v6.lock().unwrap().insert(nlri, op);
        self.notify.notify_one();
    }

    fn apply_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>) {
        self.pending_v4
            .lock()
            .unwrap()
            .insert(nlri, PendingV4::Blackhole);
        self.notify.notify_one();
    }

    fn withdraw_blackhole_v4(&self, nlri: Nlri<Ipv4Addr>) {
        self.pending_v4
            .lock()
            .unwrap()
            .insert(nlri, PendingV4::Withdraw);
        self.notify.notify_one();
    }

    fn apply_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>) {
        self.pending_v6
            .lock()
            .unwrap()
            .insert(nlri, PendingV6::Blackhole);
        self.notify.notify_one();
    }

    fn withdraw_blackhole_v6(&self, nlri: Nlri<Ipv6Addr>) {
        self.pending_v6
            .lock()
            .unwrap()
            .insert(nlri, PendingV6::Withdraw);
        self.notify.notify_one();
    }
}

/// Apply one drained batch to the kernel FIB.
///
/// Extracted from the `spawn_writer` loop so it can be called directly in
/// tests without going through the tokio scheduler. Static dispatch via
/// `W: FibWrite` — no vtable.
pub(crate) async fn process_batch<W: FibWrite>(
    writer: &W,
    v4_batch: HashMap<Nlri<Ipv4Addr>, PendingV4>,
    v6_batch: HashMap<Nlri<Ipv6Addr>, PendingV6>,
) {
    for (nlri, op) in v4_batch {
        let (dst, prefix_len) = (nlri.prefix().ip(), nlri.prefix_len());
        match op {
            PendingV4::Install { gateway } => {
                if let Err(e) = writer.install_v4(dst, prefix_len, gateway).await {
                    tracing::warn!(
                        prefix = %format!("{dst}/{prefix_len}"),
                        %gateway,
                        "FIB install failed: {e}"
                    );
                }
            }
            PendingV4::Blackhole => {
                if let Err(e) = writer.install_blackhole_v4(dst, prefix_len).await {
                    tracing::warn!(
                        prefix = %format!("{dst}/{prefix_len}"),
                        "FIB blackhole install failed: {e}"
                    );
                }
            }
            PendingV4::Withdraw => {
                if let Err(e) = writer.withdraw_v4(dst, prefix_len).await {
                    tracing::warn!(
                        prefix = %format!("{dst}/{prefix_len}"),
                        "FIB withdraw failed: {e}"
                    );
                }
            }
        }
    }

    for (nlri, op) in v6_batch {
        let (dst, prefix_len) = (nlri.prefix().ip(), nlri.prefix_len());
        match op {
            PendingV6::Install { gateway } => {
                if let Err(e) = writer.install_v6(dst, prefix_len, gateway).await {
                    tracing::warn!(
                        prefix = %format!("{dst}/{prefix_len}"),
                        %gateway,
                        "FIB install (v6) failed: {e}"
                    );
                }
            }
            PendingV6::Blackhole => {
                if let Err(e) = writer.install_blackhole_v6(dst, prefix_len).await {
                    tracing::warn!(
                        prefix = %format!("{dst}/{prefix_len}"),
                        "FIB blackhole install (v6) failed: {e}"
                    );
                }
            }
            PendingV6::Withdraw => {
                if let Err(e) = writer.withdraw_v6(dst, prefix_len).await {
                    tracing::warn!(
                        prefix = %format!("{dst}/{prefix_len}"),
                        "FIB withdraw (v6) failed: {e}"
                    );
                }
            }
        }
    }
}

fn spawn_writer<W: FibWrite + Send + Sync + 'static>(
    writer: W,
    pending_v4: Arc<Mutex<HashMap<Nlri<Ipv4Addr>, PendingV4>>>,
    pending_v6: Arc<Mutex<HashMap<Nlri<Ipv6Addr>, PendingV6>>>,
    notify: Arc<Notify>,
) {
    tokio::spawn(async move {
        loop {
            notify.notified().await;
            // Drain both maps atomically so the event loop can keep writing
            // new entries while we process this batch.
            let v4_batch = std::mem::take(&mut *pending_v4.lock().unwrap());
            let v6_batch = std::mem::take(&mut *pending_v6.lock().unwrap());
            process_batch(&writer, v4_batch, v6_batch).await;
        }
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
        sync::{Arc, Mutex},
    };

    use pathvector_rib::{BestPathChange, RouteBuilder};
    use pathvector_sys::FibWrite;
    use pathvector_types::{AsPath, NextHop, Nlri, Origin};

    use super::{ApplyFibChange, FibManager, PendingV4, PendingV6};

    // ── MockFibWriter ─────────────────────────────────────────────────────────

    #[derive(Debug, Default, Clone)]
    struct Calls {
        installed_v4: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
        withdrawn_v4: Vec<(Ipv4Addr, u8)>,
        installed_v6: Vec<(Ipv6Addr, u8, Ipv6Addr)>,
        withdrawn_v6: Vec<(Ipv6Addr, u8)>,
        blackhole_v4: Vec<(Ipv4Addr, u8)>,
        blackhole_v6: Vec<(Ipv6Addr, u8)>,
    }

    /// A `FibWrite` implementation that records every call for inspection.
    /// Static dispatch — no vtable. Returns `impl Future` via `async fn`.
    #[derive(Clone)]
    struct MockFibWriter {
        calls: Arc<Mutex<Calls>>,
        fail_v4: bool,
        fail_v6: bool,
    }

    impl MockFibWriter {
        fn new() -> (Self, Arc<Mutex<Calls>>) {
            let calls = Arc::new(Mutex::new(Calls::default()));
            (
                Self {
                    calls: Arc::clone(&calls),
                    fail_v4: false,
                    fail_v6: false,
                },
                calls,
            )
        }

        fn failing() -> (Self, Arc<Mutex<Calls>>) {
            let (mut w, calls) = Self::new();
            w.fail_v4 = true;
            (w, calls)
        }

        fn failing_v6() -> (Self, Arc<Mutex<Calls>>) {
            let (mut w, calls) = Self::new();
            w.fail_v6 = true;
            (w, calls)
        }
    }

    impl FibWrite for MockFibWriter {
        async fn install_v4(
            &self,
            dst: Ipv4Addr,
            prefix_len: u8,
            gateway: Ipv4Addr,
        ) -> std::io::Result<()> {
            if self.fail_v4 {
                return Err(std::io::Error::other("mock install_v4 failure"));
            }
            self.calls
                .lock()
                .unwrap()
                .installed_v4
                .push((dst, prefix_len, gateway));
            Ok(())
        }

        async fn withdraw_v4(&self, dst: Ipv4Addr, prefix_len: u8) -> std::io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .withdrawn_v4
                .push((dst, prefix_len));
            Ok(())
        }

        async fn install_v6(
            &self,
            dst: Ipv6Addr,
            prefix_len: u8,
            gateway: Ipv6Addr,
        ) -> std::io::Result<()> {
            if self.fail_v6 {
                return Err(std::io::Error::other("mock install_v6 failure"));
            }
            self.calls
                .lock()
                .unwrap()
                .installed_v6
                .push((dst, prefix_len, gateway));
            Ok(())
        }

        async fn withdraw_v6(&self, dst: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
            if self.fail_v6 {
                return Err(std::io::Error::other("mock withdraw_v6 failure"));
            }
            self.calls
                .lock()
                .unwrap()
                .withdrawn_v6
                .push((dst, prefix_len));
            Ok(())
        }

        async fn install_blackhole_v4(&self, dst: Ipv4Addr, prefix_len: u8) -> std::io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .blackhole_v4
                .push((dst, prefix_len));
            Ok(())
        }

        async fn withdraw_blackhole_v4(
            &self,
            dst: Ipv4Addr,
            prefix_len: u8,
        ) -> std::io::Result<()> {
            // Reuse withdrawn_v4 for withdraw — distinguish by checking blackhole_v4 absence.
            self.calls
                .lock()
                .unwrap()
                .withdrawn_v4
                .push((dst, prefix_len));
            Ok(())
        }

        async fn install_blackhole_v6(&self, dst: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .blackhole_v6
                .push((dst, prefix_len));
            Ok(())
        }

        async fn withdraw_blackhole_v6(
            &self,
            dst: Ipv6Addr,
            prefix_len: u8,
        ) -> std::io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .withdrawn_v6
                .push((dst, prefix_len));
            Ok(())
        }
    }

    // ── process_batch unit tests ──────────────────────────────────────────────
    //
    // These call `process_batch` directly, bypassing the tokio scheduler
    // entirely — no yields, no timing, no spawned-task race conditions.
    // Static dispatch: the compiler monomorphises `process_batch<MockFibWriter>`
    // at compile time; no vtable is involved.

    fn v4_install(gw: &str) -> PendingV4 {
        PendingV4::Install {
            gateway: gw.parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn test_process_batch_install_v4_calls_writer() {
        let (mock, calls) = MockFibWriter::new();
        let gw: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let mut v4 = HashMap::new();
        v4.insert(nlri, v4_install("192.0.2.1"));
        super::process_batch(&mock, v4, HashMap::new()).await;
        let c = calls.lock().unwrap();
        assert_eq!(c.installed_v4, vec![(Ipv4Addr::new(10, 0, 0, 0), 8, gw)]);
        assert!(c.withdrawn_v4.is_empty());
    }

    #[tokio::test]
    async fn test_process_batch_withdraw_v4_calls_writer() {
        let (mock, calls) = MockFibWriter::new();
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let mut v4 = HashMap::new();
        v4.insert(nlri, PendingV4::Withdraw);
        super::process_batch(&mock, v4, HashMap::new()).await;
        let c = calls.lock().unwrap();
        assert_eq!(c.withdrawn_v4, vec![(Ipv4Addr::new(10, 0, 0, 0), 8)]);
        assert!(c.installed_v4.is_empty());
    }

    #[tokio::test]
    async fn test_process_batch_install_v6_calls_writer() {
        let (mock, calls) = MockFibWriter::new();
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let mut v6 = HashMap::new();
        v6.insert(nlri, PendingV6::Install { gateway: gw });
        super::process_batch(&mock, HashMap::new(), v6).await;
        let c = calls.lock().unwrap();
        assert_eq!(
            c.installed_v6,
            vec![("2001:db8::".parse().unwrap(), 32, gw)]
        );
        assert!(c.withdrawn_v6.is_empty());
    }

    #[tokio::test]
    async fn test_process_batch_withdraw_v6_calls_writer() {
        let (mock, calls) = MockFibWriter::new();
        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let mut v6 = HashMap::new();
        v6.insert(nlri, PendingV6::Withdraw);
        super::process_batch(&mock, HashMap::new(), v6).await;
        let c = calls.lock().unwrap();
        assert_eq!(c.withdrawn_v6, vec![("2001:db8::".parse().unwrap(), 32)]);
        assert!(c.installed_v6.is_empty());
    }

    #[tokio::test]
    async fn test_process_batch_blackhole_v4_calls_install_blackhole() {
        let (mock, calls) = MockFibWriter::new();
        let nlri: Nlri<Ipv4Addr> = "192.0.2.0/24".parse().unwrap();
        let mut v4 = HashMap::new();
        v4.insert(nlri, PendingV4::Blackhole);
        super::process_batch(&mock, v4, HashMap::new()).await;
        let c = calls.lock().unwrap();
        assert_eq!(
            c.blackhole_v4,
            vec![("192.0.2.0".parse().unwrap(), 24)],
            "Blackhole variant must call install_blackhole_v4"
        );
        assert!(c.installed_v4.is_empty(), "must not call install_v4");
    }

    #[tokio::test]
    async fn test_process_batch_blackhole_v6_calls_install_blackhole() {
        let (mock, calls) = MockFibWriter::new();
        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let mut v6 = HashMap::new();
        v6.insert(nlri, PendingV6::Blackhole);
        super::process_batch(&mock, HashMap::new(), v6).await;
        let c = calls.lock().unwrap();
        assert_eq!(
            c.blackhole_v6,
            vec![("2001:db8::".parse().unwrap(), 32)],
            "Blackhole variant must call install_blackhole_v6"
        );
        assert!(c.installed_v6.is_empty(), "must not call install_v6");
    }

    #[tokio::test]
    async fn test_process_batch_install_failure_does_not_panic() {
        // A failing writer must log a warning and continue — not panic or abort.
        let (mock, calls) = MockFibWriter::failing();
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let mut v4 = HashMap::new();
        v4.insert(nlri, v4_install("192.0.2.1"));
        // The withdraw on a different prefix must still succeed after the install fails.
        let nlri2: Nlri<Ipv4Addr> = "172.16.0.0/12".parse().unwrap();
        v4.insert(nlri2, PendingV4::Withdraw);
        super::process_batch(&mock, v4, HashMap::new()).await;
        let c = calls.lock().unwrap();
        // install_v4 errored (fail_v4=true), withdraw_v4 succeeded.
        assert!(
            c.installed_v4.is_empty(),
            "failed install must not be recorded"
        );
        assert_eq!(c.withdrawn_v4.len(), 1);
    }

    #[tokio::test]
    async fn test_process_batch_mixed_v4_and_v6_processed_independently() {
        let (mock, calls) = MockFibWriter::new();
        let nlri4: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let nlri6: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let gw6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut v4 = HashMap::new();
        v4.insert(nlri4, PendingV4::Withdraw);
        let mut v6 = HashMap::new();
        v6.insert(nlri6, PendingV6::Install { gateway: gw6 });
        super::process_batch(&mock, v4, v6).await;
        let c = calls.lock().unwrap();
        assert_eq!(c.withdrawn_v4.len(), 1);
        assert_eq!(c.installed_v6.len(), 1);
        assert!(c.installed_v4.is_empty());
        assert!(c.withdrawn_v6.is_empty());
    }

    fn nlri4(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn nlri6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    fn route4(prefix: &str, gateway: &str) -> pathvector_rib::Route<Ipv4Addr> {
        RouteBuilder::new(nlri4(prefix), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(gateway.parse().unwrap()))
            .build()
    }

    fn route6(prefix: &str, gateway: &str) -> pathvector_rib::Route<Ipv6Addr> {
        RouteBuilder::new(nlri6(prefix), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6(gateway.parse().unwrap()))
            .build()
    }

    fn route4_no_nh(prefix: &str) -> pathvector_rib::Route<Ipv4Addr> {
        RouteBuilder::new(nlri4(prefix), Origin::Igp, AsPath::new()).build()
    }

    fn make_fm() -> FibManager {
        FibManager {
            pending_v4: Default::default(),
            pending_v6: Default::default(),
            notify: Default::default(),
        }
    }

    // ── apply_v4 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_apply_v4_announced_records_install() {
        let fm = make_fm();
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4("10.0.0.0/8", "192.0.2.1"),
        ));
        let snap = fm.pending_v4_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[&nlri4("10.0.0.0/8")],
            PendingV4::Install {
                gateway: "192.0.2.1".parse().unwrap()
            }
        );
    }

    #[test]
    fn test_apply_v4_withdrawn_records_withdraw() {
        let fm = make_fm();
        fm.apply_v4(BestPathChange::Withdrawn(nlri4("192.168.0.0/24")));
        let snap = fm.pending_v4_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[&nlri4("192.168.0.0/24")], PendingV4::Withdraw);
    }

    #[test]
    fn test_apply_v4_unchanged_records_nothing() {
        let fm = make_fm();
        fm.apply_v4(BestPathChange::Unchanged);
        assert!(fm.pending_v4_snapshot().is_empty());
    }

    #[test]
    fn test_apply_v4_no_next_hop_skipped() {
        let fm = make_fm();
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4_no_nh("10.0.0.0/8"),
        ));
        assert!(
            fm.pending_v4_snapshot().is_empty(),
            "route without next-hop must not be recorded"
        );
    }

    #[test]
    fn test_apply_v4_deduplicates_same_prefix() {
        // A rapid withdraw followed by a re-announce should leave only Install.
        let fm = make_fm();
        fm.apply_v4(BestPathChange::Withdrawn(nlri4("10.0.0.0/8")));
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4("10.0.0.0/8", "192.0.2.1"),
        ));
        let snap = fm.pending_v4_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[&nlri4("10.0.0.0/8")],
            PendingV4::Install {
                gateway: "192.0.2.1".parse().unwrap()
            },
            "last write wins — Install must overwrite the earlier Withdraw"
        );
    }

    #[test]
    fn test_apply_v4_deduplicates_oscillating_gateway() {
        // Two rapid best-path changes for the same prefix — only the last gateway survives.
        let fm = make_fm();
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4("10.0.0.0/8", "192.0.2.1"),
        ));
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4("10.0.0.0/8", "192.0.2.2"),
        ));
        let snap = fm.pending_v4_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[&nlri4("10.0.0.0/8")],
            PendingV4::Install {
                gateway: "192.0.2.2".parse().unwrap()
            },
            "last gateway wins"
        );
    }

    #[test]
    fn test_apply_v4_multiple_prefixes_tracked_independently() {
        let fm = make_fm();
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4("10.0.0.0/8", "192.0.2.1"),
        ));
        fm.apply_v4(BestPathChange::Withdrawn(nlri4("172.16.0.0/12")));
        let snap = fm.pending_v4_snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            snap[&nlri4("10.0.0.0/8")],
            PendingV4::Install {
                gateway: "192.0.2.1".parse().unwrap()
            }
        );
        assert_eq!(snap[&nlri4("172.16.0.0/12")], PendingV4::Withdraw);
    }

    // ── apply_v6 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_apply_v6_announced_records_install() {
        let fm = make_fm();
        fm.apply_v6(BestPathChange::Announced(
            nlri6("2001:db8::/32"),
            route6("2001:db8::/32", "2001:db8::1"),
        ));
        let snap = fm.pending_v6_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[&nlri6("2001:db8::/32")],
            PendingV6::Install {
                gateway: "2001:db8::1".parse().unwrap()
            }
        );
    }

    #[test]
    fn test_apply_v6_withdrawn_records_withdraw() {
        let fm = make_fm();
        fm.apply_v6(BestPathChange::Withdrawn(nlri6("2001:db8::/32")));
        let snap = fm.pending_v6_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[&nlri6("2001:db8::/32")], PendingV6::Withdraw);
    }

    #[test]
    fn test_apply_v6_unchanged_records_nothing() {
        let fm = make_fm();
        fm.apply_v6(BestPathChange::<Ipv6Addr>::Unchanged);
        assert!(fm.pending_v6_snapshot().is_empty());
    }

    #[test]
    fn test_apply_v6_deduplicates_same_prefix() {
        let fm = make_fm();
        fm.apply_v6(BestPathChange::Withdrawn(nlri6("2001:db8::/32")));
        fm.apply_v6(BestPathChange::Announced(
            nlri6("2001:db8::/32"),
            route6("2001:db8::/32", "2001:db8::1"),
        ));
        let snap = fm.pending_v6_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[&nlri6("2001:db8::/32")],
            PendingV6::Install {
                gateway: "2001:db8::1".parse().unwrap()
            },
            "Install must overwrite the earlier Withdraw"
        );
    }

    #[test]
    fn test_apply_v6_with_link_local_uses_global_as_gateway() {
        let fm = make_fm();
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6WithLinkLocal { global, link_local })
            .build();
        fm.apply_v6(BestPathChange::Announced(nlri6("2001:db8::/32"), route));
        let snap = fm.pending_v6_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[&nlri6("2001:db8::/32")],
            PendingV6::Install { gateway: global },
            "V6WithLinkLocal must use the global address as the kernel gateway"
        );
    }

    #[test]
    fn test_apply_v6_non_v6_next_hop_skipped() {
        let fm = make_fm();
        // A route with a V4 next-hop applied to apply_v6 should be silently dropped.
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4(Ipv4Addr::new(192, 0, 2, 1)))
            .build();
        fm.apply_v6(BestPathChange::Announced(nlri6("2001:db8::/32"), route));
        assert!(
            fm.pending_v6_snapshot().is_empty(),
            "V4 next-hop on a V6 change must be silently skipped"
        );
    }

    #[test]
    fn test_apply_v6_no_next_hop_skipped() {
        let fm = make_fm();
        let route = RouteBuilder::new(nlri6("2001:db8::/32"), Origin::Igp, AsPath::new()).build();
        fm.apply_v6(BestPathChange::Announced(nlri6("2001:db8::/32"), route));
        assert!(fm.pending_v6_snapshot().is_empty());
    }

    // ── DaemonOracle ─────────────────────────────────────────────────────────

    #[test]
    fn test_daemon_oracle_empty_snapshot_not_reachable() {
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        assert!(!oracle.is_reachable(&NextHop::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(
            oracle
                .igp_metric(&NextHop::V4(Ipv4Addr::new(10, 0, 0, 1)))
                .is_none()
        );
    }

    #[test]
    fn test_daemon_oracle_v6_next_hop_not_reachable() {
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!oracle.is_reachable(&NextHop::V6(gw)));
        assert!(oracle.igp_metric(&NextHop::V6(gw)).is_none());
    }

    #[test]
    fn test_daemon_oracle_v6_with_link_local_falls_back_to_link_local() {
        // global=2001:db8::1 is not in the FIB, so we fall back to the
        // link-local. fe80::1 is always on-link → reachable.
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        let nh = NextHop::V6WithLinkLocal {
            global: "2001:db8::1".parse().unwrap(),
            link_local: "fe80::1".parse().unwrap(),
        };
        assert!(oracle.is_reachable(&nh));
    }

    #[test]
    fn test_daemon_oracle_igp_metric_v6_with_link_local_no_metric_when_both_miss() {
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        let nh = NextHop::V6WithLinkLocal {
            global: "2001:db8::1".parse().unwrap(),
            link_local: "2001:db8::2".parse().unwrap(),
        };
        assert!(
            oracle.igp_metric(&nh).is_none(),
            "no route in FIB means no IGP metric for V6WithLinkLocal"
        );
    }

    #[test]
    fn test_daemon_oracle_igp_metric_v6_with_link_local_unspecified_global_checks_link_local() {
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        // global=:: (unspecified) forces the code to skip the global branch
        // and look up the link-local. Neither is in the empty FIB, so None.
        let nh = NextHop::V6WithLinkLocal {
            global: Ipv6Addr::UNSPECIFIED,
            link_local: "fe80::1".parse().unwrap(),
        };
        assert!(oracle.igp_metric(&nh).is_none());
    }

    #[test]
    fn test_daemon_oracle_v6_with_link_local_unreachable_when_both_miss() {
        // When neither global nor link-local is reachable, the route is rejected.
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        // link_local here is not actually in fe80::/10, so is_link_local_v6 → false.
        let nh = NextHop::V6WithLinkLocal {
            global: "2001:db8::1".parse().unwrap(),
            link_local: "2001:db8::2".parse().unwrap(),
        };
        assert!(!oracle.is_reachable(&nh));
    }

    #[test]
    fn test_daemon_oracle_v6_with_link_local_global_reachable_returns_true() {
        // global = fe80::1 is link-local → is_v6_reachable returns true immediately,
        // so the "prefer global" branch (line 59) is taken and true is returned
        // without consulting the link-local.
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        let nh = NextHop::V6WithLinkLocal {
            global: "fe80::1".parse().unwrap(),
            link_local: "fe80::2".parse().unwrap(),
        };
        assert!(oracle.is_reachable(&nh));
    }

    #[tokio::test]
    async fn test_fib_manager_new_spawns_writer_and_processes_batch() {
        // FibManager::new() is never called in the other tests (they use make_fm()
        // to bypass the tokio::spawn). This test exercises the real constructor and
        // the spawned writer loop by applying a change and waiting for it to drain.
        let (mock, calls) = MockFibWriter::new();
        let fm = FibManager::new(mock);
        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        fm.apply_v4(BestPathChange::Withdrawn(nlri));
        // Give the spawned writer task one scheduler tick to wake and drain.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            calls.lock().unwrap().withdrawn_v4,
            vec![(Ipv4Addr::new(10, 0, 0, 0), 8)]
        );
    }

    #[tokio::test]
    async fn test_process_batch_v6_install_failure_logs_and_continues() {
        // The v6 install/withdraw error arms (tracing::warn inside process_batch)
        // are reached when the writer returns Err for install_v6/withdraw_v6.
        let (mock, calls) = MockFibWriter::failing_v6();
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let nlri6: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let nlri6b: Nlri<Ipv6Addr> = "2001:db8:1::/48".parse().unwrap();
        let mut v6 = HashMap::new();
        v6.insert(nlri6, PendingV6::Install { gateway: gw });
        v6.insert(nlri6b, PendingV6::Withdraw);
        super::process_batch(&mock, HashMap::new(), v6).await;
        let c = calls.lock().unwrap();
        assert!(
            c.installed_v6.is_empty(),
            "failed install_v6 must not be recorded"
        );
        assert!(
            c.withdrawn_v6.is_empty(),
            "failed withdraw_v6 must not be recorded"
        );
    }
}
