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
use pathvector_sys::{FibWriter, KernelOracle as SysOracle};
use pathvector_types::{NextHop, Nlri};
use tokio::sync::Notify;

// ── DaemonOracle ─────────────────────────────────────────────────────────────

/// Implements [`NextHopOracle`] by querying the in-process [`FibSnapshot`].
///
/// [`FibSnapshot`]: pathvector_sys::FibSnapshot
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
    Install { gateway: Ipv4Addr },
    Withdraw,
}

/// The desired kernel state for an IPv6 prefix.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PendingV6 {
    Install { gateway: Ipv6Addr },
    Withdraw,
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
    pub(crate) fn new(writer: FibWriter) -> Self {
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

    /// Record the desired FIB state for the prefix in `change`.
    ///
    /// For `Announced`: records `Install { gateway }`. For `Withdrawn`: records
    /// `Withdraw`. For `Unchanged`: no-op. Routes with no usable IPv4 next-hop
    /// are silently skipped.
    ///
    /// If a pending entry already exists for this NLRI, it is overwritten —
    /// only the latest desired state is retained.
    pub(crate) fn apply_v4(&self, change: BestPathChange<Ipv4Addr>) {
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
    pub(crate) fn apply_v6(&self, change: BestPathChange<Ipv6Addr>) {
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
}

fn spawn_writer(
    writer: FibWriter,
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
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pathvector_rib::{BestPathChange, RouteBuilder};
    use pathvector_types::{AsPath, NextHop, Nlri, Origin};

    use super::{FibManager, PendingV4, PendingV6};

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
}
