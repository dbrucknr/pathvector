//! FIB integration for pathvectord.
//!
//! Two components:
//!
//! - [`DaemonOracle`] — wraps [`pathvector_sys::KernelOracle`] and implements
//!   [`NextHopOracle`] so the BGP decision process (RFC 4271 §9.1 steps 1 & 8)
//!   can consult the live kernel FIB for next-hop reachability and IGP metrics.
//!
//! - [`FibManager`] — consumes [`BestPathChange`] values from the event loop
//!   and serialises the corresponding `RTM_NEWROUTE` / `RTM_DELROUTE` calls
//!   to a background task, keeping route installation off the BGP event-loop
//!   hot path.

use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_rib::{BestPathChange, oracle::NextHopOracle};
use pathvector_sys::{FibWriter, KernelOracle as SysOracle};
use pathvector_types::NextHop;
use tokio::sync::mpsc;

// ── DaemonOracle ─────────────────────────────────────────────────────────────

/// Implements [`NextHopOracle`] by querying the in-process [`FibSnapshot`].
///
/// [`FibSnapshot`]: pathvector_sys::FibSnapshot
pub(crate) struct DaemonOracle(pub(crate) SysOracle);

impl NextHopOracle for DaemonOracle {
    fn is_reachable(&self, next_hop: &NextHop) -> bool {
        match next_hop {
            NextHop::V4(addr) => self.0.is_v4_reachable(*addr),
            NextHop::V6(addr) | NextHop::V6WithLinkLocal { global: addr, .. } => {
                self.0.is_v6_reachable(*addr)
            }
        }
    }

    fn igp_metric(&self, next_hop: &NextHop) -> Option<u32> {
        match next_hop {
            NextHop::V4(addr) => self.0.igp_metric_v4(*addr),
            NextHop::V6(addr) | NextHop::V6WithLinkLocal { global: addr, .. } => {
                self.0.igp_metric_v6(*addr)
            }
        }
    }
}

// ── FibManager ───────────────────────────────────────────────────────────────

enum FibChange {
    InstallV4 {
        dst: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    },
    WithdrawV4 {
        dst: Ipv4Addr,
        prefix_len: u8,
    },
    InstallV6 {
        dst: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
    },
    WithdrawV6 {
        dst: Ipv6Addr,
        prefix_len: u8,
    },
}

fn spawn_writer(writer: FibWriter, mut rx: mpsc::Receiver<FibChange>) {
    tokio::spawn(async move {
        while let Some(change) = rx.recv().await {
            match change {
                FibChange::InstallV4 {
                    dst,
                    prefix_len,
                    gateway,
                } => {
                    if let Err(e) = writer.install_v4(dst, prefix_len, gateway).await {
                        tracing::warn!(
                            prefix = %format!("{dst}/{prefix_len}"),
                            gateway = %gateway,
                            "FIB install failed: {e}"
                        );
                    }
                }
                FibChange::WithdrawV4 { dst, prefix_len } => {
                    if let Err(e) = writer.withdraw_v4(dst, prefix_len).await {
                        tracing::warn!(
                            prefix = %format!("{dst}/{prefix_len}"),
                            "FIB withdraw failed: {e}"
                        );
                    }
                }
                FibChange::InstallV6 {
                    dst,
                    prefix_len,
                    gateway,
                } => {
                    if let Err(e) = writer.install_v6(dst, prefix_len, gateway).await {
                        tracing::warn!(
                            prefix = %format!("{dst}/{prefix_len}"),
                            gateway = %gateway,
                            "FIB install (v6) failed: {e}"
                        );
                    }
                }
                FibChange::WithdrawV6 { dst, prefix_len } => {
                    if let Err(e) = writer.withdraw_v6(dst, prefix_len).await {
                        tracing::warn!(
                            prefix = %format!("{dst}/{prefix_len}"),
                            "FIB withdraw (v6) failed: {e}"
                        );
                    }
                }
            }
        }
    });
}

/// Serialises FIB mutations from the BGP event loop to a background task.
///
/// `apply_v4` is intentionally synchronous: it puts a `FibChange` onto a
/// bounded channel and returns immediately so the event loop is never blocked
/// on kernel I/O. The background task drains the channel and issues the
/// actual netlink calls via [`FibWriter`].
pub(crate) struct FibManager {
    tx: mpsc::Sender<FibChange>,
}

impl FibManager {
    /// Spawns the background writer task and returns a `FibManager`.
    pub(crate) fn new(writer: FibWriter) -> Self {
        let (tx, rx) = mpsc::channel::<FibChange>(4096);
        spawn_writer(writer, rx);
        Self { tx }
    }

    /// Test constructor — returns the manager together with the channel receiver
    /// so tests can inspect queued changes without running the background task.
    #[cfg(test)]
    fn new_for_test() -> (Self, mpsc::Receiver<FibChange>) {
        let (tx, rx) = mpsc::channel::<FibChange>(4096);
        (Self { tx }, rx)
    }

    /// Enqueue a FIB update derived from a `BestPathChange<Ipv4Addr>`.
    ///
    /// No-op for `BestPathChange::Unchanged` and for `Announced` routes that
    /// carry no IPv4 next-hop.
    pub(crate) fn apply_v4(&self, change: BestPathChange<Ipv4Addr>) {
        match change {
            BestPathChange::Announced(nlri, route) => {
                let Some(NextHop::V4(gateway)) = route.next_hop else {
                    return;
                };
                let (dst, prefix_len) = (nlri.prefix().ip(), nlri.prefix_len());
                let _ = self.tx.try_send(FibChange::InstallV4 {
                    dst,
                    prefix_len,
                    gateway,
                });
            }
            BestPathChange::Withdrawn(nlri) => {
                let (dst, prefix_len) = (nlri.prefix().ip(), nlri.prefix_len());
                let _ = self.tx.try_send(FibChange::WithdrawV4 { dst, prefix_len });
            }
            BestPathChange::Unchanged => {}
        }
    }

    /// Enqueue a FIB update derived from a `BestPathChange<Ipv6Addr>`.
    ///
    /// No-op for `BestPathChange::Unchanged` and for `Announced` routes whose
    /// next-hop is not an IPv6 global address (e.g. the next-hop was not set).
    pub(crate) fn apply_v6(&self, change: BestPathChange<Ipv6Addr>) {
        match change {
            BestPathChange::Announced(nlri, route) => {
                let gateway = match route.next_hop {
                    Some(NextHop::V6(gw)) => gw,
                    Some(NextHop::V6WithLinkLocal { global, .. }) => global,
                    _ => return,
                };
                let (dst, prefix_len) = (nlri.prefix().ip(), nlri.prefix_len());
                let _ = self.tx.try_send(FibChange::InstallV6 {
                    dst,
                    prefix_len,
                    gateway,
                });
            }
            BestPathChange::Withdrawn(nlri) => {
                let (dst, prefix_len) = (nlri.prefix().ip(), nlri.prefix_len());
                let _ = self.tx.try_send(FibChange::WithdrawV6 { dst, prefix_len });
            }
            BestPathChange::Unchanged => {}
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pathvector_rib::{BestPathChange, RouteBuilder};
    use pathvector_types::{AsPath, NextHop, Nlri, Origin};

    use tokio::sync::mpsc;

    use super::{FibChange, FibManager};

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

    /// Drain all pending `FibChange` entries from the test receiver.
    fn drain(rx: &mut mpsc::Receiver<FibChange>) -> Vec<FibChange> {
        let mut out = Vec::new();
        while let Ok(c) = rx.try_recv() {
            out.push(c);
        }
        out
    }

    // ── apply_v4 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_apply_v4_announced_enqueues_install() {
        let (fm, mut rx) = FibManager::new_for_test();
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4("10.0.0.0/8", "192.0.2.1"),
        ));
        let changes = drain(&mut rx);
        assert_eq!(changes.len(), 1);
        let FibChange::InstallV4 { dst, prefix_len, gateway } = &changes[0] else {
            panic!("expected InstallV4");
        };
        assert_eq!(*dst, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(*prefix_len, 8);
        assert_eq!(*gateway, "192.0.2.1".parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn test_apply_v4_withdrawn_enqueues_withdraw() {
        let (fm, mut rx) = FibManager::new_for_test();
        fm.apply_v4(BestPathChange::Withdrawn(nlri4("192.168.0.0/24")));
        let changes = drain(&mut rx);
        assert_eq!(changes.len(), 1);
        let FibChange::WithdrawV4 { dst, prefix_len } = &changes[0] else {
            panic!("expected WithdrawV4");
        };
        assert_eq!(*dst, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(*prefix_len, 24);
    }

    #[tokio::test]
    async fn test_apply_v4_unchanged_enqueues_nothing() {
        let (fm, mut rx) = FibManager::new_for_test();
        fm.apply_v4(BestPathChange::Unchanged);
        assert!(drain(&mut rx).is_empty());
    }

    #[tokio::test]
    async fn test_apply_v4_no_next_hop_skipped() {
        let (fm, mut rx) = FibManager::new_for_test();
        fm.apply_v4(BestPathChange::Announced(
            nlri4("10.0.0.0/8"),
            route4_no_nh("10.0.0.0/8"),
        ));
        assert!(drain(&mut rx).is_empty(), "route without next-hop must not be installed");
    }

    // ── apply_v6 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_apply_v6_announced_enqueues_install() {
        let (fm, mut rx) = FibManager::new_for_test();
        fm.apply_v6(BestPathChange::Announced(
            nlri6("2001:db8::/32"),
            route6("2001:db8::/32", "2001:db8::1"),
        ));
        let changes = drain(&mut rx);
        assert_eq!(changes.len(), 1);
        let FibChange::InstallV6 { dst, prefix_len, gateway } = &changes[0] else {
            panic!("expected InstallV6");
        };
        assert_eq!(*dst, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(*prefix_len, 32);
        assert_eq!(*gateway, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[tokio::test]
    async fn test_apply_v6_withdrawn_enqueues_withdraw() {
        let (fm, mut rx) = FibManager::new_for_test();
        fm.apply_v6(BestPathChange::Withdrawn(nlri6("2001:db8::/32")));
        let changes = drain(&mut rx);
        assert_eq!(changes.len(), 1);
        let FibChange::WithdrawV6 { dst, prefix_len } = &changes[0] else {
            panic!("expected WithdrawV6");
        };
        assert_eq!(*dst, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(*prefix_len, 32);
    }

    #[tokio::test]
    async fn test_apply_v6_unchanged_enqueues_nothing() {
        let (fm, mut rx) = FibManager::new_for_test();
        fm.apply_v6(BestPathChange::<Ipv6Addr>::Unchanged);
        assert!(drain(&mut rx).is_empty());
    }

    // ── DaemonOracle ─────────────────────────────────────────────────────────

    #[test]
    fn test_daemon_oracle_empty_snapshot_not_reachable() {
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        assert!(!oracle.is_reachable(&NextHop::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(oracle.igp_metric(&NextHop::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
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
    fn test_daemon_oracle_v6_with_link_local_uses_global() {
        use pathvector_rib::oracle::NextHopOracle;
        use pathvector_sys::KernelFib;
        let (kfib, _rx) = KernelFib::new(254);
        let oracle = super::DaemonOracle(kfib.oracle());
        let nh = NextHop::V6WithLinkLocal {
            global: "2001:db8::1".parse().unwrap(),
            link_local: "fe80::1".parse().unwrap(),
        };
        assert!(!oracle.is_reachable(&nh));
    }
}
