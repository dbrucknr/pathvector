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

use std::net::Ipv4Addr;

use pathvector_rib::{BestPathChange, oracle::NextHopOracle};
use pathvector_sys::{FibWriter, KernelOracle as SysOracle};
use pathvector_types::{NextHop, Nlri};
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
        let (tx, mut rx) = mpsc::channel::<FibChange>(4096);
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
                }
            }
        });
        Self { tx }
    }

    /// Enqueue a FIB update derived from a `BestPathChange<Ipv4Addr>`.
    ///
    /// No-op for `BestPathChange::Unchanged` and for `Announced` routes that
    /// carry no IPv4 next-hop (e.g. routes with only an IPv6 next-hop).
    pub(crate) fn apply_v4(&self, change: BestPathChange<Ipv4Addr>) {
        match change {
            BestPathChange::Announced(nlri, route) => {
                let Some(NextHop::V4(gateway)) = route.next_hop else {
                    return;
                };
                let (dst, prefix_len) = nlri_v4_parts(nlri);
                let _ = self.tx.try_send(FibChange::InstallV4 {
                    dst,
                    prefix_len,
                    gateway,
                });
            }
            BestPathChange::Withdrawn(nlri) => {
                let (dst, prefix_len) = nlri_v4_parts(nlri);
                let _ = self.tx.try_send(FibChange::WithdrawV4 { dst, prefix_len });
            }
            BestPathChange::Unchanged => {}
        }
    }
}

fn nlri_v4_parts(nlri: Nlri<Ipv4Addr>) -> (Ipv4Addr, u8) {
    (nlri.prefix().ip(), nlri.prefix_len())
}
