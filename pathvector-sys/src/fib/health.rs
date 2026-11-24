//! Whether the FIB snapshot still mirrors the kernel, and how fast the
//! supervisor retries when it does not.
//!
//! Netlink cannot guarantee that a listener sees every route change.
//! netlink(7) says so directly:
//!
//! > "Netlink is not a reliable protocol."
//!
//! > "reliable transmissions from kernel to user are impossible in any case.
//! > The kernel can't send a netlink message if the socket buffer is full: the
//! > message will be dropped and the kernel and the user-space process will no
//! > longer have the same view of kernel state. It is up to the application to
//! > detect when this happens (via the `ENOBUFS` error returned by
//! > recvmsg(2)) and resynchronize."
//!
//! [`SnapshotHealth`] is how the snapshot reports that it may have missed
//! changes, and [`FibStatus`] adds counters for monitoring. Both are published
//! by [`KernelFib`](super::KernelFib) on a `watch` channel and can be read
//! from any [`KernelOracle`](super::KernelOracle).

use std::{error::Error, fmt, io, time::Duration, time::Instant};

// ── Health ────────────────────────────────────────────────────────────────────

/// Whether the snapshot mirrors the kernel routing table.
///
/// # Lookups while not ready
///
/// Reachability queries always answer from the current snapshot, whatever its
/// health: **stale but flagged**, never refused. While the snapshot is
/// [`Degraded`](Self::Degraded) it holds the last state the supervisor knew,
/// with every change it did receive applied, and it is replaced in one step
/// when the resynchronizing dump completes. Answering "unreachable" for every
/// next hop instead would make the BGP decision process drop every route at
/// once on a transient socket overrun, which is a far larger error than a few
/// seconds of staleness. Callers that need a stronger guarantee can check
/// [`is_ready`](Self::is_ready) or wait on the status channel.
///
/// While [`Starting`](Self::Starting) the snapshot is empty, so nothing is
/// reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotHealth {
    /// No route dump has completed yet; the snapshot is empty.
    ///
    /// On platforms without netlink the health stays here for good.
    Starting,
    /// The snapshot mirrors the kernel: the last dump completed while the
    /// table was not changing, and every notification since then has been
    /// received and applied.
    Ready {
        /// When the snapshot last became ready.
        since: Instant,
    },
    /// The snapshot may differ from the kernel. Lookups still answer from it
    /// (see the type docs) while the supervisor resynchronizes.
    Degraded {
        /// When the snapshot stopped being trustworthy. Retries do not move it.
        since: Instant,
        /// The most recent reason. Retries can change it, for example from
        /// [`DegradedCause::ConnectionLost`] to
        /// [`DegradedCause::ConnectFailed`].
        cause: DegradedCause,
        /// Resynchronization attempts started since `since`.
        attempts: u32,
    },
}

impl SnapshotHealth {
    /// Returns `true` when the snapshot mirrors the kernel.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// The reason the snapshot may be stale, if it is degraded.
    #[must_use]
    pub fn degraded_cause(&self) -> Option<DegradedCause> {
        match self {
            Self::Degraded { cause, .. } => Some(*cause),
            _ => None,
        }
    }
}

/// Why the snapshot may no longer match the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DegradedCause {
    /// The kernel dropped route notifications because the socket's receive
    /// buffer was full: `recvmsg(2)` failed with `ENOBUFS`.
    NotificationsLost,
    /// The netlink connection ended. The socket failed with an error other
    /// than `ENOBUFS`, or a datagram could not be decoded, and the connection
    /// shut down.
    ConnectionLost,
    /// Opening or subscribing a new netlink socket failed.
    ConnectFailed(IoFailure),
    /// The kernel answered a route dump with an error.
    DumpFailed(IoFailure),
    /// A route dump may have missed routes: the kernel flagged it
    /// `NLM_F_DUMP_INTR`, or the routing table of that family changed while
    /// it was being dumped.
    DumpInconsistent,
    /// A route dump did not finish within its [`DumpTimeout`].
    DumpStalled,
}

impl DegradedCause {
    /// Whether this cause means notifications were lost, as opposed to a
    /// failed attempt to recover from an earlier loss.
    pub(crate) fn is_loss(self) -> bool {
        matches!(self, Self::NotificationsLost | Self::ConnectionLost)
    }
}

impl fmt::Display for DegradedCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotificationsLost => f.write_str("route notifications lost (ENOBUFS)"),
            Self::ConnectionLost => f.write_str("netlink connection lost"),
            Self::ConnectFailed(e) => write!(f, "opening a netlink socket failed: {e}"),
            Self::DumpFailed(e) => write!(f, "route dump failed: {e}"),
            Self::DumpInconsistent => f.write_str("route table changed during the dump"),
            Self::DumpStalled => f.write_str("route dump did not finish in time"),
        }
    }
}

/// The parts of an [`io::Error`] worth keeping in a [`DegradedCause`]:
/// `io::Error` itself is neither `Clone` nor `Eq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoFailure {
    kind: io::ErrorKind,
    errno: Option<i32>,
}

impl IoFailure {
    /// The error's kind.
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        self.kind
    }

    /// The OS error number (positive), if the error came from the OS or from
    /// a netlink error message.
    #[must_use]
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }
}

impl From<&io::Error> for IoFailure {
    fn from(e: &io::Error) -> Self {
        Self {
            kind: e.kind(),
            errno: e.raw_os_error(),
        }
    }
}

impl fmt::Display for IoFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.errno {
            Some(errno) => write!(f, "{} (os error {errno})", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

// ── Status ────────────────────────────────────────────────────────────────────

/// The snapshot's [`SnapshotHealth`] plus counters for monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FibStatus {
    pub(crate) health: SnapshotHealth,
    pub(crate) losses: u64,
    pub(crate) resyncs: u64,
}

impl FibStatus {
    pub(crate) const STARTING: Self = Self {
        health: SnapshotHealth::Starting,
        losses: 0,
        resyncs: 0,
    };

    /// Whether the snapshot mirrors the kernel.
    #[must_use]
    pub fn health(&self) -> SnapshotHealth {
        self.health
    }

    /// How many times notifications were found to be lost: each `ENOBUFS`
    /// overrun and each connection loss counts once.
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.losses
    }

    /// How many complete route dumps have replaced the snapshot, the initial
    /// one included.
    #[must_use]
    pub fn resyncs(&self) -> u64 {
        self.resyncs
    }
}

impl Default for FibStatus {
    fn default() -> Self {
        Self::STARTING
    }
}

// ── Backoff ───────────────────────────────────────────────────────────────────

/// How long the supervisor waits before each resynchronization attempt.
///
/// The `n`-th consecutive attempt waits `initial · 2ⁿ`, capped at `max`. The
/// first wait after a loss also lets a burst of changes settle, so a storm of
/// overruns costs one dump rather than one per overrun; notifications that
/// arrive during a wait are still applied. The sequence restarts from
/// `initial` only after the snapshot has stayed ready for at least `max`, so a
/// socket that overruns again right after every recovery backs off instead of
/// dumping the table in a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResyncBackoff {
    initial: Duration,
    max: Duration,
}

impl ResyncBackoff {
    /// 100 ms initial delay, 10 s cap.
    pub const DEFAULT: Self = Self {
        initial: Duration::from_millis(100),
        max: Duration::from_secs(10),
    };

    /// Creates a backoff policy.
    ///
    /// # Errors
    ///
    /// [`ResyncBackoffError::ZeroInitial`] if `initial` is zero (retries
    /// would spin), [`ResyncBackoffError::InitialExceedsMax`] if `initial`
    /// is greater than `max`.
    pub fn new(initial: Duration, max: Duration) -> Result<Self, ResyncBackoffError> {
        if initial.is_zero() {
            return Err(ResyncBackoffError::ZeroInitial);
        }
        if initial > max {
            return Err(ResyncBackoffError::InitialExceedsMax);
        }
        Ok(Self { initial, max })
    }

    /// The first delay.
    #[must_use]
    pub fn initial(&self) -> Duration {
        self.initial
    }

    /// The longest delay.
    #[must_use]
    pub fn max(&self) -> Duration {
        self.max
    }

    /// The delay before attempt `attempt` (0-based) of a retry sequence.
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }
}

impl Default for ResyncBackoff {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The longest one family's route dump may take before the supervisor gives
/// up on it and replaces the connection.
///
/// A dump can stop without an error reaching the reader: when `netlink_dump`
/// cannot queue its next chunk it leaves the dump running and only retries
/// once another message has been read from the socket. The deadline bounds
/// that case and any other stall. It covers the whole dump of one family,
/// BGP-installed routes included, so set it well above what a dump of the
/// largest expected kernel table takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpTimeout(Duration);

impl DumpTimeout {
    /// 60 s.
    pub const DEFAULT: Self = Self(Duration::from_secs(60));

    /// A deadline of `limit`, or `None` if it is zero.
    #[must_use]
    pub fn new(limit: Duration) -> Option<Self> {
        (!limit.is_zero()).then_some(Self(limit))
    }

    /// The deadline.
    #[must_use]
    pub fn get(&self) -> Duration {
        self.0
    }
}

impl Default for DumpTimeout {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why [`ResyncBackoff::new`] rejected its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncBackoffError {
    /// The initial delay was zero.
    ZeroInitial,
    /// The initial delay was greater than the cap.
    InitialExceedsMax,
}

impl fmt::Display for ResyncBackoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroInitial => f.write_str("the initial resync delay must not be zero"),
            Self::InitialExceedsMax => {
                f.write_str("the initial resync delay must not exceed the maximum")
            }
        }
    }
}

impl Error for ResyncBackoffError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_rejects_zero_and_inverted_bounds() {
        let ms = Duration::from_millis;
        assert_eq!(
            ResyncBackoff::new(Duration::ZERO, ms(10)),
            Err(ResyncBackoffError::ZeroInitial)
        );
        assert_eq!(
            ResyncBackoff::new(ms(20), ms(10)),
            Err(ResyncBackoffError::InitialExceedsMax)
        );
        assert!(ResyncBackoff::new(ms(10), ms(10)).is_ok());
    }

    #[test]
    fn backoff_doubles_and_saturates_at_max() {
        let b = ResyncBackoff::new(Duration::from_millis(100), Duration::from_secs(1)).unwrap();
        let delays: Vec<_> = (0..6).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(delays, [100, 200, 400, 800, 1000, 1000]);
        // Shifts past the width of u32 must not panic or wrap.
        assert_eq!(b.delay(40), Duration::from_secs(1));
        assert_eq!(b.delay(u32::MAX), Duration::from_secs(1));
    }

    #[test]
    fn default_backoff_is_valid() {
        let d = ResyncBackoff::default();
        assert_eq!(ResyncBackoff::new(d.initial(), d.max()), Ok(d));
    }

    #[test]
    fn io_failure_keeps_kind_and_errno() {
        let e = io::Error::from_raw_os_error(105);
        let f = IoFailure::from(&e);
        assert_eq!(f.errno(), Some(105));
        assert_eq!(f.kind(), e.kind());
        let e = io::Error::other("no errno");
        assert_eq!(IoFailure::from(&e).errno(), None);
    }

    #[test]
    fn only_overruns_and_connection_losses_count_as_losses() {
        let failure = IoFailure::from(&io::Error::other("x"));
        assert!(DegradedCause::NotificationsLost.is_loss());
        assert!(DegradedCause::ConnectionLost.is_loss());
        assert!(!DegradedCause::ConnectFailed(failure).is_loss());
        assert!(!DegradedCause::DumpFailed(failure).is_loss());
        assert!(!DegradedCause::DumpInconsistent.is_loss());
        assert!(!DegradedCause::DumpStalled.is_loss());
    }

    #[test]
    fn dump_timeout_rejects_zero() {
        assert_eq!(DumpTimeout::new(Duration::ZERO), None);
        assert_eq!(
            DumpTimeout::new(Duration::from_secs(1)).map(|t| t.get()),
            Some(Duration::from_secs(1))
        );
        assert_eq!(DumpTimeout::default().get(), Duration::from_secs(60));
    }
}
