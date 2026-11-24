//! The publication boundary between the RTR session (which *learns* VRPs) and
//! everything that *reads* them (validation, `status()`, `subscribe()`).
//!
//! # Consistency model
//!
//! Learning is separated from publishing:
//!
//! * While a transfer is in flight its records accumulate in a [`Staged`]
//!   value that nothing else can see: a [`Snapshot`] for a full (Reset Query)
//!   load, a delta list for an incremental (Serial Query) one.
//! * At a validated End of Data [`Shared::commit`] publishes **data, resume
//!   state (serial), status and the subscriber notification together**. A
//!   transfer that fails for any reason — EOF, malformed PDU, protocol
//!   violation, cancellation — is simply dropped, so the installed VRPs, the
//!   remembered serial, `status()` and subscribers all still describe the
//!   previous completed generation, and the next query resumes from exactly
//!   that generation.
//! * Invalidation that the protocol *requires* (RFC 8210 §5.1 flush) goes
//!   through [`Shared::flush`], which clears data and resume state together
//!   and notifies subscribers, because validation results changed.
//!
//! RFC 8210 §4 ties the current serial to a *completed* response; the public
//! `subscribe()` contract promises completed-sync notifications. Neither
//! says the data must be applied transactionally, so this is a design choice
//! made for the sake of those two contracts: validation never observes a
//! half-applied generation, and a router's decisions (derived from
//! generation N) are never mixed with generation N+1's records until the
//! daemon has been told N+1 exists.
//!
//! # Cost
//!
//! * Full load: records are inserted into a private [`Snapshot`] (same
//!   per-record cost as before) and installed with an O(1) pointer swap under
//!   both family locks. Peak memory is old + new table for the duration of
//!   the load — the price of keeping the old generation valid meanwhile.
//! * Incremental: one `VrpOp` (≈ 32 bytes) per Prefix PDU is staged, then
//!   applied in order under both family locks. Validation is blocked for
//!   O(delta) at commit instead of being interleaved with the network read.

use std::{
    sync::RwLock,
    time::{Duration, Instant, SystemTime},
};

use tokio::sync::watch;

use crate::{
    pdu::{Pdu, RtrVersion},
    protocol::{Query, Resume},
    table::{RoaTable, Snapshot, VrpOp},
};

/// A point-in-time snapshot of RTR session health, for operator visibility
/// (gRPC/CLI in Phase 1).
///
/// `serial`, `version`, `roa_count`, `last_update` and `wall_clock_update` always
/// describe the *installed* generation — they change together, at a completed
/// sync or an invalidation, never mid-transfer.
#[derive(Debug, Clone)]
pub struct RtrStatus {
    pub connected: bool,
    pub version: Option<RtrVersion>,
    /// Serial of the installed generation that a Serial Query would resume
    /// from, or `None` when there is nothing to resume from (never synced,
    /// invalidated, or the cache said the serial is unusable).
    pub serial: Option<u32>,
    pub roa_count: usize,
    pub last_update: Option<Instant>,
    /// Same instant as `last_update`, in wall-clock form — `Instant` is
    /// monotonic and can't be converted to a Unix timestamp for operator-
    /// facing display (e.g. correlating with validator logs).
    pub wall_clock_update: Option<SystemTime>,
    pub last_error: Option<String>,
}

impl RtrStatus {
    pub(crate) fn disconnected() -> Self {
        Self {
            connected: false,
            version: None,
            serial: None,
            roa_count: 0,
            last_update: None,
            wall_clock_update: None,
            last_error: None,
        }
    }

    /// `true` if the cache has never synced, or hasn't synced within
    /// `expire`. Informational only in this phase — nothing clears the cache
    /// automatically on staleness (see crate-level docs: stale-but-recent ROA
    /// data is preferable to no data for a blackhole operator's ROV decisions).
    #[must_use]
    pub fn is_stale(&self, expire: Duration) -> bool {
        self.last_update.is_none_or(|t| t.elapsed() > expire)
    }
}

/// Records of a transfer in flight, invisible until [`Shared::commit`].
pub(crate) enum Staged {
    /// Reset Query: the complete new set, replacing everything on commit.
    Full(Snapshot),
    /// Serial Query: changes to apply, in order, to the installed set.
    Delta(Vec<VrpOp>),
}

impl Staged {
    /// The staging area appropriate for the answer to `query`.
    pub(crate) fn for_query(query: Query) -> Self {
        match query {
            Query::Reset => Self::Full(Snapshot::new()),
            Query::Serial(_) => Self::Delta(Vec::new()),
        }
    }

    /// Stages the change a Prefix PDU describes (other PDUs are ignored).
    pub(crate) fn push(&mut self, pdu: &Pdu) {
        if let Some(op) = VrpOp::from_pdu(pdu) {
            match self {
                Self::Full(snapshot) => snapshot.apply(op),
                Self::Delta(ops) => ops.push(op),
            }
        }
    }
}

struct Core {
    status: RtrStatus,
    /// What the client remembers about the cache for an incremental
    /// (Serial Query) resume. `None` means the next query must be a Reset
    /// Query. Always consistent with `status.serial`.
    resume: Option<Resume>,
}

/// State shared between the session task and every [`crate::RtrHandle`].
pub(crate) struct Shared {
    table: RoaTable,
    /// Status and resume state, always changed together — and, at a commit,
    /// together with the table.
    core: RwLock<Core>,
    /// Fires whenever validation results may have changed (a completed sync,
    /// full or incremental, or an invalidation). The value itself is an
    /// unused generation counter — only the change notification matters. See
    /// [`crate::RtrHandle::subscribe`].
    changed: watch::Sender<u64>,
}

impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            table: RoaTable::new(),
            core: RwLock::new(Core {
                status: RtrStatus::disconnected(),
                resume: None,
            }),
            changed: watch::channel(0).0,
        }
    }

    /// A cache already holding `table`, reporting `connected` — for tests.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn with_table(table: RoaTable) -> Self {
        let mut status = RtrStatus::disconnected();
        status.connected = true;
        status.roa_count = table.len();
        Self {
            table,
            core: RwLock::new(Core {
                status,
                resume: None,
            }),
            changed: watch::channel(0).0,
        }
    }

    pub(crate) fn table(&self) -> &RoaTable {
        &self.table
    }

    pub(crate) fn status(&self) -> RtrStatus {
        self.core.read().unwrap().status.clone()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub(crate) fn resume(&self) -> Option<Resume> {
        self.core.read().unwrap().resume
    }

    fn notify(&self) {
        self.changed.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Publishes a completed transfer: VRPs, resume state and status change
    /// together under one lock, and subscribers are notified afterwards —
    /// every completed sync, even one that changed nothing, because
    /// `subscribe()` promises completed-sync notifications.
    pub(crate) fn commit(&self, staged: Staged, resume: Resume) {
        {
            let mut core = self.core.write().unwrap();
            match staged {
                Staged::Full(snapshot) => self.table.install(snapshot),
                Staged::Delta(ops) => self.table.apply_delta(&ops),
            }
            core.resume = Some(resume);
            let now = SystemTime::now();
            core.status = RtrStatus {
                connected: true,
                version: Some(resume.version),
                serial: Some(resume.serial.get()),
                roa_count: self.table.len(),
                last_update: Some(Instant::now()),
                wall_clock_update: Some(now),
                last_error: None,
            };
        }
        self.notify();
    }

    /// RFC 8210 §5.1: "the router MUST flush all data learned from that
    /// cache." Clears every VRP and the resume state, and — because
    /// validation results just changed — notifies subscribers so policy is
    /// re-evaluated against the (now empty) cache.
    pub(crate) fn flush(&self) {
        let had_data = {
            let mut core = self.core.write().unwrap();
            let had_data = !self.table.is_empty();
            self.table.clear();
            core.resume = None;
            core.status.serial = None;
            core.status.roa_count = 0;
            core.status.version = None;
            had_data
        };
        if had_data {
            self.notify();
        }
    }

    /// Drops the incremental resume state — the cache said (Cache Reset,
    /// version change) that the remembered serial cannot be used. The
    /// installed VRPs are *not* touched: they stay valid until the
    /// replacement load commits or the cache's data expires, so nothing
    /// observable changes and nobody is notified.
    pub(crate) fn forget_resume(&self) {
        let mut core = self.core.write().unwrap();
        core.resume = None;
        core.status.serial = None;
    }

    pub(crate) fn set_disconnected(&self, error: String) {
        let mut core = self.core.write().unwrap();
        core.status.connected = false;
        core.status.last_error = Some(error);
    }

    /// Records a non-fatal failure of the latest sync attempt. The transport
    /// is still live, so `connected` is deliberately left as-is.
    pub(crate) fn set_last_error(&self, text: String) {
        self.core.write().unwrap().status.last_error = Some(text);
    }

    /// Applies one Prefix PDU straight to the installed table and notifies —
    /// the test-util shortcut for "a ROA was published".
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn insert_for_testing(&self, pdu: &Pdu) {
        self.table.apply_prefix_pdu(pdu);
        self.core.write().unwrap().status.roa_count = self.table.len();
        self.notify();
    }
}

/// Convenience for tests building a table from tuples.
#[cfg(any(test, feature = "test-util"))]
pub(crate) fn table_from(
    v4: impl IntoIterator<Item = (std::net::Ipv4Addr, u8, u8, u32)>,
    v6: impl IntoIterator<Item = (std::net::Ipv6Addr, u8, u8, u32)>,
) -> RoaTable {
    use crate::pdu::PrefixFlags;
    let table = RoaTable::new();
    for (prefix, prefix_len, max_len, asn) in v4 {
        table.apply_prefix_pdu(&Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len,
            max_len,
            prefix,
            asn,
        });
    }
    for (prefix, prefix_len, max_len, asn) in v6 {
        table.apply_prefix_pdu(&Pdu::Ipv6Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len,
            max_len,
            prefix,
            asn,
        });
    }
    table
}
