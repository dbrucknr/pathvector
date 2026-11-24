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
//!   both family locks; the replaced trees are freed afterwards, outside every
//!   lock (freeing 500 000 VRPs takes ≈ 20 ms). Peak memory is old + new table for the duration of
//!   the load — the price of keeping the old generation valid meanwhile.
//! * Incremental: one `VrpOp` (≈ 32 bytes) per Prefix PDU is staged, then
//!   applied in order under both family locks. Validation is blocked for
//!   O(delta) at commit instead of being interleaved with the network read.

use std::{
    sync::RwLock,
    time::{Duration, Instant, SystemTime},
};

use tokio::{sync::watch, time::Instant as MonotonicInstant};

use crate::{
    pdu::{Pdu, RtrVersion},
    protocol::{Query, Resume},
    table::{Retired, RoaTable, Snapshot, VrpOp},
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
    /// When the installed generation must be discarded if no further sync
    /// completes: the last End of Data's receipt time plus the effective
    /// Expire Interval (RFC 8210 §6). `None` when there is no installed
    /// generation. Only a *completed* sync moves this; connecting, bytes and
    /// notifications do not.
    pub expires_at: Option<Instant>,
    /// `true` from the moment the installed generation expired (and was
    /// flushed) until the next completed sync.
    pub expired: bool,
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
            expires_at: None,
            expired: false,
        }
    }

    /// `true` if the cache has never synced, or hasn't synced within
    /// `expire`.
    ///
    /// This is a caller-chosen *freshness check*, not the protocol's expiry:
    /// the client enforces RFC 8210 §6 itself, using the Expire Interval the
    /// cache advertised (or the configured one for v0), and discards the data
    /// when it elapses (see [`RtrStatus::expires_at`] / [`RtrStatus::expired`]).
    /// Use `is_stale` for a softer, earlier warning threshold.
    #[must_use]
    pub fn is_stale(&self, expire: Duration) -> bool {
        self.last_update.is_none_or(|t| t.elapsed() > expire)
    }
}

/// Records of a transfer in flight, invisible until [`Shared::commit`].
pub(crate) enum Staged {
    /// Reset Query: the complete new set, replacing everything on commit.
    Full(Snapshot),
    /// Serial Query: changes to apply, in order, to the installed set —
    /// valid only against the generation identified by `base`.
    Delta { base: Epoch, ops: Vec<VrpOp> },
}

/// Identifies the installed generation a delta is relative to. It advances
/// whenever the installed data is invalidated (flush, expiry, resume state
/// dropped), so a delta staged before such an event can be recognised as
/// stale at commit instead of being applied to a different table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Epoch(u64);

/// A delta was staged against a generation that has since been invalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stale;

impl Staged {
    /// The staging area appropriate for the answer to `query`.
    pub(crate) fn for_query(query: Query, base: Epoch) -> Self {
        match query {
            Query::Reset => Self::Full(Snapshot::new()),
            Query::Serial(_) => Self::Delta {
                base,
                ops: Vec::new(),
            },
        }
    }

    /// Stages the change a Prefix PDU describes (other PDUs are ignored).
    pub(crate) fn push(&mut self, pdu: &Pdu) {
        if let Some(op) = VrpOp::from_pdu(pdu) {
            match self {
                Self::Full(snapshot) => snapshot.apply(op),
                Self::Delta { ops, .. } => ops.push(op),
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
    /// See [`Epoch`].
    epoch: Epoch,
    /// Monotonic instant at which the installed generation must be
    /// discarded unless another sync completes first. `None` iff there is no
    /// installed generation to expire. Mirrors `status.expires_at`.
    expiry: Option<MonotonicInstant>,
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
    /// Mirrors `Core::expiry` (always updated under the `core` write lock) so
    /// the expiry watcher can sleep until the current deadline and be woken
    /// the moment it moves.
    deadline: watch::Sender<Option<MonotonicInstant>>,
}

impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            table: RoaTable::new(),
            core: RwLock::new(Core {
                status: RtrStatus::disconnected(),
                resume: None,
                epoch: Epoch(0),
                expiry: None,
            }),
            changed: watch::channel(0).0,
            deadline: watch::channel(None).0,
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
                epoch: Epoch(0),
                expiry: None,
            }),
            changed: watch::channel(0).0,
            deadline: watch::channel(None).0,
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

    /// What the next query is based on: the resume state and the epoch of the
    /// generation it describes, read together so they cannot disagree.
    pub(crate) fn basis(&self) -> (Option<Resume>, Epoch) {
        let core = self.core.read().unwrap();
        (core.resume, core.epoch)
    }

    fn notify(&self) {
        self.changed.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Publishes a completed transfer: VRPs, resume state, status and expiry
    /// deadline change together under one lock, and subscribers are notified
    /// afterwards — every completed sync, even one that changed nothing,
    /// because `subscribe()` promises completed-sync notifications.
    ///
    /// `expire` is the effective Expire Interval; the new deadline is `now +
    /// expire` (RFC 8210 §6: "Countdown for this timer starts upon receipt
    /// of the containing End Of Data PDU"). This is the *only* way the
    /// deadline moves forward.
    ///
    /// # Errors
    ///
    /// [`Stale`] if `staged` is a delta against a generation that was
    /// invalidated while the transfer was in flight (e.g. the cache expired);
    /// nothing is applied.
    pub(crate) fn commit(
        &self,
        staged: Staged,
        resume: Resume,
        expire: Duration,
    ) -> Result<(), Stale> {
        let retired;
        {
            let mut core = self.core.write().unwrap();
            retired = match staged {
                Staged::Full(snapshot) => Some(self.table.install(snapshot)),
                Staged::Delta { base, ops } => {
                    if base != core.epoch {
                        return Err(Stale);
                    }
                    self.table.apply_delta(&ops);
                    None
                }
            };
            core.resume = Some(resume);
            let now = MonotonicInstant::now();
            let deadline = now + expire;
            core.expiry = Some(deadline);
            self.deadline.send_replace(Some(deadline));
            core.status = RtrStatus {
                connected: true,
                version: Some(resume.version),
                serial: Some(resume.serial.get()),
                roa_count: self.table.len(),
                last_update: Some(now.into_std()),
                wall_clock_update: Some(SystemTime::now()),
                last_error: None,
                expires_at: Some(deadline.into_std()),
                expired: false,
            };
        }
        // Free the replaced generation only now: no lock is held and
        // subscribers already know the new one is live.
        self.notify();
        drop(retired);
        Ok(())
    }

    /// RFC 8210 §5.1: "the router MUST flush all data learned from that
    /// cache." Clears every VRP and the resume state, and — because
    /// validation results just changed — notifies subscribers so policy is
    /// re-evaluated against the (now empty) cache.
    pub(crate) fn flush(&self) {
        let (had_data, retired) = {
            let mut core = self.core.write().unwrap();
            self.invalidate(&mut core)
        };
        if had_data {
            self.notify();
        }
        drop(retired);
    }

    /// Discards every VRP and all resume state, under the caller's `core`
    /// lock. Returns whether there was any data (i.e. whether validation
    /// results changed) and the discarded trees, which the caller must drop
    /// only after releasing the lock (freeing them is O(size)).
    fn invalidate(&self, core: &mut Core) -> (bool, Retired) {
        let had_data = core.status.roa_count != 0;
        let retired = self.table.take_all();
        core.resume = None;
        core.epoch = Epoch(core.epoch.0.wrapping_add(1));
        core.expiry = None;
        self.deadline.send_replace(None);
        core.status.serial = None;
        core.status.roa_count = 0;
        core.status.version = None;
        core.status.expires_at = None;
        (had_data, retired)
    }

    /// RFC 8210 §6: "The router MUST NOT retain the data past the time
    /// indicated by [the Expire Interval]." Called by the expiry watcher when
    /// `deadline` passes. Discards every VRP and all resume state (so the
    /// next query is a Reset Query), marks the status expired and — because
    /// every validation result just became `NotFound` — notifies subscribers.
    ///
    /// Returns `false` without effect if `deadline` is no longer the current
    /// one (a sync completed, or the data was flushed, in the meantime).
    pub(crate) fn expire(&self, deadline: MonotonicInstant) -> bool {
        let (had_data, retired) = {
            let mut core = self.core.write().unwrap();
            if core.expiry != Some(deadline) {
                return false;
            }
            let (had_data, retired) = self.invalidate(&mut core);
            core.status.expired = true;
            core.status.last_error = Some(
                "cache data expired: no sync completed within the cache's Expire Interval \
                 (RFC 8210 §6); all VRPs discarded"
                    .to_string(),
            );
            (had_data, retired)
        };
        if had_data {
            self.notify();
        }
        drop(retired);
        true
    }

    /// Sleeps until the current deadline, expires the cache when it passes,
    /// and follows the deadline as completed syncs move it. Runs for the life
    /// of the client, *independently* of the session loop: it is not
    /// interrupted by, and does not wait for, connects, back-off sleeps,
    /// pending queries or partial reads. Never returns.
    pub(crate) async fn watch_expiry(&self) {
        let mut rx = self.deadline.subscribe();
        loop {
            let current = *rx.borrow_and_update();
            match current {
                None => {
                    if rx.changed().await.is_err() {
                        return;
                    }
                }
                Some(at) => {
                    tokio::select! {
                        () = tokio::time::sleep_until(at) => {
                            // If a sync renewed the deadline at the last
                            // moment this is a no-op and `rx` already holds
                            // the new value.
                            self.expire(at);
                        }
                        changed = rx.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
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
        core.epoch = Epoch(core.epoch.0.wrapping_add(1));
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
