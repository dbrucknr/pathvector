//! RTR session management: connect, version negotiation (RFC 8210 v1 with
//! RFC 6810 v0 fallback), Serial/Reset Query sync, and automatic reconnect.
//!
//! The client never blocks its caller on network I/O. [`RtrClient::spawn`]
//! returns an [`RtrHandle`] immediately; the actual TCP session runs forever
//! in a background task, retrying on any failure. Callers observe session
//! health via [`RtrHandle::status`] rather than through a `Result` — there is
//! no "did the client start successfully" moment to report on, only
//! "is it currently connected."
//!
//! # Where things live
//!
//! * `protocol.rs` — pure state machine: what a PDU *means* (RFC 8210 §§5, 7, 8)
//!   and how to react (`Violation`). No sockets, no clocks.
//! * `cache.rs` — the publication boundary: staging, atomic commit, flush and
//!   expiry; what `validate_*`, `status()` and `subscribe()` read.
//! * `timers.rs` — RFC 8210 §6 interval ranges and the effective timers.
//! * `frame.rs` — pure incremental decoder: bytes in, PDUs out.
//! * `transport.rs` — the socket adapter around it; cancellation-safe reads.
//! * this module — the I/O loop that connects them: reads PDUs, feeds them to
//!   the state machine, writes queries and Error Reports, sleeps.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use tokio::{net::TcpStream, sync::watch};
use tracing::warn;

#[cfg(any(test, feature = "test-util"))]
use crate::cache::table_from;
use crate::{
    cache::{RtrStatus, Shared, Staged},
    error::{RtrConfigError, RtrError},
    frame::Frame,
    pdu::{self, Pdu, RtrVersion},
    protocol::{self, Consequence, Exchange, Negotiation, Query, Resume, Step, Violation},
    table::RoaValidity,
    timers::Timers,
    transport::{Connection, ReadError},
};

/// Configuration for an RTR session.
///
/// The three intervals are *defaults*: they apply to the first sync, to every
/// RFC 6810 (v0) session (whose End of Data carries no intervals), and until
/// a v1 cache advertises its own in End of Data, which then take precedence
/// (clamped to the RFC 8210 §6 ranges, see below). [`RtrConfig::validate`]
/// checks them against those ranges; `RtrClient::spawn` does not reject a
/// configuration that fails it (it has no error channel), so callers that
/// accept operator input should call it first.
///
/// | Field | RFC 8210 §6 range | Recommended |
/// |---|---|---|
/// | `refresh_interval` | 1 s ..= 86 400 s | 3 600 s |
/// | `retry_interval` | 1 s ..= 7 200 s | 600 s |
/// | `expire_interval` | 600 s ..= 172 800 s | 7 200 s |
#[derive(Debug, Clone)]
pub struct RtrConfig {
    pub host: String,
    pub port: u16,
    /// RFC 8210 §6 Refresh Interval: how long to wait between successful syncs
    /// before polling again. Overridden by the server's `EndOfData` interval
    /// on a v1 session.
    pub refresh_interval: Duration,
    /// How long to wait after a connection failure before reconnecting.
    /// Also reused as the pause before retrying a query on the *same*
    /// connection after an RFC 8210 §12 Error Code 2 ("No Data Available")
    /// response — the one non-fatal error code, where a fresh connection
    /// isn't warranted.
    pub retry_interval: Duration,
    /// RFC 8210 §6 Expire Interval: how long, from receipt of End of Data, the
    /// data may be retained without another *completed* sync. **Enforced**:
    /// when it elapses every VRP and the resume state are discarded, so all
    /// validation results become `NotFound` (ROV fails open), `status()`
    /// reports `expired`, and subscribers are notified. Overridden by the
    /// server's `EndOfData` interval on a v1 session; applies as-is to v0.
    pub expire_interval: Duration,
    /// Protocol version to attempt first. Falls back to `V0` automatically on
    /// an `ErrorReport` indicating unsupported version.
    pub initial_version: RtrVersion,
}

impl RtrConfig {
    /// Checks the timer defaults against the ranges RFC 8210 §6 allows a cache
    /// to advertise, and the requirement that Expire exceed Refresh and Retry.
    ///
    /// # Errors
    ///
    /// The first violated constraint.
    pub fn validate(&self) -> Result<(), RtrConfigError> {
        use crate::timers::{EXPIRE_SECS, REFRESH_SECS, RETRY_SECS};

        fn check(
            field: &'static str,
            value: Duration,
            range: &std::ops::RangeInclusive<u32>,
        ) -> Result<(), RtrConfigError> {
            let (min, max) = (
                Duration::from_secs(u64::from(*range.start())),
                Duration::from_secs(u64::from(*range.end())),
            );
            if (min..=max).contains(&value) {
                Ok(())
            } else {
                Err(RtrConfigError::OutOfRange {
                    field,
                    value,
                    min,
                    max,
                })
            }
        }
        check("refresh_interval", self.refresh_interval, &REFRESH_SECS)?;
        check("retry_interval", self.retry_interval, &RETRY_SECS)?;
        check("expire_interval", self.expire_interval, &EXPIRE_SECS)?;
        if self.expire_interval <= self.refresh_interval.max(self.retry_interval) {
            return Err(RtrConfigError::ExpireNotAfterPollIntervals {
                expire: self.expire_interval,
                refresh: self.refresh_interval,
                retry: self.retry_interval,
            });
        }
        Ok(())
    }
}

impl Default for RtrConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            // Routinator's default `--rtr` listen port. Its HTTP status/
            // metrics API defaults to 8323 — a previous version of this
            // default mixed the two up (caught by a smoke test against a
            // real `nlnetlabs/routinator` container).
            port: 3323,
            refresh_interval: Duration::from_secs(3600),
            retry_interval: Duration::from_secs(600),
            expire_interval: Duration::from_secs(7200),
            initial_version: RtrVersion::V1,
        }
    }
}

/// A cheap-clone (`Arc`-backed) handle to a running RTR client. Safe to hold
/// from any number of callers (gRPC handlers, and in a later phase, policy
/// conditions) — `validate_*`/`status` never block on network I/O.
#[derive(Clone)]
pub struct RtrHandle(Arc<Shared>);

impl RtrHandle {
    #[must_use]
    pub fn validate_v4(&self, prefix: Ipv4Addr, prefix_len: u8, origin_asn: u32) -> RoaValidity {
        self.0.table().validate_v4(prefix, prefix_len, origin_asn)
    }

    #[must_use]
    pub fn validate_v6(&self, prefix: Ipv6Addr, prefix_len: u8, origin_asn: u32) -> RoaValidity {
        self.0.table().validate_v6(prefix, prefix_len, origin_asn)
    }

    /// # Panics
    ///
    /// Panics only if the internal status lock is poisoned (a prior holder
    /// panicked while holding it) — not an expected runtime condition.
    #[must_use]
    pub fn status(&self) -> RtrStatus {
        self.0.status()
    }

    /// Returns a receiver that fires whenever validation results may have
    /// changed: a completed sync (full or incremental, even an empty one), a
    /// flush the protocol requires (RFC 8210 §5.1 session mismatch), or the
    /// cache's data expiring (RFC 8210 §6 — every result becomes `NotFound`).
    /// It never fires for a transfer that did not complete. Callers should
    /// re-evaluate
    /// anything derived from ROA validity (e.g. `pathvectord`'s import
    /// policies) on each change; this is what lets a route accepted before
    /// the first sync (or before a ROA update) get correctly re-judged once
    /// the cache reflects it, without waiting for a session reset.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

/// Namespace for spawning an RTR client; not constructed directly.
pub struct RtrClient;

impl RtrClient {
    /// Spawns the RTR client's background task and returns an immediately
    /// usable handle. The handle works — returning `NotFound`/disconnected
    /// status — even before the first TCP connection succeeds; callers never
    /// block on connection setup.
    #[must_use]
    pub fn spawn(config: RtrConfig) -> (RtrHandle, tokio::task::JoinHandle<()>) {
        let shared = Arc::new(Shared::new());
        let handle = RtrHandle(Arc::clone(&shared));
        let join = tokio::spawn(run(config, shared));
        (handle, join)
    }
}

/// Builds an `RtrHandle` with a fixed set of ROAs already loaded, and
/// `status().connected == true` — for tests that need deterministic ROA data
/// without running a real or mock RTR server. Each tuple is
/// `(prefix, prefix_len, max_len, origin_asn)`.
///
/// # Panics
///
/// If a tuple is one a real cache could not send: either length longer than
/// the address family, or `max_len < prefix_len`.
#[cfg(any(test, feature = "test-util"))]
#[must_use]
pub fn for_testing(
    v4: impl IntoIterator<Item = (Ipv4Addr, u8, u8, u32)>,
    v6: impl IntoIterator<Item = (Ipv6Addr, u8, u8, u32)>,
) -> RtrHandle {
    RtrHandle(Arc::new(Shared::with_table(table_from(v4, v6))))
}

impl RtrHandle {
    /// Inserts one ROA into the cache and fires the same change notification
    /// a real incremental sync would — for tests that need to simulate "a
    /// ROA was published/changed" after the handle was already built (e.g.
    /// via [`for_testing`]), without a real or mock RTR server.
    ///
    /// # Panics
    ///
    /// Panics if the lengths cannot form a VRP (see [`for_testing`]), or if
    /// the internal status lock is poisoned.
    #[cfg(any(test, feature = "test-util"))]
    pub fn insert_roa_v4(&self, prefix: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) {
        self.0
            .insert_for_testing(&Pdu::announce_v4(prefix, prefix_len, max_len, asn));
    }

    /// IPv6 counterpart of [`RtrHandle::insert_roa_v4`].
    ///
    /// # Panics
    ///
    /// As for [`RtrHandle::insert_roa_v4`].
    #[cfg(any(test, feature = "test-util"))]
    pub fn insert_roa_v6(&self, prefix: Ipv6Addr, prefix_len: u8, max_len: u8, asn: u32) {
        self.0
            .insert_for_testing(&Pdu::announce_v6(prefix, prefix_len, max_len, asn));
    }
}

/// The client task: the reconnecting session loop, and — as an independent
/// sibling future in the same task, so both stop together when the task is
/// aborted — the expiry watcher. Neither ever completes.
async fn run(config: RtrConfig, shared: Arc<Shared>) {
    tokio::select! {
        () = run_session_loop(config, Arc::clone(&shared)) => {}
        () = shared.watch_expiry() => {}
    }
}

/// Outer reconnect loop. Never returns except via task cancellation.
async fn run_session_loop(config: RtrConfig, shared: Arc<Shared>) {
    // `negotiated_version` persists across reconnects: once a server is known
    // to speak (or not speak) v1, later reconnect attempts reuse that
    // knowledge rather than re-running the v1-attempt-then-fallback dance
    // every time. This is a deliberate, documented choice: it's a better
    // default than forcing a reset to `initial_version` on every reconnect,
    // since a server's version support doesn't change between one TCP
    // connection and the next. The *incremental resume state* (version,
    // session ID, serial) lives in `Shared`, not here, so every path that
    // invalidates it does so in one place.
    let mut negotiated_version = config.initial_version;

    loop {
        match TcpStream::connect((config.host.as_str(), config.port)).await {
            Ok(stream) => {
                let result = run_one_connection(
                    &mut Connection::new(stream),
                    &config,
                    &shared,
                    &mut negotiated_version,
                )
                .await;
                if let Err(e) = result {
                    warn!(
                        host = %config.host,
                        port = config.port,
                        error = %e,
                        "RTR session error"
                    );
                    shared.set_disconnected(e.to_string());
                    // RFC 8210 §6: "a protocol version mismatch overrides"
                    // the Retry Interval — the cache just told us which
                    // version it speaks, so reconnect at once.
                    if matches!(e, RtrError::VersionChanged { .. }) {
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!(
                    host = %config.host,
                    port = config.port,
                    error = %e,
                    "RTR connect failed"
                );
                shared.set_disconnected(e.to_string());
            }
        }
        tokio::time::sleep(config.retry_interval).await;
    }
}

/// One TCP connection's lifecycle: repeated sync-then-idle cycles until an
/// error occurs (malformed PDU, protocol violation, EOF, ...), at which
/// point control returns to `run_session_loop` for backoff-and-reconnect.
async fn run_one_connection(
    connection: &mut Connection<TcpStream>,
    config: &RtrConfig,
    shared: &Arc<Shared>,
    version_hint: &mut RtrVersion,
) -> Result<(), RtrError> {
    // RFC 8210 §6 timers. Start as configured (used for the very first sync,
    // before any cache has told us otherwise, and for every v0 session —
    // RFC 6810 End of Data carries no intervals); each completed v1 sync
    // replaces them with the cache's own (clamped) values. "The router SHOULD
    // NOT retry sooner than [the cache's advertised Retry Interval]." The
    // Expire Interval is consumed at commit time (see `sync`), where it
    // starts the data's expiry countdown.
    let defaults = Timers::new(
        config.refresh_interval,
        config.retry_interval,
        config.expire_interval,
    );
    let mut timers = defaults;
    // §7: every connection starts a fresh negotiation. A remembered session
    // is resumed at the version it was learned at; otherwise start from the
    // last version known to work with this cache.
    let mut negotiation =
        Negotiation::Proposed(shared.resume().map_or(*version_hint, |r| r.version));

    loop {
        timers = sync(
            connection,
            shared,
            &mut negotiation,
            version_hint,
            defaults,
            timers,
        )
        .await?;

        // Idle until the refresh timer fires or the server sends an
        // unsolicited Serial Notify — either way, loop back to the top and
        // re-sync via Serial Query. The timer may win while a PDU is only
        // partly received; `read_frame` is cancellation safe, so the rest of
        // it is picked up by the exchange that follows.
        tokio::select! {
            () = tokio::time::sleep(timers.refresh) => {}
            read = connection.read_frame() => {
                let frame = received(connection, shared, negotiation.version(), read).await?;
                if let Err(violation) = protocol::on_idle(
                    negotiation.version(),
                    shared.resume(),
                    frame.version,
                    &frame.pdu,
                ) {
                    return Err(reject(connection, shared, negotiation.version(), violation, &frame.raw).await);
                }
            }
        }
    }
}

/// Runs query/response/transfer exchanges until one completes, returning the
/// timers in force after that End of Data (the cache's, for v1; `defaults`
/// for v0).
///
/// Handles, without dropping the connection: one round of v1→v0 fallback
/// (RFC 8210 §7), Cache Reset (§8.3 — forget the resume state and issue a
/// Reset Query), and Error Code 2 (§8.4 — retry with a Reset Query). What
/// each received PDU *means* is decided by [`Exchange`]; this function only
/// performs the I/O and table effects the verdicts call for.
async fn sync(
    connection: &mut Connection<TcpStream>,
    shared: &Arc<Shared>,
    negotiation: &mut Negotiation,
    version_hint: &mut RtrVersion,
    defaults: Timers,
    timers: Timers,
) -> Result<Timers, RtrError> {
    // Forces the *next* query to be a `ResetQuery` regardless of remembered
    // serial/session state. Set by Cache Reset and by Error Code 2.
    // Deliberately does not touch the installed VRPs: they stay valid until
    // the replacement load *commits* (see `cache.rs`).
    let mut force_reset = false;
    'exchange: loop {
        // Resume state and the epoch of the generation it describes, read
        // together: a delta staged for this query is only valid against that
        // generation.
        let (resume, epoch) = shared.basis();
        let query = Query::choose(resume, force_reset);
        let mut exchange = Exchange::new(query, *negotiation);
        // Records of this transfer accumulate here, invisible to validation,
        // status and subscribers, until a validated End of Data commits them
        // (see `cache.rs`). If the exchange ends any other way the staged
        // records are dropped with it.
        let mut staged = Staged::for_query(query, epoch);
        connection
            .write_pdu(negotiation.version(), &query.pdu())
            .await?;

        loop {
            let read = connection.read_frame().await;
            let frame = received(connection, shared, negotiation.version(), read).await?;
            let step = match exchange.on_pdu(frame.version, &frame.pdu) {
                Ok(step) => step,
                Err(violation) => {
                    // Remember what the cache actually speaks, even when the
                    // exchange is being abandoned (a v0 answer to a v1
                    // resume), so the reconnect starts at the right version.
                    *negotiation = exchange.negotiation();
                    *version_hint = negotiation.version();
                    return Err(reject(
                        connection,
                        shared,
                        negotiation.version(),
                        violation,
                        &frame.raw,
                    )
                    .await);
                }
            };
            *negotiation = exchange.negotiation();
            *version_hint = negotiation.version();

            match step {
                // RFC 8210 §5: a v0-only cache receiving a v1 query may
                // simply "respond with a version 0 response" instead of an
                // ErrorReport. §7: the router MUST then "either downgrade to
                // version 0 or terminate the connection".
                Step::Accepted {
                    downgraded_from, ..
                } => {
                    if let Some(proposed) = downgraded_from {
                        warn!(
                            sent = ?proposed,
                            got = ?negotiation.version(),
                            "RTR server answered at a lower protocol version than requested; downgrading"
                        );
                    }
                }
                Step::Prefix => staged.push(&frame.pdu),
                Step::Ignore => {}
                Step::Complete {
                    session,
                    serial,
                    intervals,
                } => {
                    let resume = Resume {
                        version: negotiation.version(),
                        session,
                        serial,
                    };
                    if let Some(effective) = publish(shared, staged, resume, defaults, intervals) {
                        return Ok(effective);
                    }
                    // The generation this delta was relative to was
                    // invalidated (the cache expired) while it was in flight.
                    // Applying it to what is left would publish a fragment as
                    // if it were the cache: ask for the full set instead.
                    warn!(
                        "RTR incremental update completed after the cache was invalidated; \
                         discarding it and issuing a Reset Query"
                    );
                    force_reset = true;
                    continue 'exchange;
                }
                // RFC 8210 §8.3: "When a router receives this, the router
                // SHOULD attempt to connect to any more-preferred caches in
                // its cache list. If there are no more-preferred caches, it
                // MUST issue a Reset Query and get an entire new load from
                // the cache." This client has a single cache. The remembered
                // serial is exactly what the cache just refused to serve, so
                // forget it *now*: if the connection dies before the
                // replacement load completes, the next connection must not
                // repeat the refused Serial Query.
                Step::ResetRequired => {
                    warn!(
                        "RTR cache cannot serve an incremental update (Cache Reset); \
                         issuing a Reset Query"
                    );
                    shared.forget_resume();
                    force_reset = true;
                    continue 'exchange;
                }
                Step::DowngradeToV0 { text } => {
                    warn!(text = %text, "RTR server rejected protocol v1, falling back to v0");
                    *negotiation = Negotiation::Proposed(RtrVersion::V0);
                    *version_hint = RtrVersion::V0;
                    // v0 and v1 session state (serial, session ID) are not
                    // interchangeable (RFC 8210 §5.1) — force a full resync
                    // under the new version. The installed VRPs stay until
                    // that load commits.
                    shared.forget_resume();
                    continue 'exchange;
                }
                // RFC 8210 §12/§8.4: Error Code 2 ("No Data Available") is
                // the only error code not marked "(fatal)" — the cache is
                // healthy but has nothing to answer with yet (typically:
                // still pulling its initial data set after a reboot). This
                // MUST NOT tear down the session, but §8.4 is explicit about
                // *what* to retry with: "If no other caches are available,
                // the router MUST issue periodic Reset Queries until it gets
                // a new usable load" — not a repeat of whatever query just
                // failed.
                Step::NoDataAvailable { text } => {
                    warn!(
                        text = %text,
                        "RTR cache reports no data available yet; forcing a Reset \
                         Query retry on the same connection"
                    );
                    shared.set_last_error(text);
                    force_reset = true;
                    tokio::time::sleep(timers.retry).await;
                    continue 'exchange;
                }
            }
        }
    }
}

/// Commits a completed transfer, applying the End of Data's timing
/// parameters. Returns the timers now in force, or `None` if the staged delta
/// had gone stale (nothing was applied).
fn publish(
    shared: &Shared,
    staged: Staged,
    resume: Resume,
    defaults: Timers,
    intervals: Option<pdu::EndOfDataIntervals>,
) -> Option<Timers> {
    let effective = defaults.after_end_of_data(intervals);
    for c in &effective.clamped {
        warn!(
            interval = c.name,
            advertised = c.advertised,
            used = c.used,
            "RTR cache advertised an interval outside its RFC 8210 §6 range; clamped"
        );
    }
    if effective.expire_not_after_poll_intervals {
        warn!(
            expire = effective.timers.expire.as_secs(),
            "RTR cache's Expire Interval is not larger than its Refresh/Retry Interval \
             (RFC 8210 §6 requires it to be); honouring it as advertised"
        );
    }
    // Data, serial, status, expiry deadline and the subscriber notification
    // are published together, here and only here.
    shared
        .commit(staged, resume, effective.timers.expire)
        .ok()
        .map(|()| effective.timers)
}

/// Upper bound on the offending-PDU copy placed in an outgoing Error Report
/// (RFC 8210 §5.11: the "Erroneous PDU field MAY be truncated" for a PDU of
/// excessive length). Every legal non-Error-Report PDU a cache sends is at
/// most 32 bytes, so this never truncates one; it only stops a hostile
/// oversized PDU from being echoed back at full length.
const MAX_ERROR_REPORT_PDU_COPY: usize = 256;

/// How long to wait for an Error Report to be accepted by the socket before
/// giving up and closing anyway.
const ERROR_REPORT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Carries out the RFC-mandated reaction to a protocol [`Violation`]: send the
/// Error Report (best effort), apply the consequence to the cached data, and
/// return the error that ends the session.
async fn reject(
    connection: &mut Connection<TcpStream>,
    shared: &Arc<Shared>,
    version: RtrVersion,
    violation: Violation,
    offending_pdu: &[u8],
) -> RtrError {
    if let Some(spec) = violation.report {
        let report = Pdu::ErrorReport {
            error_code: spec.code,
            pdu_copy: offending_pdu[..offending_pdu.len().min(MAX_ERROR_REPORT_PDU_COPY)].to_vec(),
            text: spec.text.to_string(),
        };
        // The session is being dropped either way; a stuck or closed peer
        // must not delay the cleanup below.
        let _ = tokio::time::timeout(
            ERROR_REPORT_WRITE_TIMEOUT,
            connection.write_pdu(version, &report),
        )
        .await;
    }
    match violation.consequence {
        Consequence::Drop => {}
        Consequence::ForgetResume => shared.forget_resume(),
        Consequence::Flush => shared.flush(),
    }
    violation.error
}

/// Turns the outcome of [`Connection::read_frame`] into a PDU, carrying out
/// the reaction to a peer that sent something that is not one.
///
/// Takes the *outcome* rather than doing the read, so the idle loop can race
/// only the (cancellation-safe) read against its timer: once bytes are being
/// rejected, nothing can interrupt the Error Report or its consequence.
async fn received(
    connection: &mut Connection<TcpStream>,
    shared: &Arc<Shared>,
    version: RtrVersion,
    read: Result<Frame, ReadError>,
) -> Result<Frame, RtrError> {
    match read {
        Ok(frame) => Ok(frame),
        Err(ReadError::Transport(error)) => Err(error),
        Err(ReadError::Malformed(bad)) => Err(reject(
            connection,
            shared,
            version,
            Violation::malformed(bad.error),
            &bad.raw,
        )
        .await),
    }
}

#[cfg(test)]
mod tests {
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    use super::*;
    use crate::{
        pdu::EndOfDataIntervals,
        protocol::{ERROR_CODE_NO_DATA_AVAILABLE, ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION},
        transport::{read_pdu, write_pdu},
    };

    /// Minimal scripted RTR server for tests: accepts one connection, then
    /// runs `script` against the raw stream, giving full control over
    /// adversarial or unusual server behavior that a real validator won't
    /// easily exercise (malformed PDUs, version-fallback triggers, mid-stream
    /// disconnects).
    async fn spawn_mock_server<F, Fut>(script: F) -> (RtrConfig, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let join = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            script(stream).await;
        });
        let config = RtrConfig {
            host: addr.ip().to_string(),
            port: addr.port(),
            ..Default::default()
        };
        (config, join)
    }

    async fn read_one(stream: &mut TcpStream) -> Pdu {
        read_pdu(stream).await.unwrap().1
    }

    async fn write_one(stream: &mut TcpStream, version: RtrVersion, pdu: &Pdu) {
        write_pdu(stream, version, pdu).await.unwrap();
    }

    #[tokio::test]
    async fn full_sync_populates_table_and_status() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            // Expect a Reset Query (first-ever sync).
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 7 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::announce_v4("192.0.2.0".parse().unwrap(), 24, 24, 65001),
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 7,
                    serial: 1,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;
            // Keep the connection open so the client enters its idle phase
            // without immediately observing EOF.
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not report connected within 5s");

        assert_eq!(
            handle.validate_v4("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::Valid
        );
        let status = handle.status();
        assert_eq!(status.version, Some(RtrVersion::V1));
        assert_eq!(status.serial, Some(1));
        assert_eq!(status.roa_count, 1);
    }

    /// `RtrHandle::subscribe`'s receiver must fire once the first sync
    /// completes — this is the signal `pathvectord` uses to re-evaluate
    /// routes that were accepted while the cache was still empty.
    #[tokio::test]
    async fn subscribe_fires_after_full_sync_completes() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 1 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 1,
                    serial: 1,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        let mut changed = handle.subscribe();

        tokio::time::timeout(Duration::from_secs(5), changed.changed())
            .await
            .expect("subscribe() did not fire within 5s")
            .expect("watch sender dropped unexpectedly");
    }

    /// A second, incremental sync (triggered by an unsolicited
    /// `SerialNotify`) must fire the same channel again — proves the
    /// notification isn't a one-shot "first sync only" signal, since a ROA
    /// published after startup must also trigger re-evaluation.
    #[tokio::test]
    async fn subscribe_fires_again_after_incremental_sync() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 1 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 1,
                    serial: 1,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;

            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::SerialNotify {
                    session_id: 1,
                    serial: 2,
                },
            )
            .await;
            assert_eq!(
                read_one(&mut stream).await,
                Pdu::SerialQuery {
                    session_id: 1,
                    serial: 1,
                }
            );
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 1 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 1,
                    serial: 2,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        let mut changed = handle.subscribe();

        tokio::time::timeout(Duration::from_secs(5), changed.changed())
            .await
            .expect("subscribe() did not fire for the first sync within 5s")
            .expect("watch sender dropped unexpectedly");
        tokio::time::timeout(Duration::from_secs(5), changed.changed())
            .await
            .expect("subscribe() did not fire again for the incremental sync within 5s")
            .expect("watch sender dropped unexpectedly");
    }

    /// `insert_roa_v4`/`insert_roa_v6` must fire the same channel a real
    /// sync does — proves the test-util mutation path and the real wire path
    /// share one notification mechanism, not two that could drift apart.
    #[test]
    fn insert_roa_v4_and_v6_fire_the_same_channel_as_real_sync() {
        let handle = for_testing(std::iter::empty(), std::iter::empty());
        let mut changed = handle.subscribe();
        assert!(changed.has_changed().is_ok_and(|c| !c));

        handle.insert_roa_v4(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 65001);
        assert!(changed.has_changed().unwrap());
        changed.mark_unchanged();

        handle.insert_roa_v6("2001:db8::".parse().unwrap(), 32, 32, 65001);
        assert!(changed.has_changed().unwrap());
    }

    /// An unsolicited `SerialNotify` received during the idle phase must
    /// trigger an immediate resync — not wait for the (potentially hours-
    /// long) refresh timer. This test doesn't need `tokio::time::pause`:
    /// the server advertises the default 3600s `refresh_interval`, and the
    /// test's own 5-second real-time timeout is itself the proof — if the
    /// idle `tokio::select!` only ever fired on the timer branch, this test
    /// would time out roughly 3595 seconds before that timer could.
    #[tokio::test]
    async fn unsolicited_serial_notify_triggers_immediate_resync_not_timer_wait() {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let (config, _server) = spawn_mock_server(move |mut stream| async move {
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 1 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 1,
                    serial: 1,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;

            // Server-initiated notification — the client never asked for
            // this, and the refresh timer (3600s) is nowhere close to firing.
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::SerialNotify {
                    session_id: 1,
                    serial: 2,
                },
            )
            .await;

            let observed = read_pdu(&mut stream).await.map_err(|e| e.to_string());
            let _ = result_tx.send(observed);
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (_handle, _join) = RtrClient::spawn(config);

        let (next_query_version, next_query) =
            tokio::time::timeout(Duration::from_secs(5), result_rx)
                .await
                .expect(
                    "client did not resync in response to Serial Notify within 5s \
                     — did it wait for the 3600s refresh timer instead?",
                )
                .expect("mock server task's result channel closed unexpectedly")
                .expect("mock server failed to read the follow-up PDU");

        assert_eq!(next_query_version, RtrVersion::V1);
        assert_eq!(
            next_query,
            Pdu::SerialQuery {
                session_id: 1,
                serial: 1
            }
        );
    }

    #[tokio::test]
    async fn v1_rejected_falls_back_to_v0_and_completes_sync() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            // First attempt: v1 Reset Query, rejected.
            let first = read_one(&mut stream).await;
            assert_eq!(first, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::ErrorReport {
                    error_code: ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION,
                    pdu_copy: vec![],
                    text: "only v0 supported".to_string(),
                },
            )
            .await;

            // Second attempt: same connection, now at v0.
            let second = read_one(&mut stream).await;
            assert_eq!(second, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V0,
                &Pdu::CacheResponse { session_id: 3 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V0,
                &Pdu::EndOfData {
                    session_id: 3,
                    serial: 9,
                    intervals: None,
                },
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not report connected within 5s");

        assert_eq!(handle.status().version, Some(RtrVersion::V0));
        assert_eq!(handle.status().serial, Some(9));
    }

    /// RFC 8210 §12: Error Code 2 ("No Data Available") is explicitly the
    /// *only* non-fatal error code — all 8 others are marked "(fatal)" and
    /// MUST cause the session to be dropped, but code 2 means "the cache is
    /// healthy but has no data yet" (e.g. still pulling its initial data set
    /// after a reboot) and should be retried, not treated as a session-ending
    /// failure. Proves this by having the mock server send two Reset Queries'
    /// worth of round trips *on the same TCP connection* — if the client
    /// disconnected on the `ErrorReport` (the pre-fix behavior), the second
    /// `read_one` below would never observe a second query on this stream at
    /// all (the client would instead open a *new* TCP connection, which this
    /// mock server, listening once via `TcpListener::accept` inside
    /// `spawn_mock_server`, never accepts).
    #[tokio::test]
    async fn error_code_2_no_data_available_retries_on_same_connection() {
        let (mut config, _server) = spawn_mock_server(|mut stream| async move {
            let first = read_one(&mut stream).await;
            assert_eq!(first, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::ErrorReport {
                    error_code: ERROR_CODE_NO_DATA_AVAILABLE,
                    pdu_copy: vec![],
                    text: "cache still loading initial data set".to_string(),
                },
            )
            .await;

            // Same connection, retried Reset Query — no reconnect in between.
            let second = read_one(&mut stream).await;
            assert_eq!(second, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 7 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 7,
                    serial: 5,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;
        // Keep the test fast — the fix reuses `retry_interval` as the pause
        // before resending the query.
        config.retry_interval = Duration::from_millis(20);

        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect(
            "client did not recover and complete sync within 5s — did it \
             disconnect on the non-fatal ErrorReport instead of retrying?",
        );

        assert_eq!(handle.status().serial, Some(5));
    }

    /// RFC 8210 §8.4: "If no other caches are available, the router MUST
    /// issue periodic Reset Queries until it gets a new usable load" — not a
    /// repeat of whatever query just failed. `sync_once` recomputes its next
    /// query from the remembered serial/session ID, so once a session is
    /// established, a code-2 response to a *Serial* Query would otherwise
    /// resend another Serial Query, never satisfying this requirement.
    ///
    /// Also proves the pre-reset table's data survives *until* the
    /// replacement full load actually starts arriving (not discarded the
    /// instant Error Code 2 is received — this crate's own design treats
    /// stale-but-recent ROA data as preferable to no data at all, and RFC
    /// 8210 §12 frames this error as a transient condition, potentially for
    /// a long retry window), and that the old ROA is correctly gone once the
    /// replacement load — which doesn't include it — completes.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn error_code_2_after_serial_query_forces_reset_query() {
        let old_roa_prefix: Ipv4Addr = "198.51.100.0".parse().unwrap();
        // Synchronization for the "old ROA survives the retry window"
        // assertion: a plain poll-until-`Valid` loop starting at test start
        // would trivially succeed during the *initial* sync, long before
        // Error Code 2 is even sent — proving nothing about the retry
        // window specifically. `mock_saw_reset` fires once the mock has
        // observed the forced Reset Query (i.e. the test is now definitely
        // inside the retry window, past the Error Code 2 response); the
        // mock then blocks on `release` before sending the replacement
        // load, so the assertion below is guaranteed to run at the one
        // point in time that actually matters.
        let (mock_saw_reset_tx, mock_saw_reset_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (mut config, _server) = spawn_mock_server(move |mut stream| async move {
            // Establish an initial session/serial via a normal Reset Query,
            // carrying one ROA that the replacement load below will not
            // include.
            let first = read_one(&mut stream).await;
            assert_eq!(first, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 4 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::announce_v4(old_roa_prefix, 24, 24, 65099),
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 4,
                    serial: 10,
                    // `retry: 1` (RFC 8210 §6's minimum allowed value) keeps
                    // the test fast — this is the value the fix under test
                    // must honor as the pause before the forced Reset Query
                    // below, per the second half of Codex's review comment
                    // on PR #38 (retain and honor the cache-advertised Retry
                    // Interval once a v1 session has supplied one).
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 1,
                        expire: 7200,
                    }),
                },
            )
            .await;

            // Unsolicited Serial Notify triggers an immediate resync via
            // Serial Query (not waiting on the 3600s refresh timer) — same
            // trigger used by `unsolicited_serial_notify_triggers_immediate_resync_not_timer_wait`.
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::SerialNotify {
                    session_id: 4,
                    serial: 11,
                },
            )
            .await;
            let second = read_one(&mut stream).await;
            assert_eq!(
                second,
                Pdu::SerialQuery {
                    session_id: 4,
                    serial: 10
                }
            );
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::ErrorReport {
                    error_code: ERROR_CODE_NO_DATA_AVAILABLE,
                    pdu_copy: vec![],
                    text: "cache lost state, needs full reload".to_string(),
                },
            )
            .await;

            // The client must now send a Reset Query, not another Serial
            // Query — even though it still remembers session_id=4/serial=10.
            let third = read_one(&mut stream).await;
            assert_eq!(
                third,
                Pdu::ResetQuery,
                "RFC 8210 §8.4: Error Code 2 MUST be followed by a Reset \
                 Query, not a repeat of the Serial Query that failed"
            );
            // Tell the test it's now safe to check the pre-reset ROA is
            // still present — we've observed the forced Reset Query but
            // haven't sent anything back yet — then wait for the test to
            // finish that check before sending the replacement load, so the
            // two can't race.
            let _ = mock_saw_reset_tx.send(());
            let _ = release_rx.await;
            // Replacement full load — deliberately omits `old_roa_prefix`.
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 9 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::announce_v4("203.0.113.0".parse().unwrap(), 24, 24, 65001),
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 9,
                    serial: 3,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;
        config.retry_interval = Duration::from_millis(20);

        let (handle, _join) = RtrClient::spawn(config);

        // Wait until the mock has observed the forced Reset Query — this is
        // the one point in time that actually proves the retry window
        // survived without an eager clear (checking any earlier could pass
        // trivially off the initial sync's own data, before Error Code 2 is
        // even sent).
        tokio::time::timeout(Duration::from_secs(5), mock_saw_reset_rx)
            .await
            .expect("mock never observed the forced Reset Query within 5s")
            .expect("mock's sender was dropped without signaling");

        assert_eq!(
            handle.validate_v4(old_roa_prefix, 24, 65099),
            RoaValidity::Valid,
            "the pre-reset ROA must still be present at this exact point — \
             after the forced Reset Query was sent, but before the \
             replacement load has arrived — otherwise the fix is clearing \
             the table too early, on Error Code 2 receipt rather than once \
             the replacement load actually arrives"
        );
        release_tx
            .send(())
            .expect("mock's release receiver was dropped");

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().serial == Some(3) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect(
            "client did not complete the forced Reset Query resync within \
             5s — did it repeat the failed Serial Query instead?",
        );

        assert_eq!(handle.status().version, Some(RtrVersion::V1));
        assert_eq!(
            handle.validate_v4(old_roa_prefix, 24, 65099),
            RoaValidity::NotFound,
            "the pre-reset ROA must not survive the replacement full load, \
             which doesn't include it"
        );
        assert_eq!(
            handle.validate_v4("203.0.113.1".parse().unwrap(), 24, 65001),
            RoaValidity::Valid,
            "the replacement load's own ROA must be present"
        );
    }

    /// RFC 8210 §5 documents a v0-only cache as potentially replying
    /// directly with a version-0 response instead of an `ErrorReport` —
    /// this is the gap the fix in `sync_once` closes: adopt whatever
    /// version the server actually replies at, not just on an explicit
    /// rejection.
    #[tokio::test]
    async fn server_silently_replies_at_v0_without_error_report() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            // Client sends a v1 Reset Query...
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            // ...but the server answers directly at v0, no ErrorReport.
            write_one(
                &mut stream,
                RtrVersion::V0,
                &Pdu::CacheResponse { session_id: 5 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V0,
                &Pdu::EndOfData {
                    session_id: 5,
                    serial: 1,
                    intervals: None,
                },
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not report connected within 5s");

        // The status must reflect the version the server actually used,
        // not the version the client originally sent.
        assert_eq!(handle.status().version, Some(RtrVersion::V0));
    }

    /// After silently adopting v0 (no `ErrorReport`), the *next* outbound
    /// query on the same connection must be encoded at v0 too — proving
    /// the adopted version isn't forgotten after the first exchange.
    #[tokio::test]
    async fn adopted_version_is_used_for_subsequent_queries() {
        // The critical assertion here happens *after* the client already
        // reports `connected`, so it can't rely on the "malformed exchange
        // never completes sync, so the outer .expect(connected) times out"
        // pattern the other tests use for early-assertion protection. A
        // `assert_eq!` inside the detached mock-server task at this point
        // would panic silently (its `JoinHandle` is never awaited) instead
        // of failing the test — so the observed PDU is sent back over a
        // channel and asserted on in the test body instead, where a failure
        // actually fails the test.
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let (config, _server) = spawn_mock_server(move |mut stream| async move {
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V0,
                &Pdu::CacheResponse { session_id: 7 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V0,
                &Pdu::EndOfData {
                    session_id: 7,
                    serial: 1,
                    intervals: None,
                },
            )
            .await;

            // Trigger an immediate resync via SerialNotify.
            write_one(
                &mut stream,
                RtrVersion::V0,
                &Pdu::SerialNotify {
                    session_id: 7,
                    serial: 2,
                },
            )
            .await;
            let observed = read_pdu(&mut stream).await.map_err(|e| e.to_string());
            let _ = result_tx.send(observed);
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not report connected within 5s");

        let (next_query_version, next_query) =
            tokio::time::timeout(Duration::from_secs(5), result_rx)
                .await
                .expect("mock server did not observe a follow-up query within 5s")
                .expect("mock server task's result channel closed unexpectedly")
                .expect("mock server failed to read the follow-up PDU");

        // The client's follow-up query must be encoded at v0 (the version
        // byte in its header, adopted from the earlier silent downgrade),
        // not the v1 it originally sent the Reset Query at.
        assert_eq!(next_query_version, RtrVersion::V0);
        assert_eq!(
            next_query,
            Pdu::SerialQuery {
                session_id: 7,
                serial: 1
            }
        );
    }

    #[tokio::test]
    async fn disconnect_mid_sync_reports_disconnected_without_clearing_table() {
        // First connection: full sync, then the server drops the connection
        // instead of idling. Second connection is never made in this test —
        // we only assert on the disconnected state after the first drop.
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 1 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::announce_v4("203.0.113.0".parse().unwrap(), 24, 24, 65010),
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 1,
                    serial: 1,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;
            // Drop the connection immediately instead of idling.
            drop(stream);
        })
        .await;

        // The server completes a full sync and then closes immediately —
        // `connected` can flip true then false (via the resulting `Closed`
        // error) faster than any poll interval could reliably observe the
        // transient `true` state on localhost. Poll for the actual invariant
        // under test instead: the client eventually reports an error (proof
        // the disconnect was detected) while the synced data survives it.
        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().last_error.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not report an error within 5s");

        assert!(!handle.status().connected);
        // Stale-but-recent data survives a transient disconnect.
        assert_eq!(
            handle.validate_v4("203.0.113.1".parse().unwrap(), 24, 65010),
            RoaValidity::Valid
        );
    }

    #[tokio::test]
    async fn session_id_mismatch_on_end_of_data_clears_table_and_errors() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 1 },
            )
            .await;
            // End of Data with a session ID that does NOT match the Cache
            // Response's session_id — a protocol violation the client must
            // detect rather than silently accepting the diff.
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 99,
                    serial: 1,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().last_error.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not report an error within 5s");

        assert!(!handle.status().connected);
        assert!(handle.status().last_error.unwrap().contains("session ID"));
    }

    /// A server (misbehaving or compromised) that declares an absurd PDU
    /// length must be rejected based on the 8-byte header alone — before
    /// the client attempts to allocate a buffer for the (nonexistent) rest
    /// of the PDU. Without `MAX_PDU_LEN`, this would be an unbounded
    /// allocation attempt sized directly from untrusted network input.
    #[tokio::test]
    async fn oversized_pdu_length_is_rejected_without_allocating() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            // Hand-craft a header claiming a length far beyond MAX_PDU_LEN,
            // for a Cache Reset PDU (type 8) whose real length is always 8.
            // Written directly rather than via `pdu::encode`, which always
            // computes a correct length — we need a malicious one here.
            let mut header = Vec::new();
            header.push(1u8); // version 1
            header.push(8u8); // PDU type: Cache Reset
            header.extend_from_slice(&0u16.to_be_bytes()); // reserved field
            header.extend_from_slice(&(u32::MAX - 1).to_be_bytes()); // absurd length
            stream.write_all(&header).await.unwrap();
            // Deliberately never send the (nonexistent) huge payload — the
            // client must reject based on the header alone, not hang
            // waiting for bytes that will never arrive.
            tokio::time::sleep(Duration::from_secs(10)).await;
        })
        .await;

        let (handle, _join) = RtrClient::spawn(config);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if handle.status().last_error.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not report an error within 5s — did it hang trying to allocate?");

        assert!(!handle.status().connected);
    }

    // ── RtrConfig::validate (RFC 8210 §6 ranges) ─────────────────────────

    fn config_with(refresh: u64, retry: u64, expire: u64) -> RtrConfig {
        RtrConfig {
            refresh_interval: Duration::from_secs(refresh),
            retry_interval: Duration::from_secs(retry),
            expire_interval: Duration::from_secs(expire),
            ..Default::default()
        }
    }

    #[test]
    fn default_config_is_valid() {
        assert_eq!(RtrConfig::default().validate(), Ok(()));
    }

    #[test]
    fn range_boundaries_validate() {
        assert_eq!(config_with(1, 1, 600).validate(), Ok(()));
        assert_eq!(config_with(86_400, 7_200, 172_800).validate(), Ok(()));
    }

    #[test]
    fn out_of_range_timers_are_rejected_by_field() {
        for (cfg, field) in [
            (config_with(0, 600, 7200), "refresh_interval"),
            (config_with(86_401, 600, 172_800), "refresh_interval"),
            (config_with(3600, 0, 7200), "retry_interval"),
            (config_with(3600, 7_201, 172_800), "retry_interval"),
            (config_with(300, 60, 599), "expire_interval"),
            (config_with(3600, 600, 172_801), "expire_interval"),
        ] {
            match cfg.validate() {
                Err(RtrConfigError::OutOfRange { field: f, .. }) => assert_eq!(f, field),
                other => panic!("{cfg:?}: expected OutOfRange({field}), got {other:?}"),
            }
        }
    }

    /// §6: "Caches MUST set Expire Interval to a value larger than either
    /// Refresh Interval or Retry Interval."
    #[test]
    fn expire_must_exceed_refresh_and_retry() {
        for cfg in [config_with(3600, 600, 3600), config_with(600, 700, 700)] {
            assert!(matches!(
                cfg.validate(),
                Err(RtrConfigError::ExpireNotAfterPollIntervals { .. })
            ));
        }
        assert_eq!(config_with(3600, 600, 3601).validate(), Ok(()));
    }
}
