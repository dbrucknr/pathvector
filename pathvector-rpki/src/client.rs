//! RTR session management: connect, version negotiation (RFC 8210 v1 with
//! RFC 6810 v0 fallback), Serial/Reset Query sync, and automatic reconnect.
//!
//! The client never blocks its caller on network I/O. [`RtrClient::spawn`]
//! returns an [`RtrHandle`] immediately; the actual TCP session runs forever
//! in a background task, retrying on any failure. Callers observe session
//! health via [`RtrHandle::status`] rather than through a `Result` — there is
//! no "did the client start successfully" moment to report on, only
//! "is it currently connected."

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};
use tracing::warn;

use crate::{
    error::{PduError, RtrError},
    pdu::{self, EndOfDataIntervals, Pdu, RtrVersion},
    table::{RoaTable, RoaValidity},
};

/// RFC 8210 §8.4 error code for "Unsupported Protocol Version" — the trigger
/// for falling back from v1 to v0.
const ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION: u16 = 4;

/// RFC 8210 §12 error code for "No Data Available" — the *only* error code
/// explicitly not marked "(fatal)". The cache is healthy but has nothing to
/// answer with yet (commonly: still pulling its initial data set after a
/// reboot). Unlike every other error code, this MUST NOT cause the session
/// to be dropped — see `sync_once`'s dedicated match arm.
const ERROR_CODE_NO_DATA_AVAILABLE: u16 = 2;

/// Upper bound on a single PDU's declared length. The largest legitimate
/// PDU in practice is an `ErrorReport` carrying a copy of the offending PDU
/// plus UTF-8 text, or a `RouterKey` carrying an SPKI — neither approaches
/// this. Rejecting anything larger before allocating a buffer for it closes
/// off a trivial memory-exhaustion vector: without this cap, a misbehaving
/// or compromised RTR server could declare a length near `u32::MAX` and
/// force an equivalent-sized allocation attempt per PDU.
const MAX_PDU_LEN: u32 = 64 * 1024;

/// Configuration for an RTR session.
#[derive(Debug, Clone)]
pub struct RtrConfig {
    pub host: String,
    pub port: u16,
    /// RFC 8210 §6 default: how long to wait between successful syncs before
    /// polling again. Overridden by the server's `EndOfData` intervals once a
    /// v1 session is established.
    pub refresh_interval: Duration,
    /// How long to wait after a connection failure before reconnecting.
    /// Also reused as the pause before retrying a query on the *same*
    /// connection after an RFC 8210 §12 Error Code 2 ("No Data Available")
    /// response — the one non-fatal error code, where a fresh connection
    /// isn't warranted.
    pub retry_interval: Duration,
    /// How long cached data may go unrefreshed before it's considered stale.
    /// Not enforced automatically in this phase — see [`RtrStatus::is_stale`].
    pub expire_interval: Duration,
    /// Protocol version to attempt first. Falls back to `V0` automatically on
    /// an `ErrorReport` indicating unsupported version.
    pub initial_version: RtrVersion,
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

/// A point-in-time snapshot of RTR session health, for operator visibility
/// (gRPC/CLI in Phase 1).
#[derive(Debug, Clone)]
pub struct RtrStatus {
    pub connected: bool,
    pub version: Option<RtrVersion>,
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
    fn disconnected() -> Self {
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

struct Shared {
    table: RoaTable,
    status: RwLock<RtrStatus>,
    /// Fires whenever the ROA table changes (a completed sync, full or
    /// incremental). The value itself is an unused generation counter — only
    /// the change notification matters. See [`RtrHandle::subscribe`].
    changed: watch::Sender<u64>,
}

/// A cheap-clone (`Arc`-backed) handle to a running RTR client. Safe to hold
/// from any number of callers (gRPC handlers, and in a later phase, policy
/// conditions) — `validate_*`/`status` never block on network I/O.
#[derive(Clone)]
pub struct RtrHandle(Arc<Shared>);

impl RtrHandle {
    #[must_use]
    pub fn validate_v4(&self, prefix: Ipv4Addr, prefix_len: u8, origin_asn: u32) -> RoaValidity {
        self.0.table.validate_v4(prefix, prefix_len, origin_asn)
    }

    #[must_use]
    pub fn validate_v6(&self, prefix: Ipv6Addr, prefix_len: u8, origin_asn: u32) -> RoaValidity {
        self.0.table.validate_v6(prefix, prefix_len, origin_asn)
    }

    /// # Panics
    ///
    /// Panics only if the internal status lock is poisoned (a prior holder
    /// panicked while holding it) — not an expected runtime condition.
    #[must_use]
    pub fn status(&self) -> RtrStatus {
        self.0.status.read().unwrap().clone()
    }

    /// Returns a receiver that fires whenever the ROA table changes — a
    /// completed sync, full or incremental. Callers should re-evaluate
    /// anything derived from ROA validity (e.g. `pathvectord`'s import
    /// policies) on each change; this is what lets a route accepted before
    /// the first sync (or before a ROA update) get correctly re-judged once
    /// the cache reflects it, without waiting for a session reset.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.changed.subscribe()
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
        let shared = Arc::new(Shared {
            table: RoaTable::new(),
            status: RwLock::new(RtrStatus::disconnected()),
            changed: watch::channel(0).0,
        });
        let handle = RtrHandle(Arc::clone(&shared));
        let join = tokio::spawn(run_session_loop(config, shared));
        (handle, join)
    }
}

/// Builds an `RtrHandle` with a fixed set of ROAs already loaded, and
/// `status().connected == true` — for tests that need deterministic ROA data
/// without running a real or mock RTR server. Each tuple is
/// `(prefix, prefix_len, max_len, origin_asn)`.
#[cfg(any(test, feature = "test-util"))]
#[must_use]
pub fn for_testing(
    v4: impl IntoIterator<Item = (Ipv4Addr, u8, u8, u32)>,
    v6: impl IntoIterator<Item = (Ipv6Addr, u8, u8, u32)>,
) -> RtrHandle {
    let table = RoaTable::new();
    for (prefix, prefix_len, max_len, asn) in v4 {
        table.apply_prefix_pdu(&Pdu::Ipv4Prefix {
            flags: pdu::PrefixFlags { announce: true },
            prefix_len,
            max_len,
            prefix,
            asn,
        });
    }
    for (prefix, prefix_len, max_len, asn) in v6 {
        table.apply_prefix_pdu(&Pdu::Ipv6Prefix {
            flags: pdu::PrefixFlags { announce: true },
            prefix_len,
            max_len,
            prefix,
            asn,
        });
    }
    let mut status = RtrStatus::disconnected();
    status.connected = true;
    status.roa_count = table.len();
    RtrHandle(Arc::new(Shared {
        table,
        status: RwLock::new(status),
        changed: watch::channel(0).0,
    }))
}

impl RtrHandle {
    /// Inserts one ROA into the cache and fires the same change notification
    /// a real incremental sync would — for tests that need to simulate "a
    /// ROA was published/changed" after the handle was already built (e.g.
    /// via [`for_testing`]), without a real or mock RTR server.
    ///
    /// # Panics
    ///
    /// Panics only if the internal status lock is poisoned (a prior holder
    /// panicked while holding it) — not an expected runtime condition.
    #[cfg(any(test, feature = "test-util"))]
    pub fn insert_roa_v4(&self, prefix: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) {
        self.0.table.apply_prefix_pdu(&Pdu::Ipv4Prefix {
            flags: pdu::PrefixFlags { announce: true },
            prefix_len,
            max_len,
            prefix,
            asn,
        });
        self.0.status.write().unwrap().roa_count = self.0.table.len();
        self.0.changed.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// IPv6 counterpart of [`RtrHandle::insert_roa_v4`].
    ///
    /// # Panics
    ///
    /// Panics only if the internal status lock is poisoned (a prior holder
    /// panicked while holding it) — not an expected runtime condition.
    #[cfg(any(test, feature = "test-util"))]
    pub fn insert_roa_v6(&self, prefix: Ipv6Addr, prefix_len: u8, max_len: u8, asn: u32) {
        self.0.table.apply_prefix_pdu(&Pdu::Ipv6Prefix {
            flags: pdu::PrefixFlags { announce: true },
            prefix_len,
            max_len,
            prefix,
            asn,
        });
        self.0.status.write().unwrap().roa_count = self.0.table.len();
        self.0.changed.send_modify(|g| *g = g.wrapping_add(1));
    }
}

/// Outer reconnect loop. Never returns except via task cancellation.
async fn run_session_loop(config: RtrConfig, shared: Arc<Shared>) {
    // `negotiated_version` and `session_id` persist across reconnects: once a
    // server is known to speak (or not speak) v1, and once a session ID has
    // been established, later reconnect attempts reuse that knowledge rather
    // than re-running the v1-attempt-then-fallback dance every time. This is
    // a deliberate, documented choice: it's a better default than forcing a
    // reset to `initial_version` on every reconnect, since a server's version
    // support doesn't change between one TCP connection and the next.
    let mut negotiated_version = config.initial_version;
    let mut session_id: Option<u16> = None;

    loop {
        match TcpStream::connect((config.host.as_str(), config.port)).await {
            Ok(mut stream) => {
                let result = run_one_connection(
                    &mut stream,
                    &config,
                    &shared,
                    &mut negotiated_version,
                    &mut session_id,
                )
                .await;
                if let Err(e) = result {
                    warn!(
                        host = %config.host,
                        port = config.port,
                        error = %e,
                        "RTR session error"
                    );
                    set_disconnected(&shared, e.to_string());
                }
            }
            Err(e) => {
                warn!(
                    host = %config.host,
                    port = config.port,
                    error = %e,
                    "RTR connect failed"
                );
                set_disconnected(&shared, e.to_string());
            }
        }
        tokio::time::sleep(config.retry_interval).await;
    }
}

fn set_disconnected(shared: &Arc<Shared>, error: String) {
    let mut status = shared.status.write().unwrap();
    status.connected = false;
    status.last_error = Some(error);
}

/// Outcome of draining the diff stream after a successful sync handshake.
enum DiffOutcome {
    /// Reached `EndOfData`; the table now reflects the server's current
    /// state. Carries the server-advertised intervals, if the session is v1.
    Complete(Option<EndOfDataIntervals>),
    /// The server sent `CacheReset`: it cannot serve an incremental update
    /// from our serial. The table has been cleared; the caller should
    /// immediately re-sync with a Reset Query on the same connection (no
    /// need to reconnect).
    ResyncNeeded,
}

/// One TCP connection's lifecycle: repeated sync-then-idle cycles until an
/// error occurs (malformed PDU, session ID mismatch, EOF, ...), at which
/// point control returns to `run_session_loop` for backoff-and-reconnect.
async fn run_one_connection(
    stream: &mut TcpStream,
    config: &RtrConfig,
    shared: &Arc<Shared>,
    negotiated_version: &mut RtrVersion,
    session_id: &mut Option<u16>,
) -> Result<(), RtrError> {
    let mut refresh = config.refresh_interval;
    // RFC 8210 §6: "The router SHOULD NOT retry sooner than [the cache's
    // advertised Retry Interval]." Starts at `config.retry_interval` (used
    // for the very first sync, before any cache has told us otherwise) and
    // is updated below once a v1 session actually supplies one. `expire` is
    // read directly from `RtrConfig`/`RtrStatus::is_stale` by callers that
    // need it; nothing here needs to hold onto it beyond this point.
    let mut retry = config.retry_interval;

    loop {
        let new_session_id =
            sync_once(stream, shared, negotiated_version, *session_id, retry).await?;
        *session_id = Some(new_session_id);

        match apply_diff_stream(stream, shared, new_session_id).await? {
            DiffOutcome::ResyncNeeded => {}
            DiffOutcome::Complete(intervals) => {
                if let Some(iv) = intervals {
                    refresh = Duration::from_secs(u64::from(iv.refresh));
                    retry = Duration::from_secs(u64::from(iv.retry));
                }

                {
                    let mut status = shared.status.write().unwrap();
                    status.connected = true;
                    status.version = Some(*negotiated_version);
                    status.serial = shared.table.serial();
                    status.roa_count = shared.table.len();
                    status.last_update = Some(Instant::now());
                    status.wall_clock_update = Some(SystemTime::now());
                    status.last_error = None;
                }

                // Idle until the refresh timer fires or the server sends an
                // unsolicited Serial Notify — either way, loop back to the
                // top and re-sync via Serial Query.
                tokio::select! {
                    () = tokio::time::sleep(refresh) => {}
                    pdu_result = read_pdu(stream) => {
                        match pdu_result?.1 {
                            Pdu::SerialNotify { .. } => {}
                            other => {
                                return Err(RtrError::UnexpectedPdu {
                                    expected: "Serial Notify",
                                    got: format!("{other:?}"),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Sends a Reset Query (first sync, or after a table clear) or Serial Query
/// (resuming from a known serial), handling one round of v1→v0 fallback if
/// the server rejects v1 with an "Unsupported Protocol Version" error.
/// Returns the session ID from the resulting Cache Response.
async fn sync_once(
    stream: &mut TcpStream,
    shared: &Arc<Shared>,
    negotiated_version: &mut RtrVersion,
    known_session_id: Option<u16>,
    retry_interval: Duration,
) -> Result<u16, RtrError> {
    let mut attempted_fallback = false;
    loop {
        let query = match (shared.table.serial(), known_session_id) {
            (Some(serial), Some(sid)) => Pdu::SerialQuery {
                session_id: sid,
                serial,
            },
            _ => Pdu::ResetQuery,
        };
        write_pdu(stream, *negotiated_version, &query).await?;

        let (observed_version, response) = read_pdu(stream).await?;

        match response {
            // RFC 8210 §5: a v0-only cache receiving a v1 query may simply
            // "respond with a version 0 response" instead of an
            // ErrorReport. `decode_payload` always trusts each PDU's own
            // wire version byte (so the data itself decodes correctly
            // regardless), but our *outbound* encoding for the next query
            // is chosen from `negotiated_version` — if we don't adopt what
            // the server actually used, every subsequent query is sent at
            // the wrong version. Catch that here, not only on an explicit
            // error.
            Pdu::CacheResponse { session_id } => {
                if observed_version != *negotiated_version {
                    warn!(
                        sent = ?*negotiated_version,
                        got = ?observed_version,
                        "RTR server accepted at a different protocol version than requested; adopting it"
                    );
                    *negotiated_version = observed_version;
                }
                return Ok(session_id);
            }
            // The explicit-rejection path. Deliberately not gated on the
            // ErrorReport's own wire version: some servers echo the
            // rejection at the version they support (v0), others at the
            // version they received (v1) — either way, an
            // "Unsupported Protocol Version" error_code is unambiguous
            // signal to retry at v0 once. `attempted_fallback` is the only
            // guard needed to prevent looping.
            Pdu::ErrorReport {
                error_code, text, ..
            } if error_code == ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION && !attempted_fallback => {
                warn!(text = %text, "RTR server rejected protocol v1, falling back to v0");
                *negotiated_version = RtrVersion::V0;
                // v0 and v1 session state (serial, session ID) are not
                // interchangeable — force a full resync under the new version.
                shared.table.clear();
                attempted_fallback = true;
            }
            // RFC 8210 §12/§8.4: Error Code 2 ("No Data Available") is the
            // only error code not marked "(fatal)" — the cache is healthy
            // but has nothing to answer with yet (typically: still pulling
            // its initial data set after a reboot). This MUST NOT tear down
            // the session, but §8.4 is explicit about *what* to retry with:
            // "If no other caches are available, the router MUST issue
            // periodic Reset Queries until it gets a new usable load" — not
            // a repeat of whatever query just failed. If this arrived in
            // response to a Serial Query, blindly looping would resend
            // another Serial Query, not a Reset Query. Clearing the table
            // forces the next loop iteration's query to be `ResetQuery`
            // (mirrors the v1→v0 fallback arm above) and, per the same
            // reasoning, ensures the eventual full reload doesn't leave
            // stale entries behind that the new data no longer contains —
            // `apply_diff_stream` has no way to know which records the
            // *previous* sync contributed, so nothing else in this codebase
            // reconciles that on our behalf.
            Pdu::ErrorReport {
                error_code, text, ..
            } if error_code == ERROR_CODE_NO_DATA_AVAILABLE => {
                warn!(
                    text = %text,
                    "RTR cache reports no data available yet; forcing a Reset \
                     Query retry on the same connection"
                );
                {
                    // Transport is still live — only the last sync attempt
                    // failed — so `connected` is deliberately left as-is.
                    let mut status = shared.status.write().unwrap();
                    status.last_error = Some(text);
                }
                shared.table.clear();
                tokio::time::sleep(retry_interval).await;
            }
            Pdu::ErrorReport {
                error_code, text, ..
            } => {
                return Err(RtrError::ErrorReported {
                    code: error_code,
                    text,
                });
            }
            other => {
                return Err(RtrError::UnexpectedPdu {
                    expected: "Cache Response",
                    got: format!("{other:?}"),
                });
            }
        }
    }
}

/// Reads PDUs until `EndOfData` (or `CacheReset`), applying Prefix PDUs to
/// the table as they arrive.
async fn apply_diff_stream(
    stream: &mut TcpStream,
    shared: &Arc<Shared>,
    expected_session_id: u16,
) -> Result<DiffOutcome, RtrError> {
    loop {
        let (_version, pdu) = read_pdu(stream).await?;
        match &pdu {
            Pdu::Ipv4Prefix { .. } | Pdu::Ipv6Prefix { .. } => {
                shared.table.apply_prefix_pdu(&pdu);
            }
            Pdu::RouterKey => {
                // Decoded-and-discarded — Phase 1 doesn't act on BGPsec keys.
            }
            Pdu::CacheReset => {
                shared.table.clear();
                return Ok(DiffOutcome::ResyncNeeded);
            }
            Pdu::EndOfData {
                session_id,
                serial,
                intervals,
            } => {
                if *session_id != expected_session_id {
                    // Invalidates everything just applied in this diff — the
                    // server is telling us, after the fact, that this data
                    // belonged to a session we don't recognize.
                    shared.table.clear();
                    return Err(RtrError::SessionIdMismatch {
                        expected: expected_session_id,
                        got: *session_id,
                    });
                }
                shared.table.set_serial(*serial);
                // Fires on every completed sync, full or incremental — the
                // single, correct point to notify subscribers (see
                // `RtrHandle::subscribe`) that the table just changed.
                shared.changed.send_modify(|g| *g = g.wrapping_add(1));
                return Ok(DiffOutcome::Complete(*intervals));
            }
            other => {
                return Err(RtrError::UnexpectedPdu {
                    expected: "Prefix, Router Key, Cache Reset, or End of Data",
                    got: format!("{other:?}"),
                });
            }
        }
    }
}

/// Reads one complete PDU off the wire: the 8-byte header first (to learn the
/// declared length), then the remaining `len - 8` bytes.
///
/// Returns the *wire* protocol version alongside the decoded PDU. This
/// matters because a server may reply at a different version than we sent
/// without an `ErrorReport` — RFC 8210 §5 describes this directly: a
/// v0-only cache receiving a v1 query "responds with a version 0 response."
/// Callers that care about version negotiation (`sync_once`) must inspect
/// this rather than assuming the response matches what was sent.
async fn read_pdu(stream: &mut TcpStream) -> Result<(RtrVersion, Pdu), RtrError> {
    let mut header = [0u8; 8];
    read_exact_mapped(stream, &mut header).await?;
    let (version, pdu_type, field, len) = pdu::decode_header(&header)?;

    if len > MAX_PDU_LEN {
        return Err(RtrError::Pdu(PduError::InvalidLength { pdu_type: 0, len }));
    }

    let mut full = header.to_vec();
    if let Some(remaining) = (len as usize).checked_sub(8) {
        let mut rest = vec![0u8; remaining];
        read_exact_mapped(stream, &mut rest).await?;
        full.extend_from_slice(&rest);
    }
    // If `len < 8`, `full` stays at just the 8-byte header; decode_payload's
    // own length check below reports a proper InvalidLength error rather
    // than us needing a separate underflow guard.
    let pdu = pdu::decode_payload(version, pdu_type, field, len, &full)?;
    Ok((version, pdu))
}

async fn read_exact_mapped(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), RtrError> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(RtrError::Closed),
        Err(e) => Err(RtrError::Io(e)),
    }
}

async fn write_pdu(stream: &mut TcpStream, version: RtrVersion, pdu: &Pdu) -> Result<(), RtrError> {
    let bytes = pdu::encode(version, pdu);
    stream.write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;
    use crate::pdu::PrefixFlags;

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
                &Pdu::Ipv4Prefix {
                    flags: PrefixFlags { announce: true },
                    prefix_len: 24,
                    max_len: 24,
                    prefix: "192.0.2.0".parse().unwrap(),
                    asn: 65001,
                },
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

    /// RFC 8210 §5.7: a `CacheReset` PDU received mid-diff (in place of a
    /// Prefix PDU or `EndOfData`) means the server can't serve this sync
    /// after all and the client must restart with a fresh Reset Query on
    /// the *same* TCP connection — not treat it as a fatal error requiring
    /// a reconnect. `apply_diff_stream`'s `DiffOutcome::ResyncNeeded` path
    /// implements this; this test isolates it (previously only reachable
    /// indirectly through other tests).
    #[tokio::test]
    async fn cache_reset_mid_stream_triggers_full_resync_on_same_connection() {
        let (config, _server) = spawn_mock_server(|mut stream| async move {
            // First attempt: normal Reset Query, accepted, then the server
            // gives up mid-diff instead of sending prefixes + End of Data.
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 1 },
            )
            .await;
            write_one(&mut stream, RtrVersion::V1, &Pdu::CacheReset).await;

            // Second attempt: same TCP connection. The table was cleared, so
            // the client has no serial to resume from and must send another
            // Reset Query (not a Serial Query) — this time the server
            // completes the sync normally.
            assert_eq!(read_one(&mut stream).await, Pdu::ResetQuery);
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 2 },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::Ipv4Prefix {
                    flags: PrefixFlags { announce: true },
                    prefix_len: 24,
                    max_len: 24,
                    prefix: "198.51.100.0".parse().unwrap(),
                    asn: 65020,
                },
            )
            .await;
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::EndOfData {
                    session_id: 2,
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
                if handle.status().connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect(
            "client did not complete the post-CacheReset resync within 5s \
             (did it treat CacheReset as fatal instead of resyncing?)",
        );

        // Confirm the *second* session's data actually made it in — proving
        // the resync completed, not just that the connection stayed open.
        assert_eq!(
            handle.validate_v4("198.51.100.1".parse().unwrap(), 24, 65020),
            RoaValidity::Valid
        );
        assert_eq!(handle.status().serial, Some(1));
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
    /// resend another Serial Query, never satisfying this requirement. Also
    /// proves the table is cleared before the forced Reset Query, so a stale
    /// ROA from the pre-reset table can't survive into the post-reset table
    /// if the fresh load doesn't include it.
    #[tokio::test]
    async fn error_code_2_after_serial_query_forces_reset_query() {
        let (mut config, _server) = spawn_mock_server(|mut stream| async move {
            // Establish an initial session/serial via a normal Reset Query.
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
            write_one(
                &mut stream,
                RtrVersion::V1,
                &Pdu::CacheResponse { session_id: 9 },
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
                &Pdu::Ipv4Prefix {
                    flags: PrefixFlags { announce: true },
                    prefix_len: 24,
                    max_len: 24,
                    prefix: "203.0.113.0".parse().unwrap(),
                    asn: 65010,
                },
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
}
