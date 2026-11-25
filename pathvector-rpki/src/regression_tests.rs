//! Black-box regression tests for the RTR client's synchronisation state
//! machine (issues #86, #87, #88, #90).
//!
//! Every test drives the real client (`RtrClient::spawn`) against a scripted
//! loopback RTR server and observes only what a peer or a library user can
//! observe: the PDUs the server actually receives, the validation results of
//! the public handle, the status snapshot, and the `subscribe()` channel.
//! Expected behaviour is derived from the RFC 8210 text quoted on each test,
//! not from what the implementation does.

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc},
};

use crate::{
    RoaValidity, RtrClient, RtrConfig, RtrHandle, RtrVersion,
    pdu::{EndOfDataIntervals, Pdu},
    transport::{read_pdu, write_pdu},
};

// ── Harness ──────────────────────────────────────────────────────────────

/// What the scripted server observed arriving from the client.
#[derive(Debug)]
struct Seen {
    /// Zero-based index of the TCP connection it arrived on.
    conn: usize,
    version: RtrVersion,
    pdu: Pdu,
}

/// Scripted RTR cache. Accepts *every* connection (so a reconnect is
/// observable rather than silently refused) and runs `script(conn_index,
/// stream, seen)` for each one.
struct MockCache {
    config: RtrConfig,
    seen: mpsc::UnboundedReceiver<Seen>,
    accepted: Arc<AtomicUsize>,
}

impl MockCache {
    async fn spawn<F, Fut>(script: F) -> Self
    where
        F: Fn(usize, TcpStream, Tap) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let (tx, seen) = mpsc::unbounded_channel();
        let script = Arc::new(script);
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let conn = counter.fetch_add(1, Ordering::SeqCst);
                let tap = Tap {
                    conn,
                    tx: tx.clone(),
                };
                tokio::spawn(Arc::clone(&script)(conn, stream, tap));
            }
        });
        Self {
            config: RtrConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                // Fast reconnect so a "futile reconnect loop" shows up as
                // extra connections within the test window.
                retry_interval: Duration::from_millis(50),
                ..Default::default()
            },
            seen,
            accepted,
        }
    }

    /// Next PDU the server saw, or a test failure naming what was awaited.
    async fn next_seen(&mut self, what: &str) -> Seen {
        for _ in 0..TICKS_BEFORE_GIVING_UP {
            match self.seen.try_recv() {
                Ok(seen) => return seen,
                Err(mpsc::error::TryRecvError::Empty) => tick().await,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    panic!("server task ended before seeing: {what}")
                }
            }
        }
        panic!("timed out waiting for the server to see: {what}")
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Handed to each connection script so everything the server reads is
/// reported to the test.
#[derive(Clone)]
struct Tap {
    conn: usize,
    tx: mpsc::UnboundedSender<Seen>,
}

impl Tap {
    /// Reads one PDU from the client and reports it to the test.
    async fn read(&self, stream: &mut TcpStream) -> Option<Pdu> {
        let (version, pdu) = read_pdu(stream).await.ok()?;
        let _ = self.tx.send(Seen {
            conn: self.conn,
            version,
            pdu: pdu.clone(),
        });
        Some(pdu)
    }
}

async fn send(stream: &mut TcpStream, version: RtrVersion, pdu: Pdu) {
    write_pdu(stream, version, &pdu).await.unwrap();
}

fn v4(prefix: &str, len: u8, asn: u32) -> Pdu {
    Pdu::announce_v4(prefix.parse().unwrap(), len, len, asn)
}

fn eod(session_id: u16, serial: u32) -> Pdu {
    Pdu::EndOfData {
        session_id,
        serial,
        intervals: Some(EndOfDataIntervals {
            refresh: 3600,
            retry: 600,
            expire: 7200,
        }),
    }
}

/// Never completes — keeps a scripted connection open without involving the
/// (possibly paused) clock.
async fn hold_open() {
    std::future::pending::<()>().await;
}

fn a() -> Ipv4Addr {
    "192.0.2.1".parse().unwrap()
}

fn b() -> Ipv4Addr {
    "198.51.100.1".parse().unwrap()
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..TICKS_BEFORE_GIVING_UP {
        if cond() {
            return;
        }
        tick().await;
    }
    panic!("timed out waiting for: {what}");
}

/// ~5 s of 1 ms ticks.
const TICKS_BEFORE_GIVING_UP: usize = 5_000;

/// One scheduling step that works whether or not the clock is paused.
///
/// With a paused clock the runtime auto-advances time whenever it is idle and
/// its zero-timeout I/O poll finds nothing ready — which can happen if the
/// peer's bytes are still in flight inside the kernel. Sleeping the *thread*
/// for a moment first guarantees loopback data has landed, so the poll sees
/// it and no virtual time is skipped. (On an unpaused clock this is merely a
/// 1 ms pause.)
async fn tick() {
    std::thread::sleep(Duration::from_millis(1));
    tokio::time::sleep(Duration::from_millis(1)).await;
}

fn validate(handle: &RtrHandle, addr: Ipv4Addr, asn: u32) -> RoaValidity {
    handle.validate_v4(addr, 24, asn)
}

// ── #87: Cache Reset as a normal response to a Serial Query ──────────────

/// RFC 8210 §8.3 (No Incremental Update Available): the cache "may respond
/// to a Serial Query with a Cache Reset ... When a router receives this, the
/// router SHOULD attempt to connect to any more-preferred caches in its cache
/// list. If there are no more-preferred caches, it MUST issue a Reset Query
/// and get an entire new load from the cache." (The diagram shows Serial
/// Query → Cache Reset → Reset Query → Cache Response → payload → End of
/// Data on one connection.) §5.3/§5.9 repeat that Cache Reset is the cache's
/// reply to a Serial Query.
///
/// Issue #87 reproduction: the client treated that reply as `UnexpectedPdu`,
/// dropped the connection, and — because it still remembered serial/session 1
/// — repeated the same Serial Query on every reconnect.
#[tokio::test]
async fn cache_reset_in_reply_to_serial_query_triggers_reset_query_on_same_connection() {
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let go_rx = Arc::new(tokio::sync::Mutex::new(Some(go_rx)));
    let (notify_tx, notify_rx) = tokio::sync::oneshot::channel::<()>();
    let notify_rx = Arc::new(tokio::sync::Mutex::new(Some(notify_rx)));
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go_rx = Arc::clone(&go_rx);
        let notify_rx = Arc::clone(&notify_rx);
        async move {
            let _ = conn;
            tap.read(&mut s).await; // initial Reset Query
            send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
            send(&mut s, RtrVersion::V1, v4("192.0.2.0", 24, 65001)).await;
            send(&mut s, RtrVersion::V1, eod(1, 1)).await;

            // Prompt an incremental poll — but only once the test has looked
            // at the state produced by the first sync.
            let rx = notify_rx.lock().await.take().unwrap();
            let _ = rx.await;
            send(
                &mut s,
                RtrVersion::V1,
                Pdu::SerialNotify {
                    session_id: 1,
                    serial: 2,
                },
            )
            .await;
            tap.read(&mut s).await; // Serial Query {1, 1}
            send(&mut s, RtrVersion::V1, Pdu::CacheReset).await;
            tap.read(&mut s).await; // must be a Reset Query

            // Hold the replacement load back so the test can look at the
            // client's state while the full load is outstanding.
            let rx = go_rx.lock().await.take().unwrap();
            let _ = rx.await;
            send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 2 }).await;
            send(&mut s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
            send(&mut s, RtrVersion::V1, eod(2, 5)).await;
            hold_open().await;
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let mut changed = handle.subscribe();

    let first = cache.next_seen("initial Reset Query").await;
    assert_eq!(first.pdu, Pdu::ResetQuery);
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
    assert!(changed.has_changed().unwrap(), "first sync must notify");
    changed.mark_unchanged();
    notify_tx.send(()).unwrap();

    let second = cache.next_seen("Serial Query after Serial Notify").await;
    assert_eq!(
        second.pdu,
        Pdu::SerialQuery {
            session_id: 1,
            serial: 1
        }
    );

    // §8.3: the only acceptable follow-up to Cache Reset (no other cache
    // configured) is a Reset Query — on the same connection.
    let third = cache
        .next_seen("Reset Query after Cache Reset (client likely dropped the session)")
        .await;
    assert_eq!(third.pdu, Pdu::ResetQuery, "§8.3: MUST issue a Reset Query");
    assert_eq!(third.conn, 0, "Reset Query must reuse the connection");
    assert_eq!(third.version, RtrVersion::V1);

    // While the full load is outstanding the incremental resume state must
    // already be gone: a Cache Reset means serial 1 is no longer usable.
    assert_eq!(
        handle.status().serial,
        None,
        "status must not advertise a serial the cache said it cannot serve"
    );

    go_tx.send(()).unwrap();
    wait_for("full reload to complete", || {
        handle.status().serial == Some(5)
    })
    .await;

    // Records absent from the new full load must disappear; the new ones
    // appear; subscribers see the transition.
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::NotFound);
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::Valid);
    assert!(
        changed.has_changed().unwrap(),
        "subscribers must be notified of the full reload"
    );
    assert_eq!(handle.status().roa_count, 1);
    assert_eq!(cache.accepted(), 1, "no reconnect loop");
}

/// §8.1: "In all other cases, the router lacks the necessary data for fast
/// resynchronization and therefore MUST fall back to a Reset Query." After a
/// Cache Reset the old serial is explicitly unusable, so if the connection
/// is lost before the replacement load completes, the *next* connection must
/// open with a Reset Query — not repeat the Serial Query the cache already
/// refused.
#[tokio::test]
async fn reconnect_after_cache_reset_opens_with_reset_query_not_serial_query() {
    let mut cache = MockCache::spawn(|conn, mut s, tap| async move {
        if conn == 0 {
            {
                tap.read(&mut s).await; // Reset Query
                send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
                send(&mut s, RtrVersion::V1, eod(1, 1)).await;
                send(
                    &mut s,
                    RtrVersion::V1,
                    Pdu::SerialNotify {
                        session_id: 1,
                        serial: 2,
                    },
                )
                .await;
                tap.read(&mut s).await; // Serial Query
                send(&mut s, RtrVersion::V1, Pdu::CacheReset).await;
                tap.read(&mut s).await; // Reset Query
                // Die before answering the Reset Query.
                drop(s);
            }
        } else {
            tap.read(&mut s).await;
            hold_open().await;
        }
    })
    .await;

    let (_handle, _join) = RtrClient::spawn(cache.config.clone());
    assert_eq!(cache.next_seen("Reset Query").await.pdu, Pdu::ResetQuery);
    assert!(matches!(
        cache.next_seen("Serial Query").await.pdu,
        Pdu::SerialQuery { .. }
    ));
    let reset = cache.next_seen("Reset Query after Cache Reset").await;
    assert_eq!((reset.conn, reset.pdu), (0, Pdu::ResetQuery));
    let after_reconnect = cache.next_seen("first PDU on the second connection").await;
    assert_eq!(after_reconnect.conn, 1);
    assert_eq!(
        after_reconnect.pdu,
        Pdu::ResetQuery,
        "must not resume from a serial the cache said it cannot serve"
    );
}

// ── Shared scenario pieces for #90 / #88 / #86 ───────────────────────────

/// One-shot-per-`open` latch letting the test decide when a scripted server
/// proceeds (so assertions about intermediate client state cannot race the
/// server's next move).
#[derive(Clone)]
struct Gate(Arc<Notify>);

impl Gate {
    fn new() -> Self {
        Self(Arc::new(Notify::new()))
    }

    fn open(&self) {
        self.0.notify_one();
    }

    async fn wait(&self) {
        self.0.notified().await;
    }
}

/// Server side of a normal first sync at v1: Reset Query → session 1 → VRP A
/// (192.0.2.0/24 AS65001) → End of Data serial 1.
async fn initial_v1_sync(s: &mut TcpStream, tap: &Tap) {
    assert_eq!(tap.read(s).await, Some(Pdu::ResetQuery));
    send(s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
    send(s, RtrVersion::V1, v4("192.0.2.0", 24, 65001)).await;
    send(s, RtrVersion::V1, eod(1, 1)).await;
}

async fn notify(s: &mut TcpStream, version: RtrVersion, session_id: u16, serial: u32) {
    send(s, version, Pdu::SerialNotify { session_id, serial }).await;
}

fn error_report(seen: &Seen) -> (u16, Vec<u8>) {
    match &seen.pdu {
        Pdu::ErrorReport {
            error_code,
            pdu_copy,
            ..
        } => (*error_code, pdu_copy.clone()),
        other => panic!("expected an Error Report from the client, saw {other:?}"),
    }
}

const CORRUPT_DATA: u16 = 0;
const UNEXPECTED_PROTOCOL_VERSION: u16 = 8;

// ── #90: negotiated version and session identity ─────────────────────────

/// RFC 8210 §5.1: "If, at any time after the protocol version has been
/// negotiated (Section 7), either the router or the cache finds that the
/// value of the Session ID is not the same as the other's, the party which
/// detects the mismatch MUST immediately terminate the session with an Error
/// Report PDU with code 0 ("Corrupt Data"), and the router MUST flush all
/// data learned from that cache." §5.5: "In response to a Serial Query, the
/// Session ID being the same reassures the router that the Serial Numbers
/// are commensurate".
///
/// Issue #90: a Cache Response with session 99 to a Serial Query for session
/// 1 was accepted as a continuation, and its diff applied on top of the
/// session-1 VRPs.
#[tokio::test]
async fn cache_response_with_other_session_id_to_serial_query_is_rejected_and_flushed() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_v1_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V1, 1, 2).await;
                tap.read(&mut s).await; // Serial Query {1, 1}
                send(
                    &mut s,
                    RtrVersion::V1,
                    Pdu::CacheResponse { session_id: 99 },
                )
                .await;
                send(&mut s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
                send(&mut s, RtrVersion::V1, eod(99, 2)).await;
                tap.read(&mut s).await; // expect the client's Error Report
                hold_open().await;
            } else {
                // Recovery: a fresh full load under the new session.
                tap.read(&mut s).await;
                send(
                    &mut s,
                    RtrVersion::V1,
                    Pdu::CacheResponse { session_id: 99 },
                )
                .await;
                send(&mut s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
                send(&mut s, RtrVersion::V1, eod(99, 7)).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let mut changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    changed.mark_unchanged();
    go.open();

    cache.next_seen("Serial Query").await;
    let report = cache
        .next_seen("Error Report for the session mismatch")
        .await;
    assert_eq!(report.conn, 0);
    assert_eq!(error_report(&report).0, CORRUPT_DATA, "§5.1: code 0");

    // §5.1: flush everything learned from that cache — and nothing from the
    // rejected response may have been combined with it.
    wait_for("flush", || handle.status().roa_count == 0).await;
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::NotFound);
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::NotFound);
    assert!(
        changed.has_changed().unwrap(),
        "the flush changes validity results, so subscribers must hear of it"
    );

    // Recovery is a full resynchronisation, not a resumed Serial Query.
    let reconnect = cache.next_seen("first PDU after reconnect").await;
    assert_eq!((reconnect.conn, reconnect.pdu), (1, Pdu::ResetQuery));
    wait_for("full resync", || handle.status().serial == Some(7)).await;
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::Valid);
}

/// RFC 8210 §7: "Once the cache and router have agreed upon a Protocol
/// Version ... that version is stable for the life of the session ... If
/// either party receives a PDU for a different Protocol Version once the
/// above negotiation completes, that party MUST drop the session; unless the
/// PDU containing the unexpected Protocol Version was itself an Error Report
/// PDU, the party dropping the session SHOULD send an Error Report with an
/// error code of 8 ("Unexpected Protocol Version")."
///
/// Issue #90: the client adopted a different version on *any* Cache
/// Response, even after negotiation.
#[tokio::test]
async fn cache_response_at_other_version_after_negotiation_drops_session_with_error_8() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_v1_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V1, 1, 2).await;
                tap.read(&mut s).await; // Serial Query
                // Negotiated v1; the cache now answers at v0.
                send(&mut s, RtrVersion::V0, Pdu::CacheResponse { session_id: 1 }).await;
                tap.read(&mut s).await; // Error Report
                hold_open().await;
            } else {
                tap.read(&mut s).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    go.open();

    cache.next_seen("Serial Query").await;
    let report = cache.next_seen("Error Report 8").await;
    assert_eq!(error_report(&report).0, UNEXPECTED_PROTOCOL_VERSION);

    // A version violation does not make the installed data wrong (§5.1 only
    // mandates a flush for a Session ID mismatch) and the session identity
    // is intact, so the reconnect resumes at the agreed version.
    let reconnect = cache.next_seen("first PDU after reconnect").await;
    assert_eq!(reconnect.conn, 1);
    assert_eq!(reconnect.version, RtrVersion::V1);
    assert_eq!(
        reconnect.pdu,
        Pdu::SerialQuery {
            session_id: 1,
            serial: 1
        }
    );
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
}

/// Same §7 clause, for a payload PDU: a Prefix PDU whose version differs
/// from the Cache Response that opened the transfer. The Error Report's
/// encapsulated PDU must be the offending bytes, bounded.
#[tokio::test]
async fn prefix_pdu_at_other_version_mid_transfer_drops_session_with_error_8() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_v1_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V1, 1, 2).await;
                tap.read(&mut s).await; // Serial Query
                send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
                send(&mut s, RtrVersion::V0, v4("198.51.100.0", 24, 65020)).await;
                tap.read(&mut s).await; // Error Report
                hold_open().await;
            } else {
                tap.read(&mut s).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    go.open();
    cache.next_seen("Serial Query").await;

    let report = cache.next_seen("Error Report 8").await;
    let (code, copy) = error_report(&report);
    assert_eq!(code, UNEXPECTED_PROTOCOL_VERSION);
    assert_eq!(copy.len(), 20, "the offending IPv4 Prefix PDU, 20 bytes");
    assert_eq!(copy[0], 0, "...as received, i.e. with version byte 0");
    assert_eq!(copy[1], 4, "...type 4 (IPv4 Prefix)");
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::NotFound);
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
}

/// §5.1 applies to the idle-phase notification as well: a Serial Notify is
/// a PDU carrying a Session ID and a Protocol Version.
#[tokio::test]
async fn idle_serial_notify_at_other_version_drops_session_with_error_8() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_v1_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V0, 1, 2).await;
                tap.read(&mut s).await; // Error Report
                hold_open().await;
            } else {
                tap.read(&mut s).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    go.open();

    let report = cache
        .next_seen("Error Report 8 (client probably accepted the notify and sent a Serial Query)")
        .await;
    assert_eq!(error_report(&report).0, UNEXPECTED_PROTOCOL_VERSION);
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
}

/// §5.2: a Serial Notify "reassures the router that the Serial Numbers are
/// commensurate, i.e., the cache session has not been changed" — one for a
/// different session is the §5.1 mismatch: code 0, flush.
#[tokio::test]
async fn idle_serial_notify_with_other_session_id_flushes_with_error_0() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_v1_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V1, 7, 2).await;
                tap.read(&mut s).await; // Error Report
                hold_open().await;
            } else {
                tap.read(&mut s).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let mut changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    changed.mark_unchanged();
    go.open();

    let report = cache
        .next_seen("Error Report 0 (client probably accepted the notify)")
        .await;
    assert_eq!(error_report(&report).0, CORRUPT_DATA);
    wait_for("flush", || handle.status().roa_count == 0).await;
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::NotFound);
    assert!(changed.has_changed().unwrap());
    let reconnect = cache.next_seen("first PDU after reconnect").await;
    assert_eq!(reconnect.pdu, Pdu::ResetQuery);
}

/// RFC 8210 §7: "The router MUST ignore any Serial Notify PDUs it might
/// receive from the cache during this initial startup period, regardless of
/// the Protocol Version field in the Serial Notify PDU." — valid, and
/// required for caches that speak v0.
#[tokio::test]
async fn serial_notify_during_version_negotiation_is_ignored() {
    let mut cache = MockCache::spawn(|_conn, mut s, tap| async move {
        tap.read(&mut s).await; // Reset Query
        // Wrong version *and* an unrelated session/serial: still ignorable.
        notify(&mut s, RtrVersion::V0, 9, 5).await;
        notify(&mut s, RtrVersion::V1, 9, 6).await;
        send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
        send(&mut s, RtrVersion::V1, v4("192.0.2.0", 24, 65001)).await;
        send(&mut s, RtrVersion::V1, eod(1, 1)).await;
        hold_open().await;
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    wait_for("sync despite startup notifies", || {
        handle.status().serial == Some(1)
    })
    .await;
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
    assert_eq!(
        cache.accepted(),
        1,
        "ignoring the notifies keeps the session"
    );
}

/// RFC 8210 §5.1: "routers MUST treat sessions with different Protocol
/// Version fields as separate sessions even if they do happen to have the
/// same Session ID" and §7 (a reply "at version 0 ... the router MUST either
/// downgrade to version 0 or terminate the connection").
///
/// After a reconnect the client resumes a v1 session with a Serial Query. A
/// cache that answers at v0 is a *different* session, so its diff must not
/// be applied to the v1 data. The client must start over with a Reset Query
/// at v0 and end up with only the v0 session's data.
#[tokio::test]
async fn resume_answered_at_lower_version_is_a_new_session_and_forces_full_resync() {
    let mut cache = MockCache::spawn(|conn, mut s, tap| async move {
        match conn {
            0 => {
                initial_v1_sync(&mut s, &tap).await;
                drop(s); // transport failure
            }
            1 => {
                // Resume attempt at v1...
                assert_matches_serial_query(tap.read(&mut s).await.as_ref());
                // ...answered at v0 with a "diff" that would add B.
                send(&mut s, RtrVersion::V0, Pdu::CacheResponse { session_id: 1 }).await;
                send(&mut s, RtrVersion::V0, v4("198.51.100.0", 24, 65020)).await;
                send(
                    &mut s,
                    RtrVersion::V0,
                    Pdu::EndOfData {
                        session_id: 1,
                        serial: 2,
                        intervals: None,
                    },
                )
                .await;
                hold_open().await;
            }
            _ => {
                // The full load at v0: only B (A is gone from this cache).
                tap.read(&mut s).await;
                send(&mut s, RtrVersion::V0, Pdu::CacheResponse { session_id: 4 }).await;
                send(&mut s, RtrVersion::V0, v4("198.51.100.0", 24, 65020)).await;
                send(
                    &mut s,
                    RtrVersion::V0,
                    Pdu::EndOfData {
                        session_id: 4,
                        serial: 9,
                        intervals: None,
                    },
                )
                .await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("initial Reset Query").await;
    let resume = cache.next_seen("Serial Query on reconnect").await;
    assert_eq!(resume.version, RtrVersion::V1);
    let reset = cache
        .next_seen("Reset Query at v0 (client probably continued the v1 session)")
        .await;
    assert_eq!(reset.pdu, Pdu::ResetQuery);
    assert_eq!(reset.version, RtrVersion::V0);
    wait_for("v0 full load", || handle.status().serial == Some(9)).await;
    assert_eq!(handle.status().version, Some(RtrVersion::V0));
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::NotFound);
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::Valid);
}

fn assert_matches_serial_query(pdu: Option<&Pdu>) {
    assert!(
        matches!(pdu, Some(Pdu::SerialQuery { .. })),
        "expected a Serial Query, got {pdu:?}"
    );
}

// ── #88: data, serial state and notifications stay consistent ────────────

fn v6(prefix: &str, len: u8, asn: u32) -> Pdu {
    Pdu::announce_v6(prefix.parse().unwrap(), len, len, asn)
}

fn withdraw(pdu: Pdu) -> Pdu {
    pdu.withdrawn()
}

fn a6() -> std::net::Ipv6Addr {
    "2001:db8::1".parse().unwrap()
}

fn b6() -> std::net::Ipv6Addr {
    "2001:db9::1".parse().unwrap()
}

/// Session 1, serial 1, holding A (v4 `192.0.2.0/24` AS65001) and A6 (v6
/// `2001:db8::/32` AS65001).
async fn initial_dual_family_sync(s: &mut TcpStream, tap: &Tap) {
    assert_eq!(tap.read(s).await, Some(Pdu::ResetQuery));
    send(s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
    send(s, RtrVersion::V1, v4("192.0.2.0", 24, 65001)).await;
    send(s, RtrVersion::V1, v6("2001:db8::", 32, 65001)).await;
    send(s, RtrVersion::V1, eod(1, 1)).await;
}

/// The changes the failing transfers below announce: withdraw A and A6,
/// announce B (`198.51.100.0/24` AS65020) and B6 (`2001:db9::/32` AS65020).
async fn send_partial_changes(s: &mut TcpStream) {
    send(s, RtrVersion::V1, withdraw(v4("192.0.2.0", 24, 65001))).await;
    send(s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
    send(s, RtrVersion::V1, withdraw(v6("2001:db8::", 32, 65001))).await;
    send(s, RtrVersion::V1, v6("2001:db9::", 32, 65020)).await;
}

fn generation(changed: &tokio::sync::watch::Receiver<u64>) -> u64 {
    *changed.borrow()
}

/// Gives the client time to process everything the server has written. The
/// pre-fix bug is "visible within microseconds", so this only ever makes the
/// assertions that follow *more* likely to catch it, never less.
async fn settle() {
    for _ in 0..150 {
        tick().await;
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    /// Connection lost mid-transfer.
    Eof,
    /// A PDU of unknown type. Answered with Error Report 5, after which the
    /// resume point is forgotten.
    MalformedPdu,
    /// RFC 8210 §5.9 defines Cache Reset only as the reply to a Serial
    /// Query; mid-transfer it is a protocol violation.
    CacheResetMidTransfer,
    /// End of Data whose Protocol Version differs from the Cache Response's
    /// (RFC 8210 §5.8).
    EndOfDataAtOtherVersion,
}

/// Issue #88 reproduction, generalised: announcements *and* withdrawals of
/// both families are streamed, then the transfer fails before End of Data.
///
/// RFC 8210 §4 associates the current serial with a *completed* response, and
/// the public `subscribe()` contract promises completed-sync notifications.
/// So until End of Data validates, nothing may be visible: VRPs, status and
/// notifications must all still describe the previous generation. The
/// reconnect resumes from exactly that generation, unless the failure was a
/// refused PDU: then the same serial would draw the same change set again, so
/// the client asks for everything.
async fn failed_incremental_transfer_publishes_nothing(failure: Failure) {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_dual_family_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V1, 1, 2).await;
                tap.read(&mut s).await; // Serial Query {1, 1}
                send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
                send_partial_changes(&mut s).await;
                match failure {
                    Failure::Eof => drop(s),
                    Failure::MalformedPdu => {
                        use tokio::io::AsyncWriteExt;
                        s.write_all(&[1, 5, 0, 0, 0, 0, 0, 8]).await.unwrap();
                        hold_open().await;
                    }
                    Failure::CacheResetMidTransfer => {
                        send(&mut s, RtrVersion::V1, Pdu::CacheReset).await;
                        hold_open().await;
                    }
                    Failure::EndOfDataAtOtherVersion => {
                        send(
                            &mut s,
                            RtrVersion::V0,
                            Pdu::EndOfData {
                                session_id: 1,
                                serial: 2,
                                intervals: None,
                            },
                        )
                        .await;
                        hold_open().await;
                    }
                }
            } else {
                tap.read(&mut s).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let mut changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    let before = generation(&changed);
    changed.mark_unchanged();
    go.open();
    cache.next_seen("Serial Query").await;

    wait_for("the failed transfer to end the session", || {
        !handle.status().connected
    })
    .await;

    let ctx = format!("after {failure:?}");
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid, "{ctx}");
    assert_eq!(
        validate(&handle, b(), 65020),
        RoaValidity::NotFound,
        "{ctx}"
    );
    assert_eq!(
        handle.validate_v6(a6(), 32, 65001),
        RoaValidity::Valid,
        "{ctx}"
    );
    assert_eq!(
        handle.validate_v6(b6(), 32, 65020),
        RoaValidity::NotFound,
        "{ctx}"
    );
    assert_eq!(generation(&changed), before, "{ctx}: nothing completed");
    assert!(!changed.has_changed().unwrap(), "{ctx}");
    let (serial, query) = if matches!(failure, Failure::MalformedPdu) {
        (None, Pdu::ResetQuery)
    } else {
        (
            Some(1),
            Pdu::SerialQuery {
                session_id: 1,
                serial: 1,
            },
        )
    };
    let status = handle.status();
    assert_eq!(status.serial, serial, "{ctx}");
    assert_eq!(status.roa_count, 2, "{ctx}");

    // ...and the next query matches.
    let mut reconnect = cache.next_seen("first PDU after reconnect").await;
    while reconnect.conn == 0 {
        reconnect = cache.next_seen("first PDU after reconnect").await;
    }
    assert_eq!((reconnect.conn, reconnect.pdu), (1, query), "{ctx}");
}

#[tokio::test]
async fn eof_mid_incremental_transfer_publishes_nothing() {
    failed_incremental_transfer_publishes_nothing(Failure::Eof).await;
}

#[tokio::test]
async fn malformed_pdu_mid_incremental_transfer_publishes_nothing() {
    failed_incremental_transfer_publishes_nothing(Failure::MalformedPdu).await;
}

#[tokio::test]
async fn cache_reset_mid_incremental_transfer_publishes_nothing() {
    failed_incremental_transfer_publishes_nothing(Failure::CacheResetMidTransfer).await;
}

/// Also #90: "Ensure mismatched data is not committed or combined with
/// old-session VRPs."
#[tokio::test]
async fn end_of_data_at_other_version_publishes_nothing() {
    failed_incremental_transfer_publishes_nothing(Failure::EndOfDataAtOtherVersion).await;
}

/// A *full* load that dies part-way (here: after Cache Reset made the router
/// ask for one) must not have discarded the previous generation (RFC 8210
/// §12 treats the no-data window as transient; this crate's design is that
/// stale-but-recent VRPs beat none) nor exposed the half-loaded one. The
/// resume state, however, was legitimately dropped by the Cache Reset, so the
/// status serial is `None` and the reconnect starts with a Reset Query.
#[tokio::test]
async fn interrupted_full_load_keeps_previous_vrps_and_publishes_nothing() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_dual_family_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V1, 1, 2).await;
                tap.read(&mut s).await; // Serial Query
                send(&mut s, RtrVersion::V1, Pdu::CacheReset).await;
                tap.read(&mut s).await; // Reset Query
                send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 2 }).await;
                send(&mut s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
                send(&mut s, RtrVersion::V1, v6("2001:db9::", 32, 65020)).await;
                drop(s);
            } else {
                tap.read(&mut s).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let mut changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    let before = generation(&changed);
    changed.mark_unchanged();
    go.open();
    cache.next_seen("Serial Query").await;
    cache.next_seen("Reset Query after Cache Reset").await;
    wait_for("the interrupted load to end the session", || {
        !handle.status().connected
    })
    .await;

    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
    assert_eq!(handle.validate_v6(a6(), 32, 65001), RoaValidity::Valid);
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::NotFound);
    assert_eq!(handle.validate_v6(b6(), 32, 65020), RoaValidity::NotFound);
    assert_eq!(generation(&changed), before);
    assert_eq!(handle.status().serial, None);
    assert_eq!(handle.status().roa_count, 2);
    let reconnect = cache.next_seen("first PDU after reconnect").await;
    assert_eq!((reconnect.conn, reconnect.pdu), (1, Pdu::ResetQuery));
}

/// Nothing a transfer carries is visible before its End of Data; at End of
/// Data the whole change set — announcements and withdrawals, both families,
/// VRPs, serial, status — appears together, with exactly one notification.
/// Run for both an incremental update and a full reload.
async fn transfer_is_published_atomically_at_end_of_data(full_reload: bool) {
    let go = Gate::new();
    let go_s = go.clone();
    let finish = Gate::new();
    let finish_s = finish.clone();
    let mut cache = MockCache::spawn(move |_conn, mut s, tap| {
        let go = go_s.clone();
        let finish = finish_s.clone();
        async move {
            initial_dual_family_sync(&mut s, &tap).await;
            go.wait().await;
            notify(&mut s, RtrVersion::V1, 1, 2).await;
            tap.read(&mut s).await; // Serial Query
            if full_reload {
                send(&mut s, RtrVersion::V1, Pdu::CacheReset).await;
                tap.read(&mut s).await; // Reset Query
                send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 2 }).await;
                send(&mut s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
                send(&mut s, RtrVersion::V1, v6("2001:db9::", 32, 65020)).await;
            } else {
                send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
                send_partial_changes(&mut s).await;
            }
            finish.wait().await;
            send(
                &mut s,
                RtrVersion::V1,
                eod(if full_reload { 2 } else { 1 }, 9),
            )
            .await;
            hold_open().await;
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    let before = generation(&changed);
    go.open();
    cache.next_seen("Serial Query").await;
    if full_reload {
        cache.next_seen("Reset Query").await;
    }
    settle().await;

    // Mid-transfer: the previous generation, whole.
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
    assert_eq!(handle.validate_v6(a6(), 32, 65001), RoaValidity::Valid);
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::NotFound);
    assert_eq!(handle.validate_v6(b6(), 32, 65020), RoaValidity::NotFound);
    assert_eq!(generation(&changed), before);

    finish.open();
    wait_for("End of Data", || handle.status().serial == Some(9)).await;

    // After End of Data: the new generation, whole, announced once.
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::NotFound);
    assert_eq!(handle.validate_v6(a6(), 32, 65001), RoaValidity::NotFound);
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::Valid);
    assert_eq!(handle.validate_v6(b6(), 32, 65020), RoaValidity::Valid);
    assert_eq!(handle.status().roa_count, 2);
    assert_eq!(
        generation(&changed),
        before + 1,
        "exactly one notification for the completed transfer"
    );
}

#[tokio::test]
async fn incremental_transfer_is_published_atomically_at_end_of_data() {
    transfer_is_published_atomically_at_end_of_data(false).await;
}

#[tokio::test]
async fn full_reload_is_published_atomically_at_end_of_data() {
    transfer_is_published_atomically_at_end_of_data(true).await;
}

/// RFC 8210 §5.1 session mismatch detected at End of Data, after a
/// half-applied transfer: everything learned from the cache is flushed —
/// both the old generation *and* the rejected transfer's data, which must
/// not survive "combined with old-session VRPs" — subscribers hear about it
/// once, and the status is coherent (no serial, no records).
#[tokio::test]
async fn end_of_data_session_mismatch_flushes_old_and_staged_data_with_one_notification() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            if conn == 0 {
                initial_dual_family_sync(&mut s, &tap).await;
                go.wait().await;
                notify(&mut s, RtrVersion::V1, 1, 2).await;
                tap.read(&mut s).await; // Serial Query
                send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
                send_partial_changes(&mut s).await;
                send(&mut s, RtrVersion::V1, eod(99, 2)).await;
                tap.read(&mut s).await; // Error Report
                hold_open().await;
            } else {
                tap.read(&mut s).await;
                hold_open().await;
            }
        }
    })
    .await;

    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    let before = generation(&changed);
    go.open();
    cache.next_seen("Serial Query").await;
    let report = cache.next_seen("Error Report").await;
    assert_eq!(error_report(&report).0, CORRUPT_DATA);
    wait_for("flush", || handle.status().roa_count == 0).await;

    for (addr, asn) in [(a(), 65001), (b(), 65020)] {
        assert_eq!(validate(&handle, addr, asn), RoaValidity::NotFound);
    }
    assert_eq!(handle.validate_v6(a6(), 32, 65001), RoaValidity::NotFound);
    assert_eq!(handle.validate_v6(b6(), 32, 65020), RoaValidity::NotFound);
    assert_eq!(handle.status().serial, None);
    assert_eq!(
        generation(&changed),
        before + 1,
        "one notification for the flush"
    );
    let reconnect = cache.next_seen("first PDU after reconnect").await;
    assert_eq!(reconnect.pdu, Pdu::ResetQuery);
}

// ── #86: cache expiry (RFC 8210 §6) ──────────────────────────────────────
//
// RFC 8210 §6, Expire Interval: "This parameter tells the router how long it
// can continue to use the current version of the data while unable to
// perform a successful subsequent query. The router MUST NOT retain the data
// past the time indicated by this parameter. Countdown for this timer starts
// upon receipt of the containing End Of Data PDU. Minimum allowed value: 600
// seconds (10 minutes). Maximum allowed value: 172800 seconds (2 days)."
//
// These tests freeze the clock once the first sync is installed
// (`tokio::time::pause`) and move it with `advance`, so "7199 s" and "7201 s"
// are exact, and the surrounding network behaviour (stalled query,
// reconnect back-off, ...) is whatever the scripted cache does.

fn eod_with(session_id: u16, serial: u32, refresh: u32, retry: u32, expire: u32) -> Pdu {
    Pdu::EndOfData {
        session_id,
        serial,
        intervals: Some(EndOfDataIntervals {
            refresh,
            retry,
            expire,
        }),
    }
}

/// [`initial_dual_family_sync`] with the End of Data of the caller's choice,
/// at the caller's protocol version.
async fn dual_family_sync_with(
    s: &mut TcpStream,
    tap: &Tap,
    version: RtrVersion,
    end_of_data: Pdu,
) {
    assert_eq!(tap.read(s).await, Some(Pdu::ResetQuery));
    send(s, version, Pdu::CacheResponse { session_id: 1 }).await;
    send(s, version, v4("192.0.2.0", 24, 65001)).await;
    send(s, version, v6("2001:db8::", 32, 65001)).await;
    send(s, version, end_of_data).await;
}

/// Lets in-flight loopback I/O and any timers that just became due run.
async fn settle_io() {
    for _ in 0..10 {
        tick().await;
        tokio::task::yield_now().await;
    }
}

/// Moves the (paused) clock forward and lets the client react.
async fn advance_secs(secs: u64) {
    tokio::time::advance(Duration::from_secs(secs)).await;
    settle_io().await;
}

/// Spawns the client, waits (in real time) for its first completed sync, then
/// freezes the clock.
async fn spawn_synced_and_paused(
    cache: &mut MockCache,
) -> (RtrHandle, tokio::sync::watch::Receiver<u64>) {
    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    let changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    tokio::time::pause();
    (handle, changed)
}

fn both_families_valid(handle: &RtrHandle) -> bool {
    validate(handle, a(), 65001) == RoaValidity::Valid
        && handle.validate_v6(a6(), 32, 65001) == RoaValidity::Valid
}

fn both_families_not_found(handle: &RtrHandle) -> bool {
    validate(handle, a(), 65001) == RoaValidity::NotFound
        && handle.validate_v6(a6(), 32, 65001) == RoaValidity::NotFound
}

/// Retention before expiry, removal at expiry, for both families — and the
/// cache-advertised value (7200 s) is what counts, not the configured one
/// (172800 s). At expiry, validation results change (everything becomes
/// `NotFound`, i.e. ROV fails open), so subscribers are notified; the status
/// shows an empty, expired cache with nothing to resume from.
#[tokio::test]
async fn vrps_are_kept_until_the_advertised_expire_interval_then_removed() {
    let mut cache = MockCache::spawn(|_c, mut s, tap| async move {
        dual_family_sync_with(
            &mut s,
            &tap,
            RtrVersion::V1,
            eod_with(1, 1, 3600, 600, 7200),
        )
        .await;
        hold_open().await;
    })
    .await;
    cache.config.expire_interval = Duration::from_secs(172_800);
    let (handle, changed) = spawn_synced_and_paused(&mut cache).await;
    let before = generation(&changed);

    advance_secs(7199).await;
    assert!(both_families_valid(&handle), "retained 1 s before expiry");
    assert_eq!(generation(&changed), before);
    assert!(!handle.status().expired);
    assert!(handle.status().expires_at.is_some());

    advance_secs(2).await;
    assert!(
        both_families_not_found(&handle),
        "must not retain past expiry"
    );
    assert_eq!(
        generation(&changed),
        before + 1,
        "validation results changed, so subscribers must be told exactly once"
    );
    let status = handle.status();
    assert!(status.expired);
    assert_eq!(status.roa_count, 0);
    assert_eq!(status.serial, None, "nothing left to resume from");
    assert_eq!(status.expires_at, None);
    assert!(
        status
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("expire")),
        "operators must be able to see why: {:?}",
        status.last_error
    );
}

/// "Do not extend expiry merely because TCP is connected or bytes/
/// notifications arrive; require a successful completed update." Here the
/// refresh poll (Serial Query at 3600 s) is never answered — a stalled query
/// — and the cache keeps sending Serial Notifies.
#[tokio::test]
async fn stalled_query_and_notifications_do_not_extend_expiry() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |_c, mut s, tap| {
        let go = go_s.clone();
        async move {
            dual_family_sync_with(
                &mut s,
                &tap,
                RtrVersion::V1,
                eod_with(1, 1, 3600, 600, 7200),
            )
            .await;
            tap.read(&mut s).await; // the refresh Serial Query, never answered
            go.wait().await;
            for serial in 2..6 {
                notify(&mut s, RtrVersion::V1, 1, serial).await;
            }
            hold_open().await;
        }
    })
    .await;
    let (handle, changed) = spawn_synced_and_paused(&mut cache).await;
    let before = generation(&changed);

    advance_secs(3601).await;
    assert!(matches!(
        cache.next_seen("refresh Serial Query").await.pdu,
        Pdu::SerialQuery { .. }
    ));
    advance_secs(2000).await;
    go.open();
    settle_io().await;
    advance_secs(1598).await; // t = 7199
    assert!(both_families_valid(&handle));

    advance_secs(2).await; // t = 7201
    assert!(
        both_families_not_found(&handle),
        "a connected-but-stalled session must still expire"
    );
    assert_eq!(generation(&changed), before + 1);
}

/// RFC 8210 §8.4: Error Code 2 ("No Data Available") keeps the session up
/// and the router retries — but a cache with no data has not *completed* an
/// update, so the deadline is untouched.
#[tokio::test]
async fn no_data_available_responses_do_not_renew_expiry() {
    let mut cache = MockCache::spawn(|_c, mut s, tap| async move {
        dual_family_sync_with(
            &mut s,
            &tap,
            RtrVersion::V1,
            eod_with(1, 1, 3600, 600, 7200),
        )
        .await;
        while tap.read(&mut s).await.is_some() {
            send(
                &mut s,
                RtrVersion::V1,
                Pdu::ErrorReport {
                    error_code: 2,
                    pdu_copy: vec![],
                    text: "still loading".into(),
                },
            )
            .await;
        }
    })
    .await;
    let (handle, changed) = spawn_synced_and_paused(&mut cache).await;
    let before = generation(&changed);

    for _ in 0..70 {
        advance_secs(100).await; // t = 7000
    }
    assert!(both_families_valid(&handle));
    for _ in 0..3 {
        advance_secs(100).await; // t = 7300
    }
    assert!(both_families_not_found(&handle));
    assert_eq!(generation(&changed), before + 1);
}

/// Reconnect back-off must not delay or defer expiry: the cache goes away
/// after the first sync and every reconnect attempt is dropped at once.
#[tokio::test]
async fn expiry_fires_during_disconnect_and_reconnect_backoff() {
    let mut cache = MockCache::spawn(|conn, mut s, tap| async move {
        if conn == 0 {
            dual_family_sync_with(
                &mut s,
                &tap,
                RtrVersion::V1,
                eod_with(1, 1, 3600, 600, 7200),
            )
            .await;
        }
        drop(s);
    })
    .await;
    cache.config.retry_interval = Duration::from_secs(600);
    let (handle, changed) = spawn_synced_and_paused(&mut cache).await;
    let before = generation(&changed);

    advance_secs(7100).await;
    assert!(!handle.status().connected);
    assert!(both_families_valid(&handle), "transient outage keeps data");
    advance_secs(101).await;
    assert!(both_families_not_found(&handle));
    assert_eq!(generation(&changed), before + 1);
}

/// A completed update — and only that — restarts the countdown.
#[tokio::test]
async fn completed_update_renews_the_deadline() {
    let mut cache = MockCache::spawn(|_c, mut s, tap| async move {
        dual_family_sync_with(
            &mut s,
            &tap,
            RtrVersion::V1,
            eod_with(1, 1, 3600, 600, 7200),
        )
        .await;
        // Answer the refresh poll at t = 3600 with an empty change set.
        tap.read(&mut s).await;
        send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
        send(&mut s, RtrVersion::V1, eod_with(1, 2, 3600, 600, 7200)).await;
        // ...and stall every later poll.
        tap.read(&mut s).await;
        hold_open().await;
    })
    .await;
    let (handle, _changed) = spawn_synced_and_paused(&mut cache).await;

    advance_secs(3600).await;
    wait_for("the refresh sync", || handle.status().serial == Some(2)).await;
    // First deadline (t = 7200) is now long past...
    advance_secs(3700).await; // t ≈ 7300
    assert!(
        both_families_valid(&handle),
        "deadline was renewed to ≈ 10800"
    );
    advance_secs(3000).await; // t ≈ 10300
    assert!(both_families_valid(&handle));
    advance_secs(700).await; // t ≈ 11000
    assert!(
        both_families_not_found(&handle),
        "…and the renewed one expires too"
    );
}

/// v0 End of Data carries no intervals (RFC 6810): the configured Expire
/// Interval applies. v1 End of Data carries the cache's value, which wins
/// over the configured one whether it is shorter *or* longer.
async fn expires_after(
    version: RtrVersion,
    advertised: Option<u32>,
    configured: u64,
    just_before: u64,
    just_after: u64,
) {
    let mut cache = MockCache::spawn(move |_c, mut s, tap| async move {
        let end_of_data = match advertised {
            Some(expire) => eod_with(1, 1, 300, 60, expire),
            None => Pdu::EndOfData {
                session_id: 1,
                serial: 1,
                intervals: None,
            },
        };
        dual_family_sync_with(&mut s, &tap, version, end_of_data).await;
        hold_open().await;
    })
    .await;
    cache.config.refresh_interval = Duration::from_secs(300);
    cache.config.expire_interval = Duration::from_secs(configured);
    let (handle, _changed) = spawn_synced_and_paused(&mut cache).await;
    advance_secs(just_before).await;
    assert!(
        both_families_valid(&handle),
        "{version:?}/{advertised:?}/{configured}: must still be valid at {just_before}s"
    );
    advance_secs(just_after - just_before).await;
    assert!(
        both_families_not_found(&handle),
        "{version:?}/{advertised:?}/{configured}: must be gone by {just_after}s"
    );
}

#[tokio::test]
async fn v0_session_expires_after_the_configured_interval() {
    expires_after(RtrVersion::V0, None, 1000, 999, 1001).await;
}

#[tokio::test]
async fn v1_advertised_expire_shorter_than_configured_wins() {
    expires_after(RtrVersion::V1, Some(900), 7200, 899, 901).await;
}

#[tokio::test]
async fn v1_advertised_expire_longer_than_configured_wins() {
    expires_after(RtrVersion::V1, Some(7200), 1000, 7199, 7201).await;
}

/// RFC 8210 §6 allows 600..=172800 s. A cache advertising less (here 5 s)
/// is out of range; honouring it literally would let one bad End of Data
/// empty the cache within seconds, so it is clamped to the minimum.
#[tokio::test]
async fn out_of_range_advertised_expire_is_clamped_to_the_rfc_minimum() {
    expires_after(RtrVersion::V1, Some(5), 7200, 599, 601).await;
}

/// An incremental transfer that began before the cache expired must not be
/// applied on top of the (now empty) table afterwards: the delta is relative
/// to a generation that no longer exists, so applying it would publish a
/// fragment as if it were the cache. The router instead asks for a full load
/// on the same connection.
#[tokio::test]
async fn incremental_transfer_in_flight_at_expiry_is_not_applied_to_the_flushed_cache() {
    let go = Gate::new();
    let go_s = go.clone();
    let finish = Gate::new();
    let finish_s = finish.clone();
    let mut cache = MockCache::spawn(move |_c, mut s, tap| {
        let go = go_s.clone();
        let finish = finish_s.clone();
        async move {
            dual_family_sync_with(
                &mut s,
                &tap,
                RtrVersion::V1,
                eod_with(1, 1, 3600, 600, 7200),
            )
            .await;
            go.wait().await;
            notify(&mut s, RtrVersion::V1, 1, 2).await;
            tap.read(&mut s).await; // Serial Query (immediate, on notify)
            send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
            send(&mut s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
            finish.wait().await;
            send(&mut s, RtrVersion::V1, eod_with(1, 2, 3600, 600, 7200)).await;
            // The router must now ask for everything.
            tap.read(&mut s).await;
            send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
            send(&mut s, RtrVersion::V1, v4("192.0.2.0", 24, 65001)).await;
            send(&mut s, RtrVersion::V1, v6("2001:db8::", 32, 65001)).await;
            send(&mut s, RtrVersion::V1, v4("198.51.100.0", 24, 65020)).await;
            send(&mut s, RtrVersion::V1, eod_with(1, 3, 3600, 600, 7200)).await;
            hold_open().await;
        }
    })
    .await;
    let (handle, _changed) = spawn_synced_and_paused(&mut cache).await;

    go.open();
    settle_io().await;
    assert!(matches!(
        cache.next_seen("Serial Query").await.pdu,
        Pdu::SerialQuery { .. }
    ));
    advance_secs(7201).await;
    assert!(both_families_not_found(&handle), "expired mid-transfer");

    finish.open();
    let next = cache.next_seen("Reset Query after the stale delta").await;
    assert_eq!(
        next.pdu,
        Pdu::ResetQuery,
        "a delta must not be applied to an empty cache"
    );
    assert_eq!(next.conn, 0, "…and no reconnect is needed");
    wait_for("full reload", || handle.status().serial == Some(3)).await;
    assert!(both_families_valid(&handle));
    assert_eq!(validate(&handle, b(), 65020), RoaValidity::Valid);
    assert!(
        !handle.status().expired,
        "a completed sync clears `expired`"
    );
}

// ── #89: a refresh must not lose the bytes of a partially received PDU ───

/// The cache writes the first `split` bytes of a Serial Notify while the
/// router is idle, and the rest only after the router's *timer-driven* Serial
/// Query arrives — so the refresh timer provably fired with exactly `split`
/// bytes of a frame already received. TCP guarantees only the byte stream, so
/// the router must reassemble the Notify and carry on in the same session.
///
/// RFC 8210 §5.2 lets a cache send Serial Notify at any time, and §5.1 makes
/// the Length field, not the transport's segmentation, delimit a PDU.
async fn refresh_with_partial_notify_keeps_the_session(version: RtrVersion, split: usize) {
    const SESSION: u16 = 7;
    let end_of_data = move |serial: u32| match version {
        RtrVersion::V0 => Pdu::EndOfData {
            session_id: SESSION,
            serial,
            intervals: None,
        },
        // 1 s is the smallest Refresh Interval §6 allows a cache to advertise.
        RtrVersion::V1 => eod_with(SESSION, serial, 1, 600, 7200),
    };
    let mut cache = MockCache::spawn(move |conn, mut s, tap| async move {
        use tokio::io::AsyncWriteExt;
        if conn != 0 {
            hold_open().await;
        }
        tap.read(&mut s).await; // Reset Query
        send(
            &mut s,
            version,
            Pdu::CacheResponse {
                session_id: SESSION,
            },
        )
        .await;
        send(&mut s, version, end_of_data(1)).await;
        let notify = crate::pdu::encode(
            version,
            &Pdu::SerialNotify {
                session_id: SESSION,
                serial: 2,
            },
        );
        s.write_all(&notify[..split]).await.unwrap();
        tap.read(&mut s).await; // Serial Query, sent because the timer fired
        s.write_all(&notify[split..]).await.unwrap();
        send(
            &mut s,
            version,
            Pdu::CacheResponse {
                session_id: SESSION,
            },
        )
        .await;
        send(&mut s, version, end_of_data(2)).await;
        // Anything further (an Error Report in particular) is reported.
        while tap.read(&mut s).await.is_some() {}
        hold_open().await;
    })
    .await;
    cache.config.initial_version = version;
    // v0 End of Data carries no intervals, so the configured one applies.
    if version == RtrVersion::V0 {
        cache.config.refresh_interval = Duration::from_millis(200);
    }

    let (handle, join) = RtrClient::spawn(cache.config.clone());
    let ctx = format!("{version:?}, split at byte {split}");
    cache.next_seen("Reset Query").await;
    let query = cache.next_seen("timer-driven Serial Query").await;
    assert_eq!(
        query.pdu,
        Pdu::SerialQuery {
            session_id: SESSION,
            serial: 1
        },
        "{ctx}"
    );
    wait_for(&format!("the refresh to complete ({ctx})"), || {
        handle.status().serial == Some(2) || !handle.status().connected
    })
    .await;
    let status = handle.status();
    assert_eq!(
        (status.connected, status.serial, status.last_error),
        (true, Some(2), None),
        "{ctx}: the refresh must complete on the original session"
    );
    assert_eq!(cache.accepted(), 1, "{ctx}: no reconnect");
    join.abort();
}

/// Every proper split point of the 12-byte Serial Notify: all seven partial
/// headers, the exact header boundary, and all partial bodies.
async fn every_split_of_a_notify(version: RtrVersion) {
    let cases: Vec<_> = (1..12)
        .map(|split| {
            tokio::spawn(refresh_with_partial_notify_keeps_the_session(
                version, split,
            ))
        })
        .collect();
    let mut failed = Vec::new();
    for (split, case) in (1..12).zip(cases) {
        if case.await.is_err() {
            failed.push(split);
        }
    }
    assert!(
        failed.is_empty(),
        "{version:?}: lost bytes at splits {failed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_timer_mid_notify_loses_no_bytes_v1() {
    every_split_of_a_notify(RtrVersion::V1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_timer_mid_notify_loses_no_bytes_v0() {
    every_split_of_a_notify(RtrVersion::V0).await;
}

// ── #91: prefix tuple bounds ─────────────────────────────────────────────
//
// RFC 8210 §5.1: Max Length "MUST NOT be less than the Prefix Length
// element." §5.6 / §5.7: Prefix Length and Max Length are 0..32 for IPv4 and
// 0..128 for IPv6 (RFC 6810 §5 says the same for version 0). §12 code 0,
// "Corrupt Data (fatal)": "The receiver believes the received PDU to be
// corrupt in a manner not specified by another error code", and "Errors which
// are considered fatal MUST cause the session to be dropped." §5.11: the
// Error Report carries the erroneous PDU.
//
// The PDUs are written as raw bytes: a conforming encoder must not be able to
// produce them.

#[derive(Debug, Clone, Copy)]
struct RawPrefix {
    v6: bool,
    flags: u8,
    prefix_len: u8,
    max_len: u8,
    asn: u32,
}

impl RawPrefix {
    /// Bytes of an IPv4 (192.0.2.0) or IPv6 (`2001:db8::`) Prefix PDU.
    fn bytes(self, version: RtrVersion) -> Vec<u8> {
        let address: Vec<u8> = if self.v6 {
            "2001:db8::"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
        } else {
            "192.0.2.0".parse::<Ipv4Addr>().unwrap().octets().to_vec()
        };
        let mut out = vec![u8::from(version == RtrVersion::V1)];
        out.push(if self.v6 { 6 } else { 4 });
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(if self.v6 { 32u32 } else { 20 }).to_be_bytes());
        out.extend_from_slice(&[self.flags, self.prefix_len, self.max_len, 0]);
        out.extend_from_slice(&address);
        out.extend_from_slice(&self.asn.to_be_bytes());
        out
    }
}

/// `(v6, prefix_len, max_len)` tuples the RFC forbids.
const IMPOSSIBLE_TUPLES: &[(bool, u8, u8)] = &[
    (false, 24, 16), // Max Length below Prefix Length
    (false, 32, 31), // ... by one, at the family limit
    (false, 33, 33), // Prefix Length above 32
    (false, 24, 33), // Max Length above 32
    (false, 0, 255), // ... at the field's limit
    (false, 255, 255),
    (true, 48, 32), // Max Length below Prefix Length
    (true, 128, 127),
    (true, 129, 129), // Prefix Length above 128
    (true, 64, 129),  // Max Length above 128
    (true, 255, 255),
];

/// Initial sync of one VRP, then an incremental update that carries one
/// valid record followed by `bad`.
async fn corrupt_record_in_an_update(version: RtrVersion, bad: RawPrefix) {
    let go = Gate::new();
    let go_s = go.clone();
    let end_of_data = move |serial: u32| match version {
        RtrVersion::V0 => Pdu::EndOfData {
            session_id: 1,
            serial,
            intervals: None,
        },
        RtrVersion::V1 => eod(1, serial),
    };
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let go = go_s.clone();
        async move {
            use tokio::io::AsyncWriteExt;
            tap.read(&mut s).await;
            if conn != 0 {
                hold_open().await;
            }
            send(&mut s, version, Pdu::CacheResponse { session_id: 1 }).await;
            send(&mut s, version, v4("192.0.2.0", 24, 65001)).await;
            send(&mut s, version, end_of_data(1)).await;
            go.wait().await;
            send(
                &mut s,
                version,
                Pdu::SerialNotify {
                    session_id: 1,
                    serial: 2,
                },
            )
            .await;
            tap.read(&mut s).await; // Serial Query
            send(&mut s, version, Pdu::CacheResponse { session_id: 1 }).await;
            send(&mut s, version, v4("198.51.100.0", 24, 65020)).await;
            s.write_all(&bad.bytes(version)).await.unwrap();
            // The router may already have dropped the connection.
            let _ = s
                .write_all(&crate::pdu::encode(version, &end_of_data(2)))
                .await;
            tap.read(&mut s).await; // the Error Report
            hold_open().await;
        }
    })
    .await;
    cache.config.initial_version = version;

    let ctx = format!("{version:?} {bad:?}");
    let (handle, join) = RtrClient::spawn(cache.config.clone());
    let changed = handle.subscribe();
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    let before = generation(&changed);
    go.open();
    cache.next_seen("Serial Query").await;

    wait_for(&format!("the session to be dropped ({ctx})"), || {
        !handle.status().connected || handle.status().serial == Some(2)
    })
    .await;
    assert!(
        !handle.status().connected,
        "{ctx}: corrupt data was committed"
    );

    // Nothing of the failed update is visible, and the old data is intact.
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid, "{ctx}");
    assert_eq!(
        validate(&handle, b(), 65020),
        RoaValidity::NotFound,
        "{ctx}"
    );
    assert_eq!(handle.status().roa_count, 1, "{ctx}");
    assert_eq!(generation(&changed), before, "{ctx}: nothing completed");

    let report = cache.next_seen("Error Report").await;
    assert_eq!(report.conn, 0, "{ctx}");
    assert_eq!(report.version, version, "{ctx}");
    assert_eq!(error_report(&report), (0, bad.bytes(version)), "{ctx}");

    // The refused delta would be refused again: ask for the full set.
    let reconnect = cache.next_seen("first PDU after reconnect").await;
    assert_eq!(
        (reconnect.conn, reconnect.pdu),
        (1, Pdu::ResetQuery),
        "{ctx}"
    );
    join.abort();
}

#[tokio::test]
async fn impossible_prefix_tuples_are_corrupt_data_v1() {
    for &(v6, prefix_len, max_len) in IMPOSSIBLE_TUPLES {
        for flags in [1, 0] {
            let bad = RawPrefix {
                v6,
                flags,
                prefix_len,
                max_len,
                asn: 65020,
            };
            corrupt_record_in_an_update(RtrVersion::V1, bad).await;
        }
    }
}

#[tokio::test]
async fn impossible_prefix_tuples_are_corrupt_data_v0() {
    for &(v6, prefix_len, max_len) in IMPOSSIBLE_TUPLES {
        let bad = RawPrefix {
            v6,
            flags: 1,
            prefix_len,
            max_len,
            asn: 65020,
        };
        corrupt_record_in_an_update(RtrVersion::V0, bad).await;
    }
}

/// The boundaries of the legal ranges are accepted, as are set reserved Flags
/// bits and a non-zero reserved octet (§5: reserved fields "MUST be ignored
/// on receipt").
#[tokio::test]
async fn boundary_prefix_tuples_and_reserved_bits_are_accepted() {
    let cases = [
        (false, 0, 0),
        (false, 0, 32),
        (false, 32, 32),
        (true, 0, 0),
        (true, 0, 128),
        (true, 128, 128),
    ];
    let mut cache = MockCache::spawn(move |_, mut s, tap| async move {
        use tokio::io::AsyncWriteExt;
        tap.read(&mut s).await;
        send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
        for (i, (v6, prefix_len, max_len)) in (0u32..).zip(cases) {
            let mut bytes = RawPrefix {
                v6,
                flags: 0xff, // announce, with every reserved bit set
                prefix_len,
                max_len,
                asn: 64500 + i,
            }
            .bytes(RtrVersion::V1);
            bytes[11] = 0xff; // the reserved "zero" octet
            s.write_all(&bytes).await.unwrap();
        }
        send(&mut s, RtrVersion::V1, eod(1, 1)).await;
        hold_open().await;
    })
    .await;
    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    wait_for("the sync", || handle.status().serial == Some(1)).await;
    assert_eq!(handle.status().roa_count, cases.len());
    // The /32 and /128 VRPs match exactly their own host route.
    assert_eq!(
        handle.validate_v4("192.0.2.0".parse().unwrap(), 32, 64502),
        RoaValidity::Valid
    );
    assert_eq!(
        handle.validate_v6("2001:db8::".parse().unwrap(), 128, 64505),
        RoaValidity::Valid
    );
}

/// The same for the very first (Reset Query) load: nothing at all becomes
/// visible. Before the bounds were checked, the 192.0.2.0/24 "max length 16"
/// record below was installed and made every route under it `Invalid`
/// (RFC 6811 §2: covered, never matched).
#[tokio::test]
async fn impossible_tuple_in_the_initial_load_publishes_nothing() {
    let bad = RawPrefix {
        v6: false,
        flags: 1,
        prefix_len: 24,
        max_len: 16,
        asn: 65001,
    };
    let mut cache = MockCache::spawn(move |conn, mut s, tap| async move {
        use tokio::io::AsyncWriteExt;
        tap.read(&mut s).await;
        if conn != 0 {
            hold_open().await;
        }
        send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
        s.write_all(&bad.bytes(RtrVersion::V1)).await.unwrap();
        tap.read(&mut s).await; // the Error Report
        hold_open().await;
    })
    .await;
    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    let report = cache.next_seen("Error Report").await;
    assert_eq!(error_report(&report), (0, bad.bytes(RtrVersion::V1)));
    wait_for("the session to be dropped", || {
        handle.status().last_error.is_some()
    })
    .await;
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::NotFound);
    let status = handle.status();
    assert_eq!((status.roa_count, status.serial), (0, None));
    assert_eq!(
        status.last_error.as_deref(),
        Some("RTR PDU error: invalid Prefix PDU: Max Length 16 is less than Prefix Length 24")
    );
}

/// A corrupt PDU is corrupt whenever it arrives, including between exchanges.
#[tokio::test]
async fn impossible_tuple_while_idle_is_reported_as_corrupt_data() {
    let bad = RawPrefix {
        v6: true,
        flags: 1,
        prefix_len: 129,
        max_len: 129,
        asn: 65001,
    };
    let mut cache = MockCache::spawn(move |conn, mut s, tap| async move {
        use tokio::io::AsyncWriteExt;
        tap.read(&mut s).await;
        if conn != 0 {
            hold_open().await;
        }
        send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
        send(&mut s, RtrVersion::V1, v4("192.0.2.0", 24, 65001)).await;
        send(&mut s, RtrVersion::V1, eod(1, 1)).await;
        s.write_all(&bad.bytes(RtrVersion::V1)).await.unwrap();
        tap.read(&mut s).await; // the Error Report
        hold_open().await;
    })
    .await;
    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    let report = cache.next_seen("Error Report").await;
    assert_eq!(error_report(&report), (0, bad.bytes(RtrVersion::V1)));
    assert_eq!(
        validate(&handle, a(), 65001),
        RoaValidity::Valid,
        "completed data stays"
    );
}

/// Address bits beyond the Prefix Length are not part of the Prefix (RFC 6811
/// §2), so they distinguish neither the VRP nor its withdrawal.
#[tokio::test]
async fn trailing_address_bits_do_not_affect_a_vrp_or_its_withdrawal() {
    let go = Gate::new();
    let go_s = go.clone();
    let mut cache = MockCache::spawn(move |_, mut s, tap| {
        let go = go_s.clone();
        async move {
            tap.read(&mut s).await;
            send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
            send(&mut s, RtrVersion::V1, v4("192.0.2.99", 24, 65001)).await;
            send(&mut s, RtrVersion::V1, eod(1, 1)).await;
            go.wait().await;
            notify(&mut s, RtrVersion::V1, 1, 2).await;
            tap.read(&mut s).await;
            send(&mut s, RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }).await;
            send(
                &mut s,
                RtrVersion::V1,
                withdraw(v4("192.0.2.200", 24, 65001)),
            )
            .await;
            send(&mut s, RtrVersion::V1, eod(1, 2)).await;
            hold_open().await;
        }
    })
    .await;
    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    cache.next_seen("Reset Query").await;
    wait_for("first sync", || handle.status().serial == Some(1)).await;
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::Valid);
    go.open();
    wait_for("withdrawal", || handle.status().serial == Some(2)).await;
    assert_eq!(validate(&handle, a(), 65001), RoaValidity::NotFound);
    assert_eq!(handle.status().roa_count, 0);
}

// ── Error Reports for other malformed input ──────────────────────────────
//
// RFC 8210 §12: code 0 "Corrupt Data", code 4 "Unsupported Protocol
// Version" ("The Protocol Version is not known by the receiver"), code 5
// "Unsupported PDU Type", code 8 "Unexpected Protocol Version" — all fatal,
// and "Errors which are considered fatal MUST cause the session to be
// dropped" (RFC 6810 §10 lists the same codes 0, 4 and 5 for version 0).
// §5.11: "An Error Report PDU MUST NOT be sent for an Error Report PDU. If
// an erroneous Error Report PDU is received, the session SHOULD be dropped."
// "If the error is associated with a PDU of excessive length ... or a
// possibly corrupt length, the Erroneous PDU field MAY be truncated" — so
// otherwise the whole offending PDU is echoed.
//
// The offending PDUs are written as raw bytes, and the client's reply is
// parsed here field by field, so neither relies on the crate's codec.

const UNSUPPORTED_PROTOCOL_VERSION: u16 = 4;
const UNSUPPORTED_PDU_TYPE: u16 = 5;

const SERIAL_NOTIFY: u8 = 0;
const CACHE_RESPONSE: u8 = 3;
const IPV4_PREFIX: u8 = 4;
const IPV6_PREFIX: u8 = 6;
const END_OF_DATA: u8 = 7;
const CACHE_RESET: u8 = 8;
const ERROR_REPORT: u8 = 10;

fn version_byte(version: RtrVersion) -> u8 {
    u8::from(version == RtrVersion::V1)
}

/// A header declaring `len`, followed by `body` — the two need not agree.
fn raw_pdu(version: u8, pdu_type: u8, len: u32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![version, pdu_type, 0, 1];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A PDU whose Length is truthful about its (patterned) `body`.
fn sized_pdu(version: u8, pdu_type: u8, body_len: usize) -> Vec<u8> {
    let body: Vec<u8> = (0u8..=250).cycle().take(body_len).collect();
    raw_pdu(
        version,
        pdu_type,
        8 + u32::try_from(body_len).unwrap(),
        &body,
    )
}

fn end_of_data(version: RtrVersion, serial: u32) -> Pdu {
    match version {
        RtrVersion::V0 => Pdu::EndOfData {
            session_id: 1,
            serial,
            intervals: None,
        },
        RtrVersion::V1 => eod(1, serial),
    }
}

/// Where in the session the offending bytes arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum When {
    /// In reply to the Serial Query that opens a new connection: RFC 8210 §7
    /// negotiation is not complete.
    Negotiating,
    /// After a Cache Response and one record: the version is agreed.
    MidTransfer,
    /// After a completed sync, between exchanges.
    Idle,
}

const ALWAYS: [When; 3] = [When::Negotiating, When::MidTransfer, When::Idle];
const AFTER_AGREEMENT: [When; 2] = [When::MidTransfer, When::Idle];

/// What the client did about the offending bytes.
struct Reaction {
    /// Every byte it sent between receiving them and closing the connection.
    reply: Vec<u8>,
    /// The first PDU on its next connection.
    next_query: Pdu,
    /// A VRP from the completed sync is still served, and nothing from the
    /// failed transfer is.
    data_intact: bool,
    /// `status().serial` once it had reconnected.
    serial: Option<u32>,
}

/// Completes a first sync (VRP A, serial 1), then has the cache send
/// `offence` at the point `when` and reports the client's reaction. Fails if
/// the client does not close that connection.
async fn offend(version: RtrVersion, when: When, offence: Vec<u8>) -> Reaction {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
    let offending_conn = usize::from(when == When::Negotiating);
    let mut cache = MockCache::spawn(move |conn, mut s, tap| {
        let offence = offence.clone();
        let reply_tx = reply_tx.clone();
        async move {
            if conn > offending_conn {
                tap.read(&mut s).await;
                hold_open().await;
            }
            tap.read(&mut s).await; // Reset Query, or Serial Query on conn 1
            if conn == 0 {
                send(&mut s, version, Pdu::CacheResponse { session_id: 1 }).await;
                send(&mut s, version, v4("192.0.2.0", 24, 65001)).await;
                send(&mut s, version, end_of_data(version, 1)).await;
                if when == When::Negotiating {
                    return; // close; the client reconnects and resumes
                }
            }
            if when == When::MidTransfer {
                send(
                    &mut s,
                    version,
                    Pdu::SerialNotify {
                        session_id: 1,
                        serial: 2,
                    },
                )
                .await;
                tap.read(&mut s).await; // Serial Query
                send(&mut s, version, Pdu::CacheResponse { session_id: 1 }).await;
                send(&mut s, version, v4("198.51.100.0", 24, 65020)).await;
            }
            s.write_all(&offence).await.unwrap();
            let mut reply = Vec::new();
            // A reset instead of a clean close still ends the connection.
            let _ = s.read_to_end(&mut reply).await;
            let _ = reply_tx.send(reply);
        }
    })
    .await;
    cache.config.initial_version = version;

    let (handle, join) = RtrClient::spawn(cache.config.clone());
    let reply = tokio::time::timeout(Duration::from_secs(5), reply_rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{version:?} {when:?}: the session was not dropped"))
        .unwrap();
    let next_query = loop {
        let seen = cache.next_seen("first PDU after reconnect").await;
        if seen.conn > offending_conn {
            break seen.pdu;
        }
    };
    let reaction = Reaction {
        reply,
        next_query,
        data_intact: validate(&handle, a(), 65001) == RoaValidity::Valid
            && validate(&handle, b(), 65020) == RoaValidity::NotFound
            && handle.status().roa_count == 1,
        serial: handle.status().serial,
    };
    join.abort();
    reaction
}

/// What becomes of the resume point. Either way the completed VRPs stay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resume {
    /// The next query is the same Serial Query (§8.1: appropriate after "a
    /// broken session with the same cache").
    Kept,
    /// The next query is a Reset Query.
    Forgotten,
}

fn assert_resume(reaction: &Reaction, expected: Resume, ctx: &str) {
    assert!(reaction.data_intact, "{ctx}: completed data must stay");
    let (query, serial) = match expected {
        Resume::Kept => (
            Pdu::SerialQuery {
                session_id: 1,
                serial: 1,
            },
            Some(1),
        ),
        Resume::Forgotten => (Pdu::ResetQuery, None),
    };
    assert_eq!(
        (&reaction.next_query, reaction.serial),
        (&query, serial),
        "{ctx}"
    );
}

/// The reply must be exactly one Error Report (§5.11 layout). Returns its
/// Protocol Version, Error Code, Erroneous PDU and Error Text.
fn parse_report(reply: &[u8], ctx: &str) -> (u8, u16, Vec<u8>, String) {
    assert!(
        reply.len() >= 16,
        "{ctx}: expected an Error Report, got {reply:?}"
    );
    let be32 = |at: usize| u32::from_be_bytes(reply[at..at + 4].try_into().unwrap()) as usize;
    assert_eq!(reply[1], ERROR_REPORT, "{ctx}: PDU type");
    assert_eq!(be32(4), reply.len(), "{ctx}: exactly one PDU");
    let copy_len = be32(8);
    let text_at = 12 + copy_len;
    assert_eq!(text_at + 4 + be32(text_at), reply.len(), "{ctx}: lengths");
    (
        reply[0],
        u16::from_be_bytes([reply[2], reply[3]]),
        reply[12..text_at].to_vec(),
        String::from_utf8(reply[text_at + 4..].to_vec()).unwrap(),
    )
}

/// One offence that must be answered with an Error Report.
#[derive(Debug, Clone)]
struct Reported {
    /// Version of the session the offence arrives in.
    session: RtrVersion,
    when: When,
    offence: Vec<u8>,
    code: u16,
    /// The expected Erroneous PDU field.
    echo: Vec<u8>,
    resume: Resume,
}

impl Reported {
    async fn check(self) {
        let ctx = format!(
            "{:?} session, {:?}, offence {:?}",
            self.session,
            self.when,
            &self.offence[..self.offence.len().min(24)]
        );
        let reaction = offend(self.session, self.when, self.offence).await;
        let (version, code, echo, text) = parse_report(&reaction.reply, &ctx);
        assert_eq!(code, self.code, "{ctx}: error code ({text})");
        assert_eq!(version, version_byte(self.session), "{ctx}: report version");
        assert_eq!(echo, self.echo, "{ctx}: Erroneous PDU");
        assert_resume(&reaction, self.resume, &ctx);
    }
}

/// Runs independent cases concurrently, reporting every failure.
async fn check_all(cases: Vec<Reported>) {
    let total = cases.len();
    let running: Vec<_> = cases
        .into_iter()
        .map(|case| tokio::spawn(case.check()))
        .collect();
    let mut failed = 0;
    for case in running {
        failed += usize::from(case.await.is_err());
    }
    assert_eq!(failed, 0, "{failed} of {total} cases failed (see above)");
}

/// §12 code 5. Type 5 is unused and 11 upwards unassigned in both versions.
/// A refused record in a change set would be refused again from the same
/// serial, so the resume point is forgotten (this client's choice, as for a
/// forbidden prefix; the RFCs do not say).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_pdu_type_is_answered_with_error_5() {
    let mut cases = Vec::new();
    for session in [RtrVersion::V0, RtrVersion::V1] {
        for when in ALWAYS {
            for (pdu_type, body_len) in [(5, 0), (11, 4), (255, 12)] {
                let offence = sized_pdu(version_byte(session), pdu_type, body_len);
                cases.push(Reported {
                    session,
                    when,
                    echo: offence.clone(),
                    offence,
                    code: UNSUPPORTED_PDU_TYPE,
                    resume: Resume::Forgotten,
                });
            }
        }
    }
    check_all(cases).await;
}

/// §12 code 0 for a Length no PDU can have: shorter than the header, or past
/// this client's 64 KiB bound. Only the header can be echoed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn impossible_length_is_answered_with_error_0() {
    let mut cases = Vec::new();
    for session in [RtrVersion::V0, RtrVersion::V1] {
        for when in ALWAYS {
            for len in [0, 7, 65_537, u32::MAX] {
                let offence = raw_pdu(version_byte(session), CACHE_RESET, len, &[]);
                cases.push(Reported {
                    session,
                    when,
                    echo: offence.clone(),
                    offence,
                    code: CORRUPT_DATA,
                    resume: Resume::Forgotten,
                });
            }
        }
    }
    check_all(cases).await;
}

/// §12 code 0 for a Length that is wrong for the PDU type (§§5.2–5.9 give
/// each fixed-size PDU its Length).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_length_for_the_type_is_answered_with_error_0() {
    use RtrVersion::{V0, V1};
    // (session version, PDU type, wrong body length)
    let wrong = [
        (V1, SERIAL_NOTIFY, 0),
        (V1, SERIAL_NOTIFY, 8),
        (V1, CACHE_RESPONSE, 4),
        (V1, IPV4_PREFIX, 11),
        (V1, IPV4_PREFIX, 16),
        (V1, IPV6_PREFIX, 12),
        (V1, END_OF_DATA, 4),  // the version 0 Length
        (V0, END_OF_DATA, 16), // the version 1 Length
        (V1, CACHE_RESET, 1),
        (V0, SERIAL_NOTIFY, 8),
    ];
    let mut cases = Vec::new();
    for (session, pdu_type, body_len) in wrong {
        for when in ALWAYS {
            let offence = sized_pdu(version_byte(session), pdu_type, body_len);
            cases.push(Reported {
                session,
                when,
                echo: offence.clone(),
                offence,
                code: CORRUPT_DATA,
                resume: Resume::Forgotten,
            });
        }
    }
    check_all(cases).await;
}

/// §5.11 allows truncating the echo of a PDU "too long to be any legal PDU
/// other than another Error Report"; a hostile one is not echoed in full.
#[tokio::test]
async fn an_oversized_offending_pdu_is_echoed_truncated() {
    let offence = sized_pdu(1, CACHE_RESPONSE, 4000);
    Reported {
        session: RtrVersion::V1,
        when: When::MidTransfer,
        echo: offence[..256].to_vec(),
        offence,
        code: CORRUPT_DATA,
        resume: Resume::Forgotten,
    }
    .check()
    .await;
}

/// §7: "If either party receives a PDU containing an unrecognized Protocol
/// Version (neither 0 nor 1) during this negotiation, it MUST either
/// downgrade to a known version or terminate the connection, with an Error
/// Report PDU unless the received PDU is itself an Error Report PDU." This
/// client terminates, with code 4. Nothing is wrong with the data or the
/// serial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_version_during_negotiation_is_answered_with_error_4() {
    let mut cases = Vec::new();
    for session in [RtrVersion::V0, RtrVersion::V1] {
        for wire in [2, 255] {
            for (pdu_type, body_len) in [
                (CACHE_RESPONSE, 0),
                (CACHE_RESET, 0),
                (IPV4_PREFIX, 12),
                (99, 4), // version is judged before the type
            ] {
                let offence = sized_pdu(wire, pdu_type, body_len);
                cases.push(Reported {
                    session,
                    when: When::Negotiating,
                    echo: offence.clone(),
                    offence,
                    code: UNSUPPORTED_PROTOCOL_VERSION,
                    resume: Resume::Kept,
                });
            }
        }
        // An unrecognized version whose Length cannot be trusted either.
        let offence = raw_pdu(2, CACHE_RESPONSE, 3, &[]);
        cases.push(Reported {
            session,
            when: When::Negotiating,
            echo: offence.clone(),
            offence,
            code: UNSUPPORTED_PROTOCOL_VERSION,
            resume: Resume::Kept,
        });
    }
    check_all(cases).await;
}

/// §7: "If either party receives a PDU for a different Protocol Version once
/// the above negotiation completes, that party MUST drop the session; ... the
/// party dropping the session SHOULD send an Error Report with an error code
/// of 8". An unrecognized version is a different one, Serial Notify included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_version_after_negotiation_is_answered_with_error_8() {
    let mut cases = Vec::new();
    for session in [RtrVersion::V0, RtrVersion::V1] {
        for when in AFTER_AGREEMENT {
            for (pdu_type, body_len) in [(SERIAL_NOTIFY, 4), (CACHE_RESPONSE, 0), (99, 4)] {
                let offence = sized_pdu(2, pdu_type, body_len);
                cases.push(Reported {
                    session,
                    when,
                    echo: offence.clone(),
                    offence,
                    code: UNEXPECTED_PROTOCOL_VERSION,
                    resume: Resume::Kept,
                });
            }
        }
    }
    check_all(cases).await;
}

/// The same §7 clause comes first when the PDU of the other (known) version
/// is also malformed: its type and Length belong to a version this session
/// does not speak.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_pdu_at_the_other_version_after_negotiation_is_error_8() {
    let mut cases = Vec::new();
    for (session, other) in [(RtrVersion::V1, 0), (RtrVersion::V0, 1)] {
        for when in AFTER_AGREEMENT {
            for offence in [
                sized_pdu(other, 11, 4),
                sized_pdu(other, CACHE_RESET, 4),
                raw_pdu(other, CACHE_RESET, 7, &[]),
            ] {
                cases.push(Reported {
                    session,
                    when,
                    echo: offence.clone(),
                    offence,
                    code: UNEXPECTED_PROTOCOL_VERSION,
                    resume: Resume::Kept,
                });
            }
        }
    }
    check_all(cases).await;
}

/// §7: "The router MUST ignore any Serial Notify PDUs it might receive from
/// the cache during this initial startup period, regardless of the Protocol
/// Version field in the Serial Notify PDU" (§5.2: "even if the Serial Notify
/// PDU is for an unexpected protocol version"). That includes versions this
/// client does not know: the session carries on, and nothing is sent back.
#[tokio::test]
async fn serial_notify_of_unknown_version_during_negotiation_is_ignored() {
    for session in [RtrVersion::V0, RtrVersion::V1] {
        let mut cache = MockCache::spawn(move |conn, mut s, tap| async move {
            use tokio::io::AsyncWriteExt;
            if conn != 0 {
                hold_open().await;
            }
            tap.read(&mut s).await; // Reset Query
            let notify = sized_pdu(2, SERIAL_NOTIFY, 4);
            // Split inside the header and inside the body.
            for piece in [&notify[..3], &notify[3..10], &notify[10..]] {
                s.write_all(piece).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = s.write_all(&sized_pdu(255, SERIAL_NOTIFY, 4)).await;
            let _ = write_pdu(&mut s, session, &Pdu::CacheResponse { session_id: 1 }).await;
            let _ = write_pdu(&mut s, session, &v4("192.0.2.0", 24, 65001)).await;
            let _ = write_pdu(&mut s, session, &end_of_data(session, 1)).await;
            // Anything the router says now (an Error Report) is reported.
            while tap.read(&mut s).await.is_some() {}
            hold_open().await;
        })
        .await;
        cache.config.initial_version = session;
        let (handle, join) = RtrClient::spawn(cache.config.clone());
        cache.next_seen("Reset Query").await;
        wait_for("the sync, or a failure", || {
            handle.status().serial == Some(1) || handle.status().last_error.is_some()
        })
        .await;
        let status = handle.status();
        assert_eq!(
            (status.connected, status.serial, status.last_error),
            (true, Some(1), None),
            "{session:?}"
        );
        settle().await;
        assert!(
            cache.seen.try_recv().is_err(),
            "{session:?}: nothing is sent in reply"
        );
        assert_eq!(cache.accepted(), 1, "{session:?}: no reconnect");
        join.abort();
    }
}

/// A Serial Notify is 12 bytes (§5.2). One of an unknown version with any
/// other Length is not something to skip over.
#[tokio::test]
async fn wrong_length_serial_notify_of_unknown_version_is_not_ignored() {
    let offence = sized_pdu(2, SERIAL_NOTIFY, 8);
    Reported {
        session: RtrVersion::V1,
        when: When::Negotiating,
        echo: offence.clone(),
        offence,
        code: UNSUPPORTED_PROTOCOL_VERSION,
        resume: Resume::Kept,
    }
    .check()
    .await;
}

/// An Error Report body: the two inner lengths need not be truthful.
fn report_body(copy_len: u32, copy: &[u8], text_len: u32, text: &[u8]) -> Vec<u8> {
    let mut body = copy_len.to_be_bytes().to_vec();
    body.extend_from_slice(copy);
    body.extend_from_slice(&text_len.to_be_bytes());
    body.extend_from_slice(text);
    body
}

/// §5.11: "An Error Report PDU MUST NOT be sent for an Error Report PDU. If
/// an erroneous Error Report PDU is received, the session SHOULD be dropped."
/// (§7 repeats the exception for both version rules.) Whatever is wrong with
/// it, and whenever it arrives, the client says nothing and closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_error_report_is_ever_sent_for_an_error_report() {
    let report = |version: u8, body: &[u8]| {
        raw_pdu(
            version,
            ERROR_REPORT,
            8 + u32::try_from(body.len()).unwrap(),
            body,
        )
    };
    let well_formed = report_body(0, &[], 2, b"no");
    let mut cases = Vec::new();
    for session in [RtrVersion::V0, RtrVersion::V1] {
        let v = version_byte(session);
        for offence in [
            report(v, &report_body(500, &[], 0, &[])), // copy overruns
            report(v, &report_body(0, &[], 500, &[])), // text overruns
            report(v, &report_body(0, &[], 2, &[0xc3, 0x28])), // not UTF-8
            report(v, &[0, 0, 0, 0]),                  // no text length
            report(v, &[]),                            // header only
            raw_pdu(v, ERROR_REPORT, 7, &[]),
            raw_pdu(v, ERROR_REPORT, 65_537, &[]),
            report(2, &well_formed),
            report(2, &report_body(500, &[], 0, &[])),
            raw_pdu(2, ERROR_REPORT, 7, &[]),
            report(1 - v, &report_body(500, &[], 0, &[])),
        ] {
            for when in ALWAYS {
                let offence = offence.clone();
                cases.push(tokio::spawn(async move {
                    let ctx = format!("{session:?} {when:?} {offence:?}");
                    let reaction = offend(session, when, offence).await;
                    assert_eq!(reaction.reply, [0u8; 0], "{ctx}");
                    assert_resume(&reaction, Resume::Kept, &ctx);
                }));
            }
        }
    }
    for case in cases {
        case.await.unwrap();
    }
}

/// §7 case 1: a v0-only cache "may terminate the connection, perhaps with a
/// version 0 Error Report PDU. In this case, the router MAY retry the
/// connection using protocol version 0."
#[tokio::test]
async fn fallback_survives_a_cache_that_closes_after_rejecting_v1() {
    let mut cache = MockCache::spawn(|conn, mut s, tap| async move {
        use tokio::io::AsyncWriteExt;
        tap.read(&mut s).await;
        if conn == 0 {
            let body = report_body(0, &[], 0, &[]);
            let mut rejection = raw_pdu(0, ERROR_REPORT, 16, &body);
            rejection[3] = 4; // Unsupported Protocol Version
            s.write_all(&rejection).await.unwrap();
            return;
        }
        send(&mut s, RtrVersion::V0, Pdu::CacheResponse { session_id: 1 }).await;
        send(&mut s, RtrVersion::V0, end_of_data(RtrVersion::V0, 1)).await;
        hold_open().await;
    })
    .await;
    let (handle, _join) = RtrClient::spawn(cache.config.clone());
    wait_for("a version 0 sync", || handle.status().serial == Some(1)).await;
    assert_eq!(handle.status().version, Some(RtrVersion::V0));
    let mut last = cache.next_seen("v1 Reset Query").await;
    assert_eq!((last.conn, last.version), (0, RtrVersion::V1));
    while last.conn == 0 {
        // Only queries: never an Error Report in reply to the rejection.
        last = cache.next_seen("v0 Reset Query").await;
        assert_eq!(last.pdu, Pdu::ResetQuery);
        assert_eq!(last.version, RtrVersion::V0);
    }
}

// ── Cost report ──────────────────────────────────────────────────────────

/// Full-load wall time, from the router's Reset Query reaching the cache to
/// the completed-sync notification, over loopback TCP with the whole response
/// written at once. Run with
/// `cargo test --release -p pathvector-rpki -- --ignored --nocapture sync_cost`.
///
/// Each run opens ~600 short connections; many back-to-back runs exhaust the
/// ephemeral port range (reported as a stall with the connect error).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark: prints timings, asserts nothing"]
async fn sync_cost_report() {
    use tokio::io::AsyncWriteExt;

    for (records, iterations) in [(100u32, 301), (1_000, 201), (10_000, 101)] {
        let mut response =
            crate::pdu::encode(RtrVersion::V1, &Pdu::CacheResponse { session_id: 1 });
        for i in 0..records {
            let address = Ipv4Addr::from(0x0a00_0000 + (i << 8));
            response.extend(crate::pdu::encode(
                RtrVersion::V1,
                &v4(&address.to_string(), 24, 64500),
            ));
        }
        response.extend(crate::pdu::encode(RtrVersion::V1, &eod(1, 1)));
        let response = Arc::new(response);

        let mut samples = Vec::new();
        for _ in 0..iterations {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let response = Arc::clone(&response);
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                read_pdu(&mut s).await.unwrap();
                let _ = started_tx.send(std::time::Instant::now());
                s.write_all(&response).await.unwrap();
                hold_open().await;
            });
            let (handle, join) = RtrClient::spawn(RtrConfig {
                port,
                ..Default::default()
            });
            let mut changed = handle.subscribe();
            // A failed attempt would sit out the 600 s retry interval: say why
            // instead.
            let stalled = |handle: &RtrHandle| -> ! {
                panic!("sync stalled: {:?}", handle.status().last_error)
            };
            let limit = Duration::from_secs(5);
            let Ok(started) = tokio::time::timeout(limit, started_rx).await else {
                stalled(&handle)
            };
            let started = started.unwrap();
            if tokio::time::timeout(limit, changed.changed())
                .await
                .is_err()
            {
                stalled(&handle)
            }
            samples.push(started.elapsed());
            assert_eq!(handle.status().roa_count, records as usize);
            join.abort();
            server.abort();
        }
        samples.sort();
        println!(
            "full sync of {records:>6} VRPs: median {:?} (min {:?}, {iterations} runs)",
            samples[samples.len() / 2],
            samples[0]
        );
    }
}
