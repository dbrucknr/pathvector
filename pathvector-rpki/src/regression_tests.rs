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
    client::{read_pdu, write_pdu},
    pdu::{EndOfDataIntervals, Pdu, PrefixFlags},
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
        tokio::time::timeout(Duration::from_secs(5), self.seen.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for the server to see: {what}"))
            .unwrap_or_else(|| panic!("server task ended before seeing: {what}"))
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
    Pdu::Ipv4Prefix {
        flags: PrefixFlags { announce: true },
        prefix_len: len,
        max_len: len,
        prefix: prefix.parse().unwrap(),
        asn,
    }
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
    tokio::time::timeout(Duration::from_secs(5), async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for: {what}"));
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
