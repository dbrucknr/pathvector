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
    sync::mpsc,
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
