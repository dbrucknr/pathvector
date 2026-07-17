//! A deliberately adversarial BGP peer for `pathvector-e2e`'s fault-injection
//! tests (TODO.md Tier 3 #11).
//!
//! Listens on `:179` and, on each accepted connection, replays one of a fixed
//! set of scenarios selected by its only argument:
//!
//! - `bad-marker` / `bad-length` / `bad-type` — a single 19-byte frame with a
//!   corrupted marker, length, or type field (RFC 4271 §6.1 Message Header
//!   Error). Sent immediately, with no preceding OPEN exchange, so
//!   pathvectord is in `OpenSent` when it arrives — the state where a prior
//!   bug in `pathvector-session` silently dropped the connection instead of
//!   sending the RFC-mandated NOTIFICATION first.
//! - `truncated-header` — fewer than 19 bytes, then the connection is held
//!   open indefinitely (never closed), so pathvectord's codec is left
//!   genuinely waiting for more bytes that never arrive.
//! - `truncated-open` — a few bytes short of a complete header, then an
//!   immediate close — exercises the EOF path during the OPEN exchange.
//! - `malformed-update-origin` — a real OPEN/KEEPALIVE handshake to
//!   Established, one clean UPDATE, then a second UPDATE for the same prefix
//!   carrying an invalid ORIGIN value (RFC 7606 treat-as-withdraw).
//! - `missing-origin` — same shape as `malformed-update-origin`, but the
//!   second UPDATE omits the ORIGIN attribute entirely rather than carrying
//!   an invalid value (RFC 7606 §3(d): missing well-known mandatory
//!   attribute, still treat-as-withdraw).
//!
//! For the three header-error and two truncation scenarios, no valid frame
//! exists to reuse from `pathvector_session`'s encoder by construction, so
//! the bytes are hand-rolled directly — mirroring `mock_rtr_server.rs`'s
//! independent raw-byte-builder pattern. The `malformed-update-origin`
//! scenario's legitimate preamble (OPEN, KEEPALIVE, first clean UPDATE) does
//! reuse `pathvector_session::message` and `Framed`/`BgpCodec`, since that
//! decoder-side behavior is already unit/transport-tested elsewhere — only
//! the one deliberately-invalid ORIGIN attribute can't be constructed through
//! the type system (`Origin::from_u8` has no invalid discriminant to pick),
//! so that one frame is hand-rolled after reclaiming the raw stream via
//! `Framed::into_inner`. `missing-origin` doesn't need any hand-rolling at
//! all — simply omitting an attribute from `UpdateMessage.attributes` is
//! fully expressible through the normal encoder.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{BgpMessage, OpenMessage, PathAttribute, UpdateMessage};
use pathvector_types::{AsPath, Asn, Origin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

const FAULT_PEER_AS: u16 = 65098;
const FAULT_PEER_BGP_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 98);
const TEST_PREFIX: &str = "10.99.0.0/24";

/// Marker + length + type — RFC 4271 §4.1.
const HEADER_LEN: u16 = 19;
const MARKER_VALID: [u8; 16] = [0xFF; 16];

const MSG_TYPE_UPDATE: u8 = 2;
const MSG_TYPE_KEEPALIVE: u8 = 4;

#[tokio::main]
async fn main() {
    let scenario = std::env::args()
        .nth(1)
        .expect("usage: mock_bgp_fault_peer <scenario>");

    let listener = TcpListener::bind("0.0.0.0:179").await.expect("bind :179");
    println!("mock_bgp_fault_peer ({scenario}) listening on :179");
    loop {
        let (stream, addr) = listener.accept().await.expect("accept connection");
        println!("accepted connection from {addr}, running scenario {scenario}");
        tokio::spawn(handle_connection(stream, scenario.clone()));
    }
}

async fn handle_connection(stream: TcpStream, scenario: String) {
    match scenario.as_str() {
        "bad-marker" => write_frame_then_drain(stream, &bad_marker_frame()).await,
        "bad-length" => write_frame_then_drain(stream, &bad_length_frame()).await,
        "bad-type" => write_frame_then_drain(stream, &bad_type_frame()).await,
        "truncated-header" => truncated_header(stream).await,
        "truncated-open" => truncated_open(stream).await,
        "malformed-update-origin" => malformed_update_origin(stream).await,
        "missing-origin" => missing_origin_update(stream).await,
        other => panic!("unknown scenario: {other}"),
    }
}

// ── RFC 4271 §6.1 Message Header Error frames ─────────────────────────────

/// 19-byte frame with an all-zero marker (must be all `0xFF` per RFC 4271
/// §4.1) — triggers `CodecError::InvalidMarker`. The type byte is
/// irrelevant: the marker is checked before the length or type.
fn bad_marker_frame() -> Vec<u8> {
    let mut buf = vec![0u8; 16];
    buf.extend_from_slice(&HEADER_LEN.to_be_bytes());
    buf.push(MSG_TYPE_KEEPALIVE);
    buf
}

/// Valid marker, length field (10) below the 19-byte minimum — triggers
/// `CodecError::InvalidLength`.
fn bad_length_frame() -> Vec<u8> {
    let mut buf = MARKER_VALID.to_vec();
    buf.extend_from_slice(&10u16.to_be_bytes());
    buf.push(MSG_TYPE_KEEPALIVE);
    buf
}

/// Valid marker and length, unrecognized type byte (99; the valid range is
/// 1-5) — triggers `CodecError::UnknownMessageType`.
fn bad_type_frame() -> Vec<u8> {
    let mut buf = MARKER_VALID.to_vec();
    buf.extend_from_slice(&HEADER_LEN.to_be_bytes());
    buf.push(99);
    buf
}

/// Write `frame`, then drain (ignoring content) until pathvectord closes the
/// connection — expected once it sends its NOTIFICATION and tears down.
async fn write_frame_then_drain(mut stream: TcpStream, frame: &[u8]) {
    if stream.write_all(frame).await.is_err() {
        return;
    }
    let mut buf = [0u8; 256];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

// ── OPEN-exchange truncation scenarios ─────────────────────────────────────

/// Fewer than `HEADER_LEN` bytes, then the connection is held open
/// indefinitely. Dropping the stream here would send FIN, silently turning
/// this into the `truncated-open` (EOF) case instead of "codec waiting for
/// more bytes that never arrive."
async fn truncated_header(mut stream: TcpStream) {
    let _ = stream.write_all(&[0xFFu8; 10]).await;
    std::future::pending::<()>().await;
}

/// A handful of bytes, not even a complete header, then an immediate close —
/// exercises pathvectord's EOF path during the OPEN exchange.
async fn truncated_open(mut stream: TcpStream) {
    let _ = stream.write_all(&[0xFFu8; 5]).await;
    let _ = stream.shutdown().await;
}

// ── RFC 7606 malformed UPDATE over a real handshake ────────────────────────

async fn malformed_update_origin(stream: TcpStream) {
    let mut framed = Framed::new(stream, BgpCodec::new());

    let Some(Ok(BgpMessage::Open(peer_open))) = framed.next().await else {
        eprintln!("expected OPEN as the first message; closing");
        return;
    };
    println!("received OPEN from peer AS {}", peer_open.my_as);

    let our_open = OpenMessage {
        version: 4,
        my_as: FAULT_PEER_AS,
        hold_time: 9,
        bgp_id: FAULT_PEER_BGP_ID,
        capabilities: vec![],
    };
    if framed.send(BgpMessage::Open(our_open)).await.is_err() {
        return;
    }
    if framed.send(BgpMessage::Keepalive).await.is_err() {
        return;
    }

    // Drain until pathvectord's own KEEPALIVE arrives, confirming it reached
    // Established on its side before we send anything UPDATE-shaped.
    loop {
        match framed.next().await {
            Some(Ok(BgpMessage::Keepalive)) => break,
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    println!("session established");

    let clean = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(
                FAULT_PEER_AS,
            ))])),
            PathAttribute::NextHop(FAULT_PEER_BGP_ID),
        ],
        announced: vec![TEST_PREFIX.parse().expect("valid prefix literal")],
    };
    if framed.send(BgpMessage::Update(clean)).await.is_err() {
        return;
    }
    println!("sent clean UPDATE for {TEST_PREFIX}");

    // Give the test a real window to observe the clean route present in
    // Loc-RIB before it gets withdrawn below — without this, both UPDATEs
    // could be processed between two of the test's polling ticks, and the
    // route would never be observably present at all.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // A valid `Origin` can't encode an out-of-range value, so this frame
    // can't be built via `UpdateMessage`/`.encode()` — reclaim the raw
    // stream and hand-roll it directly.
    let mut stream = framed.into_inner();
    if stream
        .write_all(&malformed_origin_update_frame())
        .await
        .is_err()
    {
        return;
    }
    println!("sent malformed UPDATE (invalid ORIGIN) for {TEST_PREFIX}");

    // Hold the session open so the test can observe the withdrawal without
    // racing a session teardown.
    let mut buf = [0u8; 256];
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(3)) => {
                if stream.write_all(&keepalive_frame()).await.is_err() {
                    return;
                }
            }
            n = stream.read(&mut buf) => {
                if matches!(n, Ok(0) | Err(_)) {
                    return;
                }
            }
        }
    }
}

/// Hand-rolled malformed UPDATE: no withdrawn routes, one ORIGIN attribute
/// with an invalid value byte (the valid range is 0-2), announcing
/// `TEST_PREFIX`.
fn malformed_origin_update_frame() -> Vec<u8> {
    let mut body = vec![0u8, 0]; // withdrawn_len = 0

    // flags (well-known mandatory, transitive), type = ORIGIN (1), len = 1,
    // value = 5 (invalid — RFC 4271 ORIGIN is 0-2).
    let attrs: [u8; 4] = [0x40, 1, 1, 5];
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&attrs);

    body.push(24); // prefix length for 10.99.0.0/24
    body.extend_from_slice(&[10, 99, 0]);

    let mut frame = MARKER_VALID.to_vec();
    let total_len = HEADER_LEN + u16::try_from(body.len()).expect("body always fits in u16");
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.push(MSG_TYPE_UPDATE);
    frame.extend_from_slice(&body);
    frame
}

fn keepalive_frame() -> Vec<u8> {
    let mut frame = MARKER_VALID.to_vec();
    frame.extend_from_slice(&HEADER_LEN.to_be_bytes());
    frame.push(MSG_TYPE_KEEPALIVE);
    frame
}

/// RFC 7606 §3(d): "If any of the well-known mandatory attributes are not
/// present in an UPDATE message, then 'treat-as-withdraw' MUST be used."
///
/// Same shape as `malformed_update_origin`, but the second UPDATE simply
/// omits `PathAttribute::Origin` from `attributes` (keeping `AsPath`/
/// `NextHop`) instead of carrying an invalid value — no raw-byte hand-rolling
/// needed, since a missing attribute is expressible through the normal
/// `UpdateMessage`/encoder path.
async fn missing_origin_update(stream: TcpStream) {
    let mut framed = Framed::new(stream, BgpCodec::new());

    let Some(Ok(BgpMessage::Open(peer_open))) = framed.next().await else {
        eprintln!("expected OPEN as the first message; closing");
        return;
    };
    println!("received OPEN from peer AS {}", peer_open.my_as);

    let our_open = OpenMessage {
        version: 4,
        my_as: FAULT_PEER_AS,
        hold_time: 9,
        bgp_id: FAULT_PEER_BGP_ID,
        capabilities: vec![],
    };
    if framed.send(BgpMessage::Open(our_open)).await.is_err() {
        return;
    }
    if framed.send(BgpMessage::Keepalive).await.is_err() {
        return;
    }

    // Drain until pathvectord's own KEEPALIVE arrives, confirming it reached
    // Established on its side before we send anything UPDATE-shaped.
    loop {
        match framed.next().await {
            Some(Ok(BgpMessage::Keepalive)) => break,
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    println!("session established");

    let clean = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(
                FAULT_PEER_AS,
            ))])),
            PathAttribute::NextHop(FAULT_PEER_BGP_ID),
        ],
        announced: vec![TEST_PREFIX.parse().expect("valid prefix literal")],
    };
    if framed.send(BgpMessage::Update(clean)).await.is_err() {
        return;
    }
    println!("sent clean UPDATE for {TEST_PREFIX}");

    // Give the test a real window to observe the clean route present in
    // Loc-RIB before it gets withdrawn below — without this, both UPDATEs
    // could be processed between two of the test's polling ticks, and the
    // route would never be observably present at all.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // RFC 7606 §3(d): same prefix, ORIGIN omitted entirely (AS_PATH and
    // NEXT_HOP still present, so this is unambiguously "missing mandatory
    // attribute," not "missing everything").
    let missing_origin = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(
                FAULT_PEER_AS,
            ))])),
            PathAttribute::NextHop(FAULT_PEER_BGP_ID),
        ],
        announced: vec![TEST_PREFIX.parse().expect("valid prefix literal")],
    };
    if framed
        .send(BgpMessage::Update(missing_origin))
        .await
        .is_err()
    {
        return;
    }
    println!("sent UPDATE missing ORIGIN for {TEST_PREFIX}");

    // Hold the session open so the test can observe the withdrawal without
    // racing a session teardown — and to prove the session itself survives
    // (RFC 7606 §3(d) treat-as-withdraw, not a NOTIFICATION/session reset).
    let mut stream = framed.into_inner();
    let mut buf = [0u8; 256];
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(3)) => {
                if stream.write_all(&keepalive_frame()).await.is_err() {
                    return;
                }
            }
            n = stream.read(&mut buf) => {
                if matches!(n, Ok(0) | Err(_)) {
                    return;
                }
            }
        }
    }
}
