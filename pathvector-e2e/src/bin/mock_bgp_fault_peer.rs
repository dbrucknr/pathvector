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
//! - `duplicate-mp-reach` — a real OPEN/KEEPALIVE handshake to Established,
//!   then a single UPDATE carrying two `MP_REACH_NLRI` attributes (RFC 7606
//!   §3(g): unlike every other malformed-attribute case in this file, this
//!   one is NOT treat-as-withdraw — it MUST reset the session with a
//!   Malformed Attribute List NOTIFICATION).
//! - `attribute-flags-conflict` — same shape as `malformed-update-origin`,
//!   but the second UPDATE's ORIGIN attribute carries a *valid* value (IGP)
//!   with a *wrong* flags byte (Optional bit set, which RFC 4271 §4.3
//!   forbids for a well-known attribute) — isolating RFC 7606 §3(c)'s
//!   Attribute Flags Error check from the pre-existing invalid-value check
//!   `malformed-update-origin` already proves.
//! - `malformed-otc` — same shape again, but the second UPDATE carries an
//!   ONLY_TO_CUSTOMER (RFC 9234 §5) attribute with length 3 instead of the
//!   required 4 — proving the security-relevant fix that a malformed OTC is
//!   treated as withdraw rather than silently discarded (which would let a
//!   route bypass OTC-based leak detection entirely).
//! - `ebgp-local-pref` — unlike every other scenario above, this UPDATE is
//!   not malformed at all: a real OPEN/KEEPALIVE handshake to Established,
//!   then one well-formed UPDATE carrying an explicit LOCAL_PREF attribute
//!   (RFC 4271 §5.1.5: LOCAL_PREF received from an external peer MUST be
//!   ignored by the receiving speaker). Tests policy-violating-but-
//!   well-formed input, not corrupted wire format.
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
use pathvector_session::message::{
    BgpMessage, Capability, MpReachNlri, OpenMessage, PathAttribute, Prefix, UpdateMessage,
};
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Origin};
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
        "duplicate-mp-reach" => duplicate_mp_reach_update(stream).await,
        "attribute-flags-conflict" => attribute_flags_conflict_update(stream).await,
        "malformed-otc" => malformed_otc_update(stream).await,
        "ebgp-local-pref" => ebgp_local_pref_update(stream).await,
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

/// RFC 7606 §3(c) (revising RFC 4271 §4.3): "If the value of either the
/// Optional or Transitive bits in the Attribute Flags is in conflict with
/// their specified values, then the attribute MUST be treated as malformed
/// and the 'treat-as-withdraw' approach used."
///
/// Same shape as `malformed_update_origin`, but the fault is in the flags
/// byte, not the value — a normal `PathAttribute::Origin` encode always
/// emits the correct flags, so this can't be built through the type-safe
/// encoder either, and gets the same raw-byte hand-roll treatment.
async fn attribute_flags_conflict_update(stream: TcpStream) {
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
    // Loc-RIB before it gets withdrawn below.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // A normal encode of `PathAttribute::Origin` always emits the correct
    // flags byte, so this frame can't be built via `UpdateMessage`/`.encode()`
    // — reclaim the raw stream and hand-roll it directly.
    let mut stream = framed.into_inner();
    if stream
        .write_all(&attribute_flags_conflict_frame())
        .await
        .is_err()
    {
        return;
    }
    println!("sent UPDATE with ORIGIN carrying a valid value but conflicting flags");

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
/// with a *valid* value (0 = IGP) but flags `0xC0` (Optional=1, Transitive=1)
/// instead of the required well-known-mandatory `0x40` (Optional=0,
/// Transitive=1) — isolates the flags check from the value check.
fn attribute_flags_conflict_frame() -> Vec<u8> {
    let mut attrs = Vec::new();
    // ORIGIN: flags = 0xC0 (wrong: Optional bit set on a well-known
    // attribute), type = 1, len = 1, value = 0 (IGP — a valid value). This
    // is the one attribute under test.
    attrs.extend_from_slice(&[0xC0, 1, 1, 0]);
    // AS_PATH and NEXT_HOP: present with *correct* flags and valid content,
    // deliberately included so this scenario isolates the Attribute Flags
    // Error check from the separate (already fixed, already tested)
    // missing-well-known-mandatory-attribute check — without these, a
    // broken/disabled flags check would still make this UPDATE end up
    // treat-as-withdrawn for the wrong reason (missing AS_PATH/NEXT_HOP),
    // masking a real regression in the flags check itself.
    attrs.extend_from_slice(&[0x40, 2, 0]); // AS_PATH: empty sequence
    attrs.extend_from_slice(&[0x40, 3, 4, 10, 0, 0, 98]); // NEXT_HOP

    let mut body = vec![0u8, 0]; // withdrawn_len = 0
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

/// RFC 9234 §5: "The OTC Attribute is considered malformed if the length
/// value is not 4. An UPDATE message with a malformed OTC Attribute SHALL be
/// handled using the approach of 'treat-as-withdraw' \[RFC7606\]." Security-
/// relevant: OTC is RFC 9234's entire route-leak-detection mechanism, so a
/// malformed OTC being silently discarded (rather than withdrawing the
/// route) would let a route bypass leak detection instead of being dropped.
///
/// Same shape as `attribute_flags_conflict_update` — a 3-byte OTC value
/// can't be built via the type-safe encoder (`PathAttribute::OnlyToCustomer`
/// always encodes exactly 4 bytes), so this is hand-rolled too.
async fn malformed_otc_update(stream: TcpStream) {
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
    // Loc-RIB before it gets withdrawn below.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut stream = framed.into_inner();
    if stream.write_all(&malformed_otc_frame()).await.is_err() {
        return;
    }
    println!("sent UPDATE with 3-byte (malformed) OTC attribute");

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

/// Hand-rolled malformed UPDATE: no withdrawn routes, well-formed ORIGIN/
/// AS_PATH/NEXT_HOP, plus an ONLY_TO_CUSTOMER (type 35) attribute with a
/// 3-byte value instead of the required 4.
fn malformed_otc_frame() -> Vec<u8> {
    let mut attrs = Vec::new();
    // ORIGIN: well-known mandatory, transitive, len 1, IGP.
    attrs.extend_from_slice(&[0x40, 1, 1, 0]);
    // AS_PATH: well-known mandatory, transitive, len 0 (empty sequence — a
    // single-hop path from this fault peer's own perspective doesn't matter
    // for this test, only that the attribute is syntactically present).
    attrs.extend_from_slice(&[0x40, 2, 0]);
    // NEXT_HOP: well-known mandatory, transitive, len 4, 10.0.0.98.
    attrs.extend_from_slice(&[0x40, 3, 4, 10, 0, 0, 98]);
    // ONLY_TO_CUSTOMER: optional transitive (0xC0), type 35, len 3 (wrong —
    // RFC 9234 §5 requires exactly 4), 3 arbitrary value bytes.
    attrs.extend_from_slice(&[0xC0, 35, 3, 0, 0, 1]);

    let mut body = vec![0u8, 0]; // withdrawn_len = 0
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

/// RFC 7606 §3(g): "If the MP_REACH_NLRI attribute or the MP_UNREACH_NLRI
/// attribute appears more than once in the UPDATE message, then a
/// NOTIFICATION message MUST be sent with the Error Subcode 'Malformed
/// Attribute List'." Unlike every other scenario in this file, this one
/// expects pathvectord to actually reset the session — no `into_inner`
/// hand-rolling needed, since encoding two attributes of the same type is
/// just normal `Vec` iteration in the encoder (see the equivalent unit-level
/// trick in `pathvector-session/src/message/update.rs`'s
/// `test_duplicate_mp_reach_nlri_requires_session_reset`).
async fn duplicate_mp_reach_update(stream: TcpStream) {
    let mut framed = Framed::new(stream, BgpCodec::new());

    let Some(Ok(BgpMessage::Open(peer_open))) = framed.next().await else {
        eprintln!("expected OPEN as the first message; closing");
        return;
    };
    println!("received OPEN from peer AS {}", peer_open.my_as);

    // Unlike the other scenarios in this file, this one negotiates the
    // MultiProtocol(IPv4 unicast) capability — the MP_REACH_NLRI attribute
    // sent below carries IPv4 unicast content, and properly negotiating it
    // removes capability-mismatch handling as a confound: if the duplicate
    // detection were ever disabled/broken, the single (post-dedup)
    // MpReachNlri would fall through to pathvectord's already-supported,
    // deterministic mp_v4 route-install path instead of an unnegotiated-
    // AFI/SAFI code path whose behavior isn't what this scenario means to
    // exercise.
    let our_open = OpenMessage {
        version: 4,
        my_as: FAULT_PEER_AS,
        hold_time: 9,
        bgp_id: FAULT_PEER_BGP_ID,
        capabilities: vec![Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)],
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

    // Give the e2e test a real window to observe the fault peer's session
    // as Established (via gRPC) before the fault below resets it — without
    // this, "session reached Established" and "session got reset" could
    // both happen faster than the test's own polling could ever observe
    // the intermediate Established state, letting a broken fix produce a
    // false pass (never confirmed Established, so "not Established" is
    // trivially and vacuously true from the very first poll).
    tokio::time::sleep(Duration::from_secs(2)).await;

    // IPv4 unicast content (not IPv6) deliberately: this scenario's fault
    // peer never negotiates the IPv6 MultiProtocol capability (its OPEN
    // carries none), so an IPv6 MP_REACH_NLRI would additionally exercise
    // capability-mismatch handling — a second, unrelated variable this
    // scenario isn't meant to test. IPv4-via-MP_REACH_NLRI is always
    // meaningful regardless of capability negotiation (pathvectord already
    // supports it independently, per the RFC 7606 §3(d) fix's mp_v4
    // handling), keeping this scenario isolated to §3(g) alone.
    let mp_reach = || {
        PathAttribute::MpReachNlri(MpReachNlri {
            afi_safi: AfiSafi::IPV4_UNICAST,
            next_hop: NextHop::V4(FAULT_PEER_BGP_ID),
            prefixes: vec![Prefix::V4(
                TEST_PREFIX.parse().expect("valid prefix literal"),
            )],
        })
    };
    let duplicate = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![mp_reach(), mp_reach()],
        announced: vec![],
    };
    if framed.send(BgpMessage::Update(duplicate)).await.is_err() {
        return;
    }
    println!("sent UPDATE with duplicate MP_REACH_NLRI attributes");

    // Keep sending our own KEEPALIVEs after this — critically, this means if
    // pathvectord's fix were disabled/broken, the session would stay fully
    // alive (bidirectional keepalives, no hold-timer expiry) rather than
    // eventually being torn down by an unrelated 9s HoldTimerExpired that
    // would make this test pass for the wrong reason. A real regression here
    // must show up as "no NOTIFICATION arrives, session stays Established
    // indefinitely," not as a hold-timer timeout race. A 1s interval
    // (rather than the RFC-typical hold_time/3 = 3s) is deliberate: under
    // real-teeth testing, a 3s interval left too little margin against
    // ordinary Docker/host scheduling jitter, and a delayed keepalive was
    // directly observed causing a spurious `HoldTimerExpired` NOTIFICATION
    // instead of the fix's own `MalformedAttributeList` — a false signal
    // unrelated to the code under test.
    let mut ticks = 0;
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                if framed.send(BgpMessage::Keepalive).await.is_err() {
                    return;
                }
                ticks += 1;
                if ticks > 60 {
                    // Long past any reasonable test timeout — give up rather
                    // than looping forever if something is very wrong.
                    return;
                }
            }
            msg = framed.next() => {
                match msg {
                    Some(Ok(BgpMessage::Notification(n))) => {
                        println!("received NOTIFICATION as expected: {n:?}");
                        return;
                    }
                    Some(Ok(_)) => {} // ignore KEEPALIVE/other, keep looping
                    _ => return, // EOF or codec error — connection closed
                }
            }
        }
    }
}

/// RFC 4271 §5.1.5: "If it is contained in an UPDATE message that is
/// received from an external peer, then this attribute MUST be ignored by
/// the receiving speaker." Unlike every other scenario in this file, the
/// UPDATE here is entirely well-formed — this tests policy-violating input
/// (an eBGP peer attaching LOCAL_PREF, which it's never entitled to
/// influence), not corrupted wire format. Fully expressible through the
/// normal type-safe encoder, so no raw-byte hand-rolling needed.
async fn ebgp_local_pref_update(stream: TcpStream) {
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

    // A bogus, deliberately extreme LOCAL_PREF — if it were honored, it
    // would trivially win any best-path comparison against a route with the
    // conventional default (100).
    let update = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(
                FAULT_PEER_AS,
            ))])),
            PathAttribute::NextHop(FAULT_PEER_BGP_ID),
            PathAttribute::LocalPref(u32::MAX),
        ],
        announced: vec![TEST_PREFIX.parse().expect("valid prefix literal")],
    };
    if framed.send(BgpMessage::Update(update)).await.is_err() {
        return;
    }
    println!(
        "sent UPDATE for {TEST_PREFIX} carrying LOCAL_PREF={}",
        u32::MAX
    );

    // Hold the session open with periodic keepalives — this UPDATE is
    // entirely well-formed, so the session must stay Established
    // indefinitely regardless of how LOCAL_PREF ends up handled.
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
