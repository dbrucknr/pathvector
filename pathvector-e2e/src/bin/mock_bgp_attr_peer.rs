//! A peer pair for `pathvector-e2e`'s RFC 4271 §5 unrecognized-attribute
//! relay test: proves the *entire* decode → daemon storage → RIB →
//! outbound-reconstruction → encode pipeline for unrecognized transitive
//! optional attributes, not just any one layer in isolation.
//!
//! Listens on `:179` and, on the accepted connection, plays one of two
//! roles selected by its only argument:
//!
//! - `source` — completes the handshake, then sends a single hand-rolled
//!   UPDATE announcing [`TEST_PREFIX`] carrying two unrecognized attributes:
//!   [`UNKNOWN_TRANSITIVE_TYPE`] (Optional+Transitive, Partial bit
//!   genuinely clear on the wire — RFC 4271 §5's "Paths with unrecognized
//!   transitive optional attributes SHOULD be accepted" case) and
//!   [`UNKNOWN_NONTRANSITIVE_TYPE`] (Optional only — the "Unrecognized
//!   non-transitive optional attributes MUST be quietly ignored and not
//!   passed along" case, included as a negative control). Then holds the
//!   connection open.
//! - `observer` — completes the handshake, waits for pathvectord's
//!   re-advertisement of [`TEST_PREFIX`], and decodes the real wire bytes
//!   of the UPDATE it actually receives (a GoBGP CLI's rendered RIB text
//!   is not precise enough to assert an exact flags octet). Prints a
//!   single `SCENARIO_OUTCOME:` line recording, for the attribute matching
//!   [`UNKNOWN_TRANSITIVE_TYPE`]: whether it is present, whether its Partial
//!   bit (0x20) is now set (RFC 4271 §5: "passed along to other BGP peers
//!   with the Partial bit in the Attribute Flags octet set to 1"), and
//!   whether its value round-tripped unchanged; and for
//!   [`UNKNOWN_NONTRANSITIVE_TYPE`]: whether it is (wrongly) present at all.
//!
//! `source`'s UPDATE is hand-rolled raw bytes, not built through
//! `pathvector_session`'s typed `BgpMessage`/`PathAttribute` encoder —
//! that encoder unconditionally ORs the Partial bit into any
//! Optional+Transitive `PathAttribute::Unknown` on encode (RFC 4271 §5's
//! forwarding rule, applied indiscriminately), so a `source` built through
//! it would already send Partial=1 on the wire, making it impossible to
//! prove pathvectord itself performs the clear-to-set transition. See
//! `source()`'s doc comment for the full explanation; this was caught by
//! external code review (PR #52) after the original version of this file
//! shipped with exactly that false-positive.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{BgpMessage, Capability, OpenMessage, PathAttribute};
use pathvector_types::AfiSafi;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

const MOCK_AS: u16 = 65001;
const MOCK_BGP_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const TEST_PREFIX: &str = "10.160.0.0/24";

/// Optional (0x80) + Transitive (0x40) — RFC 4271 §5's "SHOULD be accepted
/// ... passed along ... with the Partial bit set" case. Not a type code any
/// `PathAttribute` variant recognizes (see `pathvector-session`'s
/// `update.rs` `ATTR_*` consts).
const UNKNOWN_TRANSITIVE_TYPE: u8 = 200;
const FLAGS_OPTIONAL_TRANSITIVE: u8 = 0x80 | 0x40;
const FLAG_PARTIAL: u8 = 0x20;
const UNKNOWN_TRANSITIVE_VALUE: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// Optional (0x80) only, non-transitive — RFC 4271 §5's "MUST be quietly
/// ignored and not passed along" case, included as a negative control.
const UNKNOWN_NONTRANSITIVE_TYPE: u8 = 201;
const FLAGS_OPTIONAL_NONTRANSITIVE: u8 = 0x80;
const UNKNOWN_NONTRANSITIVE_VALUE: [u8; 2] = [0xCA, 0xFE];

#[tokio::main]
async fn main() {
    let role = std::env::args()
        .nth(1)
        .expect("usage: mock_bgp_attr_peer <source|observer>");

    let listener = TcpListener::bind("0.0.0.0:179").await.expect("bind :179");
    println!("mock_bgp_attr_peer ({role}) listening on :179");
    loop {
        let (stream, addr) = listener.accept().await.expect("accept connection");
        println!("accepted connection from {addr}, running role {role}");
        tokio::spawn(handle_connection(stream, role.clone()));
    }
}

async fn handle_connection(stream: TcpStream, role: String) {
    match role.as_str() {
        "source" => source(stream).await,
        "observer" => observer(stream).await,
        other => panic!("unknown role: {other}"),
    }
}

async fn do_handshake(stream: TcpStream) -> Framed<TcpStream, BgpCodec> {
    let mut framed = Framed::new(stream, BgpCodec::new());

    let Some(Ok(BgpMessage::Open(peer_open))) = framed.next().await else {
        panic!("expected OPEN as the first message");
    };
    println!("received OPEN from peer AS {}", peer_open.my_as);

    let our_open = OpenMessage {
        version: 4,
        my_as: MOCK_AS,
        hold_time: 9,
        bgp_id: MOCK_BGP_ID,
        capabilities: vec![Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)],
    };
    framed.send(BgpMessage::Open(our_open)).await.unwrap();
    framed.send(BgpMessage::Keepalive).await.unwrap();

    loop {
        match framed.next().await {
            Some(Ok(BgpMessage::Keepalive)) => break,
            Some(Ok(_)) => {}
            other => panic!("expected KEEPALIVE to complete the handshake, got {other:?}"),
        }
    }
    println!("session established");
    framed
}

async fn hold_forever(mut framed: Framed<TcpStream, BgpCodec>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if framed.send(BgpMessage::Keepalive).await.is_err() {
            return;
        }
    }
}

async fn source(stream: TcpStream) {
    let framed = do_handshake(stream).await;

    // `pathvector_session::message::update::encode` (the only way to build a
    // wire frame through the typed `UpdateMessage`/`PathAttribute` API)
    // unconditionally ORs the Partial bit into any Optional+Transitive
    // `PathAttribute::Unknown` on encode, per RFC 4271 §5's forwarding rule —
    // so going through that encoder here would already send Partial=1 on the
    // wire, making it impossible to prove pathvectord itself performs the
    // clear-to-set transition (a source that also uses that encoder can't
    // originate a Partial-clear instance to relay in the first place). Hand-
    // rolling the raw frame is required, mirroring
    // `mock_bgp_fault_peer.rs`'s `attribute_flags_conflict_frame()` pattern.
    let mut stream = framed.into_inner();
    if stream
        .write_all(&unknown_transitive_partial_clear_frame())
        .await
        .is_err()
    {
        return;
    }
    println!(
        "sent route for {TEST_PREFIX} carrying unknown-transitive (type \
         {UNKNOWN_TRANSITIVE_TYPE}, Partial bit genuinely clear on the wire) and \
         unknown-non-transitive (type {UNKNOWN_NONTRANSITIVE_TYPE}) attributes"
    );

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

/// Marker + length + type — RFC 4271 §4.1.
const HEADER_LEN: u16 = 19;
const MARKER_VALID: [u8; 16] = [0xFF; 16];
const MSG_TYPE_UPDATE: u8 = 2;
const MSG_TYPE_KEEPALIVE: u8 = 4;

fn keepalive_frame() -> Vec<u8> {
    let mut frame = MARKER_VALID.to_vec();
    frame.extend_from_slice(&HEADER_LEN.to_be_bytes());
    frame.push(MSG_TYPE_KEEPALIVE);
    frame
}

/// Hand-rolled UPDATE for [`TEST_PREFIX`] carrying well-formed mandatory
/// attributes plus the two unrecognized-attribute test cases, with the
/// unknown-transitive attribute's Partial bit (0x20) genuinely clear —
/// see `source()`'s doc comment for why this can't go through the typed
/// encoder.
fn unknown_transitive_partial_clear_frame() -> Vec<u8> {
    let mut attrs = Vec::new();
    attrs.extend_from_slice(&[0x40, 1, 1, 0]); // ORIGIN = IGP
    // AS_PATH: one Sequence segment containing MOCK_AS as a 4-byte ASN.
    let mock_as = u32::from(MOCK_AS).to_be_bytes();
    attrs.extend_from_slice(&[0x40, 2, 6, 2, 1]);
    attrs.extend_from_slice(&mock_as);
    attrs.extend_from_slice(&[0x40, 3, 4]); // NEXT_HOP
    attrs.extend_from_slice(&MOCK_BGP_ID.octets());
    // Unknown transitive: Optional(0x80)|Transitive(0x40), Partial(0x20) NOT
    // set — the exact case this test needs and the typed encoder cannot
    // produce.
    attrs.push(FLAGS_OPTIONAL_TRANSITIVE);
    attrs.push(UNKNOWN_TRANSITIVE_TYPE);
    attrs.push(u8::try_from(UNKNOWN_TRANSITIVE_VALUE.len()).expect("value fits in one byte"));
    attrs.extend_from_slice(&UNKNOWN_TRANSITIVE_VALUE);
    // Unknown non-transitive: Optional(0x80) only — the negative control.
    attrs.push(FLAGS_OPTIONAL_NONTRANSITIVE);
    attrs.push(UNKNOWN_NONTRANSITIVE_TYPE);
    attrs.push(u8::try_from(UNKNOWN_NONTRANSITIVE_VALUE.len()).expect("value fits in one byte"));
    attrs.extend_from_slice(&UNKNOWN_NONTRANSITIVE_VALUE);

    let mut body = vec![0u8, 0]; // withdrawn_len = 0
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&attrs);

    let prefix: Ipv4Addr = TEST_PREFIX
        .split('/')
        .next()
        .expect("prefix literal has an address part")
        .parse()
        .expect("valid prefix address");
    body.push(24); // /24, matching TEST_PREFIX
    body.extend_from_slice(&prefix.octets()[..3]);

    let mut frame = MARKER_VALID.to_vec();
    let total_len = HEADER_LEN + u16::try_from(body.len()).expect("body always fits in u16");
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.push(MSG_TYPE_UPDATE);
    frame.extend_from_slice(&body);
    frame
}

async fn observer(stream: TcpStream) {
    let mut framed = do_handshake(stream).await;

    loop {
        match framed.next().await {
            Some(Ok(BgpMessage::Update(update))) => {
                if !update
                    .announced
                    .iter()
                    .any(|nlri| nlri.to_string() == TEST_PREFIX)
                {
                    continue;
                }

                let transitive = update.attributes.iter().find_map(|attr| match attr {
                    PathAttribute::Unknown {
                        flags,
                        type_code,
                        value,
                    } if *type_code == UNKNOWN_TRANSITIVE_TYPE => Some((*flags, value.clone())),
                    _ => None,
                });
                let nontransitive_present = update.attributes.iter().any(|attr| {
                    matches!(
                        attr,
                        PathAttribute::Unknown { type_code, .. }
                            if *type_code == UNKNOWN_NONTRANSITIVE_TYPE
                    )
                });

                let (transitive_present, partial_bit_set, value_matches) = match transitive {
                    Some((flags, value)) => (
                        true,
                        flags & FLAG_PARTIAL != 0,
                        value == UNKNOWN_TRANSITIVE_VALUE,
                    ),
                    None => (false, false, false),
                };

                println!(
                    "SCENARIO_OUTCOME: transitive_present={transitive_present} \
                     partial_bit_set={partial_bit_set} value_matches={value_matches} \
                     nontransitive_present={nontransitive_present}"
                );

                hold_forever(framed).await;
                return;
            }
            Some(Ok(_)) => {}
            other => panic!("connection closed unexpectedly while waiting for UPDATE: {other:?}"),
        }
    }
}
