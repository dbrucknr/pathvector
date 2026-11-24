//! A peer pair for `pathvector-e2e`'s RFC 6793 §4 / RFC 5065 AS4_PATH
//! confederation-stripping test: proves that when a route carrying a
//! confederation segment is relayed toward a fellow confederation Member-AS
//! peer that hasn't negotiated the `FourByteAsn` capability, the AS_PATH
//! *value* keeps the confed segment (RFC 5065 §5.3 — a `ConfedMember` peer
//! sees the same AS_PATH shape as an internal one) with AS_TRANS substituted
//! for the real ASN (RFC 6793 §4), while AS4_PATH, if emitted, carries the
//! real ASN and excludes the confed segment entirely (RFC 6793 §§3, 4.2.2:
//! "declared invalid for the AS4_PATH attribute and MUST NOT be included").
//!
//! **What "two-byte" means here:** the `two-byte-observer` role omits the
//! `FourByteAsn` capability in its own OPEN, so the session negotiates
//! [`AsnWidth::Two`](pathvector_session::message::AsnWidth) (RFC 6793 §4.2 —
//! pathvectord is talking to an OLD BGP speaker). Since issue #95 pathvectord
//! really does emit two-octet AS_PATH on such a session, and its own
//! `BgpCodec` would merge AS4_PATH back into AS_PATH on receipt (§4.2.3) — so
//! this observer does **not** use `BgpCodec` after the handshake. It reads the
//! raw UPDATE bytes and parses AS_PATH at two octets per ASN and AS4_PATH at
//! four, exactly as an OLD speaker would see them. `wire_as_path_two_octet`
//! in the outcome line is true only if AS_PATH parses cleanly (consumed
//! exactly) at two octets per ASN, so a four-octet encoding on this session
//! fails the scenario. (Before #95 this peer silently decoded 4-octet bytes
//! and proved only the *logical* downgrade decision.) Real interop against a
//! third-party 2-byte-only implementation (e.g. GoBGP `--as2`) remains
//! untested; see `TODO.md`.
//!
//! Listens on `:179` and, on the accepted connection, plays one of two roles
//! selected by its only argument:
//!
//! - `confed-source` — advertises the `FourByteAsn` capability (so this
//!   session negotiates 4-byte AS_PATH encoding), then sends a single UPDATE
//!   announcing [`TEST_PREFIX`] whose AS_PATH leads with an
//!   `AS_CONFED_SEQUENCE` segment (well-formed per RFC 5065 §5 condition 2 —
//!   this peer is configured `confederation_member = true` on pathvectord's
//!   side) followed by an ordinary `AS_SEQUENCE` segment containing
//!   [`FOUR_BYTE_ASN`] (a value that doesn't fit in 2 bytes).
//! - `two-byte-observer` — deliberately does **not** advertise `FourByteAsn`
//!   (so the session is two-octet — see above), then parses the raw wire
//!   bytes of pathvectord's re-advertised UPDATE and logs a
//!   `SCENARIO_OUTCOME:` line recording: whether AS_PATH is genuinely
//!   two-octet on the wire, whether the AS_PATH
//!   value still contains the leading `AS_CONFED_SEQUENCE` segment (it
//!   must — RFC 5065 §5.3), whether it substitutes AS_TRANS (23456) for the
//!   4-byte ASN (RFC 6793 §4), whether AS4_PATH is present and carries the
//!   real 4-byte ASN, and whether AS4_PATH excludes the confed segment.
//!
//! The source role is built with `pathvector_session`'s own `BgpMessage`
//! encoder; only the observer's receive side parses raw bytes (see above).

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{BgpMessage, Capability, OpenMessage, PathAttribute};
use pathvector_types::{AfiSafi, AsPath, AsPathSegment, Asn, Origin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

const SOURCE_AS: u16 = 65010;
const OBSERVER_AS: u16 = 65020;
const SOURCE_BGP_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const OBSERVER_BGP_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 20);
const TEST_PREFIX: &str = "10.170.0.0/24";
const AS_TRANS: u32 = 23_456;
/// Deliberately > u16::MAX so it cannot be represented in a plain 2-byte
/// AS_PATH segment — the whole point of this scenario.
const FOUR_BYTE_ASN: u32 = 700_000;

#[tokio::main]
async fn main() {
    let role = std::env::args()
        .nth(1)
        .expect("usage: mock_bgp_as4path_peer <confed-source|two-byte-observer>");

    let listener = TcpListener::bind("0.0.0.0:179").await.expect("bind :179");
    println!("mock_bgp_as4path_peer ({role}) listening on :179");
    loop {
        let (stream, addr) = listener.accept().await.expect("accept connection");
        println!("accepted connection from {addr}, running role {role}");
        tokio::spawn(handle_connection(stream, role.clone()));
    }
}

async fn handle_connection(stream: TcpStream, role: String) {
    match role.as_str() {
        "confed-source" => confed_source(stream).await,
        "two-byte-observer" => two_byte_observer(stream).await,
        other => panic!("unknown role: {other}"),
    }
}

async fn do_handshake(
    stream: TcpStream,
    my_as: u16,
    bgp_id: Ipv4Addr,
    advertise_four_byte_asn: bool,
) -> Framed<TcpStream, BgpCodec> {
    let mut framed = Framed::new(stream, BgpCodec::new());

    let Some(Ok(BgpMessage::Open(peer_open))) = framed.next().await else {
        panic!("expected OPEN as the first message");
    };
    println!("received OPEN from peer AS {}", peer_open.my_as);

    let mut capabilities = vec![Capability::MultiProtocol(AfiSafi::IPV4_UNICAST)];
    if advertise_four_byte_asn {
        capabilities.push(Capability::FourByteAsn(u32::from(my_as)));
    }
    let our_open = OpenMessage {
        version: 4,
        my_as,
        hold_time: 9,
        bgp_id,
        capabilities,
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
    println!("session established (my_as={my_as}, four_byte_asn={advertise_four_byte_asn})");
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

async fn confed_source(stream: TcpStream) {
    let mut framed = do_handshake(stream, SOURCE_AS, SOURCE_BGP_ID, true).await;

    let update = pathvector_session::message::UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_segments(vec![
                AsPathSegment::ConfedSequence(vec![Asn::new(u32::from(SOURCE_AS))]),
                AsPathSegment::Sequence(vec![Asn::new(FOUR_BYTE_ASN)]),
            ])),
            PathAttribute::NextHop(SOURCE_BGP_ID),
        ],
        announced: vec![TEST_PREFIX.parse().expect("valid prefix literal")],
    };
    framed.send(BgpMessage::Update(update)).await.unwrap();
    println!(
        "sent route for {TEST_PREFIX} with AS_PATH = [AS_CONFED_SEQUENCE({SOURCE_AS}), \
         AS_SEQUENCE({FOUR_BYTE_ASN})]"
    );

    hold_forever(framed).await;
}

async fn two_byte_observer(stream: TcpStream) {
    let framed = do_handshake(stream, OBSERVER_AS, OBSERVER_BGP_ID, false).await;

    // This peer is a genuine OLD BGP speaker (RFC 6793 §4.2): neither side
    // negotiated FourByteAsn, so AS_PATH carries two octets per ASN. pathvectord's
    // `BgpCodec` would hand us the *reconciled* path (RFC 6793 §4.2.3 merges
    // AS4_PATH back into AS_PATH on receipt), hiding exactly the wire shape this
    // scenario exists to check — so from here on read the raw bytes ourselves.
    let parts = framed.into_parts();
    let mut stream = parts.io;
    let mut buf: Vec<u8> = parts.read_buf.to_vec();

    loop {
        let (msg_type, body) = read_raw_message(&mut stream, &mut buf).await;
        if msg_type != MSG_UPDATE {
            continue;
        }
        let Some(update) = parse_raw_update(&body) else {
            continue;
        };
        if !update.announced.iter().any(|n| n == TEST_PREFIX) {
            continue;
        }

        let as_path = update.as_path.as_ref();
        let as4_path = update.as4_path.as_ref();

        // The leading segment must still be an AS_CONFED_SEQUENCE (RFC
        // 5065 §5.3 — confed segments are NOT stripped toward a fellow
        // ConfedMember peer), and it must still contain the source's own AS
        // somewhere within it. pathvectord's own prepend_confed() extends
        // this same leading segment with its own Member-AS number rather
        // than appending a second one, so the source's AS need not be the
        // first element — only that it's still present in a leading confed
        // segment.
        let wire_as_path_keeps_confed_sequence = as_path.is_some_and(|p| {
            matches!(
                p.first(),
                Some((SEG_CONFED_SEQUENCE, asns)) if asns.contains(&u32::from(SOURCE_AS))
            )
        });
        let wire_as_path_has_as_trans =
            as_path.is_some_and(|p| p.iter().any(|(_, asns)| asns.contains(&AS_TRANS)));
        let as4_path_present = as4_path.is_some();
        let as4_path_has_real_asn =
            as4_path.is_some_and(|p| p.iter().any(|(_, asns)| asns.contains(&FOUR_BYTE_ASN)));
        let as4_path_excludes_confed_segments = as4_path.is_none_or(|p| {
            !p.iter()
                .any(|(t, _)| *t == SEG_CONFED_SEQUENCE || *t == SEG_CONFED_SET)
        });

        println!(
            "SCENARIO_OUTCOME: wire_as_path_two_octet={} \
             wire_as_path_keeps_confed_sequence={wire_as_path_keeps_confed_sequence} \
             wire_as_path_has_as_trans={wire_as_path_has_as_trans} \
             as4_path_present={as4_path_present} \
             as4_path_has_real_asn={as4_path_has_real_asn} \
             as4_path_excludes_confed_segments={as4_path_excludes_confed_segments}",
            as_path.is_some(),
        );

        hold_forever_raw(stream).await;
        return;
    }
}

const MSG_UPDATE: u8 = 2;
const ATTR_AS_PATH: u8 = 2;
const ATTR_AS4_PATH: u8 = 17;
const SEG_CONFED_SET: u8 = 4;
const SEG_CONFED_SEQUENCE: u8 = 3;

/// Reads one complete BGP message (RFC 4271 §4.1: 16-byte marker, 2-byte
/// length, 1-byte type) from `stream`, using `buf` as the carry-over buffer.
/// Returns the message type and the body after the 19-byte header.
async fn read_raw_message(stream: &mut TcpStream, buf: &mut Vec<u8>) -> (u8, Vec<u8>) {
    loop {
        if buf.len() >= 19 {
            let len = usize::from(u16::from_be_bytes([buf[16], buf[17]]));
            assert!(
                len >= 19,
                "BGP message length {len} below the 19-byte header"
            );
            if buf.len() >= len {
                let msg_type = buf[18];
                let body = buf[19..len].to_vec();
                buf.drain(..len);
                return (msg_type, body);
            }
        }
        let n = stream
            .read_buf(buf)
            .await
            .expect("read from pathvectord failed");
        assert!(
            n > 0,
            "connection closed unexpectedly while waiting for UPDATE"
        );
    }
}

/// A path as `(segment type, ASNs)` pairs.
type RawPath = Vec<(u8, Vec<u32>)>;

struct RawUpdate {
    announced: Vec<String>,
    /// AS_PATH parsed at two octets per ASN — `None` if the attribute is
    /// absent *or* does not parse cleanly as a two-octet path (so a four-octet
    /// encoding on this OLD-speaker session fails the scenario).
    as_path: Option<RawPath>,
    /// AS4_PATH parsed at four octets per ASN (RFC 6793 §3.2: always four).
    as4_path: Option<RawPath>,
}

/// Parses an UPDATE body (RFC 4271 §4.3) by hand, without `BgpCodec`.
fn parse_raw_update(body: &[u8]) -> Option<RawUpdate> {
    let wd_len = usize::from(u16::from_be_bytes([*body.first()?, *body.get(1)?]));
    let attrs_off = 2 + wd_len;
    let attr_len = usize::from(u16::from_be_bytes([
        *body.get(attrs_off)?,
        *body.get(attrs_off + 1)?,
    ]));
    let attrs = body.get(attrs_off + 2..attrs_off + 2 + attr_len)?;
    let nlri = body.get(attrs_off + 2 + attr_len..)?;

    let mut as_path = None;
    let mut as4_path = None;
    let mut i = 0;
    while i < attrs.len() {
        let flags = *attrs.get(i)?;
        let type_code = *attrs.get(i + 1)?;
        let (len, hdr) = if flags & 0x10 != 0 {
            (
                usize::from(u16::from_be_bytes([*attrs.get(i + 2)?, *attrs.get(i + 3)?])),
                4,
            )
        } else {
            (usize::from(*attrs.get(i + 2)?), 3)
        };
        let value = attrs.get(i + hdr..i + hdr + len)?;
        match type_code {
            ATTR_AS_PATH => as_path = parse_segments(value, 2),
            ATTR_AS4_PATH => as4_path = parse_segments(value, 4),
            _ => {}
        }
        i += hdr + len;
    }

    // IPv4 NLRI: 1-byte prefix length, then ceil(len/8) address bytes.
    let mut announced = Vec::new();
    let mut j = 0;
    while j < nlri.len() {
        let bits = usize::from(nlri[j]);
        let octets = bits.div_ceil(8);
        let mut addr = [0u8; 4];
        addr[..octets].copy_from_slice(nlri.get(j + 1..j + 1 + octets)?);
        announced.push(format!("{}/{bits}", Ipv4Addr::from(addr)));
        j += 1 + octets;
    }

    Some(RawUpdate {
        announced,
        as_path,
        as4_path,
    })
}

/// Parses AS_PATH / AS4_PATH segments with `octets` bytes per ASN (RFC 4271
/// §4.3 segment layout). Returns `None` unless the value is consumed exactly.
fn parse_segments(value: &[u8], octets: usize) -> Option<RawPath> {
    let mut segments = Vec::new();
    let mut i = 0;
    while i < value.len() {
        let seg_type = *value.get(i)?;
        let count = usize::from(*value.get(i + 1)?);
        let end = i + 2 + count * octets;
        let raw = value.get(i + 2..end)?;
        let asns = raw
            .chunks_exact(octets)
            .map(|c| c.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)))
            .collect();
        segments.push((seg_type, asns));
        i = end;
    }
    Some(segments)
}

/// Keepalive-only hold loop over the raw stream (the observer has no codec
/// any more once it has taken the stream apart).
async fn hold_forever_raw(mut stream: TcpStream) {
    // RFC 4271 §4.4: marker (16 × 0xFF), length 19, type 4.
    let mut keepalive = vec![0xFFu8; 16];
    keepalive.extend_from_slice(&[0, 19, 4]);
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if stream.write_all(&keepalive).await.is_err() {
            return;
        }
    }
}
