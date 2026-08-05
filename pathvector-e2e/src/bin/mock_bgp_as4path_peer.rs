//! A peer pair for `pathvector-e2e`'s RFC 6793 §4 / RFC 5065 AS4_PATH
//! confederation-stripping test: proves that when a route carrying a
//! confederation segment is relayed toward a two-byte-ASN-only fellow
//! confederation Member-AS peer, the wire AS_PATH keeps the confed segment
//! (RFC 5065 §5.3 — a `ConfedMember` peer sees the same AS_PATH shape as an
//! internal one) while AS4_PATH, if emitted, excludes it entirely (RFC 6793
//! §§3, 4.2.2: "declared invalid for the AS4_PATH attribute and MUST NOT be
//! included").
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
//!   (so pathvectord treats *this* session as two-byte-only and applies the
//!   RFC 6793 §4 AS_TRANS/AS4_PATH downgrade), then decodes the real wire
//!   bytes of pathvectord's re-advertised UPDATE and logs a
//!   `SCENARIO_OUTCOME:` line recording: whether the wire AS_PATH still
//!   contains the leading `AS_CONFED_SEQUENCE` segment (it must — RFC 5065
//!   §5.3), whether it substitutes AS_TRANS (23456) for the 4-byte ASN
//!   (RFC 6793 §4), whether AS4_PATH is present and carries the real
//!   4-byte ASN, and whether AS4_PATH excludes the confed segment.
//!
//! Fully expressible via `pathvector_session`'s own `BgpMessage`/
//! `PathAttribute`/`Capability` encoder — no raw-byte hand-rolling needed.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{BgpMessage, Capability, OpenMessage, PathAttribute};
use pathvector_types::{AfiSafi, AsPath, AsPathSegment, Asn, Origin};
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
    let mut framed = do_handshake(stream, OBSERVER_AS, OBSERVER_BGP_ID, false).await;

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

                let as_path = update.attributes.iter().find_map(|attr| match attr {
                    PathAttribute::AsPath(p) => Some(p.clone()),
                    _ => None,
                });
                let as4_path = update.attributes.iter().find_map(|attr| match attr {
                    PathAttribute::As4Path(p) => Some(p.clone()),
                    _ => None,
                });

                // The leading segment must still be an AS_CONFED_SEQUENCE (RFC
                // 5065 §5.3 — confed segments are NOT stripped toward a
                // fellow ConfedMember peer), and it must still contain the
                // source's own AS somewhere within it. pathvectord's own
                // prepend_confed() extends this same leading segment with
                // its own Member-AS number rather than appending a second
                // one, so the source's AS need not be the first element —
                // only that it's still present in a leading confed segment.
                let wire_as_path_keeps_confed_sequence = as_path.as_ref().is_some_and(|p| {
                    matches!(
                        p.segments().first(),
                        Some(AsPathSegment::ConfedSequence(asns))
                            if asns.contains(&Asn::new(u32::from(SOURCE_AS)))
                    )
                });
                let wire_as_path_has_as_trans = as_path.as_ref().is_some_and(|p| {
                    p.segments()
                        .iter()
                        .flat_map(|s| s.asns().to_vec())
                        .any(|a| a == Asn::new(AS_TRANS))
                });
                let as4_path_present = as4_path.is_some();
                let as4_path_has_real_asn = as4_path.as_ref().is_some_and(|p| {
                    p.segments()
                        .iter()
                        .flat_map(|s| s.asns().to_vec())
                        .any(|a| a == Asn::new(FOUR_BYTE_ASN))
                });
                let as4_path_excludes_confed_segments = as4_path.as_ref().is_none_or(|p| {
                    !p.segments().iter().any(|s| {
                        matches!(
                            s,
                            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_)
                        )
                    })
                });

                println!(
                    "SCENARIO_OUTCOME: wire_as_path_keeps_confed_sequence={wire_as_path_keeps_confed_sequence} \
                     wire_as_path_has_as_trans={wire_as_path_has_as_trans} \
                     as4_path_present={as4_path_present} \
                     as4_path_has_real_asn={as4_path_has_real_asn} \
                     as4_path_excludes_confed_segments={as4_path_excludes_confed_segments}"
                );

                hold_forever(framed).await;
                return;
            }
            Some(Ok(_)) => {}
            other => panic!("connection closed unexpectedly while waiting for UPDATE: {other:?}"),
        }
    }
}
