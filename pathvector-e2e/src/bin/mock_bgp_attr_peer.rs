//! A peer pair for `pathvector-e2e`'s RFC 4271 §5 unrecognized-attribute
//! relay test: proves the *entire* decode → daemon storage → RIB →
//! outbound-reconstruction → encode pipeline for unrecognized transitive
//! optional attributes, not just any one layer in isolation.
//!
//! Listens on `:179` and, on the accepted connection, plays one of two
//! roles selected by its only argument:
//!
//! - `source` — completes the handshake, then sends a single UPDATE
//!   announcing [`TEST_PREFIX`] carrying two unrecognized attributes:
//!   [`UNKNOWN_TRANSITIVE_TYPE`] (Optional+Transitive, Partial bit
//!   deliberately clear — RFC 4271 §5's "Paths with unrecognized
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
//! Fully expressible via `pathvector_session`'s own `BgpMessage`/
//! `PathAttribute` encoder — `PathAttribute::Unknown`'s fields are exactly
//! what's needed to construct both a Partial-bit-clear transitive
//! unrecognized attribute and a non-transitive one, with no raw-byte
//! hand-rolling required.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{BgpMessage, Capability, OpenMessage, PathAttribute};
use pathvector_types::{AfiSafi, AsPath, Asn, Origin};
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
    let mut framed = do_handshake(stream).await;

    let update = pathvector_session::message::UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(MOCK_AS))])),
            PathAttribute::NextHop(MOCK_BGP_ID),
            PathAttribute::Unknown {
                flags: FLAGS_OPTIONAL_TRANSITIVE,
                type_code: UNKNOWN_TRANSITIVE_TYPE,
                value: UNKNOWN_TRANSITIVE_VALUE.to_vec(),
            },
            PathAttribute::Unknown {
                flags: FLAGS_OPTIONAL_NONTRANSITIVE,
                type_code: UNKNOWN_NONTRANSITIVE_TYPE,
                value: UNKNOWN_NONTRANSITIVE_VALUE.to_vec(),
            },
        ],
        announced: vec![TEST_PREFIX.parse().expect("valid prefix literal")],
    };
    framed.send(BgpMessage::Update(update)).await.unwrap();
    println!(
        "sent route for {TEST_PREFIX} carrying unknown-transitive (type \
         {UNKNOWN_TRANSITIVE_TYPE}) and unknown-non-transitive (type \
         {UNKNOWN_NONTRANSITIVE_TYPE}) attributes"
    );

    hold_forever(framed).await;
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
