//! A minimal, deterministic BGP speaker for the `pathvector-e2e` RFC 9234
//! route-leak-prevention test.
//!
//! Listens on `:179`, accepts pathvectord's dial-in connection, completes the
//! OPEN/KEEPALIVE handshake, then sends two UPDATEs:
//!
//! - `203.0.113.0/24` (TEST-NET-3) carrying a deliberately pre-attached
//!   `ONLY_TO_CUSTOMER` attribute — simulating a route that already leaked
//!   somewhere upstream. pathvectord, configured with `role = "provider"` for
//!   this peer (i.e. this peer is pathvectord's Customer), must reject it: a
//!   well-behaved Customer never sends OTC at all (RFC 9234 §5).
//! - `198.51.100.0/24` (TEST-NET-2), a clean announcement with no OTC — must
//!   be accepted.
//!
//! Deliberately does **not** advertise a Role capability of its own —
//! simulates a legacy/non-RFC-9234-aware customer router, which is exactly
//! the scenario the RFC's own non-strict default exists for: Role absence on
//! one side must not disable enforcement on the other.
//!
//! Unlike `mock_rtr_server.rs`, this reuses `pathvector-session`'s own
//! `BgpMessage` encoder rather than hand-rolling the wire format. That
//! independence mattered there because the RTR *decoder* was the code under
//! test. Here, the thing under test is pathvectord's daemon and policy
//! layer, not `pathvector-session`'s codec (already covered by its own unit
//! tests, proptests, and fuzz targets) — so reusing the crate is the right
//! call, not circular.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, OpenMessage, PathAttribute, UpdateMessage,
};
use pathvector_types::{AfiSafi, AsPath, Asn, Origin};
use tokio::net::TcpListener;
use tokio_util::codec::Framed;

const MOCK_AS: u16 = 65099;
const MOCK_BGP_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 99);
const LEAKED_PREFIX: &str = "203.0.113.0/24";
const CLEAN_PREFIX: &str = "198.51.100.0/24";
/// Arbitrary upstream ASN the "leaked" route's OTC attribute names — distinct
/// from both `MOCK_AS` and pathvectord's own configured local AS.
const UPSTREAM_AS: u32 = 65100;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:179").await.expect("bind :179");
    println!("mock_bgp_peer listening on :179");
    loop {
        let (stream, addr) = listener.accept().await.expect("accept connection");
        println!("accepted connection from {addr}");
        tokio::spawn(handle_connection(stream));
    }
}

async fn handle_connection(stream: tokio::net::TcpStream) {
    let mut framed = Framed::new(stream, BgpCodec::new());

    let Some(Ok(BgpMessage::Open(peer_open))) = framed.next().await else {
        eprintln!("expected OPEN as the first message; closing");
        return;
    };
    println!("received OPEN from peer AS {}", peer_open.my_as);

    let our_open = OpenMessage {
        version: 4,
        my_as: MOCK_AS,
        hold_time: 9,
        bgp_id: MOCK_BGP_ID,
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

    let leaked = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(MOCK_AS))])),
            PathAttribute::NextHop(MOCK_BGP_ID),
            PathAttribute::OnlyToCustomer(Asn::new(UPSTREAM_AS)),
        ],
        announced: vec![LEAKED_PREFIX.parse().expect("valid prefix literal")],
    };
    if framed.send(BgpMessage::Update(leaked)).await.is_err() {
        return;
    }
    println!("sent leaked route {LEAKED_PREFIX} (OTC = AS{UPSTREAM_AS})");

    let clean = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(MOCK_AS))])),
            PathAttribute::NextHop(MOCK_BGP_ID),
        ],
        announced: vec![CLEAN_PREFIX.parse().expect("valid prefix literal")],
    };
    if framed.send(BgpMessage::Update(clean)).await.is_err() {
        return;
    }
    println!("sent clean route {CLEAN_PREFIX}");

    // Keep the session alive (short hold_time in the e2e config) while the
    // test polls pathvectord's gRPC surface for the outcome.
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(3)) => {
                if framed.send(BgpMessage::Keepalive).await.is_err() {
                    return;
                }
            }
            msg = framed.next() => {
                if !matches!(msg, Some(Ok(_))) {
                    return;
                }
            }
        }
    }
}
