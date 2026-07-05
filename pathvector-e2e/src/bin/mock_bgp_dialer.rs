//! A minimal BGP speaker that actively **dials** a target instead of
//! listening — the mirror image of `mock_bgp_peer.rs`.
//!
//! Every other e2e test topology in this crate configures GoBGP with
//! `passive-mode = true`, so pathvectord is always the side that dials out.
//! That's fine for exercising pathvectord's outbound connect path, but it
//! never exercises pathvectord's *listener* accepting a real inbound
//! connection through a full OPEN/KEEPALIVE handshake to Established.
//!
//! This binary closes that gap for the native-IPv6-transport test: it
//! connects out to the address given as its only argument (a bracketed
//! `SocketAddr`, e.g. `"[fd00:1::10]:179"`), completes the BGP handshake as
//! the TCP-active side, and then holds the session open (answering
//! KEEPALIVEs) so the test can poll pathvectord's gRPC surface for the
//! outcome. pathvectord's own peer config points at a deliberately wrong
//! port for its own outbound dial (see `Ipv6AcceptHarness`), so this
//! connection — and therefore pathvectord's accept path — is the only way
//! the session can reach Established.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{BgpMessage, OpenMessage};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

const MOCK_AS: u16 = 65099;
const MOCK_BGP_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 99);

#[tokio::main]
async fn main() {
    let target: SocketAddr = std::env::args()
        .nth(1)
        .expect("usage: mock_bgp_dialer <bracketed-socket-addr>")
        .parse()
        .expect("argument must be a valid SocketAddr, e.g. \"[fd00:1::10]:179\"");

    println!("dialing {target}");
    let stream = TcpStream::connect(target).await.expect("connect to target");
    println!("connected to {target}");

    let mut framed = Framed::new(stream, BgpCodec::new());

    let our_open = OpenMessage {
        version: 4,
        my_as: MOCK_AS,
        hold_time: 9,
        bgp_id: MOCK_BGP_ID,
        capabilities: vec![],
    };
    framed
        .send(BgpMessage::Open(our_open))
        .await
        .expect("send OPEN");

    let Some(Ok(BgpMessage::Open(peer_open))) = framed.next().await else {
        panic!("expected OPEN in response; connection closed or unexpected message");
    };
    println!("received OPEN from peer AS {}", peer_open.my_as);

    framed
        .send(BgpMessage::Keepalive)
        .await
        .expect("send KEEPALIVE");

    // Drain until pathvectord's own KEEPALIVE arrives, confirming it reached
    // Established on its side too.
    loop {
        match framed.next().await {
            Some(Ok(BgpMessage::Keepalive)) => break,
            Some(Ok(_)) => {}
            _ => panic!("connection closed before peer's KEEPALIVE arrived"),
        }
    }
    println!("session established");

    // Hold the connection open while the test polls pathvectord's gRPC state.
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
