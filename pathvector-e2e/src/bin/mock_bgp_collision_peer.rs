//! A BGP peer that both listens *and* dials, used to force a real,
//! deliberately-sequenced (not accidental) TCP connection collision against
//! pathvectord — proving RFC 4271 §6.8 (connection collision resolution) and
//! RFC 4724 §4.2 (Established-state Graceful-Restart override) against a
//! genuine second TCP connection through pathvectord's actual listener, not
//! just an in-process mock transport.
//!
//! Takes two CLI arguments: `<pathvectord-dial-target> <scenario>`, where
//! `pathvectord-dial-target` is `host:179` (the container name is resolved
//! via Docker's embedded DNS on the test's bridge network — this mock only
//! needs to be told pathvectord's name, not its IP, because by the time this
//! mock dials back, pathvectord is already up and network-attached) and
//! `scenario` is one of:
//!
//! - `peer-id-lower` — this mock advertises a BGP ID lower than
//!   pathvectord's configured `10.0.0.2`. Per RFC 4271 §6.8 rule 3,
//!   pathvectord must keep its existing (outbound, connection #1) session
//!   and reject the incoming (connection #2) one outright.
//! - `peer-id-higher` — this mock advertises a BGP ID higher than
//!   pathvectord's `10.0.0.2`. Per RFC 4271 §6.8 rule 2, pathvectord must
//!   close connection #1 — sending a Cease/ConnectionCollisionResolution
//!   NOTIFICATION on it first — and adopt connection #2, treating it like a
//!   fresh dial (sending its own OPEN there first).
//! - `gr-established-override` — this mock advertises the Graceful Restart
//!   capability (with IPv4 unicast forwarding-preserved, so RFC 4724 §4.2's
//!   retention logic actually applies to the route below rather than
//!   treating it as a not-GR-covered family to flush) and announces one
//!   route, then completes a full handshake to Established on connection #1,
//!   then goes silent on it (never reads, writes, or drops it — so no
//!   FIN/RST is ever produced) before dialing pathvectord again to create
//!   connection #2. Per RFC 4724 §4.2, pathvectord must silently drop
//!   connection #1 (no NOTIFICATION, unlike the two scenarios above), adopt
//!   connection #2, and — the part this scenario specifically proves beyond
//!   the bare connection-adoption decision — the route announced on
//!   connection #1 must still be present immediately after connection #2
//!   reaches Established, proving retention survived this exact trigger
//!   path rather than the daemon's pre-existing GR-retention machinery
//!   (already tested elsewhere for a plain disconnect/reconnect) never
//!   getting reached at all.
//!
//! For all three scenarios, connection #1 is always pathvectord's own
//! outbound dial to this mock (accepted via the `TcpListener` started in
//! `main`); connection #2 is always this mock dialing back into
//! pathvectord's listener.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, GracefulRestartFamily, OpenMessage, PathAttribute, UpdateMessage,
};
use pathvector_types::{AfiSafi, AsPath, Asn, Origin};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

const HOLD_TIME: u16 = 9;
const MOCK_AS: u16 = 65099;

/// Announced on connection #1 before the abandon-and-redial cycle, in the
/// `gr-established-override` scenario only.
const GR_TEST_PREFIX: &str = "10.88.0.0/24";

/// Lower than pathvectord's hardcoded `10.0.0.2` (RFC 4271 §6.8 rule 3:
/// local/pathvectord's ID is higher, so it keeps its outbound connection).
const BGP_ID_LOWER: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 1);
/// Higher than pathvectord's hardcoded `10.0.0.2` (RFC 4271 §6.8 rule 2:
/// local/pathvectord's ID is lower, so it closes its outbound connection).
const BGP_ID_HIGHER: Ipv4Addr = Ipv4Addr::new(20, 0, 0, 1);
/// Used for the GR-override scenario, where BGP-ID ordering doesn't matter.
const BGP_ID_GR: Ipv4Addr = Ipv4Addr::new(30, 0, 0, 1);

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let pathvectord_target = args
        .next()
        .expect("usage: mock_bgp_collision_peer <pathvectord-dial-target> <scenario>");
    let scenario = args
        .next()
        .expect("usage: mock_bgp_collision_peer <pathvectord-dial-target> <scenario>");

    let listener = TcpListener::bind("0.0.0.0:179").await.expect("bind :179");
    println!(
        "mock_bgp_collision_peer ({scenario}) listening on :179, will dial {pathvectord_target}"
    );

    // Connection #1 must be pathvectord's own outbound dial to this mock —
    // but Docker's own HEALTHCHECK (`nc -z 127.0.0.1 179`) also connects to
    // this port periodically to confirm the listener is bound, then
    // disconnects immediately without sending anything. Loop accepting
    // connections and discard any that don't send a real OPEN as their
    // first message, so a healthcheck probe can never be mistaken for
    // pathvectord's real dial.
    let (framed1, peer_open) = loop {
        let (stream, addr) = listener.accept().await.expect("accept connection #1");
        let mut framed = Framed::new(stream, BgpCodec::new());
        match framed.next().await {
            Some(Ok(BgpMessage::Open(open))) => {
                println!("accepted connection #1 from {addr} (real OPEN received)");
                break (framed, open);
            }
            _ => {
                println!("ignoring non-BGP probe connection from {addr} (e.g. healthcheck)");
            }
        }
    };
    println!(
        "connection #1: received OPEN from peer AS {}",
        peer_open.my_as
    );

    match scenario.as_str() {
        "peer-id-lower" => {
            collision_scenario(framed1, &pathvectord_target, BGP_ID_LOWER, false).await;
        }
        "peer-id-higher" => {
            collision_scenario(framed1, &pathvectord_target, BGP_ID_HIGHER, true).await;
        }
        "gr-established-override" => {
            gr_established_override(framed1, &pathvectord_target).await;
        }
        other => panic!("unknown scenario: {other}"),
    }
}

fn open_message(bgp_id: Ipv4Addr, capabilities: Vec<Capability>) -> BgpMessage {
    BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: MOCK_AS,
        hold_time: HOLD_TIME,
        bgp_id,
        capabilities,
    })
}

/// RFC 4271 §6.8: exercises the collision-resolution comparison over two
/// real TCP connections. `mock_wins` selects which connection this mock
/// expects to survive: `false` (BGP_ID_LOWER) → pathvectord keeps
/// connection #1; `true` (BGP_ID_HIGHER) → pathvectord closes connection #1
/// (with a NOTIFICATION) and adopts connection #2. `framed1`'s peer OPEN has
/// already been consumed by the caller (see `main`'s accept loop).
async fn collision_scenario(
    mut framed1: Framed<TcpStream, BgpCodec>,
    pathvectord_target: &str,
    bgp_id: Ipv4Addr,
    mock_wins: bool,
) {
    // Respond with our OPEN, but deliberately withhold KEEPALIVE — this
    // holds pathvectord in OpenConfirm (not yet Established) so the
    // incoming connection #2 below exercises the OpenConfirm collision arm,
    // not the separate Established/GR arm.
    if framed1.send(open_message(bgp_id, vec![])).await.is_err() {
        return;
    }
    println!("connection #1: sent our OPEN (bgp_id={bgp_id}); withholding KEEPALIVE");

    // Give pathvectord's own event loop time to process our OPEN and
    // transition to OpenConfirm (peer_bgp_id now known) before we dial in —
    // otherwise pathvectord might still be in OpenSent, where an unknown
    // peer_bgp_id makes it conservatively adopt any incoming connection
    // regardless of BGP ID, rather than deciding via the comparison under
    // test here.
    tokio::time::sleep(Duration::from_secs(1)).await;

    println!("dialing {pathvectord_target} for connection #2");
    let stream2 = TcpStream::connect(pathvectord_target)
        .await
        .expect("connect to pathvectord for connection #2");
    let mut framed2 = Framed::new(stream2, BgpCodec::new());

    if mock_wins {
        // RFC 4271 §6.8 rule 2 (local BGP ID lower than peer's): pathvectord
        // closes connection #1 (Cease/ConnectionCollisionResolution
        // NOTIFICATION first), then treats connection #2 like a fresh dial —
        // sending its own OPEN there first, exactly as if it had just
        // connected out.
        let Some(Ok(BgpMessage::Open(reopened))) = framed2.next().await else {
            eprintln!("expected a fresh OPEN from pathvectord on the adopted connection #2");
            return;
        };
        println!(
            "connection #2: received pathvectord's fresh OPEN from AS {}",
            reopened.my_as
        );
        if framed2.send(open_message(bgp_id, vec![])).await.is_err() {
            return;
        }
        if framed2.send(BgpMessage::Keepalive).await.is_err() {
            return;
        }
        // Drain until pathvectord's own KEEPALIVE arrives, confirming
        // Established on connection #2.
        loop {
            match framed2.next().await {
                Some(Ok(BgpMessage::Keepalive)) => break,
                Some(Ok(_)) => {}
                _ => return,
            }
        }
        println!("connection #2: established (mock's higher BGP ID wins the collision)");
        hold_open(framed2).await;
    } else {
        // RFC 4271 §6.8 rule 3 (local BGP ID higher than peer's):
        // pathvectord keeps connection #1 and rejects connection #2
        // outright — no BGP-level response on #2 at all, just a closed
        // socket. Confirm that (best-effort — not the primary assertion,
        // which is the daemon's own reported session state via gRPC).
        if framed2.send(open_message(bgp_id, vec![])).await.is_err() {
            println!("connection #2: send failed immediately (rejected before OPEN even sent)");
        }
        match framed2.next().await {
            None => println!("connection #2: closed with no BGP response, as expected"),
            Some(other) => println!("connection #2: unexpected response: {other:?}"),
        }

        // Complete the handshake on connection #1 instead.
        if framed1.send(BgpMessage::Keepalive).await.is_err() {
            return;
        }
        loop {
            match framed1.next().await {
                Some(Ok(BgpMessage::Keepalive)) => break,
                Some(Ok(_)) => {}
                _ => return,
            }
        }
        println!("connection #1: established (mock's lower BGP ID loses the collision)");
        hold_open(framed1).await;
    }
}

/// RFC 4724 §4.2: establishes with GracefulRestart negotiated, then
/// abandons connection #1 without ever closing it (so no FIN/RST is
/// produced — pathvectord's own TCP stack sees nothing wrong), and dials a
/// fresh connection #2, again advertising GracefulRestart. Per the fix,
/// pathvectord must silently adopt connection #2 with no NOTIFICATION.
async fn gr_established_override(
    mut framed1: Framed<TcpStream, BgpCodec>,
    pathvectord_target: &str,
) {
    // RFC 4724 §3: the family list (not just the bare capability) is what
    // tells the receiving speaker which AFI/SAFIs it should actually retain
    // routes for — an empty list means "GR-negotiated but nothing declared
    // GR-covered," which would make the daemon's own §4.2 logic flush this
    // route as not-covered rather than retain it.
    let gr_capability = vec![Capability::GracefulRestart {
        restart_flags: 0,
        restart_time: 120,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: true,
        }],
    }];

    if framed1
        .send(open_message(BGP_ID_GR, gr_capability.clone()))
        .await
        .is_err()
    {
        return;
    }
    if framed1.send(BgpMessage::Keepalive).await.is_err() {
        return;
    }
    loop {
        match framed1.next().await {
            Some(Ok(BgpMessage::Keepalive)) => break,
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    println!("connection #1: established with Graceful Restart negotiated");

    // Announce one route before abandoning the connection — this is what
    // lets the test prove RFC 4724 §4.2's retention promise actually held
    // through the collision-triggered switchover below, not just that the
    // connection bookkeeping worked.
    let route = UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(MOCK_AS))])),
            PathAttribute::NextHop(BGP_ID_GR),
        ],
        announced: vec![GR_TEST_PREFIX.parse().expect("valid prefix literal")],
    };
    if framed1.send(BgpMessage::Update(route)).await.is_err() {
        return;
    }
    println!("connection #1: announced {GR_TEST_PREFIX}");

    // Give the test a window to observe the route installed before the
    // abandon-and-redial cycle below.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Abandon connection #1 without closing it: move it into a task that
    // never touches it again. Dropping the stream here would send a FIN,
    // which is exactly the "cleanly detected" case RFC 4724 §4.2 does NOT
    // cover — the whole point is that pathvectord's own TCP stack observes
    // nothing wrong with this connection.
    let stream1 = framed1.into_inner();
    tokio::spawn(async move {
        let _stream1 = stream1;
        std::future::pending::<()>().await;
    });
    println!("connection #1: abandoned silently (no FIN/RST) — simulating an undetected TCP death");

    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("dialing {pathvectord_target} for connection #2");
    let stream2 = TcpStream::connect(pathvectord_target)
        .await
        .expect("connect to pathvectord for connection #2");
    let mut framed2 = Framed::new(stream2, BgpCodec::new());

    // Per RFC 4724 §4.2, pathvectord treats this exactly like a fresh dial:
    // it sends its own OPEN on the adopted connection first, with no
    // NOTIFICATION ever appearing on connection #1.
    let Some(Ok(BgpMessage::Open(reopened))) = framed2.next().await else {
        eprintln!("expected a fresh OPEN from pathvectord on the adopted connection #2");
        return;
    };
    println!(
        "connection #2: received pathvectord's fresh OPEN from AS {}",
        reopened.my_as
    );
    if framed2
        .send(open_message(BGP_ID_GR, gr_capability))
        .await
        .is_err()
    {
        return;
    }
    if framed2.send(BgpMessage::Keepalive).await.is_err() {
        return;
    }
    loop {
        match framed2.next().await {
            Some(Ok(BgpMessage::Keepalive)) => break,
            Some(Ok(_)) => {}
            _ => return,
        }
    }
    println!("connection #2: established — RFC 4724 §4.2 override succeeded");
    hold_open(framed2).await;
}

/// Hold a completed connection open with periodic keepalives, so the test
/// has time to observe the final state via gRPC without racing a teardown.
async fn hold_open(mut framed: Framed<TcpStream, BgpCodec>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(3)) => {
                if framed.send(BgpMessage::Keepalive).await.is_err() {
                    return;
                }
            }
            msg = framed.next() => {
                match msg {
                    Some(Ok(_)) => {}
                    _ => return,
                }
            }
        }
    }
}
