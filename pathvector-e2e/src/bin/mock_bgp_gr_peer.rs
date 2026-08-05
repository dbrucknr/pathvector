//! A GracefulRestart-capable BGP peer for `pathvector-e2e`'s RFC 4724 §4.1
//! Restarting-Speaker Selection_Deferral_Timer tests.
//!
//! Listens on `:179` and, on the accepted connection, replays one of two
//! scenarios selected by its only argument:
//!
//! - `withhold-eor` — advertises the GracefulRestart capability with a
//!   nonzero `restart_time`, announces a single route, then deliberately
//!   never sends an End-of-RIB marker for the rest of the connection's
//!   lifetime. Proves pathvectord's own Selection_Deferral_Timer (not the
//!   wait-set-satisfied path) is what eventually releases outbound
//!   advertisement to other peers when a configured GR peer never completes
//!   its resync.
//! - `restart-time-zero-delayed-eor` — advertises GracefulRestart with
//!   `restart_time == 0` (RFC 4724 §3's EOR-only mode: "to indicate its
//!   intention of generating the End-of-RIB marker" with no forwarding-state
//!   preservation claim), announces the same route, then blocks until it
//!   receives an explicit release signal on [`EOR_RELEASE_CONTROL_PORT`]
//!   before sending its End-of-RIB marker. Proves the wait-set-satisfied
//!   release path treats a `restart_time == 0` peer the same as any other
//!   GR-capable peer — it must still be waited on until its real EOR
//!   arrives, not treated as if it never advertised the capability at all.
//!   Test-controlled rather than a fixed sleep (flagged by code review on
//!   PR #52: a fixed-wall-clock delay races against harness-startup and
//!   session-establishment overhead that isn't bounded by anything the mock
//!   controls) — see `SelectionDeferralHarness::release_delayed_eor` in
//!   `pathvector-e2e/src/lib.rs`.
//! - `eor-immediately` — advertises GracefulRestart with a nonzero
//!   `restart_time`, sends its End-of-RIB marker as soon as the handshake
//!   completes (no route announced first), then holds the connection open.
//!   Used alongside a second, slower mock peer (a `withhold-eor` instance
//!   under a different AS) to prove the Selection_Deferral_Timer wait-set is
//!   evaluated over the *full configured peer set*: this peer's fast EOR
//!   must not be mistaken for satisfying the other peer's outstanding EOR.
//!
//! Fully expressible via `pathvector_session`'s own `BgpMessage`/`Capability`
//! encoder — no raw-byte hand-rolling needed, matching `mock_bgp_peer.rs`'s
//! precedent (the thing under test here is pathvectord's daemon-level
//! deferral logic, not `pathvector-session`'s own codec).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, GracefulRestartFamily, OpenMessage, PathAttribute, UpdateMessage,
};
use pathvector_types::{AfiSafi, AsPath, Asn, Origin};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_util::codec::Framed;

const MOCK_AS: u16 = 65001;
const MOCK_BGP_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const TEST_PREFIX: &str = "10.150.0.0/24";
/// Port the `restart-time-zero-delayed-eor` scenario listens on for an
/// explicit "release the held-back EOR now" signal from the test — see
/// `SelectionDeferralHarness::release_delayed_eor` in
/// `pathvector-e2e/src/lib.rs`. Kept in sync manually with that constant;
/// no shared crate boundary between this binary and the harness.
const EOR_RELEASE_CONTROL_PORT: u16 = 1790;

#[tokio::main]
async fn main() {
    let scenario = std::env::args()
        .nth(1)
        .expect("usage: mock_bgp_gr_peer <scenario>");

    let eor_release = Arc::new(Notify::new());
    if scenario == "restart-time-zero-delayed-eor" {
        let notify = eor_release.clone();
        tokio::spawn(async move {
            let control_listener = TcpListener::bind(("0.0.0.0", EOR_RELEASE_CONTROL_PORT))
                .await
                .expect("bind EOR-release control port");
            println!("listening for EOR-release control signal on :{EOR_RELEASE_CONTROL_PORT}");
            loop {
                if control_listener.accept().await.is_ok() {
                    println!("received EOR-release control signal");
                    notify.notify_one();
                }
            }
        });
    }

    let listener = TcpListener::bind("0.0.0.0:179").await.expect("bind :179");
    println!("mock_bgp_gr_peer ({scenario}) listening on :179");
    loop {
        let (stream, addr) = listener.accept().await.expect("accept connection");
        println!("accepted connection from {addr}, running scenario {scenario}");
        tokio::spawn(handle_connection(
            stream,
            scenario.clone(),
            eor_release.clone(),
        ));
    }
}

async fn handle_connection(stream: TcpStream, scenario: String, eor_release: Arc<Notify>) {
    match scenario.as_str() {
        "withhold-eor" => withhold_eor(stream, 60).await,
        "restart-time-zero-delayed-eor" => restart_time_zero_delayed_eor(stream, eor_release).await,
        "eor-immediately" => eor_immediately(stream).await,
        other => panic!("unknown scenario: {other}"),
    }
}

fn gr_capability(restart_time: u16) -> Capability {
    Capability::GracefulRestart {
        // N-bit (0x04, RFC 8538) irrelevant here since restart_time carries
        // the meaning we need either way; R-bit (0x08) intentionally clear —
        // this mock is not itself claiming to be mid-restart.
        restart_flags: 0x00,
        restart_time,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: false,
        }],
    }
}

async fn do_handshake(stream: TcpStream, restart_time: u16) -> Framed<TcpStream, BgpCodec> {
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
        capabilities: vec![
            Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
            gr_capability(restart_time),
        ],
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
    println!("session established (restart_time={restart_time})");
    framed
}

fn route_update() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(u32::from(MOCK_AS))])),
            PathAttribute::NextHop(MOCK_BGP_ID),
        ],
        announced: vec![TEST_PREFIX.parse().expect("valid prefix literal")],
    }
}

/// RFC 4724 §2: "The End-of-RIB marker... For the IPv4 Unicast address
/// family, the End-of-RIB marker is an UPDATE message with the minimum
/// length." I.e. no withdrawn routes, no path attributes, no NLRI.
fn end_of_rib() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    }
}

/// Hold the connection open indefinitely with periodic KEEPALIVEs — mirrors
/// `mock_bgp_fault_peer.rs`'s tail-loop pattern.
async fn hold_forever(mut framed: Framed<TcpStream, BgpCodec>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if framed.send(BgpMessage::Keepalive).await.is_err() {
            return;
        }
    }
}

async fn withhold_eor(stream: TcpStream, restart_time: u16) {
    let mut framed = do_handshake(stream, restart_time).await;

    framed
        .send(BgpMessage::Update(route_update()))
        .await
        .unwrap();
    println!("sent route for {TEST_PREFIX}; withholding End-of-RIB indefinitely");

    hold_forever(framed).await;
}

async fn eor_immediately(stream: TcpStream) {
    let mut framed = do_handshake(stream, 60).await;

    framed.send(BgpMessage::Update(end_of_rib())).await.unwrap();
    println!("sent End-of-RIB immediately after the handshake");

    hold_forever(framed).await;
}

async fn restart_time_zero_delayed_eor(stream: TcpStream, eor_release: Arc<Notify>) {
    let mut framed = do_handshake(stream, 0).await;

    framed
        .send(BgpMessage::Update(route_update()))
        .await
        .unwrap();
    println!(
        "sent route for {TEST_PREFIX}; holding End-of-RIB until an explicit release signal \
         arrives on :{EOR_RELEASE_CONTROL_PORT}"
    );

    eor_release.notified().await;

    framed.send(BgpMessage::Update(end_of_rib())).await.unwrap();
    println!("sent End-of-RIB after the release signal");

    hold_forever(framed).await;
}
