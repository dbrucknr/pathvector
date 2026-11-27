//! Issue #98, over a real loopback TCP connection with raw wire bytes: a
//! malformed UPDATE must be handled by the RFC 4271 §8.2.2 state machine
//! *before* any RFC 7606 recovery or route emission.
//!
//! Every payload below is a hand-built UPDATE frame carrying a *route* (the
//! mandatory well-known attributes plus NLRI 198.51.100.0/24) with exactly
//! one defect chosen to hit one RFC 7606 recovery outcome, decoded by the
//! production `BgpCodec`. Responses are read back off the wire and decoded
//! with the real codec, so the exact NOTIFICATION bytes are asserted, not a
//! typed value.
//!
//! The same route delivered with no defect (`Payload::Normal`) is the parity
//! baseline: before `Established`, a malformed UPDATE must produce exactly
//! the outcome a normal UPDATE does (RFC 4271 §8.2.2 OpenSent Events 27-28
//! and OpenConfirm Events 27-28 both mandate a Finite State Machine Error).

#![allow(clippy::doc_markdown)] // RFC prose and event names, not identifiers

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use pathvector_session::message::{
    BgpMessage, Capability, NotificationError, NotificationMessage, OpenMessage, PathAttribute,
    UpdateMsgError,
};
use pathvector_session::transport::{
    SessionConfig, SessionEvent, SessionHandle, TerminationReason, spawn,
};

// ── Wire helpers ─────────────────────────────────────────────────────────────

const ORIGIN_IGP: [u8; 4] = [0x40, 0x01, 0x01, 0x00];
/// RFC 7606 §3(e): an undefined ORIGIN value (5) is treat-as-withdraw.
const ORIGIN_INVALID: [u8; 4] = [0x40, 0x01, 0x01, 0x05];
/// `AS_SEQUENCE` of one four-octet ASN, 65002.
const AS_PATH: [u8; 9] = [0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xea];
const NEXT_HOP: [u8; 7] = [0x40, 0x03, 0x04, 192, 0, 2, 1];
const NLRI: [u8; 4] = [24, 198, 51, 100];
/// RFC 7606 §7.7: an AGGREGATOR whose length fits neither the two- nor the
/// four-octet form is attribute-discard.
const AGGREGATOR_BAD_LEN: [u8; 6] = [0xC0, 0x07, 0x03, 0x01, 0x02, 0x03];
/// RFC 4271 §6.3: type 210 with the Optional bit clear is an unrecognized
/// well-known attribute → session reset, Data = (type, length, value).
const UNRECOGNIZED_WELL_KNOWN: [u8; 6] = [0x40, 210, 0x03, 0x01, 0x02, 0x03];

#[derive(Clone, Copy, Debug)]
enum Payload {
    /// A well-formed route UPDATE (parity baseline).
    Normal,
    /// RFC 7606 attribute discard (malformed AGGREGATOR).
    AttributeDiscard,
    /// RFC 7606 treat-as-withdraw (invalid ORIGIN).
    TreatAsWithdraw,
    /// RFC 4271 §6.3 session reset (unrecognized well-known attribute).
    SessionReset,
}

const ALL_PAYLOADS: [Payload; 4] = [
    Payload::Normal,
    Payload::AttributeDiscard,
    Payload::TreatAsWithdraw,
    Payload::SessionReset,
];

fn frame_of(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0xFF; 16];
    f.extend_from_slice(&u16::try_from(19 + body.len()).unwrap().to_be_bytes());
    f.push(msg_type);
    f.extend_from_slice(body);
    f
}

fn update_frame(payload: Payload) -> Vec<u8> {
    let mut attrs = Vec::new();
    attrs.extend_from_slice(match payload {
        Payload::TreatAsWithdraw => &ORIGIN_INVALID,
        _ => &ORIGIN_IGP,
    });
    attrs.extend_from_slice(&AS_PATH);
    attrs.extend_from_slice(&NEXT_HOP);
    match payload {
        Payload::AttributeDiscard => attrs.extend_from_slice(&AGGREGATOR_BAD_LEN),
        Payload::SessionReset => attrs.extend_from_slice(&UNRECOGNIZED_WELL_KNOWN),
        Payload::Normal | Payload::TreatAsWithdraw => {}
    }
    let mut body = vec![0, 0];
    body.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&attrs);
    body.extend_from_slice(&NLRI);
    frame_of(2, &body)
}

async fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 19];
    s.read_exact(&mut hdr).await.ok()?;
    let len = usize::from(u16::from_be_bytes([hdr[16], hdr[17]]));
    let mut frame = hdr.to_vec();
    frame.resize(len, 0);
    s.read_exact(&mut frame[19..]).await.ok()?;
    Some(frame)
}

async fn read_notification(s: &mut TcpStream) -> NotificationMessage {
    let frame = tokio::time::timeout(Duration::from_secs(5), read_frame(s))
        .await
        .expect("timed out waiting for a NOTIFICATION")
        .expect("connection closed before a NOTIFICATION arrived");
    match BgpMessage::decode(&frame).expect("NOTIFICATION must decode with the real codec") {
        BgpMessage::Notification(n) => n,
        other => panic!("expected a NOTIFICATION, got {other:?}"),
    }
}

/// After the NOTIFICATION the session must close the TCP connection.
async fn assert_closed(s: &mut TcpStream) {
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("timed out waiting for the session to close the connection")
        .unwrap_or(0);
    assert_eq!(n, 0, "session must drop the TCP connection");
}

fn peer_open_bytes() -> Vec<u8> {
    BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time: 90,
        bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![Capability::FourByteAsn(65002)],
    })
    .encode()
}

fn config(peer_addr: std::net::SocketAddr, hold_time: u16, retry: Duration) -> SessionConfig {
    SessionConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time,
        capabilities: vec![Capability::FourByteAsn(65001)],
        required_capabilities: vec![],
        peer_as: Some(65002),
        confederation_member: false,
        public_as: 65001,
        peer_addr,
        tcp_md5: None,
        connect_retry_time: retry,
        send_hold_time: pathvector_session::fsm::SendHoldTime::default(),
    }
}

async fn bind() -> (TcpListener, std::net::SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

/// Accept the session's connection and read its OPEN (RFC 4271 §8.2.2:
/// the session is now in `OpenSent`).
async fn accept_to_open_sent(listener: &TcpListener) -> TcpStream {
    let (mut s, _) = listener.accept().await.unwrap();
    let open = read_frame(&mut s).await.expect("session OPEN");
    assert_eq!(open[18], 1, "first message must be OPEN");
    s
}

/// Continue to `OpenConfirm`: send the peer OPEN, read the session KEEPALIVE.
async fn advance_to_open_confirm(s: &mut TcpStream) {
    s.write_all(&peer_open_bytes()).await.unwrap();
    let ka = read_frame(s).await.expect("session KEEPALIVE");
    assert_eq!(ka[18], 4, "OpenConfirm entry must send KEEPALIVE");
}

/// Continue to `Established`.
async fn advance_to_established(s: &mut TcpStream) {
    advance_to_open_confirm(s).await;
    s.write_all(&BgpMessage::Keepalive.encode()).await.unwrap();
}

async fn next_event(handle: &mut impl SessionHandle, within: Duration) -> Option<SessionEvent> {
    tokio::time::timeout(within, handle.next_event())
        .await
        .ok()
        .flatten()
}

async fn expect_established(handle: &mut impl SessionHandle) {
    let ev = next_event(handle, Duration::from_secs(5))
        .await
        .expect("session event");
    assert!(
        matches!(ev, SessionEvent::Established(_)),
        "expected Established, got {ev:?}"
    );
}

fn nlri() -> pathvector_types::Nlri<Ipv4Addr> {
    pathvector_types::Nlri::new(Ipv4Addr::new(198, 51, 100, 0), 24).unwrap()
}

// ── Before Established: RFC 4271 §8.2.2 OpenSent / OpenConfirm ───────────────

/// RFC 4271 §8.2.2 OpenSent, "any other event (Events 9, 11-13, 20, 25-28)":
/// NOTIFICATION Finite State Machine Error (RFC 6608 subcode 1), drop TCP.
/// Applies to a valid UPDATE (Event 27) *and* to a malformed one whatever its
/// RFC 7606 recovery outcome (Event 28 / recoverable): no route event may
/// cross the session boundary, and no Update-error NOTIFICATION may replace
/// the FSM error.
#[tokio::test]
async fn open_sent_update_of_every_recovery_outcome_is_an_fsm_error_with_no_route_event() {
    for payload in ALL_PAYLOADS {
        let (listener, addr) = bind().await;
        let mut handle = spawn(config(addr, 90, Duration::from_secs(120)));
        handle.start().await;

        let mut peer = accept_to_open_sent(&listener).await;
        peer.write_all(&update_frame(payload)).await.unwrap();

        // The issue-#98 symptom: a recovered malformed UPDATE used to cross
        // the route-event boundary here, before Established. Nothing — no
        // RouteUpdate, no Established, no Terminated — may be emitted.
        let ev = next_event(&mut handle, Duration::from_millis(300)).await;
        assert!(
            ev.is_none(),
            "{payload:?}: no session event expected, got {ev:?}"
        );

        let n = read_notification(&mut peer).await;
        assert_eq!(
            n,
            NotificationMessage {
                error: NotificationError::FsmErrorOpenSent,
                // RFC 6608 §4: one octet, the type of the unexpected message.
                data: vec![2]
            },
            "{payload:?}: OpenSent must answer with Finite State Machine Error subcode 1"
        );
        assert_closed(&mut peer).await;

        // Never Established, so no Terminated either: the channel is silent.
        let ev = next_event(&mut handle, Duration::from_millis(200)).await;
        assert!(
            ev.is_none(),
            "{payload:?}: no session event expected, got {ev:?}"
        );
    }
}

/// RFC 4271 §8.2.2 OpenConfirm, "any other event (Events 9, 12-13, 20,
/// 27-28)": NOTIFICATION Finite State Machine Error (RFC 6608 subcode 2),
/// drop TCP — for the normal UPDATE and every malformed recovery outcome.
#[tokio::test]
async fn open_confirm_update_of_every_recovery_outcome_is_an_fsm_error_with_no_route_event() {
    for payload in ALL_PAYLOADS {
        let (listener, addr) = bind().await;
        let mut handle = spawn(config(addr, 90, Duration::from_secs(120)));
        handle.start().await;

        let mut peer = accept_to_open_sent(&listener).await;
        advance_to_open_confirm(&mut peer).await;
        peer.write_all(&update_frame(payload)).await.unwrap();

        // The issue-#98 symptom: a recovered malformed UPDATE used to cross
        // the route-event boundary here, before Established. Nothing — no
        // RouteUpdate, no Established, no Terminated — may be emitted.
        let ev = next_event(&mut handle, Duration::from_millis(300)).await;
        assert!(
            ev.is_none(),
            "{payload:?}: no session event expected, got {ev:?}"
        );

        let n = read_notification(&mut peer).await;
        assert_eq!(
            n,
            NotificationMessage {
                error: NotificationError::FsmErrorOpenConfirm,
                data: vec![2]
            },
            "{payload:?}: OpenConfirm must answer with Finite State Machine Error subcode 2"
        );
        assert_closed(&mut peer).await;

        let ev = next_event(&mut handle, Duration::from_millis(200)).await;
        assert!(
            ev.is_none(),
            "{payload:?}: no session event expected, got {ev:?}"
        );
    }
}

// ── Established: RFC 7606 recovery outcomes ──────────────────────────────────

/// RFC 7606 §2 attribute discard: the UPDATE "continues to be processed" —
/// the route is announced (Event 27) and the session stays up.
#[tokio::test]
async fn established_attribute_discard_announces_route_and_session_stays_up() {
    let (listener, addr) = bind().await;
    let mut handle = spawn(config(addr, 90, Duration::from_secs(120)));
    handle.start().await;
    let mut peer = accept_to_open_sent(&listener).await;
    advance_to_established(&mut peer).await;
    expect_established(&mut handle).await;

    peer.write_all(&update_frame(Payload::AttributeDiscard))
        .await
        .unwrap();
    let Some(SessionEvent::RouteUpdate(u)) = next_event(&mut handle, Duration::from_secs(5)).await
    else {
        panic!("expected the discard-recovered route as a RouteUpdate");
    };
    assert_eq!(u.announced, vec![nlri()]);
    assert!(u.withdrawn.is_empty());
    assert!(
        !u.attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Aggregator { .. })),
        "the malformed AGGREGATOR must have been discarded: {:?}",
        u.attributes
    );

    // Still up: a following normal UPDATE is processed.
    peer.write_all(&update_frame(Payload::Normal))
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut handle, Duration::from_secs(5)).await,
        Some(SessionEvent::RouteUpdate(_))
    ));
}

/// RFC 7606 §2 treat-as-withdraw: the NLRI are withdrawn, the session stays
/// up (RFC 4271 §8.2.2 Established Event 27).
#[tokio::test]
async fn established_treat_as_withdraw_withdraws_route_and_session_stays_up() {
    let (listener, addr) = bind().await;
    let mut handle = spawn(config(addr, 90, Duration::from_secs(120)));
    handle.start().await;
    let mut peer = accept_to_open_sent(&listener).await;
    advance_to_established(&mut peer).await;
    expect_established(&mut handle).await;

    peer.write_all(&update_frame(Payload::TreatAsWithdraw))
        .await
        .unwrap();
    let Some(SessionEvent::RouteUpdate(u)) = next_event(&mut handle, Duration::from_secs(5)).await
    else {
        panic!("expected the treat-as-withdraw RouteUpdate");
    };
    assert!(u.announced.is_empty());
    assert_eq!(u.withdrawn, vec![nlri()]);

    peer.write_all(&update_frame(Payload::Normal))
        .await
        .unwrap();
    assert!(matches!(
        next_event(&mut handle, Duration::from_secs(5)).await,
        Some(SessionEvent::RouteUpdate(_))
    ));
}

/// RFC 4271 §8.2.2 Established Event 28 + §6.3: NOTIFICATION with the exact
/// Update error and Data, TCP dropped, `Terminated(OperatorStop)` (locally
/// detected — routes flushed, not retained as stale), and — the peer remains
/// configured — an automatic reconnect: a fresh OPEN arrives on a *new*
/// connection after the ConnectRetryTimer.
#[tokio::test]
async fn established_session_reset_sends_exact_notification_then_reconnects() {
    let (listener, addr) = bind().await;
    let mut handle = spawn(config(addr, 90, Duration::from_millis(300)));
    handle.start().await;
    let mut peer = accept_to_open_sent(&listener).await;
    advance_to_established(&mut peer).await;
    expect_established(&mut handle).await;

    peer.write_all(&update_frame(Payload::SessionReset))
        .await
        .unwrap();

    let n = read_notification(&mut peer).await;
    assert_eq!(
        n,
        NotificationMessage {
            error: NotificationError::UpdateMessage(UpdateMsgError::UnrecognizedWellKnownAttribute),
            data: vec![210, 3, 1, 2, 3],
        }
    );
    assert_closed(&mut peer).await;

    let ev = next_event(&mut handle, Duration::from_secs(5)).await;
    assert!(
        matches!(
            ev,
            Some(SessionEvent::Terminated(TerminationReason::OperatorStop))
        ),
        "expected Terminated(OperatorStop), got {ev:?}"
    );

    // Reconnect: the same listener sees a new connection and a new OPEN.
    let mut again = tokio::time::timeout(Duration::from_secs(5), accept_to_open_sent(&listener))
        .await
        .expect("session must reconnect after a locally detected protocol error");
    again.write_all(&peer_open_bytes()).await.unwrap();
}

/// RFC 4271 §8.2.2 Established Event 27: processing an UPDATE "restarts its
/// HoldTimer". A recovered (malformed-but-kept) UPDATE is an Event 27 UPDATE
/// too, so a peer sending nothing but recovered UPDATEs must not be timed
/// out. Hold time 3 s: with no restart the session would die at t=3 s; the
/// recovered UPDATEs at t=2 s and t=4 s keep it alive past t=6 s.
#[tokio::test]
async fn established_recovered_updates_restart_the_hold_timer() {
    let (listener, addr) = bind().await;
    let mut handle = spawn(config(addr, 3, Duration::from_secs(120)));
    handle.start().await;
    let (mut peer, _) = listener.accept().await.unwrap();
    assert_eq!(read_frame(&mut peer).await.unwrap()[18], 1);
    // Offer hold time 3 so the negotiated value is 3.
    let open = BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time: 3,
        bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![Capability::FourByteAsn(65002)],
    });
    peer.write_all(&open.encode()).await.unwrap();
    assert_eq!(read_frame(&mut peer).await.unwrap()[18], 4);
    peer.write_all(&BgpMessage::Keepalive.encode())
        .await
        .unwrap();
    expect_established(&mut handle).await;

    // Drain the session's own KEEPALIVEs so its writes never block.
    let (mut rd, mut wr) = peer.into_split();
    let drain = tokio::spawn(async move {
        let mut b = [0u8; 256];
        while rd.read(&mut b).await.unwrap_or(0) > 0 {}
    });

    for (i, payload) in [Payload::AttributeDiscard, Payload::TreatAsWithdraw]
        .into_iter()
        .enumerate()
    {
        tokio::time::sleep(Duration::from_secs(2)).await;
        wr.write_all(&update_frame(payload)).await.unwrap();
        let ev = next_event(&mut handle, Duration::from_secs(1)).await;
        assert!(
            matches!(ev, Some(SessionEvent::RouteUpdate(_))),
            "update {i}: expected a RouteUpdate and a live session, got {ev:?}"
        );
    }
    // t ≈ 4 s now; the hold timer was last restarted at ≈ 4 s, so t = 6 s is
    // inside the window — but beyond 3 s from the first restart only if the
    // second restart worked.
    let ev = next_event(&mut handle, Duration::from_millis(2500)).await;
    assert!(
        !matches!(ev, Some(SessionEvent::Terminated(_))),
        "recovered UPDATEs must restart the HoldTimer (RFC 4271 §8.2.2 Event 27), got {ev:?}"
    );
    drain.abort();
}
