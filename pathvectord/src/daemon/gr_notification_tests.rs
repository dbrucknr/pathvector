// daemon/gr_notification_tests.rs — issue #203: which ways of losing a session
// retain the peer's routes, with and without the RFC 8538 "N" bit.
//
// RFC 4724 §4: "the normal BGP procedures MUST be followed when the TCP session
// terminates due to the sending or receiving of a BGP NOTIFICATION message."
// Those procedures delete the peer's routes (RFC 4271 §8.2.2). RFC 4724 §4.2
// retains them when the TCP session terminates otherwise.
//
// RFC 8538 §4 changes this for speakers that exchanged the "N" bit. A speaker
// that receives a NOTIFICATION other than a Hard Reset "MUST follow the rules
// for the Receiving Speaker", and "The BGP speaker generating the BGP
// NOTIFICATION message MUST also follow the rules for the Receiving Speaker."
// "When a BGP speaker resets its session due to a HOLDTIME expiry, it should
// generate the relevant BGP NOTIFICATION message as mentioned in [RFC4271] but
// subsequently MUST follow the rules for the Receiving Speaker". §3.2: on
// receiving a Hard Reset the speaker "MUST terminate the BGP session following
// the standard procedures in [RFC4271]."
//
// Each test runs a real session task over loopback TCP against a hand-driven
// peer, and gives the daemon the `Terminated` event that session emits, so the
// path from the cause of the loss to the RIB is the production one.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use futures::StreamExt;
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::{
    BgpMessage, Capability, CeaseError, GracefulRestartFamily, MpReachNlri, NotificationError,
    NotificationMessage, OpenMessage, PathAttribute, Prefix, UpdateMessage,
};
use pathvector_session::transport::{
    self, SessionCommand, SessionConfig, SessionEvent, SessionHandle, SpawnedSessionHandle,
    TerminationReason,
};
use pathvector_types::{AfiSafi, AsPath, Asn, NextHop, Nlri, Origin, PeerType};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::FramedRead;

use super::{DaemonState, build_local_capabilities};
use crate::config;

const LOCAL_AS: u32 = 65001;
const PEER_AS: u32 = 65002;
const LOCAL_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TIMEOUT: Duration = Duration::from_secs(10);
/// RFC 8538 §2: the "N" bit in the Restart Flags.
const N_BIT: u8 = 0x04;

/// One way of losing an Established session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loss {
    /// The peer says nothing for the Hold Time.
    HoldTimerExpiry,
    /// The peer sends a message with a bad marker (RFC 4271 §6.1).
    HeaderError,
    /// The peer sends a second OPEN (RFC 4271 §6.6, RFC 6608).
    UnexpectedMessage,
    /// The peer sends an UPDATE with two `MP_REACH_NLRI` attributes
    /// (RFC 7606 §3 (g): session reset).
    UpdateError,
    /// The daemon resets the session itself and lets it reconnect.
    AutomaticReset,
    /// The TCP connection closes with no NOTIFICATION.
    TcpFailure,
    /// The peer sends a Cease other than Hard Reset.
    CeaseReceived,
    /// The peer sends a Hard Reset.
    HardResetReceived,
    /// An operator stops the session.
    OperatorStop,
}

struct Peer {
    reader: FramedRead<OwnedReadHalf, BgpCodec>,
    writer: OwnedWriteHalf,
}

impl Peer {
    async fn recv(&mut self) -> Option<BgpMessage> {
        tokio::time::timeout(TIMEOUT, self.reader.next())
            .await
            .expect("timed out waiting for the session")
            .map(|m| m.expect("decode error"))
    }

    async fn send(&mut self, msg: &BgpMessage) {
        self.send_raw(&msg.encode()).await;
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.expect("send to session");
    }

    /// The NOTIFICATION the session sends before closing, if any.
    async fn notification(&mut self) -> Option<NotificationMessage> {
        while let Some(msg) = self.recv().await {
            if let BgpMessage::Notification(n) = msg {
                return Some(n);
            }
        }
        None
    }
}

fn gr_capability(restart_flags: u8) -> Capability {
    Capability::GracefulRestart {
        restart_flags,
        restart_time: 120,
        families: [AfiSafi::IPV4_UNICAST, AfiSafi::IPV6_UNICAST]
            .into_iter()
            .map(|afi_safi| GracefulRestartFamily {
                afi_safi,
                forwarding_preserved: true,
            })
            .collect(),
    }
}

fn make_state() -> DaemonState {
    let (tx, _rx) = mpsc::channel::<UpdateMessage>(64);
    let peer = config::PeerConfig {
        address: PEER_IP,
        port: 179,
        remote_as: PEER_AS,
        import_default: Some(config::ImportDefault::Accept),
        export_default: Some(config::ExportDefault::Accept),
        import_default_v6: None,
        md5_password: None,
        is_rr_client: false,
        next_hop_self: false,
        hold_time: None,
        shutdown_message: None,
        connect_retry_time: None,
        max_prefixes_v4: None,
        max_prefixes_v6: None,
        max_prefixes_restart: None,
        role: None,
        confederation_member: false,
        blackhole_authorized_prefixes: None,
    };
    DaemonState::new(
        LOCAL_AS,
        LOCAL_ID,
        None,
        None,
        None,
        &[peer],
        [(PEER_IP, tx)].into(),
        build_local_capabilities(LOCAL_AS, 120, false, None),
    )
}

async fn next_event(session: &mut SpawnedSessionHandle) -> SessionEvent {
    tokio::time::timeout(TIMEOUT, session.next_event())
        .await
        .expect("timed out waiting for a session event")
        .expect("session ended")
}

fn v4() -> Nlri<Ipv4Addr> {
    "198.51.100.0/24".parse().unwrap()
}

fn v6() -> Nlri<Ipv6Addr> {
    "2001:db8:1::/48".parse().unwrap()
}

fn mp_reach() -> PathAttribute {
    PathAttribute::MpReachNlri(MpReachNlri {
        afi_safi: AfiSafi::IPV6_UNICAST,
        next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
        prefixes: vec![Prefix::V6(v6())],
    })
}

fn base_attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(PEER_AS)])),
    ]
}

/// Gives the daemon one route per family from the peer.
fn announce(state: &mut DaemonState) {
    let mut attributes = base_attributes();
    attributes.push(PathAttribute::NextHop(PEER_ID));
    state.on_route_update(
        PEER_IP,
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![v4()],
        },
    );
    let mut attributes = base_attributes();
    attributes.push(mp_reach());
    state.on_route_update(
        PEER_IP,
        UpdateMessage {
            withdrawn: vec![],
            attributes,
            announced: vec![],
        },
    );
}

/// What the daemon holds after a loss.
#[derive(Debug, PartialEq, Eq)]
enum Routes {
    Retained,
    Flushed,
}

fn routes(state: &DaemonState) -> Routes {
    let held = [
        state.adj_ribs_in[&PEER_IP].get(&v4()).is_some(),
        state.adj_ribs_in_v6[&PEER_IP].get(&v6()).is_some(),
        state.rib.loc_rib.best(&v4()).is_some(),
        state.rib.loc_rib_v6.best(&v6()).is_some(),
        state.gr.deadlines.contains_key(&PEER_IP),
    ];
    match held {
        [true, true, true, true, true] => Routes::Retained,
        [false, false, false, false, false] => Routes::Flushed,
        _ => panic!("half torn down: {held:?}"),
    }
}

/// Establishes a session with the "N" bit offered by the peer or not, loses it
/// as `loss` says, and reports what the daemon did with the peer's routes.
async fn lose(loss: Loss, n_bit: bool) -> Routes {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut session = transport::spawn(SessionConfig {
        local_as: LOCAL_AS,
        local_bgp_id: LOCAL_ID,
        hold_time: if loss == Loss::HoldTimerExpiry { 3 } else { 90 },
        connect_retry_time: Duration::from_secs(60),
        send_hold_time: pathvector_session::fsm::SendHoldTime::RECOMMENDED,
        capabilities: build_local_capabilities(LOCAL_AS, 120, false, None),
        required_capabilities: vec![],
        peer_as: Some(PEER_AS),
        confederation_member: false,
        public_as: LOCAL_AS,
        peer_addr: listener.local_addr().unwrap(),
        tcp_md5: None,
    });
    session.start().await;
    let (stream, _): (TcpStream, _) = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .expect("the session did not dial")
        .unwrap();
    let (r, w) = stream.into_split();
    let mut peer = Peer {
        reader: FramedRead::new(r, BgpCodec::new()),
        writer: w,
    };

    let open = BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: u16::try_from(PEER_AS).unwrap(),
        hold_time: 90,
        bgp_id: PEER_ID,
        capabilities: vec![
            Capability::FourByteAsn(PEER_AS),
            Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
            Capability::MultiProtocol(AfiSafi::IPV6_UNICAST),
            gr_capability(if n_bit { N_BIT } else { 0 }),
        ],
    });
    assert!(matches!(peer.recv().await, Some(BgpMessage::Open(_))));
    peer.send(&open).await;
    assert!(matches!(peer.recv().await, Some(BgpMessage::Keepalive)));
    peer.send(&BgpMessage::Keepalive).await;
    let SessionEvent::Established(info) = next_event(&mut session).await else {
        panic!("expected Established");
    };

    let mut state = make_state();
    state.on_established(
        PEER_IP,
        info.peer_bgp_id,
        PeerType::External,
        info.peer_as,
        info.hold_time,
        &info.peer_capabilities,
        None,
    );
    announce(&mut state);
    assert_eq!(
        state.adj_ribs_in[&PEER_IP].len() + state.adj_ribs_in_v6[&PEER_IP].len(),
        2
    );

    let cease = |sub| NotificationMessage {
        error: NotificationError::Cease(sub),
        data: vec![],
    };
    match loss {
        // Nothing to send: the silence, or the close below, is the cause.
        Loss::HoldTimerExpiry | Loss::TcpFailure => {}
        Loss::HeaderError => {
            let mut bytes = BgpMessage::Keepalive.encode();
            bytes[0] = 0;
            peer.send_raw(&bytes).await;
        }
        Loss::UnexpectedMessage => peer.send(&open).await,
        Loss::UpdateError => {
            let mut attributes = base_attributes();
            attributes.extend([mp_reach(), mp_reach()]);
            peer.send(&BgpMessage::Update(UpdateMessage {
                withdrawn: vec![],
                attributes,
                announced: vec![],
            }))
            .await;
        }
        Loss::AutomaticReset => session
            .stop_sender()
            .send(SessionCommand::AutomaticStop(cease(
                CeaseError::OutOfResources,
            )))
            .await
            .unwrap(),
        Loss::CeaseReceived => {
            peer.send(&BgpMessage::Notification(cease(
                CeaseError::AdministrativeReset,
            )))
            .await;
        }
        Loss::HardResetReceived => {
            peer.send(&BgpMessage::Notification(cease(CeaseError::HardReset)))
                .await;
        }
        Loss::OperatorStop => session.stop().await,
    }

    // Confirm on the wire that this side did or did not send a NOTIFICATION,
    // which is what the RFC clauses turn on.
    let sends_notification = matches!(
        loss,
        Loss::HoldTimerExpiry
            | Loss::HeaderError
            | Loss::UnexpectedMessage
            | Loss::UpdateError
            | Loss::AutomaticReset
            | Loss::OperatorStop
    );
    if loss == Loss::TcpFailure {
        drop(peer);
    } else {
        let sent = peer.notification().await;
        assert_eq!(sent.is_some(), sends_notification, "{loss:?}: {sent:?}");
    }

    let reason: TerminationReason = loop {
        if let SessionEvent::Terminated(reason) = next_event(&mut session).await {
            break reason;
        }
    };
    state.on_terminated(PEER_IP, reason, false);
    routes(&state)
}

async fn assert_losses(loss: Loss, without_n: Routes, with_n: Routes) {
    let (got_without, got_with) = tokio::join!(lose(loss, false), lose(loss, true));
    assert_eq!(got_without, without_n, "{loss:?} without the N bit");
    assert_eq!(got_with, with_n, "{loss:?} with the N bit");
}

/// A NOTIFICATION is sent (RFC 4724 §4), and RFC 8538 §4 names this case.
#[tokio::test]
async fn hold_timer_expiry_retains_only_with_the_n_bit() {
    assert_losses(Loss::HoldTimerExpiry, Routes::Flushed, Routes::Retained).await;
}

/// This side generates the NOTIFICATION.
#[tokio::test]
async fn message_header_error_retains_only_with_the_n_bit() {
    assert_losses(Loss::HeaderError, Routes::Flushed, Routes::Retained).await;
}

/// This side generates a Finite State Machine Error NOTIFICATION.
#[tokio::test]
async fn unexpected_message_retains_only_with_the_n_bit() {
    assert_losses(Loss::UnexpectedMessage, Routes::Flushed, Routes::Retained).await;
}

/// The converse: the speaker generating a non-Hard-Reset NOTIFICATION follows
/// the Receiving Speaker rules too.
#[tokio::test]
async fn update_error_reset_retains_only_with_the_n_bit() {
    assert_losses(Loss::UpdateError, Routes::Flushed, Routes::Retained).await;
}

/// The converse, for a reset the local system decides on (RFC 8538 §5.1
/// suggests "Graceful Cease" for Out of Resources).
#[tokio::test]
async fn automatic_reset_retains_only_with_the_n_bit() {
    assert_losses(Loss::AutomaticReset, Routes::Flushed, Routes::Retained).await;
}

/// No NOTIFICATION either way: RFC 4724 §4.2 retention applies.
#[tokio::test]
async fn tcp_failure_retains_with_and_without_the_n_bit() {
    assert_losses(Loss::TcpFailure, Routes::Retained, Routes::Retained).await;
}

#[tokio::test]
async fn received_cease_retains_only_with_the_n_bit() {
    assert_losses(Loss::CeaseReceived, Routes::Flushed, Routes::Retained).await;
}

#[tokio::test]
async fn received_hard_reset_flushes_with_and_without_the_n_bit() {
    assert_losses(Loss::HardResetReceived, Routes::Flushed, Routes::Flushed).await;
}

/// An operator stop takes the peer's routes out of service whatever was
/// negotiated. With the "N" bit exchanged this is only consistent with RFC 8538
/// if the NOTIFICATION is a Hard Reset, which this speaker does not yet send
/// (`TODO.md`).
#[tokio::test]
async fn operator_stop_flushes_with_and_without_the_n_bit() {
    assert_losses(Loss::OperatorStop, Routes::Flushed, Routes::Flushed).await;
}
