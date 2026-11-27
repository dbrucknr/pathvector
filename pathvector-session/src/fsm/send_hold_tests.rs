//! FSM changes of RFC 9687 §4.3, each test quoting the clause it checks.

use std::net::Ipv4Addr;
use std::time::Duration;

use super::*;
use crate::message::{Capability, OpenMessage, UpdateMessage};

fn config(hold_time: u16, send_hold_time: SendHoldTime) -> FsmConfig {
    FsmConfig {
        local_as: 65001,
        public_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time,
        capabilities: vec![Capability::FourByteAsn(65001), Capability::RouteRefresh],
        required_capabilities: vec![],
        peer_as: Some(65002),
        confederation_member: false,
        send_hold_time,
    }
}

fn peer_open(hold_time: u16) -> BgpMessage {
    BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time,
        bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![Capability::FourByteAsn(65002)],
    })
}

/// Drive to `OpenConfirm`, returning the FSM and every output so far.
fn open_confirm(config: FsmConfig, peer_hold: u16) -> (Fsm, Vec<FsmOutput>) {
    let mut fsm = Fsm::new(config);
    let mut out = fsm.process(FsmInput::ManualStart);
    out.extend(fsm.process(FsmInput::TcpConnected));
    out.extend(fsm.process(FsmInput::MessageReceived(peer_open(peer_hold))));
    assert_eq!(fsm.state(), State::OpenConfirm);
    (fsm, out)
}

fn established(hold_time: u16, send_hold_time: SendHoldTime) -> (Fsm, Vec<FsmOutput>) {
    let (mut fsm, _) = open_confirm(config(hold_time, send_hold_time), hold_time);
    let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
    assert_eq!(fsm.state(), State::Established);
    (fsm, out)
}

fn started(outputs: &[FsmOutput]) -> Vec<Duration> {
    outputs
        .iter()
        .filter_map(|o| match o {
            FsmOutput::StartSendHoldTimer(d) => Some(*d),
            _ => None,
        })
        .collect()
}

/// §4.3, `OpenConfirm`/Event 26: "restarts the `HoldTimer`, starts the
/// `SendHoldTimer` if the `SendHoldTime` is non-zero, and changes its state to
/// Established." Not before.
#[test]
fn send_hold_timer_starts_on_entering_established_and_not_before() {
    let (mut fsm, before) = open_confirm(config(90, SendHoldTime::default()), 90);
    assert_eq!(started(&before), []);
    let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
    assert_eq!(started(&out), [Duration::from_secs(480)]);
}

/// §6: the default is the greater of 8 minutes and 2 times the *negotiated*
/// `HoldTime`.
#[test]
fn default_send_hold_time_follows_the_negotiated_hold_time() {
    let (mut fsm, _) = open_confirm(config(3600, SendHoldTime::default()), 600);
    let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
    assert_eq!(started(&out), [Duration::from_secs(1200)]);
}

#[test]
fn configured_send_hold_time_is_used() {
    let value = SendHoldTime::from_secs(100, 90).unwrap();
    assert_eq!(
        started(&established(90, value).1),
        [Duration::from_secs(100)]
    );
}

/// §4.3: "unless the `SendHoldTime` value is zero or the negotiated `HoldTime`
/// value is zero, in which case the `SendHoldTimer` is stopped."
#[test]
fn send_hold_timer_does_not_run_when_disabled_or_without_a_hold_time() {
    assert_eq!(started(&established(90, SendHoldTime::DISABLED).1), []);
    assert_eq!(started(&established(0, SendHoldTime::default()).1), []);
    // Zero proposed by the peer only: the negotiated value is still zero.
    let (mut fsm, _) = open_confirm(config(90, SendHoldTime::default()), 0);
    let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
    assert_eq!(started(&out), []);
}

/// §4.3, Established/Event 29: NOTIFICATION "Send Hold Timer Expired" (code 8,
/// §6: no data), release resources, drop the TCP connection, change state to
/// Idle.
#[test]
fn send_hold_expiry_in_established_notifies_closes_and_goes_idle() {
    let (mut fsm, _) = established(90, SendHoldTime::default());
    let out = fsm.process(FsmInput::SendHoldTimerExpired);
    assert_eq!(fsm.state(), State::Idle);
    assert_eq!(
        out,
        [
            FsmOutput::StopSendHoldTimer,
            FsmOutput::StopHoldTimer,
            FsmOutput::StopKeepaliveTimer,
            FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::SendHoldTimerExpired,
                data: vec![],
            })),
            FsmOutput::CloseTcpConnection,
            FsmOutput::SessionTerminated,
            // Local restart policy (§8.1.1), as after Hold Timer expiry.
            FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
        ]
    );
}

/// §4.3: "The `SendHoldTimer` is stopped following any transition out of the
/// Established state", and before any NOTIFICATION of that transition is sent.
#[test]
fn every_exit_from_established_stops_the_send_hold_timer_first() {
    let cease = || NotificationMessage {
        error: NotificationError::Cease(CeaseError::AdministrativeReset),
        data: vec![],
    };
    let exits = [
        FsmInput::ManualStop,
        FsmInput::AutomaticStop(cease()),
        FsmInput::NotificationToSend(cease()),
        FsmInput::TcpFailed,
        FsmInput::MessageReceived(BgpMessage::Notification(cease())),
        FsmInput::HoldTimerExpired,
        FsmInput::SendHoldTimerExpired,
        FsmInput::CollisionDetected,
        // Unexpected message types (RFC 4271 §6.5).
        FsmInput::MessageReceived(peer_open(90)),
    ];
    for input in exits {
        let (mut fsm, _) = established(90, SendHoldTime::default());
        let label = format!("{input:?}");
        let out = fsm.process(input);
        assert_ne!(fsm.state(), State::Established, "{label}");
        assert_eq!(out[0], FsmOutput::StopSendHoldTimer, "{label}");
        assert_eq!(
            out.iter()
                .filter(|o| **o == FsmOutput::StopSendHoldTimer)
                .count(),
            1,
            "{label}"
        );
    }
}

#[test]
fn staying_established_does_not_stop_the_send_hold_timer() {
    let (mut fsm, _) = established(90, SendHoldTime::default());
    for input in [
        FsmInput::KeepaliveTimerExpired,
        FsmInput::MessageReceived(BgpMessage::Keepalive),
        FsmInput::MessageReceived(BgpMessage::Update(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })),
    ] {
        assert!(!fsm.process(input).contains(&FsmOutput::StopSendHoldTimer));
    }
}

/// RFC 9687 adds Event 29 to the Established state only; the timer does not run
/// elsewhere, so a stray expiry changes nothing.
#[test]
fn send_hold_expiry_outside_established_is_ignored() {
    let mut fsm = Fsm::new(config(90, SendHoldTime::default()));
    assert_eq!(fsm.process(FsmInput::SendHoldTimerExpired), []);
    assert_eq!(fsm.state(), State::Idle);
    fsm.process(FsmInput::ManualStart);
    assert_eq!(fsm.process(FsmInput::SendHoldTimerExpired), []);
    assert_eq!(fsm.state(), State::Connect);
    fsm.process(FsmInput::TcpConnected);
    assert_eq!(fsm.process(FsmInput::SendHoldTimerExpired), []);
    assert_eq!(fsm.state(), State::OpenSent);
    let (mut fsm, _) = open_confirm(config(90, SendHoldTime::default()), 90);
    assert_eq!(fsm.process(FsmInput::SendHoldTimerExpired), []);
    assert_eq!(fsm.state(), State::OpenConfirm);
}
