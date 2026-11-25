//! RFC 7607 §2 at the OPEN boundary (issue #111).
//!
//! "If a BGP speaker receives zero as the peer AS in an OPEN message, it MUST
//! abort the connection and send a NOTIFICATION with Error Code "OPEN Message
//! Error" and subcode "Bad Peer AS" [...]. A router MUST NOT initiate a
//! connection claiming to be AS 0."
//!
//! Which field carries the peer AS: RFC 6793 §4.1, "it MUST use the AS number
//! encoded in the Capability Value field of the "support for four-octet AS
//! number capability" in lieu of the "My Autonomous System" field".
//!
//! Neither RFC 6793 nor RFC 5492 §4 says how to treat several instances of that
//! capability with different values. A peer that sends AS 0 in any of them has
//! sent zero as its AS, so any zero instance is rejected, whatever the order.

use std::net::Ipv4Addr;

use proptest::prelude::*;

use super::*;
use crate::message::OpenMsgError;

fn config() -> FsmConfig {
    FsmConfig {
        local_as: 65001,
        public_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        capabilities: vec![Capability::FourByteAsn(65001)],
        required_capabilities: vec![],
        // No expected peer AS: the AS 0 rule may not depend on it.
        peer_as: None,
        confederation_member: false,
        send_hold_time: crate::fsm::SendHoldTime::default(),
    }
}

fn open(my_as: u16, four: &[u32]) -> OpenMessage {
    OpenMessage {
        version: 4,
        my_as,
        hold_time: 90,
        bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: four.iter().map(|&a| Capability::FourByteAsn(a)).collect(),
    }
}

fn fsm_in_open_sent(config: FsmConfig) -> Fsm {
    let mut fsm = Fsm::new(config);
    fsm.process(FsmInput::ManualStart);
    fsm.process(FsmInput::TcpConnected);
    assert_eq!(fsm.state(), State::OpenSent);
    fsm
}

/// The exact reaction RFC 7607 §2 requires: NOTIFICATION OPEN Message Error /
/// Bad Peer AS (RFC 4271 §6.2 defines no Data for it), connection aborted.
fn assert_bad_peer_as(config: FsmConfig, peer: OpenMessage) {
    let mut fsm = fsm_in_open_sent(config);
    let what = format!("{peer:?}");
    let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Open(peer)));
    assert_eq!(
        out,
        vec![
            FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::OpenMessage(OpenMsgError::BadPeerAs),
                data: vec![],
            })),
            FsmOutput::StopHoldTimer,
            FsmOutput::CloseTcpConnection,
        ],
        "{what}"
    );
    assert_eq!(fsm.state(), State::Idle, "{what}");
}

fn assert_accepted(peer: OpenMessage) {
    let mut fsm = fsm_in_open_sent(config());
    let what = format!("{peer:?}");
    fsm.process(FsmInput::MessageReceived(BgpMessage::Open(peer)));
    assert_eq!(fsm.state(), State::OpenConfirm, "{what}");
}

#[test]
fn two_octet_open_claiming_as_zero_is_bad_peer_as() {
    assert_bad_peer_as(config(), open(0, &[]));
}

#[test]
fn four_octet_capability_claiming_as_zero_is_bad_peer_as() {
    assert_bad_peer_as(config(), open(23456, &[0]));
    assert_bad_peer_as(config(), open(0, &[0]));
    // RFC 6793 §4.1: the capability is the peer AS, not `my_as`.
    assert_bad_peer_as(config(), open(65002, &[0]));
}

#[test]
fn any_zero_among_repeated_capabilities_is_bad_peer_as() {
    assert_bad_peer_as(config(), open(65002, &[65002, 0]));
    assert_bad_peer_as(config(), open(65002, &[0, 65002]));
}

/// A configuration expecting AS 0 does not make AS 0 acceptable.
#[test]
fn expecting_as_zero_does_not_admit_it() {
    let expect_zero = FsmConfig {
        peer_as: Some(0),
        ..config()
    };
    assert_bad_peer_as(expect_zero.clone(), open(0, &[]));
    assert_bad_peer_as(expect_zero, open(23456, &[0]));
}

/// RFC 6793 §4.1 "in lieu of": with a non-zero capability value, `my_as` is
/// not the peer AS.
#[test]
fn capability_value_supersedes_a_zero_my_as() {
    assert_accepted(open(0, &[65002]));
}

proptest! {
    /// Accepted exactly when no field that states the peer AS states zero.
    #[test]
    fn prop_open_is_rejected_iff_it_claims_as_zero(
        my_as in prop_oneof![Just(0u16), 1u16..],
        four in proptest::collection::vec(prop_oneof![Just(0u32), 1u32..], 0..3),
    ) {
        let claims_zero = if four.is_empty() { my_as == 0 } else { four.contains(&0) };
        let mut fsm = fsm_in_open_sent(config());
        fsm.process(FsmInput::MessageReceived(BgpMessage::Open(open(my_as, &four))));
        let want = if claims_zero { State::Idle } else { State::OpenConfirm };
        prop_assert_eq!(fsm.state(), want);
    }
}

// ── "A router MUST NOT initiate a connection claiming to be AS 0" ─────────────

/// Configurations that would claim AS 0 somewhere on the session.
fn claiming_zero() -> Vec<FsmConfig> {
    vec![
        FsmConfig {
            local_as: 0,
            ..config()
        },
        // `public_as` is what goes into `my_as` (RFC 5065 §4).
        FsmConfig {
            public_as: 0,
            ..config()
        },
        FsmConfig {
            capabilities: vec![Capability::FourByteAsn(0)],
            ..config()
        },
        FsmConfig {
            capabilities: vec![Capability::FourByteAsn(65001), Capability::FourByteAsn(0)],
            ..config()
        },
    ]
}

#[test]
fn no_connection_is_initiated_while_claiming_as_zero() {
    for config in claiming_zero() {
        for input in [FsmInput::ManualStart, FsmInput::ConnectRetryTimerExpired] {
            let what = format!("{input:?} {config:?}");
            let mut fsm = Fsm::new(config.clone());
            assert_eq!(fsm.process(input), vec![], "{what}");
            assert_eq!(fsm.state(), State::Idle, "{what}");
        }
    }
}

/// The capability set can be replaced between connection attempts, so the
/// check also guards the moment the OPEN would be written.
#[test]
fn no_open_is_sent_if_the_claim_turns_to_as_zero_after_start() {
    for via_active in [false, true] {
        let mut fsm = Fsm::new(config());
        fsm.process(FsmInput::ManualStart);
        if via_active {
            fsm.process(FsmInput::TcpFailed);
        }
        fsm.set_capabilities(vec![Capability::FourByteAsn(0)]);
        let out = fsm.process(FsmInput::TcpConnected);
        assert_eq!(
            out,
            vec![
                FsmOutput::StopConnectRetryTimer,
                FsmOutput::CloseTcpConnection
            ]
        );
        assert_eq!(fsm.state(), State::Idle);
    }
}
