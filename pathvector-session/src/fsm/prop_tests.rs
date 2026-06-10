use std::net::Ipv4Addr;
use std::time::Duration;

use proptest::prelude::*;

use super::*;
use crate::message::{
    BgpMessage, NotificationError, NotificationMessage, OpenMessage, UpdateMessage,
};

fn default_config() -> FsmConfig {
    FsmConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        capabilities: vec![],
        required_capabilities: vec![],
        peer_as: None,
    }
}

fn arb_bgp_message() -> impl Strategy<Value = BgpMessage> {
    prop_oneof![
        Just(BgpMessage::Keepalive),
        (any::<u16>(), any::<u16>(), any::<[u8; 4]>()).prop_map(|(my_as, hold_time, id)| {
            BgpMessage::Open(OpenMessage {
                version: 4,
                my_as,
                hold_time,
                bgp_id: Ipv4Addr::from(id),
                capabilities: vec![],
            })
        }),
        Just(BgpMessage::Notification(NotificationMessage {
            error: NotificationError::HoldTimerExpired,
            data: vec![],
        })),
        Just(BgpMessage::Update(UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        })),
    ]
}

fn arb_fsm_input() -> impl Strategy<Value = FsmInput> {
    prop_oneof![
        Just(FsmInput::ManualStart),
        Just(FsmInput::ManualStop),
        Just(FsmInput::TcpConnected),
        Just(FsmInput::TcpFailed),
        Just(FsmInput::ConnectRetryTimerExpired),
        Just(FsmInput::HoldTimerExpired),
        Just(FsmInput::KeepaliveTimerExpired),
        arb_bgp_message().prop_map(FsmInput::MessageReceived),
    ]
}

fn arb_non_start_input() -> impl Strategy<Value = FsmInput> {
    prop_oneof![
        Just(FsmInput::ManualStop),
        Just(FsmInput::TcpConnected),
        Just(FsmInput::TcpFailed),
        Just(FsmInput::ConnectRetryTimerExpired),
        Just(FsmInput::HoldTimerExpired),
        Just(FsmInput::KeepaliveTimerExpired),
        arb_bgp_message().prop_map(FsmInput::MessageReceived),
    ]
}

proptest! {
    /// Feed any sequence of events to a fresh FSM and verify it never panics.
    #[test]
    fn prop_process_never_panics(inputs in prop::collection::vec(arb_fsm_input(), 0..10)) {
        let mut fsm = Fsm::new(default_config());
        for input in inputs {
            fsm.process(input);
        }
    }

    /// Any input other than ManualStart is silently ignored in Idle.
    #[test]
    fn prop_idle_ignores_non_manual_start(input in arb_non_start_input()) {
        let mut fsm = Fsm::new(default_config());
        let out = fsm.process(input);
        prop_assert_eq!(fsm.state(), State::Idle);
        prop_assert!(out.is_empty());
    }

    /// local_as > 65535 → outbound OPEN carries AS_TRANS in the my_as field.
    #[test]
    fn prop_large_asn_uses_as_trans(local_as in 65536u32..=u32::MAX) {
        let config = FsmConfig { local_as, ..default_config() };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        let out = fsm.process(FsmInput::TcpConnected);
        let open = out.iter().find_map(|o| {
            if let FsmOutput::SendMessage(BgpMessage::Open(m)) = o { Some(m) } else { None }
        }).unwrap();
        prop_assert_eq!(open.my_as, AS_TRANS);
    }

    /// local_as ≤ 65535 → outbound OPEN carries local_as directly in my_as.
    #[test]
    fn prop_small_asn_sent_directly(local_as in 0u32..=65535) {
        let config = FsmConfig { local_as, ..default_config() };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        let out = fsm.process(FsmInput::TcpConnected);
        let open = out.iter().find_map(|o| {
            if let FsmOutput::SendMessage(BgpMessage::Open(m)) = o { Some(m) } else { None }
        }).unwrap();
        prop_assert_eq!(u32::from(open.my_as), local_as);
    }

    /// Negotiated hold time is min(local, peer); 0 when either side proposes 0.
    ///
    /// Peer hold times 1 and 2 are excluded — the FSM rejects them as
    /// UnacceptableHoldTime before negotiation can happen.
    #[test]
    fn prop_hold_time_negotiated_to_min(
        local_ht in prop_oneof![Just(0u16), 3u16..=65535u16],
        peer_ht  in prop_oneof![Just(0u16), 3u16..=65535u16],
    ) {
        let config = FsmConfig { hold_time: local_ht, peer_as: None, ..default_config() };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        let peer_msg = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: peer_ht,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![],
        });
        let out = fsm.process(FsmInput::MessageReceived(peer_msg));

        prop_assert_eq!(fsm.state(), State::OpenConfirm);

        let expected = if local_ht == 0 || peer_ht == 0 { 0u16 } else { local_ht.min(peer_ht) };

        if expected > 0 {
            let timer = out.iter().find_map(|o| {
                if let FsmOutput::StartHoldTimer(d) = o { Some(*d) } else { None }
            });
            prop_assert_eq!(timer, Some(Duration::from_secs(u64::from(expected))));
        } else {
            prop_assert!(out.contains(&FsmOutput::StopHoldTimer));
        }
    }
}
