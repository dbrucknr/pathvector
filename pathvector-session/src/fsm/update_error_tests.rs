//! RFC 4271 §8.2.2 state × RFC 7606 recovery-outcome matrix for received
//! UPDATE messages (Events 27 `UpdateMsg` and 28 `UpdateMsgErr`).
//!
//! The expected behavior in every cell is derived from the RFC text, not from
//! what the implementation currently does:
//!
//! | state       | RFC 4271 §8.2.2 clause                                              | required response                                         |
//! |-------------|----------------------------------------------------------------------|-----------------------------------------------------------|
//! | Idle        | "Any other event (Events 9-12, 15-28) received in the Idle state does not cause change in the state" | ignored                      |
//! | Connect     | "In response to any other events (Events 8, 10-11, 13, 19, 23, 25-28)" | stop `ConnectRetryTimer`, drop TCP, → Idle (no NOTIFICATION) |
//! | Active      | "In response to any other event (Events 8, 10-11, 13, 19, 23, 25-28)" | same as Connect                                           |
//! | OpenSent    | "In response to any other event (Events 9, 11-13, 20, 25-28)"         | NOTIFICATION FSM Error (RFC 6608 subcode 1), drop TCP, → Idle |
//! | OpenConfirm | "In response to any other event (Events 9, 12-13, 20, 27-28)"         | NOTIFICATION FSM Error (RFC 6608 subcode 2), drop TCP, → Idle |
//! | Established | Event 27: process, restart HoldTimer, stay. Event 28: NOTIFICATION with an Update error, drop TCP, → Idle | per RFC 7606 recovery outcome |
//!
//! RFC 7606 §3 changes only *which* UPDATE errors are Event 28 (session
//! reset) rather than Event 27 (recovered in place: treat-as-withdraw /
//! attribute discard). It does not authorize processing any UPDATE — valid,
//! recovered, or otherwise — in a state where RFC 4271 §8.2.2 does not.

#![allow(clippy::doc_markdown)] // RFC prose and event names, not identifiers

use std::net::Ipv4Addr;

use pathvector_types::{AsPath, Asn, Nlri, Origin};

use super::*;
use crate::message::{
    AttributeDecodeError, AttributeErrorPolicy, MalformedUpdate, PathAttribute, UpdateMsgError,
};

fn config() -> FsmConfig {
    FsmConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        capabilities: vec![Capability::FourByteAsn(65001)],
        required_capabilities: vec![],
        peer_as: Some(65002),
        confederation_member: false,
        public_as: 65001,
    }
}

fn peer_open() -> BgpMessage {
    BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time: 90,
        bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![Capability::FourByteAsn(65002)],
    })
}

const ALL_STATES: [State; 6] = [
    State::Idle,
    State::Connect,
    State::Active,
    State::OpenSent,
    State::OpenConfirm,
    State::Established,
];

/// A fresh FSM driven (via the public event API only) into `target`.
fn fsm_in(target: State) -> Fsm {
    let mut fsm = Fsm::new(config());
    if target != State::Idle {
        fsm.process(FsmInput::ManualStart);
    }
    if target == State::Active {
        fsm.process(FsmInput::TcpFailed);
    }
    if matches!(
        target,
        State::OpenSent | State::OpenConfirm | State::Established
    ) {
        fsm.process(FsmInput::TcpConnected);
    }
    if matches!(target, State::OpenConfirm | State::Established) {
        fsm.process(FsmInput::MessageReceived(peer_open()));
    }
    if target == State::Established {
        fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
    }
    assert_eq!(
        fsm.state(),
        target,
        "test helper failed to reach {target:?}"
    );
    fsm
}

fn prefix() -> Nlri<Ipv4Addr> {
    "10.1.0.0/24".parse().unwrap()
}

/// A well-formed, route-carrying UPDATE: mandatory attributes plus NLRI.
fn route_update() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        announced: vec![prefix()],
    }
}

/// RFC 7606 §3(f): a malformed `AGGREGATOR` (type 7) is attribute-discard;
/// the surviving UPDATE still carries the route.
fn attribute_discard() -> MalformedUpdate {
    MalformedUpdate {
        update: route_update(),
        errors: vec![AttributeDecodeError {
            type_code: 7,
            policy: AttributeErrorPolicy::AttributeDiscard,
            detail: "bad AGGREGATOR length",
        }],
        treat_as_withdraw: false,
        session_reset: false,
    }
}

/// RFC 7606 §3(e): a malformed `ORIGIN` (type 1) is treat-as-withdraw. The
/// decoder has already removed the bad attribute from `update`.
fn treat_as_withdraw() -> MalformedUpdate {
    let mut update = route_update();
    update
        .attributes
        .retain(|a| !matches!(a, PathAttribute::Origin(_)));
    MalformedUpdate {
        update,
        errors: vec![AttributeDecodeError {
            type_code: 1,
            policy: AttributeErrorPolicy::TreatAsWithdraw,
            detail: "invalid ORIGIN value",
        }],
        treat_as_withdraw: true,
        session_reset: false,
    }
}

/// RFC 4271 §6.3 (unamended by RFC 7606): an unrecognized well-known
/// attribute is a session reset carrying the attribute in Data.
fn session_reset() -> (MalformedUpdate, NotificationMessage) {
    let notif = NotificationMessage {
        error: NotificationError::UpdateMessage(UpdateMsgError::UnrecognizedWellKnownAttribute),
        data: vec![210, 3, 1, 2, 3],
    };
    let m = MalformedUpdate {
        update: route_update(),
        errors: vec![AttributeDecodeError {
            type_code: 210,
            policy: AttributeErrorPolicy::SessionReset {
                error: notif.error.clone(),
                data: notif.data.clone(),
            },
            detail: "unrecognized well-known attribute",
        }],
        treat_as_withdraw: false,
        session_reset: true,
    };
    (m, notif)
}

/// RFC 7606 §5.2 "Missing NLRI": treat-as-withdraw errors in an UPDATE that
/// carries attributes but no reachable NLRI escalate to session reset
/// (Malformed Attribute List).
fn missing_nlri_escalation() -> MalformedUpdate {
    MalformedUpdate {
        update: UpdateMessage {
            withdrawn: vec![],
            attributes: vec![PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2))],
            announced: vec![],
        },
        errors: vec![AttributeDecodeError {
            type_code: 1,
            policy: AttributeErrorPolicy::TreatAsWithdraw,
            detail: "invalid ORIGIN value",
        }],
        treat_as_withdraw: true,
        session_reset: false,
    }
}

fn malformed(m: MalformedUpdate) -> FsmInput {
    FsmInput::MessageReceived(BgpMessage::MalformedUpdate(m))
}

fn normal(u: UpdateMessage) -> FsmInput {
    FsmInput::MessageReceived(BgpMessage::Update(u))
}

fn no_route_update(out: &[FsmOutput]) -> bool {
    !out.iter().any(|o| matches!(o, FsmOutput::RouteUpdate(_)))
}

/// RFC 6608 §4: the FSM Error NOTIFICATION's Data is "a 1-octet, unsigned
/// integer that indicates the type of the unexpected message" — 2 for UPDATE,
/// whatever the RFC 7606 recovery outcome (a malformed UPDATE is an UPDATE).
fn fsm_error_notification(error: NotificationError) -> FsmOutput {
    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
        error,
        data: vec![2],
    }))
}

/// Every recovery outcome, as `(label, input)`.
fn all_malformed_inputs() -> Vec<(&'static str, FsmInput)> {
    vec![
        ("attribute-discard", malformed(attribute_discard())),
        ("treat-as-withdraw", malformed(treat_as_withdraw())),
        ("session-reset", malformed(session_reset().0)),
        (
            "missing-nlri-escalation",
            malformed(missing_nlri_escalation()),
        ),
    ]
}

// ── Idle: Events 27/28 are ignored ───────────────────────────────────────────

/// RFC 4271 §8.2.2 Idle: "Any other event (Events 9-12, 15-28) received in
/// the Idle state does not cause change in the state of the local system."
#[test]
fn rfc4271_8_2_2_idle_ignores_update_and_every_malformed_recovery_outcome() {
    let mut inputs = all_malformed_inputs();
    inputs.push(("normal UPDATE", normal(route_update())));
    for (label, input) in inputs {
        let mut fsm = fsm_in(State::Idle);
        let out = fsm.process(input);
        assert_eq!(fsm.state(), State::Idle, "{label}");
        assert!(out.is_empty(), "{label}: Idle must ignore it, got {out:?}");
    }
}

// ── Connect / Active: Events 27/28 → Idle, drop TCP, no NOTIFICATION ─────────

/// RFC 4271 §8.2.2 Connect and Active: "In response to any other event
/// (Events 8, 10-11, 13, 19, 23, 25-28), the local system: sets the
/// ConnectRetryTimer to zero, ... drops the TCP connection, ... changes its
/// state to Idle." No NOTIFICATION is listed, and no route may be emitted.
#[test]
fn rfc4271_8_2_2_connect_and_active_drop_to_idle_on_update_and_every_malformed_outcome() {
    for state in [State::Connect, State::Active] {
        let mut inputs = all_malformed_inputs();
        inputs.push(("normal UPDATE", normal(route_update())));
        for (label, input) in inputs {
            let mut fsm = fsm_in(state);
            let out = fsm.process(input);
            assert_eq!(fsm.state(), State::Idle, "{state:?} / {label}");
            assert_eq!(
                out,
                vec![
                    FsmOutput::StopConnectRetryTimer,
                    FsmOutput::CloseTcpConnection
                ],
                "{state:?} / {label}"
            );
        }
    }
}

// ── OpenSent / OpenConfirm: Events 27/28 → FSM Error NOTIFICATION ────────────

/// RFC 4271 §8.2.2 OpenSent: "In response to any other event (Events 9,
/// 11-13, 20, 25-28), the local system: sends the NOTIFICATION with the
/// Error Code Finite State Machine Error, ... drops the TCP connection, ...
/// changes its state to Idle." RFC 6608 §3 supplies subcode 1 ("Receive
/// Unexpected Message in OpenSent State") and §4 the Data: the one-octet type
/// of the unexpected message, here 2 (UPDATE). This applies identically to a
/// valid UPDATE (Event 27) and to every RFC 7606 recovery outcome — including
/// a session-reset error, whose own Update-error NOTIFICATION is *not* the
/// one RFC 4271 requires here (Event 28 in OpenSent is an FSM error).
#[test]
fn rfc4271_8_2_2_open_sent_sends_fsm_error_for_update_and_every_malformed_outcome() {
    let mut inputs = all_malformed_inputs();
    inputs.push(("normal UPDATE", normal(route_update())));
    for (label, input) in inputs {
        let mut fsm = fsm_in(State::OpenSent);
        let out = fsm.process(input);
        assert_eq!(fsm.state(), State::Idle, "{label}");
        assert_eq!(
            out,
            vec![
                fsm_error_notification(NotificationError::FsmErrorOpenSent),
                FsmOutput::StopHoldTimer,
                FsmOutput::CloseTcpConnection,
            ],
            "{label}"
        );
        assert!(no_route_update(&out), "{label}: no pre-Established route");
    }
}

/// RFC 4271 §8.2.2 OpenConfirm: "In response to any other event (Events 9,
/// 12-13, 20, 27-28), the local system: sends a NOTIFICATION with a code of
/// Finite State Machine Error, ... drops the TCP connection, ... changes its
/// state to Idle." RFC 6608 §3 subcode 2.
#[test]
fn rfc4271_8_2_2_open_confirm_sends_fsm_error_for_update_and_every_malformed_outcome() {
    let mut inputs = all_malformed_inputs();
    inputs.push(("normal UPDATE", normal(route_update())));
    for (label, input) in inputs {
        let mut fsm = fsm_in(State::OpenConfirm);
        let out = fsm.process(input);
        assert_eq!(fsm.state(), State::Idle, "{label}");
        assert_eq!(
            out,
            vec![
                fsm_error_notification(NotificationError::FsmErrorOpenConfirm),
                FsmOutput::StopHoldTimer,
                FsmOutput::StopKeepaliveTimer,
                FsmOutput::CloseTcpConnection,
            ],
            "{label}"
        );
        assert!(no_route_update(&out), "{label}: no pre-Established route");
    }
}

// ── Established ──────────────────────────────────────────────────────────────

fn restart_hold() -> FsmOutput {
    FsmOutput::StartHoldTimer(hold_duration(90))
}

/// Parity baseline: RFC 4271 §8.2.2 Established, Event 27 — "processes the
/// message, restarts its HoldTimer, if the negotiated HoldTime value is
/// non-zero, and remains in the Established state."
#[test]
fn rfc4271_8_2_2_established_normal_update_is_processed_and_restarts_hold_timer() {
    let mut fsm = fsm_in(State::Established);
    let out = fsm.process(normal(route_update()));
    assert_eq!(fsm.state(), State::Established);
    assert_eq!(
        out,
        vec![restart_hold(), FsmOutput::RouteUpdate(route_update())]
    );
}

/// RFC 7606 §2 attribute discard: "the malformed attribute MUST be discarded
/// and the UPDATE message continues to be processed" — i.e. Event 27, so
/// RFC 4271 §8.2.2 Established also requires restarting the HoldTimer.
#[test]
fn rfc7606_2_attribute_discard_is_processed_as_event_27_with_hold_timer_restart() {
    let mut fsm = fsm_in(State::Established);
    let out = fsm.process(malformed(attribute_discard()));
    assert_eq!(fsm.state(), State::Established);
    assert_eq!(
        out,
        vec![restart_hold(), FsmOutput::RouteUpdate(route_update())],
        "discard leaves the (cleaned) UPDATE intact — same as the normal-UPDATE baseline"
    );
}

/// RFC 7606 §2 treat-as-withdraw: the UPDATE "MUST be treated as though all
/// contained routes had been withdrawn just as if they had been listed in the
/// WITHDRAWN ROUTES field". The withdrawal is an ordinary Event 27 UPDATE:
/// the session stays up and the HoldTimer restarts.
#[test]
fn rfc7606_2_treat_as_withdraw_emits_withdrawal_and_restarts_hold_timer() {
    let mut fsm = fsm_in(State::Established);
    let out = fsm.process(malformed(treat_as_withdraw()));
    assert_eq!(fsm.state(), State::Established);
    assert_eq!(
        out,
        vec![
            restart_hold(),
            FsmOutput::RouteUpdate(UpdateMessage {
                withdrawn: vec![prefix()],
                attributes: vec![],
                announced: vec![],
            })
        ]
    );
}

/// RFC 4271 §8.2.2 Established, Event 28: "sends a NOTIFICATION message with
/// an Update error, ... deletes all routes associated with this connection,
/// ... drops the TCP connection, ... changes its state to Idle." The
/// NOTIFICATION is the specific one the triggering error requires (RFC 4271
/// §6.3 Unrecognized Well-known Attribute, Data = the attribute) and the
/// peer is still configured, so a reconnect is scheduled.
#[test]
fn rfc4271_8_2_2_established_session_reset_sends_exact_update_error_and_reconnects() {
    let (m, notif) = session_reset();
    let mut fsm = fsm_in(State::Established);
    let out = fsm.process(malformed(m));
    assert_eq!(fsm.state(), State::Idle);
    assert_eq!(
        out,
        vec![
            FsmOutput::StopHoldTimer,
            FsmOutput::StopKeepaliveTimer,
            FsmOutput::SendMessage(BgpMessage::Notification(notif)),
            FsmOutput::CloseTcpConnection,
            FsmOutput::SessionTerminated,
            FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
        ]
    );
}

/// RFC 7606 §5.2: an UPDATE with path attributes but no reachable NLRI, and
/// an error stronger than attribute discard, "MUST" use "session reset" —
/// Malformed Attribute List (RFC 7606 §3(g)/§5.2 / RFC 4271 §6.3), no data.
#[test]
fn rfc7606_5_2_missing_nlri_escalates_to_malformed_attribute_list_reset() {
    let mut fsm = fsm_in(State::Established);
    let out = fsm.process(malformed(missing_nlri_escalation()));
    assert_eq!(fsm.state(), State::Idle);
    assert_eq!(
        out,
        vec![
            FsmOutput::StopHoldTimer,
            FsmOutput::StopKeepaliveTimer,
            FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAttributeList),
                data: vec![],
            })),
            FsmOutput::CloseTcpConnection,
            FsmOutput::SessionTerminated,
            FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
        ]
    );
}

/// RFC 7606 §3(h): "if the same approach ... is specified ... that approach
/// MUST be used. Otherwise, the approach with the strongest action MUST be
/// used." A session reset beats treat-as-withdraw and attribute discard in
/// the same UPDATE.
#[test]
fn rfc7606_3_h_session_reset_beats_weaker_errors_in_the_same_update() {
    let (mut m, notif) = session_reset();
    m.errors.push(AttributeDecodeError {
        type_code: 1,
        policy: AttributeErrorPolicy::TreatAsWithdraw,
        detail: "invalid ORIGIN value",
    });
    m.errors.push(AttributeDecodeError {
        type_code: 7,
        policy: AttributeErrorPolicy::AttributeDiscard,
        detail: "bad AGGREGATOR length",
    });
    m.treat_as_withdraw = true;
    let mut fsm = fsm_in(State::Established);
    let out = fsm.process(malformed(m));
    assert_eq!(fsm.state(), State::Idle);
    assert!(
        out.contains(&FsmOutput::SendMessage(BgpMessage::Notification(notif))),
        "{out:?}"
    );
    assert!(no_route_update(&out));
}

// ── Cross-cutting invariants ─────────────────────────────────────────────────

/// RFC 4271 §8.2.2: only Established may process an UPDATE. Over every state
/// and every recovery outcome, a [`FsmOutput::RouteUpdate`] is possible only
/// from Established — the type-level guarantee this crate relies on, since
/// the transport can only forward a route by executing this output.
#[test]
fn rfc4271_8_2_2_route_update_is_never_emitted_outside_established() {
    for state in ALL_STATES {
        for (label, input) in all_malformed_inputs() {
            let mut fsm = fsm_in(state);
            let out = fsm.process(input);
            if state != State::Established {
                assert!(no_route_update(&out), "{state:?} / {label}: {out:?}");
            }
        }
    }
}

/// Parity: in every state other than Established, a malformed UPDATE of
/// *any* recovery outcome must be indistinguishable from the same route
/// payload delivered as a normal UPDATE (same state, same outputs).
#[test]
fn rfc4271_8_2_2_malformed_update_matches_normal_update_before_established() {
    for state in ALL_STATES.into_iter().filter(|s| *s != State::Established) {
        let mut baseline = fsm_in(state);
        let want = baseline.process(normal(route_update()));
        for (label, input) in all_malformed_inputs() {
            let mut fsm = fsm_in(state);
            let got = fsm.process(input);
            assert_eq!(got, want, "{state:?} / {label}");
            assert_eq!(fsm.state(), baseline.state(), "{state:?} / {label}");
        }
    }
}

/// RFC 6608 §4, all three states: the FSM Error NOTIFICATION's Data is the
/// one-octet type of the *unexpected* message, so it follows the message
/// received (1 OPEN, 3 NOTIFICATION is not "unexpected" in these states and
/// is excluded; 4 KEEPALIVE, 5 ROUTE-REFRESH), not a fixed value.
#[test]
fn rfc6608_4_fsm_error_data_is_the_unexpected_message_type() {
    let open = || peer_open();
    let rr = || {
        BgpMessage::RouteRefresh(crate::message::RouteRefreshMessage::new(
            pathvector_types::AfiSafi::IPV4_UNICAST,
        ))
    };
    // (state, message, expected type octet, expected error)
    let cases = [
        (
            State::OpenSent,
            rr(),
            5,
            NotificationError::FsmErrorOpenSent,
        ),
        (
            State::OpenConfirm,
            open(),
            1,
            NotificationError::FsmErrorOpenConfirm,
        ),
        (
            State::OpenConfirm,
            rr(),
            5,
            NotificationError::FsmErrorOpenConfirm,
        ),
        (
            State::Established,
            open(),
            1,
            NotificationError::FsmErrorEstablished,
        ),
        // RouteRefresh without the capability negotiated (this config
        // advertises none) is unexpected in Established.
        (
            State::Established,
            rr(),
            5,
            NotificationError::FsmErrorEstablished,
        ),
    ];
    for (state, msg, type_code, error) in cases {
        let mut fsm = fsm_in(state);
        let out = fsm.process(FsmInput::MessageReceived(msg.clone()));
        let want = FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
            error,
            data: vec![type_code],
        }));
        assert!(out.contains(&want), "{state:?} / {msg:?}: {out:?}");
    }
}
