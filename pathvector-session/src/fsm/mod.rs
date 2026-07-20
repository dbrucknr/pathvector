//! BGP session Finite State Machine (RFC 4271 §8).
//!
//! A pure, synchronous state machine. Feed [`FsmInput`] events via
//! [`Fsm::process`] and execute the returned [`FsmOutput`] actions.
//! The FSM holds no timers, no sockets, and performs no I/O — the transport
//! layer owns those resources and drives the FSM.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pathvector_types::PeerType;

use crate::message::{
    BgpMessage, Capability, CeaseError, NotificationError, NotificationMessage, OpenMessage,
    OpenMsgError, UpdateMessage,
};

/// Placed in the two-byte `my_as` field when the real ASN exceeds 16 bits
/// (RFC 6793).
const AS_TRANS: u16 = 23456;
/// Hold timer value while waiting for the peer's OPEN after sending ours.
const OPEN_HOLD_TIMER: Duration = Duration::from_secs(240);
/// Default connect-retry interval (RFC 4271 §10).
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(120);

// ── Configuration ─────────────────────────────────────────────────────────────

/// Local configuration for a BGP session.
#[derive(Debug, Clone)]
pub struct FsmConfig {
    /// Local AS number.
    pub local_as: u32,
    /// Local BGP identifier (router-id).
    pub local_bgp_id: Ipv4Addr,
    /// Proposed hold time in seconds. `0` disables the hold timer; any other
    /// value must be ≥ 3.
    pub hold_time: u16,
    /// Capabilities advertised in the OPEN message. Include
    /// [`Capability::FourByteAsn`] when `local_as > 65535`.
    pub capabilities: Vec<Capability>,
    /// Capabilities that the peer MUST advertise. If the peer's OPEN is missing
    /// any of these, the session is rejected with NOTIFICATION code 2 subcode 7
    /// (Unsupported Capability) per RFC 5492 §3. Empty by default.
    pub required_capabilities: Vec<Capability>,
    /// Expected peer AS. `None` skips AS validation.
    pub peer_as: Option<u32>,
}

// ── Events ────────────────────────────────────────────────────────────────────

/// Events that drive FSM state transitions.
#[derive(Debug, Clone)]
pub enum FsmInput {
    /// Operator command to start the session.
    ManualStart,
    /// Operator command to tear down the session.
    ManualStop,
    /// The connect-retry timer fired.
    ConnectRetryTimerExpired,
    /// The hold timer fired.
    HoldTimerExpired,
    /// The keepalive timer fired.
    KeepaliveTimerExpired,
    /// Outbound TCP connection was successfully established.
    TcpConnected,
    /// TCP connection attempt failed or was refused.
    TcpFailed,
    /// An inbound TCP connection arrived while an outbound connection is in
    /// progress and the local BGP ID is higher than the peer's.  RFC 4271 §6.8:
    /// close the outbound connection and restart over the incoming one.  Unlike
    /// `TcpFailed`, this does NOT emit [`FsmOutput::SessionTerminated`] —
    /// the collision is a physical-layer event, not a session teardown.
    CollisionDetected,
    /// A complete BGP message was received from the peer.
    MessageReceived(BgpMessage),
    /// The daemon requests a locally initiated, administrative teardown:
    /// send the given NOTIFICATION, then close with no automatic
    /// reconnect (no `ConnectRetryTimer`). Used for intentional peer
    /// removal/shutdown (RFC 9003 shutdown messages) and daemon-detected
    /// conditions the daemon itself will re-arm on its own schedule (e.g.
    /// RFC 4486 §4 max-prefix-exceeded, which uses its own idle-hold
    /// timer). Do **not** reuse this for a protocol error on an ongoing,
    /// still-configured peer relationship — see
    /// [`FsmInput::ProtocolErrorNotificationToSend`] for that case.
    NotificationToSend(crate::message::NotificationMessage),
    /// The daemon locally detected a protocol error while Established
    /// (e.g. RFC 7606 §3(g)'s duplicated `MP_REACH_NLRI`/`MP_UNREACH_NLRI`,
    /// which requires a session reset) and requests the given NOTIFICATION
    /// be sent before tearing down. Unlike [`FsmInput::NotificationToSend`],
    /// this **does** schedule an automatic reconnect (RFC 4271 §8.2.2 Event
    /// 28: `UpdateMsgErr` — NOTIFICATION, `ConnectRetryTimer`, drop TCP,
    /// Idle) — the peer is still configured and the error was ours to
    /// detect, not evidence the peer should be given up on.
    ///
    /// The full [`NotificationMessage`] is carried so the RFC-mandated data
    /// field is preserved verbatim.
    ProtocolErrorNotificationToSend(crate::message::NotificationMessage),
}

// ── Actions ───────────────────────────────────────────────────────────────────

/// Actions the transport layer must execute after an FSM transition.
///
/// Actions within a single response are ordered: execute them in sequence.
#[derive(Debug, Clone, PartialEq)]
pub enum FsmOutput {
    /// Initiate an outbound TCP connection to the configured peer address.
    InitiateTcpConnect,
    /// Close the TCP connection (no-op if already closed).
    CloseTcpConnection,
    /// Transmit a BGP message to the peer.
    SendMessage(BgpMessage),
    /// (Re)start the connect-retry timer with the given interval.
    StartConnectRetryTimer(Duration),
    /// Cancel the connect-retry timer.
    StopConnectRetryTimer,
    /// (Re)start the hold timer. Replaces any running hold timer.
    StartHoldTimer(Duration),
    /// Cancel the hold timer.
    StopHoldTimer,
    /// (Re)start the keepalive timer. This is a one-shot timer; the FSM
    /// re-emits this action each time [`FsmInput::KeepaliveTimerExpired`]
    /// is processed.
    StartKeepaliveTimer(Duration),
    /// Cancel the keepalive timer.
    StopKeepaliveTimer,
    /// The session reached [`State::Established`].
    SessionEstablished(SessionInfo),
    /// The session was torn down (after being Established).
    SessionTerminated,
    /// An UPDATE was received; forward to the RIB layer.
    RouteUpdate(UpdateMessage),
}

/// Information surfaced when the session reaches [`State::Established`].
#[derive(Debug, Clone, PartialEq)]
pub struct SessionInfo {
    /// Resolved peer AS (prefers [`Capability::FourByteAsn`] over `my_as`).
    pub peer_as: u32,
    /// Peer BGP identifier.
    pub peer_bgp_id: Ipv4Addr,
    /// Negotiated hold time (`min(local, peer)`; `0` means disabled).
    pub hold_time: u16,
    /// Capabilities advertised by the peer in its OPEN.
    pub peer_capabilities: Vec<Capability>,
    /// Whether this is an iBGP or eBGP session.
    ///
    /// `Internal` when `peer_as == local_as`; `External` otherwise.
    /// Used by the RIB layer for best-path step 7 and iBGP split horizon.
    pub peer_type: PeerType,
    /// Local TCP address for this session (RFC 4271 §5.1.3 `NEXT_HOP` source).
    ///
    /// Set by the transport layer from `TcpStream::local_addr()` at connect
    /// time. `None` for injected (test) transports that bypass real TCP.
    /// Carries the full address family (v4 or v6, matching the session's own
    /// transport) — the daemon decides how to use it per address family.
    pub local_addr: Option<IpAddr>,
}

// ── States ────────────────────────────────────────────────────────────────────

/// The six BGP FSM states (RFC 4271 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

// ── FSM ───────────────────────────────────────────────────────────────────────

/// BGP session finite state machine.
///
/// # Usage
///
/// ```rust
/// use std::net::Ipv4Addr;
/// use pathvector_session::fsm::{Fsm, FsmConfig, FsmInput, State};
///
/// let fsm = Fsm::new(FsmConfig {
///     local_as: 65001,
///     local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
///     hold_time: 90,
///     capabilities: vec![],
///     required_capabilities: vec![],
///     peer_as: Some(65002),
/// });
/// assert_eq!(fsm.state(), State::Idle);
/// ```
pub struct Fsm {
    state: State,
    config: FsmConfig,
    /// Peer OPEN stored when we validate it in [`State::OpenSent`].
    peer_open: Option<OpenMessage>,
    /// Negotiated hold time, set on entry to [`State::OpenConfirm`].
    negotiated_hold_time: u16,
}

impl Fsm {
    /// Create a new FSM in [`State::Idle`].
    #[must_use]
    pub fn new(config: FsmConfig) -> Self {
        Self {
            state: State::Idle,
            config,
            peer_open: None,
            negotiated_hold_time: 0,
        }
    }

    /// Current FSM state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// Replace the local capability set for the next OPEN.
    pub(crate) fn set_capabilities(&mut self, caps: Vec<crate::message::Capability>) {
        self.config.capabilities = caps;
    }

    /// Current local capability set (for tests and diagnostics).
    #[cfg(test)]
    pub(crate) fn local_capabilities(&self) -> &[crate::message::Capability] {
        &self.config.capabilities
    }

    /// BGP Identifier received in the peer's OPEN message.
    ///
    /// `None` until the peer's OPEN has been validated (i.e., before
    /// [`State::OpenConfirm`]).  Used by the transport layer to resolve RFC
    /// 4271 §6.8 connection collisions.
    #[must_use]
    pub fn peer_bgp_id(&self) -> Option<Ipv4Addr> {
        self.peer_open.as_ref().map(|o| o.bgp_id)
    }

    /// Whether the peer advertised the Graceful Restart capability in its OPEN.
    ///
    /// `false` before the peer's OPEN has been validated. Used by the
    /// transport layer to apply RFC 4724 §4.2's Established-state collision
    /// override instead of RFC 4271 §6.8's default (reject) behavior.
    #[must_use]
    pub fn peer_has_graceful_restart(&self) -> bool {
        self.peer_open.as_ref().is_some_and(|o| {
            o.capabilities
                .iter()
                .any(|c| matches!(c, Capability::GracefulRestart { .. }))
        })
    }

    /// Feed one input event, advance the FSM, and return the ordered list of
    /// actions to execute.
    pub fn process(&mut self, input: FsmInput) -> Vec<FsmOutput> {
        match self.state {
            State::Idle => self.on_idle(&input),
            State::Connect => self.on_connect(&input),
            State::Active => self.on_active(&input),
            State::OpenSent => self.on_open_sent(input),
            State::OpenConfirm => self.on_open_confirm(&input),
            State::Established => self.on_established(input),
        }
    }

    // ── Per-state handlers ────────────────────────────────────────────────────

    fn on_idle(&mut self, input: &FsmInput) -> Vec<FsmOutput> {
        match input {
            FsmInput::ManualStart | FsmInput::ConnectRetryTimerExpired => {
                self.state = State::Connect;
                vec![
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                    FsmOutput::InitiateTcpConnect,
                ]
            }
            _ => vec![],
        }
    }

    fn on_connect(&mut self, input: &FsmInput) -> Vec<FsmOutput> {
        match input {
            FsmInput::TcpConnected => self.do_tcp_connected(),
            FsmInput::TcpFailed => {
                self.state = State::Active;
                vec![FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL)]
            }
            FsmInput::ConnectRetryTimerExpired => vec![
                FsmOutput::InitiateTcpConnect,
                FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
            ],
            FsmInput::ManualStop => self.do_stop_pre_open(),
            _ => vec![],
        }
    }

    fn on_active(&mut self, input: &FsmInput) -> Vec<FsmOutput> {
        match input {
            FsmInput::TcpConnected => self.do_tcp_connected(),
            FsmInput::ConnectRetryTimerExpired => {
                self.state = State::Connect;
                vec![
                    FsmOutput::InitiateTcpConnect,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::ManualStop => self.do_stop_pre_open(),
            _ => vec![],
        }
    }

    fn on_open_sent(&mut self, input: FsmInput) -> Vec<FsmOutput> {
        match input {
            FsmInput::MessageReceived(BgpMessage::Open(peer_open)) => {
                match self.validate_open(&peer_open) {
                    Ok(negotiated) => {
                        self.negotiated_hold_time = negotiated;
                        self.peer_open = Some(peer_open);
                        self.state = State::OpenConfirm;
                        let mut out = vec![FsmOutput::SendMessage(BgpMessage::Keepalive)];
                        push_timer_actions(&mut out, negotiated);
                        out
                    }
                    Err((err, data)) => {
                        self.state = State::Idle;
                        vec![
                            FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                                error: err,
                                data,
                            })),
                            FsmOutput::StopHoldTimer,
                            FsmOutput::CloseTcpConnection,
                        ]
                    }
                }
            }
            // NOTIFICATION in OpenSent: clean up and go Idle (RFC 4271 §8.2.2 event 25).
            FsmInput::MessageReceived(BgpMessage::Notification(_)) => {
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::TcpFailed => {
                self.state = State::Active;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::HoldTimerExpired => {
                self.state = State::Idle;
                vec![
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::HoldTimerExpired,
                        data: vec![],
                    })),
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::ManualStop => {
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                        data: vec![],
                    })),
                    FsmOutput::CloseTcpConnection,
                ]
            }
            // RFC 4271 §8.2.2, OpenSent/Event 19: "If this connection is to
            // be dropped due to connection collision, the local system
            // sends a NOTIFICATION with a Cease" (subcode Connection
            // Collision Resolution, RFC 4486 §4 subcode 7 — the same
            // CeaseError variant this codebase already round-trips).
            // Transition to Active so the next TcpConnected is valid.
            FsmInput::CollisionDetected => {
                self.peer_open = None;
                self.state = State::Active;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::Cease(CeaseError::ConnectionCollisionResolution),
                        data: vec![],
                    })),
                    FsmOutput::CloseTcpConnection,
                ]
            }
            // Any other message type in OpenSent is unexpected (RFC 4271 §6.5 subcode 1).
            FsmInput::MessageReceived(_) => {
                self.state = State::Idle;
                vec![
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::FsmErrorOpenSent,
                        data: vec![],
                    })),
                    FsmOutput::StopHoldTimer,
                    FsmOutput::CloseTcpConnection,
                ]
            }
            _ => vec![],
        }
    }

    fn on_open_confirm(&mut self, input: &FsmInput) -> Vec<FsmOutput> {
        match input {
            FsmInput::MessageReceived(BgpMessage::Keepalive) => {
                let Some(info) = self.build_session_info() else {
                    // peer_open is None in OpenConfirm — this is a programming error,
                    // not a protocol event. Reset cleanly rather than panic so the
                    // daemon stays up and the peer can retry.
                    tracing::error!("peer_open missing in OpenConfirm; resetting session to Idle");
                    self.state = State::Idle;
                    return vec![
                        FsmOutput::StopHoldTimer,
                        FsmOutput::StopKeepaliveTimer,
                        FsmOutput::CloseTcpConnection,
                    ];
                };
                self.state = State::Established;
                let mut out = vec![FsmOutput::SessionEstablished(info)];
                if self.negotiated_hold_time > 0 {
                    let ht = hold_duration(self.negotiated_hold_time);
                    let ka = keepalive_interval(self.negotiated_hold_time);
                    out.push(FsmOutput::StartHoldTimer(ht));
                    out.push(FsmOutput::StartKeepaliveTimer(ka));
                }
                out
            }
            FsmInput::MessageReceived(BgpMessage::Notification(_)) | FsmInput::TcpFailed => {
                self.peer_open = None;
                self.negotiated_hold_time = 0;
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::KeepaliveTimerExpired => {
                let mut out = vec![FsmOutput::SendMessage(BgpMessage::Keepalive)];
                if self.negotiated_hold_time > 0 {
                    out.push(FsmOutput::StartKeepaliveTimer(keepalive_interval(
                        self.negotiated_hold_time,
                    )));
                }
                out
            }
            FsmInput::HoldTimerExpired => {
                self.state = State::Idle;
                vec![
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::HoldTimerExpired,
                        data: vec![],
                    })),
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::ManualStop => {
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                        data: vec![],
                    })),
                    FsmOutput::CloseTcpConnection,
                ]
            }
            // RFC 4271 §8.2.2, OpenConfirm/Event 23 (OpenCollisionDump):
            // "the local system: sends a NOTIFICATION with a Cease... drops
            // the TCP connection... changes its state to Idle" — this FSM
            // returns to Active (not Idle) per this project's collision
            // model (see the OpenSent arm above), but the NOTIFICATION is
            // required regardless of the resulting state.
            FsmInput::CollisionDetected => {
                self.peer_open = None;
                self.negotiated_hold_time = 0;
                self.state = State::Active;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::Cease(CeaseError::ConnectionCollisionResolution),
                        data: vec![],
                    })),
                    FsmOutput::CloseTcpConnection,
                ]
            }
            // Any other message type in OpenConfirm is unexpected (RFC 4271 §6.5 subcode 2).
            FsmInput::MessageReceived(_) => {
                self.state = State::Idle;
                vec![
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::FsmErrorOpenConfirm,
                        data: vec![],
                    })),
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                ]
            }
            _ => vec![],
        }
    }

    #[allow(clippy::too_many_lines)]
    fn on_established(&mut self, input: FsmInput) -> Vec<FsmOutput> {
        match input {
            FsmInput::MessageReceived(BgpMessage::Keepalive) => self.reset_hold_if_active(),
            FsmInput::MessageReceived(BgpMessage::Update(update)) => {
                let mut out = self.reset_hold_if_active();
                out.push(FsmOutput::RouteUpdate(update));
                out
            }
            FsmInput::MessageReceived(BgpMessage::Notification(_)) | FsmInput::TcpFailed => {
                self.peer_open = None;
                self.negotiated_hold_time = 0;
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::KeepaliveTimerExpired => {
                let mut out = vec![FsmOutput::SendMessage(BgpMessage::Keepalive)];
                if self.negotiated_hold_time > 0 {
                    out.push(FsmOutput::StartKeepaliveTimer(keepalive_interval(
                        self.negotiated_hold_time,
                    )));
                }
                out
            }
            FsmInput::HoldTimerExpired => {
                self.state = State::Idle;
                vec![
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::HoldTimerExpired,
                        data: vec![],
                    })),
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            FsmInput::ManualStop => {
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                        data: vec![],
                    })),
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                ]
            }
            // ROUTE-REFRESH: honoured only when both sides negotiated RFC 2918.
            // Full re-advertisement (FsmOutput::RouteRefreshRequested) is deferred;
            // for now we accept it silently when negotiated and reject it when not.
            FsmInput::MessageReceived(BgpMessage::RouteRefresh(_)) => {
                let negotiated = self
                    .peer_open
                    .as_ref()
                    .is_some_and(|o| o.capabilities.contains(&Capability::RouteRefresh))
                    && self.config.capabilities.contains(&Capability::RouteRefresh);
                if negotiated {
                    vec![]
                } else {
                    self.state = State::Idle;
                    vec![
                        FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                            error: NotificationError::FsmErrorEstablished,
                            data: vec![],
                        })),
                        FsmOutput::StopHoldTimer,
                        FsmOutput::StopKeepaliveTimer,
                        FsmOutput::CloseTcpConnection,
                        FsmOutput::SessionTerminated,
                    ]
                }
            }
            // Any other unexpected message type in Established (RFC 4271 §6.5 subcode 3).
            FsmInput::MessageReceived(_) => {
                self.state = State::Idle;
                vec![
                    FsmOutput::SendMessage(BgpMessage::Notification(NotificationMessage {
                        error: NotificationError::FsmErrorEstablished,
                        data: vec![],
                    })),
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                ]
            }
            // RFC 4724 §4.2 (modifies RFC 4271 §8.2.2 Established): when the
            // peer has advertised the Graceful Restart Capability, a new
            // incoming TCP connection is treated as proof the old one died
            // even though we never observed its failure. "Acting accordingly"
            // means: "the previous TCP session MUST be closed, and the new
            // one retained... no NOTIFICATION message should be sent -- the
            // previous TCP session is simply closed." State goes to Connect
            // (not Idle) so the caller can immediately adopt the incoming
            // connection as if it were a fresh outbound one.
            //
            // The transport layer only sends this input here when
            // `peer_has_graceful_restart()` is true — a non-GR peer keeps the
            // plain RFC 4271 §6.8 behavior of rejecting the duplicate
            // incoming connection outright.
            FsmInput::CollisionDetected => {
                self.peer_open = None;
                self.negotiated_hold_time = 0;
                self.state = State::Connect;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            // Locally initiated administrative teardown (peer removal/RFC 9003
            // shutdown, or a daemon-detected condition with its own separate
            // re-arm schedule) — no automatic reconnect.
            FsmInput::NotificationToSend(msg) => {
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::SendMessage(BgpMessage::Notification(msg)),
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                ]
            }
            // RFC 4271 §8.2.2 Event 28 (UpdateMsgErr): a locally detected
            // protocol error on an ongoing, still-configured peer — send the
            // NOTIFICATION, drop the TCP connection, and (unlike
            // `NotificationToSend`) schedule an automatic reconnect rather
            // than leaving the peer stuck in Idle indefinitely.
            FsmInput::ProtocolErrorNotificationToSend(msg) => {
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::SendMessage(BgpMessage::Notification(msg)),
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
                    FsmOutput::StartConnectRetryTimer(CONNECT_RETRY_INTERVAL),
                ]
            }
            _ => vec![],
        }
    }

    // ── Shared sub-routines ────────────────────────────────────────────────────

    /// [`FsmInput::TcpConnected`] from Connect or Active: send OPEN, enter [`State::OpenSent`].
    fn do_tcp_connected(&mut self) -> Vec<FsmOutput> {
        let open = self.make_open();
        self.state = State::OpenSent;
        vec![
            FsmOutput::StopConnectRetryTimer,
            FsmOutput::SendMessage(BgpMessage::Open(open)),
            FsmOutput::StartHoldTimer(OPEN_HOLD_TIMER),
        ]
    }

    /// [`FsmInput::ManualStop`] from Connect or Active (no OPEN exchanged yet).
    fn do_stop_pre_open(&mut self) -> Vec<FsmOutput> {
        self.state = State::Idle;
        vec![
            FsmOutput::StopConnectRetryTimer,
            FsmOutput::CloseTcpConnection,
        ]
    }

    /// Restart the hold timer if the negotiated hold time is non-zero.
    fn reset_hold_if_active(&self) -> Vec<FsmOutput> {
        if self.negotiated_hold_time > 0 {
            vec![FsmOutput::StartHoldTimer(hold_duration(
                self.negotiated_hold_time,
            ))]
        } else {
            vec![]
        }
    }

    /// Build the OPEN message we send to the peer.
    fn make_open(&self) -> OpenMessage {
        let my_as = if self.config.local_as > u32::from(u16::MAX) {
            AS_TRANS
        } else {
            #[allow(clippy::cast_possible_truncation)] // guarded by the branch above
            {
                self.config.local_as as u16
            }
        };
        OpenMessage {
            version: 4,
            my_as,
            hold_time: self.config.hold_time,
            bgp_id: self.config.local_bgp_id,
            capabilities: self.config.capabilities.clone(),
        }
    }

    /// Validate a received OPEN, returning the negotiated hold time on success.
    /// Validates the peer's OPEN message. Returns the negotiated hold time on
    /// success, or `(error, data)` where `data` is the NOTIFICATION payload.
    pub(crate) fn validate_open(
        &self,
        peer: &OpenMessage,
    ) -> Result<u16, (NotificationError, Vec<u8>)> {
        if peer.version != 4 {
            return Err((
                NotificationError::OpenMessage(OpenMsgError::UnsupportedVersionNumber),
                vec![],
            ));
        }

        // RFC 4271 §6.2: BGP Identifier must be a valid unicast IPv4 address.
        // Multicast (224.0.0.0/4) and broadcast (255.255.255.255) are not unicast.
        // Unspecified (0.0.0.0) is explicitly prohibited by §4.2.
        let bgp_id = peer.bgp_id;
        if bgp_id == Ipv4Addr::UNSPECIFIED || bgp_id.is_multicast() || bgp_id == Ipv4Addr::BROADCAST
        {
            return Err((
                NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier),
                vec![],
            ));
        }

        // RFC 6286: BGP Identifier must be unique within the AS. An iBGP peer
        // with the same BGP ID as the local speaker indicates a routing loop or
        // misconfiguration — reject with BadBgpIdentifier.
        let peer_as = resolve_as(peer);
        if peer_as == self.config.local_as && peer.bgp_id == self.config.local_bgp_id {
            return Err((
                NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier),
                vec![],
            ));
        }

        if let Some(expected) = self.config.peer_as
            && resolve_as(peer) != expected
        {
            return Err((
                NotificationError::OpenMessage(OpenMsgError::BadPeerAs),
                vec![],
            ));
        }

        // RFC 4271 §6.2: hold time values 1 and 2 are unacceptable.
        if peer.hold_time == 1 || peer.hold_time == 2 {
            return Err((
                NotificationError::OpenMessage(OpenMsgError::UnacceptableHoldTime),
                vec![],
            ));
        }

        // RFC 5492 §3: if we require a capability the peer did not advertise,
        // send NOTIFICATION code 2 subcode 7 with the unsupported codes listed
        // in the data field as capability TLVs.
        let unsupported: Vec<&Capability> = self
            .config
            .required_capabilities
            .iter()
            .filter(|req| !peer.capabilities.iter().any(|c| c.code() == req.code()))
            .collect();
        if !unsupported.is_empty() {
            let data = encode_unsupported_capabilities(&unsupported);
            return Err((
                NotificationError::OpenMessage(OpenMsgError::UnsupportedCapability),
                data,
            ));
        }

        // RFC 9234 §5.1: if both sides advertise a BGP Role, the pair must be
        // complementary (Provider↔Customer, RouteServer↔RsClient, Peer↔Peer).
        // Per the RFC's own non-strict default, a side that doesn't advertise
        // Role at all is *not* a mismatch — only an incompatible pair is.
        let local_role = self.config.capabilities.iter().find_map(|c| match c {
            Capability::Role(r) => Some(*r),
            _ => None,
        });
        // RFC 9234 §4.2: "If an eBGP speaker receives multiple but identical
        // BGP Role Capabilities with the same value in each, then the
        // speaker considers them to be a single BGP Role Capability and
        // proceeds [RFC5492]. If multiple BGP Role Capabilities are received
        // and not all of them have the same value, then the BGP speaker MUST
        // reject the connection using the Role Mismatch Notification." This
        // check is independent of local_role's compatibility with any one of
        // the peer's values — a differing pair is itself grounds for
        // rejection, before the Provider/Customer-style compatibility check
        // below ever runs.
        let mut peer_roles = peer.capabilities.iter().filter_map(|c| match c {
            Capability::Role(r) => Some(*r),
            _ => None,
        });
        let peer_role = match peer_roles.next() {
            None => None,
            Some(first) if peer_roles.all(|r| r == first) => Some(first),
            Some(_) => {
                return Err((
                    NotificationError::OpenMessage(OpenMsgError::RoleMismatch),
                    vec![],
                ));
            }
        };
        if let (Some(local), Some(peer_role)) = (local_role, peer_role)
            && !local.is_compatible_with(peer_role)
        {
            return Err((
                NotificationError::OpenMessage(OpenMsgError::RoleMismatch),
                vec![],
            ));
        }

        // If either side proposes 0, the result is 0 (timer disabled).
        let negotiated = if self.config.hold_time == 0 || peer.hold_time == 0 {
            0
        } else {
            self.config.hold_time.min(peer.hold_time)
        };

        Ok(negotiated)
    }

    /// Construct `SessionInfo` from the stored peer OPEN.
    fn build_session_info(&self) -> Option<SessionInfo> {
        let peer = self.peer_open.as_ref()?;
        let peer_as = resolve_as(peer);
        let peer_type = if peer_as == self.config.local_as {
            PeerType::Internal
        } else {
            PeerType::External
        };
        Some(SessionInfo {
            peer_as,
            peer_bgp_id: peer.bgp_id,
            hold_time: self.negotiated_hold_time,
            peer_capabilities: peer.capabilities.clone(),
            peer_type,
            local_addr: None,
        })
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

/// Encode a list of capabilities as NOTIFICATION data for Unsupported Capability
/// (RFC 5492 §3). Each entry is a capability TLV: code(1) + length(1) + value.
fn encode_unsupported_capabilities(caps: &[&Capability]) -> Vec<u8> {
    let mut data = Vec::new();
    for cap in caps {
        data.push(cap.code());
        data.push(0); // length 0 — we only need the code to identify the capability
    }
    data
}

/// Extract the effective AS number from an OPEN message.
///
/// Prefers [`Capability::FourByteAsn`] (RFC 6793) over the two-byte `my_as`
/// field, which may carry `AS_TRANS` when the real ASN exceeds 16 bits.
fn resolve_as(open: &OpenMessage) -> u32 {
    open.capabilities
        .iter()
        .find_map(|cap| {
            if let Capability::FourByteAsn(n) = cap {
                Some(*n)
            } else {
                None
            }
        })
        .unwrap_or_else(|| u32::from(open.my_as))
}

fn hold_duration(hold_time: u16) -> Duration {
    Duration::from_secs(u64::from(hold_time))
}

fn keepalive_interval(hold_time: u16) -> Duration {
    Duration::from_secs(u64::from(hold_time) / 3)
}

/// Append hold-timer and keepalive-timer start/stop actions based on the
/// negotiated hold time.
fn push_timer_actions(out: &mut Vec<FsmOutput>, negotiated: u16) {
    if negotiated > 0 {
        out.push(FsmOutput::StartHoldTimer(hold_duration(negotiated)));
        out.push(FsmOutput::StartKeepaliveTimer(keepalive_interval(
            negotiated,
        )));
    } else {
        out.push(FsmOutput::StopHoldTimer);
        out.push(FsmOutput::StopKeepaliveTimer);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod prop_tests;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pathvector_types::{AsPath, Asn, Nlri, Origin};

    use super::*;
    use crate::message::{PathAttribute, UpdateMessage};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn default_config() -> FsmConfig {
        FsmConfig {
            local_as: 65001,
            local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            capabilities: vec![Capability::FourByteAsn(65001)],
            required_capabilities: vec![],
            peer_as: Some(65002),
        }
    }

    fn peer_open(as_: u32, hold_time: u16) -> BgpMessage {
        BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: u16::try_from(as_).unwrap_or(AS_TRANS),
            hold_time,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::FourByteAsn(as_)],
        })
    }

    fn has_output(outputs: &[FsmOutput], pred: impl Fn(&FsmOutput) -> bool) -> bool {
        outputs.iter().any(pred)
    }

    fn find_send(outputs: &[FsmOutput]) -> Option<&BgpMessage> {
        outputs.iter().find_map(|o| {
            if let FsmOutput::SendMessage(m) = o {
                Some(m)
            } else {
                None
            }
        })
    }

    fn find_notification(outputs: &[FsmOutput]) -> Option<&NotificationMessage> {
        outputs.iter().find_map(|o| {
            if let FsmOutput::SendMessage(BgpMessage::Notification(n)) = o {
                Some(n)
            } else {
                None
            }
        })
    }

    #[test]
    fn test_find_notification_returns_none_when_no_notification_in_outputs() {
        let outputs = vec![FsmOutput::StopHoldTimer, FsmOutput::InitiateTcpConnect];
        assert!(find_notification(&outputs).is_none());
    }

    /// Drive the FSM through the happy path up to Established and return it.
    fn establish(config: FsmConfig) -> (Fsm, SessionInfo) {
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        let outputs = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        let info = outputs
            .iter()
            .find_map(|o| {
                if let FsmOutput::SessionEstablished(i) = o {
                    Some(i.clone())
                } else {
                    None
                }
            })
            .expect("SessionEstablished in outputs");
        (fsm, info)
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn test_manual_start_enters_connect() {
        let mut fsm = Fsm::new(default_config());
        let out = fsm.process(FsmInput::ManualStart);
        assert_eq!(fsm.state(), State::Connect);
        assert!(has_output(&out, |o| *o == FsmOutput::InitiateTcpConnect));
        assert!(has_output(&out, |o| {
            matches!(o, FsmOutput::StartConnectRetryTimer(_))
        }));
    }

    #[test]
    fn test_tcp_connected_sends_open() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        let out = fsm.process(FsmInput::TcpConnected);
        assert_eq!(fsm.state(), State::OpenSent);
        assert!(has_output(&out, |o| *o == FsmOutput::StopConnectRetryTimer));
        assert!(matches!(find_send(&out), Some(BgpMessage::Open(_))));
        assert!(has_output(&out, |o| {
            matches!(o, FsmOutput::StartHoldTimer(d) if *d == OPEN_HOLD_TIMER)
        }));
    }

    #[test]
    fn test_sent_open_has_correct_fields() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        let out = fsm.process(FsmInput::TcpConnected);
        let Some(BgpMessage::Open(open)) = find_send(&out) else {
            panic!("expected OPEN message")
        };
        assert_eq!(open.my_as, 65001);
        assert_eq!(open.bgp_id, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(open.hold_time, 90);
    }

    #[test]
    fn test_receive_open_sends_keepalive_enters_open_confirm() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        assert_eq!(fsm.state(), State::OpenConfirm);
        assert!(matches!(find_send(&out), Some(BgpMessage::Keepalive)));
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartHoldTimer(_)
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartKeepaliveTimer(_)
        )));
    }

    #[test]
    fn test_receive_keepalive_enters_established() {
        let (fsm, info) = establish(default_config());
        assert_eq!(fsm.state(), State::Established);
        assert_eq!(info.peer_as, 65002);
        assert_eq!(info.peer_bgp_id, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(info.hold_time, 90);
    }

    // ── SessionInfo contents ──────────────────────────────────────────────────

    #[test]
    fn test_session_info_peer_capabilities_forwarded() {
        // All capabilities in the peer OPEN must appear in SessionInfo so
        // the rest of the stack can gate behaviour on what was negotiated.
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let peer = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::FourByteAsn(65002),
                Capability::RouteRefresh,
                Capability::MultiProtocol(pathvector_types::AfiSafi::IPV6_UNICAST),
            ],
        });
        fsm.process(FsmInput::MessageReceived(peer));
        let outputs = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        let info = outputs
            .iter()
            .find_map(|o| {
                if let FsmOutput::SessionEstablished(i) = o {
                    Some(i.clone())
                } else {
                    None
                }
            })
            .expect("SessionEstablished");

        assert!(
            info.peer_capabilities
                .iter()
                .any(|c| matches!(c, Capability::FourByteAsn(65002)))
        );
        assert!(info.peer_capabilities.contains(&Capability::RouteRefresh));
        assert!(info.peer_capabilities.iter().any(|c| {
            matches!(c, Capability::MultiProtocol(a) if *a == pathvector_types::AfiSafi::IPV6_UNICAST)
        }));
    }

    #[test]
    fn test_session_info_external_peer_type_when_different_as() {
        // Different local_as (65001) and peer_as (65002) → eBGP → External.
        let (_, info) = establish(default_config());
        assert_eq!(info.peer_type, pathvector_types::PeerType::External);
    }

    #[test]
    fn test_session_info_internal_peer_type_when_same_as() {
        // Same AS on both sides → iBGP → Internal.
        let config = FsmConfig {
            local_as: 65002,
            peer_as: Some(65002),
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        let outputs = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        let info = outputs
            .iter()
            .find_map(|o| {
                if let FsmOutput::SessionEstablished(i) = o {
                    Some(i.clone())
                } else {
                    None
                }
            })
            .expect("SessionEstablished");
        assert_eq!(info.peer_type, pathvector_types::PeerType::Internal);
    }

    #[test]
    fn test_session_info_graceful_restart_capability_forwarded() {
        // RFC 4724: the GracefulRestart capability received from the peer
        // must be preserved in SessionInfo so the caller can decide whether
        // to hold forwarding state during a restart.
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let peer = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::FourByteAsn(65002),
                Capability::GracefulRestart {
                    restart_flags: 0x80, // R bit set — forwarding preserved
                    restart_time: 120,
                    families: vec![],
                },
            ],
        });
        fsm.process(FsmInput::MessageReceived(peer));
        let outputs = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        let info = outputs
            .iter()
            .find_map(|o| {
                if let FsmOutput::SessionEstablished(i) = o {
                    Some(i.clone())
                } else {
                    None
                }
            })
            .expect("SessionEstablished");

        let gr = info.peer_capabilities.iter().find_map(|c| {
            if let Capability::GracefulRestart {
                restart_flags,
                restart_time,
                ..
            } = c
            {
                Some((*restart_flags, *restart_time))
            } else {
                None
            }
        });
        assert_eq!(
            gr,
            Some((0x80, 120)),
            "GracefulRestart capability must be forwarded in SessionInfo (RFC 4724)"
        );
    }

    // ── Hold timer negotiation ────────────────────────────────────────────────

    #[test]
    fn test_hold_time_negotiated_to_minimum() {
        // Our hold_time=90, peer proposes 30 → negotiated=30.
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(65002, 30)));
        let hold = out.iter().find_map(|o| {
            if let FsmOutput::StartHoldTimer(d) = o {
                Some(*d)
            } else {
                None
            }
        });
        assert_eq!(hold, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_hold_time_zero_disables_timers() {
        let config = FsmConfig {
            hold_time: 0,
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(65002, 0)));
        assert_eq!(fsm.state(), State::OpenConfirm);
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::StopKeepaliveTimer));
    }

    // ── OPEN validation failures ──────────────────────────────────────────────

    #[test]
    fn test_bad_peer_as_sends_notification() {
        let mut fsm = Fsm::new(default_config()); // expects 65002
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(65099, 90)));
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::OpenMessage(OpenMsgError::BadPeerAs),
                ..
            }))
        ));
    }

    #[test]
    fn test_unacceptable_hold_time_sends_notification() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(65002, 1)));
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::OpenMessage(OpenMsgError::UnacceptableHoldTime),
                ..
            }))
        ));
    }

    #[test]
    fn test_bad_bgp_id_sends_notification() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let bad_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::UNSPECIFIED,
            capabilities: vec![Capability::FourByteAsn(65002)],
        });
        let out = fsm.process(FsmInput::MessageReceived(bad_open));
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier),
                ..
            }))
        ));
    }

    #[test]
    fn test_loopback_bgp_id_accepted() {
        // RFC 4271 §6.2 requires a "valid unicast IPv4 address". Loopback (127.x.x.x)
        // is unicast — RFC does not prohibit it. We must not over-reject.
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::LOCALHOST,
            capabilities: vec![Capability::FourByteAsn(65002)],
        });
        let out = fsm.process(FsmInput::MessageReceived(open));
        assert_eq!(
            fsm.state(),
            State::OpenConfirm,
            "loopback BGP ID must not be rejected"
        );
        // FSM sends KEEPALIVE on entering OpenConfirm — not a NOTIFICATION.
        assert!(matches!(find_send(&out), Some(BgpMessage::Keepalive)));
    }

    #[test]
    fn test_multicast_bgp_id_rejected() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let bad_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(224, 0, 0, 1), // multicast — RFC 4271 §6.2
            capabilities: vec![Capability::FourByteAsn(65002)],
        });
        let out = fsm.process(FsmInput::MessageReceived(bad_open));
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier),
                ..
            }))
        ));
    }

    #[test]
    fn test_broadcast_bgp_id_rejected() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let bad_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::BROADCAST, // 255.255.255.255 — RFC 4271 §6.2
            capabilities: vec![Capability::FourByteAsn(65002)],
        });
        let out = fsm.process(FsmInput::MessageReceived(bad_open));
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier),
                ..
            }))
        ));
    }

    // ── Hold timer expiry ─────────────────────────────────────────────────────

    #[test]
    fn test_hold_timer_expired_in_open_sent() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::HoldTimerExpired);
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::HoldTimerExpired,
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
        assert!(
            out.iter()
                .any(|o| matches!(o, FsmOutput::StartConnectRetryTimer(_))),
            "must schedule ConnectRetryTimer for automatic reconnect"
        );
    }

    #[test]
    fn test_hold_timer_expired_in_established() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::HoldTimerExpired);
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::HoldTimerExpired,
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
        assert!(
            out.iter()
                .any(|o| matches!(o, FsmOutput::StartConnectRetryTimer(_))),
            "must schedule ConnectRetryTimer for automatic reconnect — a peer that goes \
             silent (detected via hold-timer expiry, not a TCP-level error) must not leave \
             the session stuck forever with no further reconnect attempts"
        );
    }

    // ── Keepalive timer ───────────────────────────────────────────────────────

    #[test]
    fn test_keepalive_timer_expired_in_open_confirm() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        let out = fsm.process(FsmInput::KeepaliveTimerExpired);
        assert_eq!(fsm.state(), State::OpenConfirm);
        assert!(matches!(find_send(&out), Some(BgpMessage::Keepalive)));
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartKeepaliveTimer(_)
        )));
    }

    #[test]
    fn test_keepalive_timer_expired_in_established() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::KeepaliveTimerExpired);
        assert_eq!(fsm.state(), State::Established);
        assert!(matches!(find_send(&out), Some(BgpMessage::Keepalive)));
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartKeepaliveTimer(_)
        )));
    }

    #[test]
    fn test_keepalive_interval_is_third_of_hold_time() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        let ka = out.iter().find_map(|o| {
            if let FsmOutput::StartKeepaliveTimer(d) = o {
                Some(*d)
            } else {
                None
            }
        });
        assert_eq!(ka, Some(Duration::from_secs(30)));
    }

    // ── UPDATE in Established ─────────────────────────────────────────────────

    #[test]
    fn test_update_emits_route_update_and_resets_hold() {
        let (mut fsm, _) = establish(default_config());
        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(65002)])),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            announced: vec!["192.0.2.0/24".parse::<Nlri<Ipv4Addr>>().unwrap()],
        };
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Update(
            update.clone(),
        )));
        assert_eq!(fsm.state(), State::Established);
        assert!(has_output(&out, |o| matches!(o, FsmOutput::RouteUpdate(_))));
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartHoldTimer(_)
        )));
    }

    // ── NOTIFICATION received ─────────────────────────────────────────────────

    #[test]
    fn test_notification_in_open_sent_goes_idle() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let notif = BgpMessage::Notification(NotificationMessage {
            error: NotificationError::HoldTimerExpired,
            data: vec![],
        });
        let out = fsm.process(FsmInput::MessageReceived(notif));
        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
    }

    #[test]
    fn test_notification_in_established_emits_session_terminated() {
        let (mut fsm, _) = establish(default_config());
        let notif = BgpMessage::Notification(NotificationMessage {
            error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
            data: vec![],
        });
        let out = fsm.process(FsmInput::MessageReceived(notif));
        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    // ── ManualStop ────────────────────────────────────────────────────────────

    #[test]
    fn test_manual_stop_from_idle_is_noop() {
        let mut fsm = Fsm::new(default_config());
        let out = fsm.process(FsmInput::ManualStop);
        assert_eq!(fsm.state(), State::Idle);
        assert!(out.is_empty());
    }

    #[test]
    fn test_manual_stop_from_connect() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        let out = fsm.process(FsmInput::ManualStop);
        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::StopConnectRetryTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
    }

    #[test]
    fn test_manual_stop_from_established_sends_cease() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::ManualStop);
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    // ── TCP failure ───────────────────────────────────────────────────────────

    #[test]
    fn test_tcp_failed_from_connect_enters_active() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        let out = fsm.process(FsmInput::TcpFailed);
        assert_eq!(fsm.state(), State::Active);
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartConnectRetryTimer(_)
        )));
    }

    #[test]
    fn test_connect_retry_from_active_enters_connect() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpFailed);
        let out = fsm.process(FsmInput::ConnectRetryTimerExpired);
        assert_eq!(fsm.state(), State::Connect);
        assert!(has_output(&out, |o| *o == FsmOutput::InitiateTcpConnect));
    }

    #[test]
    fn test_tcp_failed_in_established_terminates_session() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::TcpFailed);
        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    // ── 4-byte ASN resolution ─────────────────────────────────────────────────

    #[test]
    fn test_four_byte_asn_preferred_over_my_as() {
        let config = FsmConfig {
            local_as: 131_072, // > 65535
            local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            capabilities: vec![Capability::FourByteAsn(131_072)],
            required_capabilities: vec![],
            peer_as: Some(131_073),
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        // Verify we send AS_TRANS in the my_as field.
        let out = fsm.process(FsmInput::TcpConnected);
        let Some(BgpMessage::Open(open)) = find_send(&out) else {
            panic!("expected OPEN")
        };
        assert_eq!(open.my_as, AS_TRANS);
        // Verify we accept a peer with 4-byte ASN via capability.
        fsm.process(FsmInput::MessageReceived(peer_open(131_073, 90)));
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        let info = out.iter().find_map(|o| {
            if let FsmOutput::SessionEstablished(i) = o {
                Some(i.clone())
            } else {
                None
            }
        });
        assert_eq!(info.unwrap().peer_as, 131_073);
    }

    // ── resolve_as: non-FourByteAsn capabilities yield the None branch ───────

    #[test]
    fn test_resolve_as_falls_back_to_my_as_when_no_four_byte_asn_cap() {
        // When the peer sends only RouteRefresh (no FourByteAsn capability),
        // `resolve_as` iterates RouteRefresh, the `else { None }` branch fires,
        // find_map returns None, and the fallback `u32::from(open.my_as)` is used.
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        let peer = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::RouteRefresh], // no FourByteAsn
        });
        fsm.process(FsmInput::MessageReceived(peer));
        let outputs = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));

        let info = outputs
            .iter()
            .find_map(|o| {
                if let FsmOutput::SessionEstablished(i) = o {
                    Some(i.clone())
                } else {
                    None
                }
            })
            .expect("SessionEstablished");

        // peer_as should be the 2-byte my_as value since there is no FourByteAsn cap.
        assert_eq!(info.peer_as, 65002);
    }

    // ── No configured peer_as → accept any ───────────────────────────────────

    #[test]
    fn test_open_accepted_when_peer_as_unconfigured() {
        let config = FsmConfig {
            peer_as: None,
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(99999, 90)));
        assert_eq!(fsm.state(), State::OpenConfirm);
        assert!(matches!(find_send(&out), Some(BgpMessage::Keepalive)));
    }

    // ── Connect / Active state gaps ───────────────────────────────────────────

    #[test]
    fn test_connect_retry_timer_from_connect_reinitiates_tcp() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart); // → Connect
        let out = fsm.process(FsmInput::ConnectRetryTimerExpired);
        assert_eq!(fsm.state(), State::Connect);
        assert!(has_output(&out, |o| *o == FsmOutput::InitiateTcpConnect));
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartConnectRetryTimer(_)
        )));
    }

    #[test]
    fn test_tcp_connected_from_active_enters_open_sent() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart); // → Connect
        fsm.process(FsmInput::TcpFailed); // → Active
        let out = fsm.process(FsmInput::TcpConnected);
        assert_eq!(fsm.state(), State::OpenSent);
        assert!(matches!(find_send(&out), Some(BgpMessage::Open(_))));
    }

    #[test]
    fn test_manual_stop_from_active() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpFailed); // → Active
        let out = fsm.process(FsmInput::ManualStop);
        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::StopConnectRetryTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
    }

    // ── OpenSent gaps ─────────────────────────────────────────────────────────

    #[test]
    fn test_unexpected_message_in_open_sent_sends_fsm_error_subcode_1() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        assert_eq!(fsm.state(), State::OpenSent);

        // KEEPALIVE is not valid in OpenSent — expect FSM Error subcode 1.
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));

        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::FsmErrorOpenSent,
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
    }

    #[test]
    fn test_tcp_failed_in_open_sent_enters_active() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::TcpFailed);
        assert_eq!(fsm.state(), State::Active);
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartConnectRetryTimer(_)
        )));
    }

    #[test]
    fn test_manual_stop_from_open_sent_sends_cease() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::ManualStop);
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                ..
            }))
        ));
    }

    // ── OpenConfirm gaps ──────────────────────────────────────────────────────

    #[test]
    fn test_unexpected_message_in_open_confirm_sends_fsm_error_subcode_2() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        assert_eq!(fsm.state(), State::OpenConfirm);

        // UPDATE is not valid in OpenConfirm — expect FSM Error subcode 2.
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Update(
            UpdateMessage {
                withdrawn: vec![],
                attributes: vec![],
                announced: vec![],
            },
        )));

        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::FsmErrorOpenConfirm,
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::StopKeepaliveTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
        // Session never reached Established, so no SessionTerminated.
        assert!(!has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    fn enter_open_confirm() -> Fsm {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        assert_eq!(fsm.state(), State::OpenConfirm);
        fsm
    }

    #[test]
    fn test_keepalive_in_open_confirm_with_missing_peer_open_resets_to_idle() {
        // Exercises the invariant-violation guard added to build_session_info:
        // if peer_open is somehow None in OpenConfirm, the FSM must reset cleanly
        // rather than panic (a panic would leave stale routes in the RIB).
        let mut fsm = enter_open_confirm();
        assert_eq!(fsm.state(), State::OpenConfirm);
        fsm.peer_open = None; // force the invariant violation

        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));

        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::StopKeepaliveTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
        // Session never reached Established, so SessionEstablished must not appear.
        assert!(!has_output(&out, |o| matches!(
            o,
            FsmOutput::SessionEstablished(_)
        )));
    }

    #[test]
    fn test_notification_in_open_confirm_terminates() {
        let mut fsm = enter_open_confirm();
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Notification(
            NotificationMessage {
                error: NotificationError::HoldTimerExpired,
                data: vec![],
            },
        )));
        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::StopKeepaliveTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    #[test]
    fn test_tcp_failed_in_open_confirm_terminates() {
        let mut fsm = enter_open_confirm();
        let out = fsm.process(FsmInput::TcpFailed);
        assert_eq!(fsm.state(), State::Idle);
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    #[test]
    fn test_hold_timer_expired_in_open_confirm() {
        let mut fsm = enter_open_confirm();
        let out = fsm.process(FsmInput::HoldTimerExpired);
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::HoldTimerExpired,
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::StopKeepaliveTimer));
        assert!(
            out.iter()
                .any(|o| matches!(o, FsmOutput::StartConnectRetryTimer(_))),
            "must schedule ConnectRetryTimer for automatic reconnect"
        );
    }

    #[test]
    fn test_manual_stop_from_open_confirm_sends_cease() {
        let mut fsm = enter_open_confirm();
        let out = fsm.process(FsmInput::ManualStop);
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::StopKeepaliveTimer));
    }

    // ── Established gaps ──────────────────────────────────────────────────────

    #[test]
    fn test_unexpected_message_in_established_sends_fsm_error_subcode_3() {
        let (mut fsm, _) = establish(default_config());

        // OPEN is never valid in Established — expect FSM Error subcode 3.
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: std::net::Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![],
        })));

        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::FsmErrorEstablished,
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::StopKeepaliveTimer));
        assert!(has_output(&out, |o| *o == FsmOutput::CloseTcpConnection));
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    #[test]
    fn test_route_refresh_without_capability_sends_fsm_error_subcode_3() {
        // Neither side advertised RouteRefresh — receiving one is unexpected.
        let (mut fsm, _) = establish(default_config());

        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::RouteRefresh(
            crate::message::RouteRefreshMessage::new(pathvector_types::AfiSafi::IPV4_UNICAST),
        )));

        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::FsmErrorEstablished,
                ..
            }))
        ));
        assert!(has_output(&out, |o| *o == FsmOutput::SessionTerminated));
    }

    #[test]
    fn test_route_refresh_with_capability_is_accepted() {
        // Both sides negotiate RouteRefresh — receiving it must not reset the session.
        let config = FsmConfig {
            capabilities: vec![Capability::RouteRefresh],
            ..default_config()
        };
        let peer_open_msg = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: std::net::Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::RouteRefresh],
        });
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open_msg));
        fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        assert_eq!(fsm.state(), State::Established);

        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::RouteRefresh(
            crate::message::RouteRefreshMessage::new(pathvector_types::AfiSafi::IPV4_UNICAST),
        )));

        assert_eq!(fsm.state(), State::Established, "session must stay up");
        assert!(
            out.is_empty(),
            "no outputs expected until re-advert is wired"
        );
    }

    #[test]
    fn test_keepalive_message_in_established_resets_hold_timer() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        assert_eq!(fsm.state(), State::Established);
        assert!(has_output(&out, |o| matches!(
            o,
            FsmOutput::StartHoldTimer(_)
        )));
    }

    // ── Catch-all _ => vec![] branches ───────────────────────────────────────

    #[test]
    fn test_unhandled_input_in_connect_is_noop() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart); // → Connect
        let out = fsm.process(FsmInput::HoldTimerExpired);
        assert_eq!(fsm.state(), State::Connect);
        assert!(out.is_empty());
    }

    #[test]
    fn test_unhandled_input_in_active_is_noop() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpFailed); // → Active
        let out = fsm.process(FsmInput::HoldTimerExpired);
        assert_eq!(fsm.state(), State::Active);
        assert!(out.is_empty());
    }

    #[test]
    fn test_unhandled_input_in_open_sent_is_noop() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected); // → OpenSent
        let out = fsm.process(FsmInput::KeepaliveTimerExpired);
        assert_eq!(fsm.state(), State::OpenSent);
        assert!(out.is_empty());
    }

    #[test]
    fn test_unhandled_input_in_open_confirm_is_noop() {
        let mut fsm = enter_open_confirm();
        let out = fsm.process(FsmInput::ConnectRetryTimerExpired);
        assert_eq!(fsm.state(), State::OpenConfirm);
        assert!(out.is_empty());
    }

    #[test]
    fn test_unhandled_input_in_established_is_noop() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::ConnectRetryTimerExpired);
        assert_eq!(fsm.state(), State::Established);
        assert!(out.is_empty());
    }

    // ── reset_hold_if_active else branch (hold_time == 0) ────────────────────

    #[test]
    fn test_keepalive_in_established_no_hold_timer_when_disabled() {
        let config = FsmConfig {
            hold_time: 0,
            ..default_config()
        };
        let (mut fsm, _) = establish(config);
        // With negotiated_hold_time == 0, a Keepalive in Established returns no outputs.
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        assert_eq!(fsm.state(), State::Established);
        assert!(out.is_empty());
    }

    // ── validate_open: UnsupportedVersionNumber ───────────────────────────────

    #[test]
    fn test_unsupported_version_in_open_sends_notification() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let bad_open = BgpMessage::Open(OpenMessage {
            version: 3,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::FourByteAsn(65002)],
        });
        let out = fsm.process(FsmInput::MessageReceived(bad_open));
        assert_eq!(fsm.state(), State::Idle);
        assert!(matches!(
            find_send(&out),
            Some(BgpMessage::Notification(NotificationMessage {
                error: NotificationError::OpenMessage(OpenMsgError::UnsupportedVersionNumber),
                ..
            }))
        ));
    }

    /// When the peer sends an OPEN with no `FourByteAsn` capability,
    /// `resolve_as` falls back to the 2-byte `my_as` field (line 547).
    #[test]
    fn test_receive_open_without_four_byte_asn_capability_falls_back_to_my_as() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        // Peer sends OPEN with no capabilities at all — resolve_as must use my_as.
        let peer_open_no_cap = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![],
        });
        fsm.process(FsmInput::MessageReceived(peer_open_no_cap));
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));

        let info = out
            .iter()
            .find_map(|o| {
                if let FsmOutput::SessionEstablished(i) = o {
                    Some(i.clone())
                } else {
                    None
                }
            })
            .expect("SessionEstablished");
        assert_eq!(
            info.peer_as, 65002,
            "peer_as must come from my_as when no FourByteAsn cap"
        );
    }

    // ── RFC 6286 — AS-wide unique BGP identifier ──────────────────────────────

    #[test]
    fn test_ibgp_peer_with_same_bgp_id_is_rejected() {
        // iBGP peer (same AS) sending our own BGP ID — routing loop / misconfiguration.
        let config = FsmConfig {
            local_as: 65001,
            peer_as: Some(65001), // iBGP
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        let duplicate_id_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65001,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1), // same as local_bgp_id in default_config
            capabilities: vec![Capability::FourByteAsn(65001)],
        });
        let out = fsm.process(FsmInput::MessageReceived(duplicate_id_open));

        assert_eq!(fsm.state(), State::Idle);
        let n = find_notification(&out).expect("expected BadBgpIdentifier NOTIFICATION");
        assert_eq!(
            n.error,
            NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier)
        );
    }

    #[test]
    fn test_ebgp_peer_with_same_bgp_id_is_allowed() {
        // eBGP peer may legitimately share a BGP ID (different AS, different operator).
        let mut fsm = Fsm::new(default_config()); // peer_as = Some(65002) — eBGP
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        let ebgp_same_id = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1), // same as our local_bgp_id
            capabilities: vec![Capability::FourByteAsn(65002)],
        });
        fsm.process(FsmInput::MessageReceived(ebgp_same_id));
        assert_eq!(
            fsm.state(),
            State::OpenConfirm,
            "eBGP peer with same BGP ID should not be rejected"
        );
    }

    // ── RFC 5492 — Unsupported Capability ─────────────────────────────────────

    #[test]
    fn test_required_capability_missing_sends_unsupported_capability_notification() {
        let config = FsmConfig {
            required_capabilities: vec![Capability::RouteRefresh],
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        // Peer OPEN has no RouteRefresh capability.
        let peer_open_no_rr = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::FourByteAsn(65002)],
        });
        let out = fsm.process(FsmInput::MessageReceived(peer_open_no_rr));

        assert_eq!(fsm.state(), State::Idle);
        let n = find_notification(&out).expect("expected UnsupportedCapability NOTIFICATION");
        assert_eq!(
            n.error,
            NotificationError::OpenMessage(OpenMsgError::UnsupportedCapability)
        );
        assert!(
            n.data.contains(&2),
            "NOTIFICATION data must contain capability code 2 (RouteRefresh)"
        );
    }

    #[test]
    fn test_required_capability_present_allows_session() {
        let config = FsmConfig {
            required_capabilities: vec![Capability::RouteRefresh],
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        // Peer OPEN includes RouteRefresh.
        let peer_open_with_rr = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::FourByteAsn(65002), Capability::RouteRefresh],
        });
        fsm.process(FsmInput::MessageReceived(peer_open_with_rr));
        assert_eq!(
            fsm.state(),
            State::OpenConfirm,
            "session should proceed to OpenConfirm"
        );
    }

    // ── RFC 9234 role-pair validation ──────────────────────────────────────────

    /// Drives an FSM configured with `local_role` (in addition to the default
    /// `FourByteAsn` capability) through `ManualStart`/`TcpConnected`, then
    /// feeds a peer OPEN advertising `peer_role` (if `Some`). Returns the
    /// resulting FSM state and outputs for the caller to assert on.
    fn negotiate_role(
        local_role: pathvector_types::Role,
        peer_role: Option<pathvector_types::Role>,
    ) -> (State, Vec<FsmOutput>) {
        let mut capabilities = vec![Capability::FourByteAsn(65001)];
        capabilities.push(Capability::Role(local_role));
        let config = FsmConfig {
            capabilities,
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        let mut peer_capabilities = vec![Capability::FourByteAsn(65002)];
        if let Some(role) = peer_role {
            peer_capabilities.push(Capability::Role(role));
        }
        let peer_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: peer_capabilities,
        });
        let out = fsm.process(FsmInput::MessageReceived(peer_open));
        (fsm.state(), out)
    }

    #[test]
    fn test_role_pair_matrix() {
        use pathvector_types::Role::{Customer, Peer, Provider, RouteServer, RsClient};

        let roles = [Provider, RouteServer, RsClient, Customer, Peer];
        let compatible = [
            (Provider, Customer),
            (Customer, Provider),
            (RouteServer, RsClient),
            (RsClient, RouteServer),
            (Peer, Peer),
        ];
        for &local in &roles {
            for &peer_role in &roles {
                let (state, out) = negotiate_role(local, Some(peer_role));
                if compatible.contains(&(local, peer_role)) {
                    assert_eq!(
                        state,
                        State::OpenConfirm,
                        "{local:?} vs {peer_role:?} should be compatible"
                    );
                } else {
                    assert_eq!(
                        state,
                        State::Idle,
                        "{local:?} vs {peer_role:?} should be rejected"
                    );
                    let n = find_notification(&out).expect("expected RoleMismatch NOTIFICATION");
                    assert_eq!(
                        n.error,
                        NotificationError::OpenMessage(OpenMsgError::RoleMismatch)
                    );
                }
            }
        }
    }

    #[test]
    fn test_role_absent_on_peer_side_is_not_a_mismatch() {
        // RFC 9234's non-strict default: we advertise a Role, the peer
        // advertises none at all — this must NOT be treated as a mismatch.
        let (state, _) = negotiate_role(pathvector_types::Role::Provider, None);
        assert_eq!(state, State::OpenConfirm);
    }

    #[test]
    fn test_role_absent_locally_is_not_a_mismatch() {
        // Symmetric case: peer advertises a Role, we don't advertise one at
        // all (no Capability::Role in our own config.capabilities).
        let config = FsmConfig {
            capabilities: vec![Capability::FourByteAsn(65001)], // no Role
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        let peer_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::FourByteAsn(65002),
                Capability::Role(pathvector_types::Role::Customer),
            ],
        });
        fsm.process(FsmInput::MessageReceived(peer_open));
        assert_eq!(fsm.state(), State::OpenConfirm);
    }

    /// Like `negotiate_role`, but the peer advertises multiple `Capability::Role`
    /// instances (in the given order) instead of at most one.
    fn negotiate_role_multi(
        local_role: pathvector_types::Role,
        peer_roles: &[pathvector_types::Role],
    ) -> (State, Vec<FsmOutput>) {
        let mut capabilities = vec![Capability::FourByteAsn(65001)];
        capabilities.push(Capability::Role(local_role));
        let config = FsmConfig {
            capabilities,
            ..default_config()
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);

        let mut peer_capabilities = vec![Capability::FourByteAsn(65002)];
        for &role in peer_roles {
            peer_capabilities.push(Capability::Role(role));
        }
        let peer_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: peer_capabilities,
        });
        let out = fsm.process(FsmInput::MessageReceived(peer_open));
        (fsm.state(), out)
    }

    /// RFC 9234 §4.2: "If an eBGP speaker receives multiple but identical BGP
    /// Role Capabilities with the same value in each, then the speaker
    /// considers them to be a single BGP Role Capability and proceeds."
    #[test]
    fn test_role_identical_duplicates_are_not_a_mismatch() {
        use pathvector_types::Role::{Customer, Provider};

        let (state, _) = negotiate_role_multi(Provider, &[Customer, Customer]);
        assert_eq!(
            state,
            State::OpenConfirm,
            "identical duplicate Role capabilities must collapse to one and proceed"
        );
    }

    /// RFC 9234 §4.2: "If multiple BGP Role Capabilities are received and not
    /// all of them have the same value, then the BGP speaker MUST reject the
    /// connection using the Role Mismatch Notification." This must hold even
    /// when the *first* advertised value alone would have been compatible —
    /// a first-instance-wins implementation would proceed to `OpenConfirm`
    /// here, never noticing the peer also sent a conflicting second value.
    #[test]
    fn test_role_differing_duplicates_are_a_mismatch_even_if_first_is_compatible() {
        use pathvector_types::Role::{Customer, Peer, Provider};

        // Customer is compatible with our Provider; Peer is not. A
        // first-wins bug would see only Customer and proceed.
        let (state, out) = negotiate_role_multi(Provider, &[Customer, Peer]);
        assert_eq!(
            state,
            State::Idle,
            "differing Role capability values must be rejected regardless of \
             whether the first one alone would have been compatible"
        );
        let n = find_notification(&out).expect("expected RoleMismatch NOTIFICATION");
        assert_eq!(
            n.error,
            NotificationError::OpenMessage(OpenMsgError::RoleMismatch)
        );
    }

    // ── RFC 4271 §6.8 collision detection ─────────────────────────────────────

    fn open_sent_fsm(local_bgp_id: Ipv4Addr) -> Fsm {
        let mut fsm = Fsm::new(FsmConfig {
            local_bgp_id,
            ..default_config()
        });
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        assert_eq!(fsm.state(), State::OpenSent);
        fsm
    }

    fn open_confirm_fsm(local_bgp_id: Ipv4Addr, peer_bgp_id: Ipv4Addr) -> Fsm {
        let mut fsm = open_sent_fsm(local_bgp_id);
        fsm.process(FsmInput::MessageReceived(BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: peer_bgp_id,
            capabilities: vec![],
        })));
        assert_eq!(fsm.state(), State::OpenConfirm);
        fsm
    }

    #[test]
    fn test_peer_bgp_id_none_before_open_received() {
        let fsm = open_sent_fsm(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(fsm.peer_bgp_id(), None);
    }

    #[test]
    fn test_peer_bgp_id_set_after_open_received() {
        let fsm = open_confirm_fsm(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(fsm.peer_bgp_id(), Some(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn test_collision_detected_in_open_sent_resets_to_active() {
        // RFC 4271 §8.2.2 OpenSent/Event 19: a connection dropped due to
        // collision "sends a NOTIFICATION with a Cease" before closing.
        let mut fsm = open_sent_fsm(Ipv4Addr::new(10, 0, 0, 2));
        let outputs = fsm.process(FsmInput::CollisionDetected);
        assert_eq!(fsm.state(), State::Active);
        assert!(fsm.peer_bgp_id().is_none());
        // Must stop hold timer and close connection — must NOT emit SessionTerminated.
        assert!(outputs.contains(&FsmOutput::StopHoldTimer));
        assert!(outputs.contains(&FsmOutput::CloseTcpConnection));
        assert!(!outputs.contains(&FsmOutput::SessionTerminated));
        let n = find_notification(&outputs)
            .expect("collision resolution must send a Cease NOTIFICATION (RFC 4271 §8.2.2)");
        assert_eq!(
            n.error,
            NotificationError::Cease(CeaseError::ConnectionCollisionResolution)
        );
    }

    #[test]
    fn test_collision_detected_in_open_confirm_resets_to_active() {
        // RFC 4271 §8.2.2 OpenConfirm/Event 23 (OpenCollisionDump): "sends a
        // NOTIFICATION with a Cease" before dropping the connection.
        let mut fsm = open_confirm_fsm(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        let outputs = fsm.process(FsmInput::CollisionDetected);
        assert_eq!(fsm.state(), State::Active);
        assert!(fsm.peer_bgp_id().is_none());
        assert!(outputs.contains(&FsmOutput::StopHoldTimer));
        assert!(outputs.contains(&FsmOutput::StopKeepaliveTimer));
        assert!(outputs.contains(&FsmOutput::CloseTcpConnection));
        assert!(!outputs.contains(&FsmOutput::SessionTerminated));
        let n = find_notification(&outputs)
            .expect("collision resolution must send a Cease NOTIFICATION (RFC 4271 §8.2.2)");
        assert_eq!(
            n.error,
            NotificationError::Cease(CeaseError::ConnectionCollisionResolution)
        );
    }

    #[test]
    fn test_collision_detected_followed_by_tcp_connected_reaches_open_sent() {
        // After CollisionDetected → Active, TcpConnected must be valid and send OPEN.
        let mut fsm = open_confirm_fsm(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        fsm.process(FsmInput::CollisionDetected);
        assert_eq!(fsm.state(), State::Active);
        let outputs = fsm.process(FsmInput::TcpConnected);
        assert_eq!(fsm.state(), State::OpenSent);
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, FsmOutput::SendMessage(BgpMessage::Open(_))))
        );
    }

    // ── RFC 4724 §4.2 — Established-state collision override ──────────────────

    /// Establish a session where the peer's OPEN advertised the Graceful
    /// Restart capability.
    fn established_fsm_with_gr() -> Fsm {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let peer = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![
                Capability::FourByteAsn(65002),
                Capability::GracefulRestart {
                    restart_flags: 0,
                    restart_time: 120,
                    families: vec![],
                },
            ],
        });
        fsm.process(FsmInput::MessageReceived(peer));
        fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        assert_eq!(fsm.state(), State::Established);
        fsm
    }

    #[test]
    fn test_peer_has_graceful_restart_false_without_capability() {
        let (fsm, _info) = establish(default_config());
        assert!(!fsm.peer_has_graceful_restart());
    }

    #[test]
    fn test_peer_has_graceful_restart_true_with_capability() {
        let fsm = established_fsm_with_gr();
        assert!(fsm.peer_has_graceful_restart());
    }

    #[test]
    fn test_collision_detected_in_established_with_gr_moves_to_connect_no_notification() {
        // RFC 4724 §4.2: "the previous TCP session MUST be closed, and the
        // new one retained... Since the previous connection is considered to
        // be terminated, no NOTIFICATION message should be sent -- the
        // previous TCP session is simply closed." And from the FSM-text
        // replacement in the same section: "...changes its state to Connect."
        let mut fsm = established_fsm_with_gr();
        let outputs = fsm.process(FsmInput::CollisionDetected);
        assert_eq!(fsm.state(), State::Connect);
        assert!(fsm.peer_bgp_id().is_none());
        assert!(
            find_notification(&outputs).is_none(),
            "RFC 4724 §4.2 requires no NOTIFICATION on this path, got {outputs:?}"
        );
        assert!(outputs.contains(&FsmOutput::StopHoldTimer));
        assert!(outputs.contains(&FsmOutput::StopKeepaliveTimer));
        assert!(outputs.contains(&FsmOutput::CloseTcpConnection));
        assert!(outputs.contains(&FsmOutput::SessionTerminated));
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, FsmOutput::StartConnectRetryTimer(_)))
        );
    }

    #[test]
    fn test_collision_detected_in_established_with_gr_followed_by_tcp_connected_reaches_open_sent()
    {
        // Mirrors test_collision_detected_followed_by_tcp_connected_reaches_open_sent
        // for the Established/GR path: after moving to Connect, the adopted
        // incoming connection's TcpConnected must drive the FSM forward.
        let mut fsm = established_fsm_with_gr();
        fsm.process(FsmInput::CollisionDetected);
        assert_eq!(fsm.state(), State::Connect);
        let outputs = fsm.process(FsmInput::TcpConnected);
        assert_eq!(fsm.state(), State::OpenSent);
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, FsmOutput::SendMessage(BgpMessage::Open(_))))
        );
    }

    #[test]
    fn test_empty_required_capabilities_never_rejects() {
        // Default config has required_capabilities: vec![] — any peer OPEN is accepted.
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let peer_open = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![],
        });
        fsm.process(FsmInput::MessageReceived(peer_open));
        assert_eq!(fsm.state(), State::OpenConfirm);
    }

    // ── Automatic reconnect after session termination ─────────────────────────

    fn reach_established(fsm: &mut Fsm) {
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        assert_eq!(fsm.state(), State::Established);
    }

    #[test]
    fn test_established_tcp_failed_schedules_reconnect() {
        let mut fsm = Fsm::new(default_config());
        reach_established(&mut fsm);

        let out = fsm.process(FsmInput::TcpFailed);
        assert_eq!(fsm.state(), State::Idle);
        assert!(
            out.contains(&FsmOutput::SessionTerminated),
            "must emit SessionTerminated"
        );
        assert!(
            out.iter()
                .any(|o| matches!(o, FsmOutput::StartConnectRetryTimer(_))),
            "must schedule ConnectRetryTimer for automatic reconnect"
        );
    }

    #[test]
    fn test_established_notification_schedules_reconnect() {
        let mut fsm = Fsm::new(default_config());
        reach_established(&mut fsm);

        let notif = BgpMessage::Notification(NotificationMessage {
            error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
            data: vec![],
        });
        let out = fsm.process(FsmInput::MessageReceived(notif));
        assert_eq!(fsm.state(), State::Idle);
        assert!(
            out.iter()
                .any(|o| matches!(o, FsmOutput::StartConnectRetryTimer(_))),
            "must schedule ConnectRetryTimer for automatic reconnect"
        );
    }

    /// RFC 4271 §8.2.2 Event 28 (`UpdateMsgErr`): a locally detected protocol
    /// error (e.g. RFC 7606 §3(g)'s duplicated `MP_REACH_NLRI`) must send the
    /// NOTIFICATION, tear down, AND schedule an automatic reconnect — unlike
    /// `NotificationToSend` (administrative/operator-initiated shutdown,
    /// which must NOT auto-reconnect). A prior version of this fix routed
    /// protocol errors through `NotificationToSend` and silently lost the
    /// reconnect, leaving a misbehaving-but-still-configured peer stuck in
    /// Idle forever.
    #[test]
    fn test_established_protocol_error_notification_schedules_reconnect() {
        use crate::message::UpdateMsgError;

        let mut fsm = Fsm::new(default_config());
        reach_established(&mut fsm);

        let notif = NotificationMessage {
            error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAttributeList),
            data: vec![],
        };
        let out = fsm.process(FsmInput::ProtocolErrorNotificationToSend(notif.clone()));
        assert_eq!(fsm.state(), State::Idle);
        assert!(
            out.contains(&FsmOutput::SendMessage(BgpMessage::Notification(notif))),
            "must send the given NOTIFICATION"
        );
        assert!(
            out.contains(&FsmOutput::CloseTcpConnection),
            "must close the TCP connection"
        );
        assert!(
            out.contains(&FsmOutput::SessionTerminated),
            "must emit SessionTerminated"
        );
        assert!(
            out.iter()
                .any(|o| matches!(o, FsmOutput::StartConnectRetryTimer(_))),
            "must schedule ConnectRetryTimer for automatic reconnect — unlike \
             NotificationToSend, a protocol error on a still-configured peer \
             must not leave it stuck in Idle indefinitely"
        );
    }

    #[test]
    fn test_idle_connect_retry_timer_restarts_connect() {
        let mut fsm = Fsm::new(default_config());
        reach_established(&mut fsm);
        fsm.process(FsmInput::TcpFailed); // → Idle with ConnectRetryTimer

        let out = fsm.process(FsmInput::ConnectRetryTimerExpired);
        assert_eq!(fsm.state(), State::Connect);
        assert!(
            out.contains(&FsmOutput::InitiateTcpConnect),
            "must re-initiate TCP connect on timer expiry"
        );
    }
}
