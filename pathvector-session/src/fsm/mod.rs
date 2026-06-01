//! BGP session Finite State Machine (RFC 4271 §8).
//!
//! A pure, synchronous state machine. Feed [`FsmInput`] events via
//! [`Fsm::process`] and execute the returned [`FsmOutput`] actions.
//! The FSM holds no timers, no sockets, and performs no I/O — the transport
//! layer owns those resources and drives the FSM.

use std::net::Ipv4Addr;
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
    /// A complete BGP message was received from the peer.
    MessageReceived(BgpMessage),
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
        Self { state: State::Idle, config, peer_open: None, negotiated_hold_time: 0 }
    }

    /// Current FSM state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
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
            FsmInput::ManualStart => {
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
                    Err(err) => {
                        self.state = State::Idle;
                        vec![
                            FsmOutput::SendMessage(BgpMessage::Notification(
                                NotificationMessage { error: err, data: vec![] },
                            )),
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
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
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
            _ => vec![],
        }
    }

    fn on_established(&mut self, input: FsmInput) -> Vec<FsmOutput> {
        match input {
            FsmInput::MessageReceived(BgpMessage::Keepalive) => self.reset_hold_if_active(),
            FsmInput::MessageReceived(BgpMessage::Update(update)) => {
                let mut out = self.reset_hold_if_active();
                out.push(FsmOutput::RouteUpdate(update));
                out
            }
            FsmInput::MessageReceived(BgpMessage::Notification(_)) | FsmInput::TcpFailed => {
                self.state = State::Idle;
                vec![
                    FsmOutput::StopHoldTimer,
                    FsmOutput::StopKeepaliveTimer,
                    FsmOutput::CloseTcpConnection,
                    FsmOutput::SessionTerminated,
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
        vec![FsmOutput::StopConnectRetryTimer, FsmOutput::CloseTcpConnection]
    }

    /// Restart the hold timer if the negotiated hold time is non-zero.
    fn reset_hold_if_active(&self) -> Vec<FsmOutput> {
        if self.negotiated_hold_time > 0 {
            vec![FsmOutput::StartHoldTimer(hold_duration(self.negotiated_hold_time))]
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
            { self.config.local_as as u16 }
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
    fn validate_open(&self, peer: &OpenMessage) -> Result<u16, NotificationError> {
        if peer.version != 4 {
            return Err(NotificationError::OpenMessage(OpenMsgError::UnsupportedVersionNumber));
        }

        if peer.bgp_id == Ipv4Addr::UNSPECIFIED {
            return Err(NotificationError::OpenMessage(OpenMsgError::BadBgpIdentifier));
        }

        if let Some(expected) = self.config.peer_as {
            if resolve_as(peer) != expected {
                return Err(NotificationError::OpenMessage(OpenMsgError::BadPeerAs));
            }
        }

        // RFC 4271 §6.2: hold time values 1 and 2 are unacceptable.
        if peer.hold_time == 1 || peer.hold_time == 2 {
            return Err(NotificationError::OpenMessage(OpenMsgError::UnacceptableHoldTime));
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
        })
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

/// Extract the effective AS number from an OPEN message.
///
/// Prefers [`Capability::FourByteAsn`] (RFC 6793) over the two-byte `my_as`
/// field, which may carry `AS_TRANS` when the real ASN exceeds 16 bits.
fn resolve_as(open: &OpenMessage) -> u32 {
    open.capabilities
        .iter()
        .find_map(|cap| if let Capability::FourByteAsn(n) = cap { Some(*n) } else { None })
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
        out.push(FsmOutput::StartKeepaliveTimer(keepalive_interval(negotiated)));
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

    use pathvector_types::{Asn, AsPath, Nlri, Origin};

    use super::*;
    use crate::message::{PathAttribute, UpdateMessage};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn default_config() -> FsmConfig {
        FsmConfig {
            local_as: 65001,
            local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            capabilities: vec![Capability::FourByteAsn(65001)],
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
        outputs.iter().find_map(|o| if let FsmOutput::SendMessage(m) = o { Some(m) } else { None })
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
                if let FsmOutput::SessionEstablished(i) = o { Some(i.clone()) } else { None }
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
            panic!("expected OPEN message");
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
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartHoldTimer(_))));
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartKeepaliveTimer(_))));
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
            .find_map(|o| if let FsmOutput::SessionEstablished(i) = o { Some(i.clone()) } else { None })
            .expect("SessionEstablished");

        assert!(info.peer_capabilities.iter().any(|c| matches!(c, Capability::FourByteAsn(65002))));
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
        let config = FsmConfig { local_as: 65002, peer_as: Some(65002), ..default_config() };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        let outputs = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        let info = outputs
            .iter()
            .find_map(|o| if let FsmOutput::SessionEstablished(i) = o { Some(i.clone()) } else { None })
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
            .find_map(|o| if let FsmOutput::SessionEstablished(i) = o { Some(i.clone()) } else { None })
            .expect("SessionEstablished");

        let gr = info.peer_capabilities.iter().find_map(|c| {
            if let Capability::GracefulRestart { restart_flags, restart_time, .. } = c {
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
            if let FsmOutput::StartHoldTimer(d) = o { Some(*d) } else { None }
        });
        assert_eq!(hold, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_hold_time_zero_disables_timers() {
        let config = FsmConfig { hold_time: 0, ..default_config() };
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
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartKeepaliveTimer(_))));
    }

    #[test]
    fn test_keepalive_timer_expired_in_established() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::KeepaliveTimerExpired);
        assert_eq!(fsm.state(), State::Established);
        assert!(matches!(find_send(&out), Some(BgpMessage::Keepalive)));
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartKeepaliveTimer(_))));
    }

    #[test]
    fn test_keepalive_interval_is_third_of_hold_time() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::MessageReceived(peer_open(65002, 90)));
        let ka = out.iter().find_map(|o| {
            if let FsmOutput::StartKeepaliveTimer(d) = o { Some(*d) } else { None }
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
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Update(update.clone())));
        assert_eq!(fsm.state(), State::Established);
        assert!(has_output(&out, |o| matches!(o, FsmOutput::RouteUpdate(_))));
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartHoldTimer(_))));
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
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartConnectRetryTimer(_))));
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
            peer_as: Some(131_073),
        };
        let mut fsm = Fsm::new(config);
        fsm.process(FsmInput::ManualStart);
        // Verify we send AS_TRANS in the my_as field.
        let out = fsm.process(FsmInput::TcpConnected);
        let Some(BgpMessage::Open(open)) = find_send(&out) else {
            panic!("expected OPEN");
        };
        assert_eq!(open.my_as, AS_TRANS);
        // Verify we accept a peer with 4-byte ASN via capability.
        fsm.process(FsmInput::MessageReceived(peer_open(131_073, 90)));
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        let info = out.iter().find_map(|o| {
            if let FsmOutput::SessionEstablished(i) = o { Some(i.clone()) } else { None }
        });
        assert_eq!(info.unwrap().peer_as, 131_073);
    }

    // ── No configured peer_as → accept any ───────────────────────────────────

    #[test]
    fn test_open_accepted_when_peer_as_unconfigured() {
        let config = FsmConfig { peer_as: None, ..default_config() };
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
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartConnectRetryTimer(_))));
    }

    #[test]
    fn test_tcp_connected_from_active_enters_open_sent() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart); // → Connect
        fsm.process(FsmInput::TcpFailed);   // → Active
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
    fn test_tcp_failed_in_open_sent_enters_active() {
        let mut fsm = Fsm::new(default_config());
        fsm.process(FsmInput::ManualStart);
        fsm.process(FsmInput::TcpConnected);
        let out = fsm.process(FsmInput::TcpFailed);
        assert_eq!(fsm.state(), State::Active);
        assert!(has_output(&out, |o| *o == FsmOutput::StopHoldTimer));
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartConnectRetryTimer(_))));
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
        assert!(!has_output(&out, |o| matches!(o, FsmOutput::SessionEstablished(_))));
    }

    #[test]
    fn test_notification_in_open_confirm_terminates() {
        let mut fsm = enter_open_confirm();
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Notification(
            NotificationMessage { error: NotificationError::HoldTimerExpired, data: vec![] },
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
    fn test_keepalive_message_in_established_resets_hold_timer() {
        let (mut fsm, _) = establish(default_config());
        let out = fsm.process(FsmInput::MessageReceived(BgpMessage::Keepalive));
        assert_eq!(fsm.state(), State::Established);
        assert!(has_output(&out, |o| matches!(o, FsmOutput::StartHoldTimer(_))));
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
        let config = FsmConfig { hold_time: 0, ..default_config() };
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
}
