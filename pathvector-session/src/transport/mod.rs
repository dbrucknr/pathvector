//! BGP TCP transport.
//!
//! Wires the [`crate::framing::BgpCodec`] and [`crate::fsm::Fsm`] together
//! over a real TCP connection. Call [`spawn`] to start a session task and
//! interact with it via the returned [`SpawnedSessionHandle`], which
//! implements the [`SessionHandle`] trait.

#[cfg(test)]
mod prop_tests;

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::framing::{BgpCodec, FramingError};
use crate::fsm::{Fsm, FsmConfig, FsmInput, FsmOutput, SessionInfo};
use crate::message::{
    BgpMessage, Capability, CodecError, MalformedUpdate, MpUnreachNlri, MsgHeaderError,
    NotificationError, NotificationMessage, OpenMessage, PathAttribute, UpdateMessage,
    UpdateMsgError,
};

/// How long to wait for a staged, not-yet-validated second (collision
/// candidate) connection to send its OPEN before giving up on it and
/// leaving the existing connection undisturbed.
///
/// RFC 4271 §6.8 doesn't specify a value for this — it's a project-level
/// resource-exhaustion guard, not a protocol requirement. Mirrors the FSM's
/// own `OPEN_HOLD_TIMER` (240s) for symmetry: this is the same "how long do
/// we wait for a peer's OPEN" question, just applied to a second,
/// unconfirmed connection instead of the primary one.
const COLLISION_CANDIDATE_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

/// Which side initiated a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionOrigin {
    Outbound,
    Inbound,
}

/// The local/peer IP addresses and initiator of one TCP connection, used to
/// test RFC 4271 §6.8's actual collision definition.
///
/// RFC 4271 §6.8 (quoted verbatim): "If the source IP address used by one
/// of these connections is the same as the destination IP address used by
/// the other, and the destination IP address used by the first connection
/// is the same as the source IP address used by the other, connection
/// collision has occurred." Deliberately IP-address-only, no ports: BGP's
/// own asymmetry (one side always dials the peer's listening port 179; the
/// other's local port is an OS-assigned ephemeral one) means a port-inclusive
/// comparison would essentially never match a genuine collision.
///
/// Translating "source"/"destination" to what `TcpStream::local_addr()` /
/// `peer_addr()` actually report takes care: those two calls always report
/// "my end" / "their end" symmetrically, regardless of which side dialed —
/// they are *not* source/destination in the RFC's packet-direction sense.
/// For an outbound connection, local = source and peer = destination. For
/// an inbound (accepted) one, local = destination and peer = source (the
/// direction is reversed, precisely because the socket API doesn't care who
/// initiated). Substituting that mapping into the RFC's own check — one
/// outbound connection and one inbound connection — reduces to: **the same**
/// local IP, **the same** peer IP, and opposite `origin`. All three are
/// necessary:
/// - Same local/peer alone (ignoring origin) also matches two *inbound*
///   connections from the same peer, which is not a collision under the
///   RFC's definition (no connection we dialed is involved at all).
/// - Opposite origin alone (ignoring endpoints) also matches a multihomed
///   local speaker's outbound dial from address A colliding with an
///   unrelated inbound connection that happens to land on a *different*
///   local address C — same peer, but not a reversed pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionIdentity {
    local: IpAddr,
    peer: IpAddr,
    origin: ConnectionOrigin,
}

impl ConnectionIdentity {
    fn is_reversed_pair_with(self, other: ConnectionIdentity) -> bool {
        self.local == other.local && self.peer == other.peer && self.origin != other.origin
    }
}

/// Captures a `TcpStream`'s local/peer IP addresses and pairs them with
/// `origin`. `None` if either address lookup fails (should not happen for a
/// connected socket, but this is used purely for the RFC 4271 §6.8 collision
/// check, not correctness-load-bearing elsewhere — treat a lookup failure
/// the same as "identity unknown," which conservatively fails the
/// reversed-pair check).
fn connection_identity(stream: &TcpStream, origin: ConnectionOrigin) -> Option<ConnectionIdentity> {
    Some(ConnectionIdentity {
        local: stream.local_addr().ok()?.ip(),
        peer: stream.peer_addr().ok()?.ip(),
        origin,
    })
}

/// A second incoming connection staged while resolving a potential RFC
/// 4271 §6.8 collision or RFC 4724 §4.2 GR override.
///
/// `open` is `None` until the candidate has sent (and had validated) its
/// own OPEN message. Once `Some`, the candidate is no longer read from —
/// it's held pending a decision, which for an `OpenSent` existing
/// connection may not be possible yet (see `try_resolve_pending_candidate`):
/// RFC 4271 §6.8's tiebreak only applies once the existing connection's own
/// peer BGP Identifier is known, and examining an `OpenSent` connection at
/// all is only sanctioned "if [the implementation] knows the BGP Identifier
/// of the peer by means outside of the protocol" — which this
/// implementation doesn't have, so it must wait for the primary's own OPEN
/// (or for the primary to fail) rather than guess.
struct CollisionCandidate<T> {
    transport: T,
    identity: ConnectionIdentity,
    open: Option<OpenMessage>,
}

// ── Transport trait ───────────────────────────────────────────────────────────

/// Abstraction over the BGP message I/O layer.
///
/// The only two operations the session event loop needs once a connection
/// exists are sending and receiving complete BGP messages. Implementations
/// supply the framing and underlying I/O; the session loop owns all FSM
/// state and timer management.
///
/// Both associated futures must be [`Send`] so the session task can be
/// spawned on a multi-threaded Tokio runtime.
pub trait BgpTransport: Send + 'static {
    /// Write one BGP message to the peer. Returns an error if the underlying
    /// connection is broken.
    fn send(&mut self, msg: BgpMessage) -> impl Future<Output = io::Result<()>> + Send + '_;
    /// Read the next decoded BGP message from the peer. Returns `None` when
    /// the connection has closed cleanly.
    fn recv(
        &mut self,
    ) -> impl Future<Output = Option<Result<BgpMessage, FramingError>>> + Send + '_;
    /// Raise (or lower) the message size limit after Extended Message capability
    /// (RFC 8654) is negotiated. Default implementation is a no-op.
    fn set_extended_message(&mut self, _enabled: bool) {}
}

// ── Production transport impl ─────────────────────────────────────────────────

struct FramedBgpTransport {
    reader: FramedRead<OwnedReadHalf, BgpCodec>,
    writer: FramedWrite<OwnedWriteHalf, BgpCodec>,
}

impl FramedBgpTransport {
    fn from_stream(stream: TcpStream) -> Self {
        let (r, w) = stream.into_split();
        Self {
            reader: FramedRead::new(r, BgpCodec::new()),
            writer: FramedWrite::new(w, BgpCodec::new()),
        }
    }
}

impl BgpTransport for FramedBgpTransport {
    async fn send(&mut self, msg: BgpMessage) -> io::Result<()> {
        self.writer.send(msg).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Option<Result<BgpMessage, FramingError>> {
        self.reader.next().await
    }

    fn set_extended_message(&mut self, enabled: bool) {
        self.reader.decoder_mut().set_extended_message(enabled);
    }
}

// ── SessionHandle trait ───────────────────────────────────────────────────────

/// Caller-facing interface for controlling a running BGP session.
///
/// The trait abstracts over both the real TCP-backed session ([`SpawnedSessionHandle`]
/// returned by [`spawn`]) and test doubles so that the daemon event loop can be
/// driven in unit tests without opening real TCP connections.
///
/// All methods mirror those on [`SpawnedSessionHandle`]; see the struct-level
/// docs there for full semantics.
pub trait SessionHandle: Send + 'static {
    /// Signal the session to begin its TCP connect / FSM start sequence.
    fn start(&self) -> impl Future<Output = ()> + Send + '_;

    /// Receive the next [`SessionEvent`] from the session.
    ///
    /// Returns `None` when the session task has exited and no further events
    /// will arrive.
    fn next_event(&mut self) -> impl Future<Output = Option<SessionEvent>> + Send + '_;

    /// Clone the outbound UPDATE sender for this session.
    fn update_sender(&self) -> mpsc::Sender<UpdateMessage>;

    /// Clone the stop-command sender so the event loop can close a session
    /// whose outbound UPDATE channel overflowed.
    fn stop_sender(&self) -> mpsc::Sender<SessionCommand>;

    /// Clone the command sender for delivering an accepted inbound TCP
    /// connection to this session (RFC 4271 §6.8 collision detection).
    fn incoming_sender(&self) -> mpsc::Sender<SessionCommand>;

    /// Send a ROUTE-REFRESH request to the peer for the given address family
    /// (RFC 2918). The peer will re-advertise all routes for that AFI/SAFI.
    ///
    /// Silently ignored if the session is not currently established or if the
    /// command channel is full.
    fn send_route_refresh(
        &self,
        rr: crate::message::RouteRefreshMessage,
    ) -> impl Future<Output = ()> + Send + '_;

    /// Push a fresh capability set to be used in the next OPEN message.
    ///
    /// Should be called immediately after a session terminates so the next
    /// reconnect attempt sends the updated capabilities. Has no effect if the
    /// session is currently established (the OPEN has already been sent).
    fn set_capabilities(
        &self,
        caps: Vec<crate::message::Capability>,
    ) -> impl Future<Output = ()> + Send + '_;
}

// ── Public API ────────────────────────────────────────────────────────────────

/// RFC 4271 §8.1 recommended default `ConnectRetry` interval.
pub const DEFAULT_CONNECT_RETRY_TIME: std::time::Duration = std::time::Duration::from_secs(120);

/// Configuration for a BGP session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub local_as: u32,
    pub local_bgp_id: Ipv4Addr,
    /// Proposed hold time in seconds (`0` to disable; otherwise ≥ 3).
    pub hold_time: u16,
    /// RFC 4271 §8.1 `ConnectRetry` timer interval.  Use
    /// [`DEFAULT_CONNECT_RETRY_TIME`] for the RFC-recommended 120 s default.
    /// Set lower in tests or latency-sensitive deployments.
    pub connect_retry_time: std::time::Duration,
    /// Capabilities advertised in the OPEN message.
    pub capabilities: Vec<Capability>,
    /// Capabilities the peer MUST advertise. If absent, the session is rejected
    /// with NOTIFICATION code 2 subcode 7 (RFC 5492). Empty by default.
    pub required_capabilities: Vec<Capability>,
    /// Expected peer AS. `None` accepts any AS.
    pub peer_as: Option<u32>,
    /// Address (IP + port) of the remote BGP peer.
    pub peer_addr: SocketAddr,
    /// RFC 2385 TCP MD5 authentication key for this peer. When set, the kernel
    /// signs every TCP segment with HMAC-MD5 keyed by this value. The peer must
    /// be configured with the same key or the session will not establish. Max 80
    /// bytes (Linux kernel limit). `None` disables MD5 authentication.
    pub md5_password: Option<String>,
}

/// Commands sent to a running session via [`SessionHandle`].
#[derive(Debug)]
pub enum SessionCommand {
    /// Begin the TCP connect / FSM start sequence.
    Start,
    /// Send CEASE NOTIFICATION and drop the connection.
    Stop,
    /// Send a specific NOTIFICATION (e.g. UPDATE Message Error) then tear down.
    ///
    /// Unlike `Stop` (which always sends CEASE), this lets the daemon signal
    /// a protocol-level error back to the peer before closing the session.
    /// Used for RFC 4271 §6.3 mandatory attribute violations.
    ///
    /// The `data` field carries the RFC-mandated diagnostic payload (e.g. the
    /// type code of the missing attribute for `MissingWellKnownAttribute`).
    Notification(crate::message::NotificationMessage),
    /// An inbound TCP connection from this peer was accepted by the daemon's
    /// BGP listener.  The session applies RFC 4271 §6.8 collision detection
    /// and either adopts the incoming connection or discards it.
    IncomingConnection(TcpStream),
    /// Send a ROUTE-REFRESH message to the peer for the given AFI/SAFI (RFC 2918).
    ///
    /// Instructs the peer to re-advertise all routes for the address family
    /// without resetting the session. Silently dropped if the session is not in
    /// `Established` state or if no transport is available.
    RouteRefresh(crate::message::RouteRefreshMessage),
    /// Replace the local capability set used in the next OPEN message.
    ///
    /// This must be sent before the session reconnects (i.e. before the
    /// `ConnectRetry` timer fires). The primary use-case is expiring the RFC 4724
    /// Restart State (R) bit after the graceful-restart window closes: the
    /// daemon sends `SetCapabilities` when it handles `SessionEvent::Terminated`
    /// so the next OPEN reflects the current restart state.
    ///
    /// Has no effect if the session is already in `Established` state.
    SetCapabilities(Vec<crate::message::Capability>),
}

/// Why a BGP session was torn down.
///
/// Used by the daemon to decide whether to retain stale routes from the peer
/// during the peer's Graceful Restart window (RFC 4724 §4.2, RFC 8538).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    /// TCP failure or hold-timer expiry — no NOTIFICATION was received from
    /// the peer before the session dropped.  RFC 4724 §4.2: the helper MAY
    /// retain stale routes from a GR-capable peer for up to `restart_time`.
    Unclean,
    /// The peer sent a NOTIFICATION.
    ///
    /// RFC 8538: when both sides have negotiated the N-bit in their
    /// `GracefulRestart` capability, the daemon MUST still retain stale routes
    /// unless the notification is `CEASE`/`HardReset` (subcode 9).  The daemon
    /// inspects the carried message to make that determination.
    Notification(crate::message::NotificationMessage),
    /// The session was torn down by the local operator (`ManualStop` or we sent
    /// a NOTIFICATION outbound).  Always flushes routes immediately.
    OperatorStop,
}

/// Events emitted by a session to its caller.
#[derive(Debug)]
pub enum SessionEvent {
    /// The session reached Established. Contains negotiated parameters.
    Established(SessionInfo),
    /// The session was torn down (after previously being Established).
    Terminated(TerminationReason),
    /// An UPDATE message was received; forward to the RIB layer.
    RouteUpdate(UpdateMessage),
}

/// Caller-facing handle returned by [`spawn`].
///
/// Implements [`SessionHandle`]. The concrete type is an implementation detail;
/// callers that need to be generic over session implementations should use the
/// [`SessionHandle`] trait bound instead.
pub struct SpawnedSessionHandle {
    cmd_tx: mpsc::Sender<SessionCommand>,
    event_rx: mpsc::Receiver<SessionEvent>,
    update_tx: mpsc::Sender<UpdateMessage>,
}

impl SpawnedSessionHandle {
    /// Send a [`SessionCommand::Stop`] to the session.
    ///
    /// Unlike [`SessionHandle::stop_sender`], this consumes the handle and
    /// waits for the send to complete — use it for direct, one-shot teardown.
    pub async fn stop(&self) {
        let _ = self.cmd_tx.send(SessionCommand::Stop).await;
    }
}

impl SessionHandle for SpawnedSessionHandle {
    async fn start(&self) {
        let _ = self.cmd_tx.send(SessionCommand::Start).await;
    }

    async fn next_event(&mut self) -> Option<SessionEvent> {
        self.event_rx.recv().await
    }

    /// Returns a cloneable sender for queuing outbound UPDATE messages to this
    /// session.
    ///
    /// Messages sent here are written to the TCP connection when the session is
    /// in the Established state. If the session is not connected, the messages
    /// are discarded. The channel has capacity 256; senders should treat a full
    /// channel as a signal to stop the session (see [`SessionHandle::stop_sender`]).
    fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
        self.update_tx.clone()
    }

    /// Returns a sender that can be used to stop the session from outside the
    /// session task.
    ///
    /// Sending [`SessionCommand::Stop`] causes the session to send a CEASE
    /// NOTIFICATION, close the TCP connection, and reset the FSM to Idle.
    /// Use this when the outbound UPDATE channel overflows: BGP has no
    /// partial-update recovery mechanism, so the only way to restore a
    /// consistent peer view is to close the session and let it re-establish
    /// (which triggers a full-table dump from a clean `AdjRibOut`).
    fn stop_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.cmd_tx.clone()
    }

    fn incoming_sender(&self) -> mpsc::Sender<SessionCommand> {
        self.cmd_tx.clone()
    }

    async fn send_route_refresh(&self, rr: crate::message::RouteRefreshMessage) {
        let _ = self.cmd_tx.send(SessionCommand::RouteRefresh(rr)).await;
    }

    async fn set_capabilities(&self, caps: Vec<crate::message::Capability>) {
        let _ = self
            .cmd_tx
            .send(SessionCommand::SetCapabilities(caps))
            .await;
    }
}

// ── TCP MD5SIG helpers (RFC 2385) ─────────────────────────────────────────────

/// Set the `TCP_MD5SIG` socket option on `fd` for the given peer IP address.
///
/// Re-exported from [`pathvector_sys`], where all unsafe OS-level code lives.
/// This crate and all other pathvector crates call this safe function without
/// writing any `unsafe` themselves.
pub use pathvector_sys::apply_tcp_md5sig;

/// Spawn a BGP session task and return a handle to control it.
///
/// The session starts in `Idle`. Call [`SessionHandle::start`] to initiate the
/// TCP connection.
#[must_use]
pub fn spawn(config: SessionConfig) -> SpawnedSessionHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(64);
    let (update_tx, update_rx) = mpsc::channel(256);

    let fsm_config = FsmConfig {
        local_as: config.local_as,
        local_bgp_id: config.local_bgp_id,
        hold_time: config.hold_time,
        capabilities: config.capabilities.clone(),
        required_capabilities: config.required_capabilities.clone(),
        peer_as: config.peer_as,
    };

    let session: Session<FramedBgpTransport> = Session {
        config,
        fsm: Fsm::new(fsm_config),
        cmd_rx,
        event_tx,
        hold_deadline: None,
        keepalive_deadline: None,
        retry_deadline: None,
        transport: None,
        pending_transport: None,
        pending_input: None,
        connect_task: None,
        connect_factory: Some(Box::new(FramedBgpTransport::from_stream)),
        local_addr: None,
        transport_identity: None,
        pending_collision_candidate: None,
        pending_collision_deadline: None,
        collision_candidate_open_timeout: COLLISION_CANDIDATE_OPEN_TIMEOUT,
        update_rx,
        termination_reason: TerminationReason::Unclean,
    };

    tokio::spawn(session.run());
    SpawnedSessionHandle {
        cmd_tx,
        event_rx,
        update_tx,
    }
}

/// Test-only variant of [`spawn`] that overrides
/// `collision_candidate_open_timeout`, so collision-candidate-deadline tests
/// can use a short, real (unpaused) wall-clock wait instead of
/// `tokio::time::pause`, which races its own auto-advance-when-idle
/// behavior against this module's real-TCP collision tests badly enough to
/// deadlock outright (not just flake) rather than actually simulate elapsed
/// time correctly alongside real socket I/O.
#[cfg(test)]
fn spawn_with_collision_timeout(
    config: SessionConfig,
    collision_candidate_open_timeout: std::time::Duration,
) -> SpawnedSessionHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(64);
    let (update_tx, update_rx) = mpsc::channel(256);

    let fsm_config = FsmConfig {
        local_as: config.local_as,
        local_bgp_id: config.local_bgp_id,
        hold_time: config.hold_time,
        capabilities: config.capabilities.clone(),
        required_capabilities: config.required_capabilities.clone(),
        peer_as: config.peer_as,
    };

    let session: Session<FramedBgpTransport> = Session {
        config,
        fsm: Fsm::new(fsm_config),
        cmd_rx,
        event_tx,
        hold_deadline: None,
        keepalive_deadline: None,
        retry_deadline: None,
        transport: None,
        pending_transport: None,
        pending_input: None,
        connect_task: None,
        connect_factory: Some(Box::new(FramedBgpTransport::from_stream)),
        local_addr: None,
        transport_identity: None,
        pending_collision_candidate: None,
        pending_collision_deadline: None,
        collision_candidate_open_timeout,
        update_rx,
        termination_reason: TerminationReason::Unclean,
    };

    tokio::spawn(session.run());
    SpawnedSessionHandle {
        cmd_tx,
        event_rx,
        update_tx,
    }
}

/// Spawn a BGP session with a pre-built transport, bypassing TCP connection
/// establishment.
///
/// The injected transport is activated when the FSM first emits
/// [`FsmOutput::InitiateTcpConnect`] — i.e., immediately after
/// [`SessionHandle::start`] is called. The session then behaves as though TCP
/// connected instantly: the FSM receives `TcpConnected` and proceeds through
/// the normal OPEN/KEEPALIVE handshake via the injected transport.
///
/// Use this in tests that need a controllable transport without binding real
/// TCP sockets, or in production integrations that supply their own I/O layer.
pub fn spawn_with<T: BgpTransport>(config: SessionConfig, transport: T) -> SpawnedSessionHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(64);
    let (update_tx, update_rx) = mpsc::channel(256);

    let fsm_config = FsmConfig {
        local_as: config.local_as,
        local_bgp_id: config.local_bgp_id,
        hold_time: config.hold_time,
        capabilities: config.capabilities.clone(),
        required_capabilities: config.required_capabilities.clone(),
        peer_as: config.peer_as,
    };

    let session: Session<T> = Session {
        config,
        fsm: Fsm::new(fsm_config),
        cmd_rx,
        event_tx,
        hold_deadline: None,
        keepalive_deadline: None,
        retry_deadline: None,
        transport: None,
        pending_transport: Some(transport),
        pending_input: None,
        connect_task: None,
        connect_factory: None,
        local_addr: None,
        transport_identity: None,
        pending_collision_candidate: None,
        pending_collision_deadline: None,
        collision_candidate_open_timeout: COLLISION_CANDIDATE_OPEN_TIMEOUT,
        update_rx,
        termination_reason: TerminationReason::Unclean,
    };

    tokio::spawn(session.run());
    SpawnedSessionHandle {
        cmd_tx,
        event_rx,
        update_tx,
    }
}

// ── Internal session worker ───────────────────────────────────────────────────

struct Session<T: BgpTransport> {
    config: SessionConfig,
    fsm: Fsm,
    cmd_rx: mpsc::Receiver<SessionCommand>,
    event_tx: mpsc::Sender<SessionEvent>,

    // Timer deadlines — None means the timer is not running.
    hold_deadline: Option<Instant>,
    keepalive_deadline: Option<Instant>,
    retry_deadline: Option<Instant>,

    // Active transport — present when connected, None otherwise.
    transport: Option<T>,
    // Transport waiting to be activated on the first InitiateTcpConnect output.
    // Used by spawn_with to inject a pre-built transport without real TCP.
    pending_transport: Option<T>,
    // Immediate FSM input to return on the next wait_for_input call.
    // Set when pending_transport is activated so the FSM receives TcpConnected
    // without going through the async connect-task path.
    pending_input: Option<FsmInput>,
    // Pending outbound TCP connect (production path only).
    connect_task: Option<JoinHandle<io::Result<TcpStream>>>,
    // Constructs a T from a freshly connected TcpStream. None in injected-transport
    // (test) mode — any reconnect attempt is treated as TcpFailed instead.
    connect_factory: Option<Box<dyn Fn(TcpStream) -> T + Send>>,
    // Local TCP address captured at connect time; forwarded in SessionEstablished
    // so the daemon can use it as the eBGP NEXT_HOP (RFC 4271 §5.1.3). Kept as
    // the full IpAddr (not narrowed to Ipv4Addr) so a v6-transport session's
    // local address isn't silently discarded -- the daemon decides how to use
    // it per address family.
    local_addr: Option<IpAddr>,
    // The local/peer IP addresses and initiator of `self.transport`'s TCP
    // connection. `None` when `self.transport` is `None`. See
    // `ConnectionIdentity`.
    transport_identity: Option<ConnectionIdentity>,
    // A second incoming connection staged while resolving a potential RFC
    // 4271 §6.8 collision or RFC 4724 §4.2 GR override. `None` unless a
    // genuine second connection is currently being staged or held pending
    // the primary's own identity; see `CollisionCandidate`,
    // `handle_collision_candidate_message`, and
    // `try_resolve_pending_candidate`.
    pending_collision_candidate: Option<CollisionCandidate<T>>,
    // Deadline for `pending_collision_candidate` to send its OPEN. `None`
    // once its OPEN has been read and validated (`CollisionCandidate::open`
    // is `Some`) or whenever `pending_collision_candidate` is `None`.
    pending_collision_deadline: Option<Instant>,
    // How long to wait for a staged candidate's OPEN. Always
    // `COLLISION_CANDIDATE_OPEN_TIMEOUT` in production; overridable in tests
    // (`spawn_with_collision_timeout`) so the deadline can be exercised with
    // real, unpaused wall-clock time instead of `tokio::time::pause()` —
    // pausing time races its own auto-advance-when-idle behavior against
    // this module's real-TCP collision tests, which can deadlock outright
    // (confirmed while writing this fix's tests) rather than just flake.
    collision_candidate_open_timeout: std::time::Duration,
    // Outbound UPDATE messages queued by the daemon.
    update_rx: mpsc::Receiver<UpdateMessage>,
    // Reason for the most recent (or current) session termination.  Set just
    // before calling fsm.process() so execute() can carry it in the event.
    termination_reason: TerminationReason,
}

impl<T: BgpTransport> Session<T> {
    async fn run(mut self) {
        loop {
            let input = self.wait_for_input().await;
            // Track why the session is terminating so SessionEvent::Terminated
            // carries the right reason.  Only relevant when Established; the
            // FSM only emits SessionTerminated from that state.
            if self.fsm.is_established() {
                self.termination_reason = match &input {
                    // Peer sent a NOTIFICATION — carry it so the daemon can
                    // apply RFC 8538 logic (HardReset vs. non-HardReset).
                    FsmInput::MessageReceived(BgpMessage::Notification(n)) => {
                        TerminationReason::Notification(n.clone())
                    }
                    // We initiated the teardown; always flush immediately.
                    // (ProtocolErrorNotificationToSend also gets a clean
                    // reason — it's a locally *detected* error, not an
                    // ambiguous peer-side failure — but unlike ManualStop/
                    // NotificationToSend it additionally schedules a
                    // reconnect, since the peer is still configured.)
                    FsmInput::ManualStop
                    | FsmInput::NotificationToSend(_)
                    | FsmInput::ProtocolErrorNotificationToSend(_) => {
                        TerminationReason::OperatorStop
                    }
                    _ => TerminationReason::Unclean,
                };
            }
            let outputs = self.fsm.process(input);
            if !self.execute(outputs).await {
                // A TCP send failed; feed TcpFailed back into the FSM.
                // Reason stays Unclean — we never received a Notification.
                let recovery = self.fsm.process(FsmInput::TcpFailed);
                self.execute(recovery).await;
            }
            // Cheap no-op unless a collision candidate is both staged and
            // already holding a validated OPEN (see `CollisionCandidate`).
            // Whatever `input` just did to `self.fsm`'s state — reaching
            // OpenConfirm from OpenSent (learning the primary's own peer
            // BGP Identifier for the first time) or dying entirely — may be
            // exactly what a deferred candidate decision was waiting on.
            self.try_resolve_pending_candidate().await;
        }
    }

    /// Block until the next [`FsmInput`] arrives from any source.
    ///
    /// Outbound UPDATEs queued via [`SessionHandle::update_sender`] are
    /// forwarded to the transport inline; they do not produce an `FsmInput`
    /// and the loop continues until a real FSM event arrives. If the write
    /// fails, `TcpFailed` is returned so the FSM can recover.
    async fn wait_for_input(&mut self) -> FsmInput {
        // Return any immediate follow-up input before awaiting new events.
        // This fires TcpConnected right after pending_transport is activated
        // in execute(), bypassing the async connect-task path.
        if let Some(input) = self.pending_input.take() {
            return input;
        }

        loop {
            let hold = deadline_fut(self.hold_deadline);
            let keepalive = deadline_fut(self.keepalive_deadline);
            let retry = deadline_fut(self.retry_deadline);
            let collision_deadline = deadline_fut(self.pending_collision_deadline);

            tokio::select! {
                biased;

                cmd = self.cmd_rx.recv() => match cmd {
                    Some(SessionCommand::Start) => return FsmInput::ManualStart,
                    // None = handle dropped → treat as operator stop.
                    Some(SessionCommand::Stop) | None => return FsmInput::ManualStop,
                    Some(SessionCommand::Notification(msg)) => {
                        return FsmInput::NotificationToSend(msg);
                    }
                    Some(SessionCommand::IncomingConnection(stream)) => {
                        if let Some(input) = self.handle_incoming_connection(stream) {
                            return input;
                        }
                        // Won the collision: incoming rejected, outbound continues.
                    }
                    Some(SessionCommand::RouteRefresh(rr)) => {
                        if let Some(t) = &mut self.transport
                            && t.send(BgpMessage::RouteRefresh(rr)).await.is_err()
                        {
                            self.drop_connection();
                            return FsmInput::TcpFailed;
                        }
                        // No FSM transition; loop continues.
                    }
                    Some(SessionCommand::SetCapabilities(caps)) => {
                        // Update the capability set used in the next OPEN message.
                        // Has no effect if we are already Established — the OPEN
                        // for the current session has already been sent.
                        if !self.fsm.is_established() {
                            self.fsm.set_capabilities(caps);
                        }
                        // No FSM transition; loop continues.
                    }
                },

                result = recv_connect(&mut self.connect_task) => {
                    self.connect_task = None;
                    return match result {
                        Ok(stream) => {
                            self.local_addr = stream.local_addr().ok().map(|a| a.ip());
                            self.transport_identity =
                                connection_identity(&stream, ConnectionOrigin::Outbound);
                            // connect_task is only spawned when connect_factory is Some.
                            self.transport = Some(self.connect_factory.as_ref().unwrap()(stream));
                            FsmInput::TcpConnected
                        }
                        Err(_) => FsmInput::TcpFailed,
                    };
                }

                msg = recv_message(&mut self.transport) => {
                    if let Some(input) = self.handle_primary_message(msg).await {
                        return input;
                    }
                }

                // A staged collision candidate (see `handle_incoming_connection`)
                // sent its first message. Doesn't itself return an `FsmInput`
                // to this select loop — any resulting FSM transitions are
                // driven synchronously inside `handle_collision_candidate_message`
                // / `try_resolve_pending_candidate`, since adopting a candidate
                // can mean feeding the FSM two follow-up inputs in sequence
                // (TcpConnected, then the candidate's own OPEN), which the
                // single-slot `pending_input` bypass can't queue.
                msg = recv_candidate_message(&mut self.pending_collision_candidate) => {
                    self.handle_collision_candidate_message(msg).await;
                }

                () = collision_deadline => {
                    tracing::debug!(
                        peer = %self.config.peer_addr,
                        "collision candidate timed out waiting for its OPEN; dropping it"
                    );
                    self.pending_collision_candidate = None;
                    self.pending_collision_deadline = None;
                }

                () = hold => {
                    self.hold_deadline = None;
                    return FsmInput::HoldTimerExpired;
                }

                () = keepalive => {
                    self.keepalive_deadline = None;
                    return FsmInput::KeepaliveTimerExpired;
                }

                () = retry => {
                    self.retry_deadline = None;
                    return FsmInput::ConnectRetryTimerExpired;
                }

                // Lowest-priority arm: outbound UPDATEs from the daemon.
                // Written directly to the transport; no FSM transition needed.
                Some(update) = self.update_rx.recv() => {
                    if let Some(t) = &mut self.transport
                        && t.send(BgpMessage::Update(update)).await.is_err()
                    {
                        self.drop_connection();
                        return FsmInput::TcpFailed;
                    }
                    // Not yet Established, or send succeeded — loop.
                }
            }
        }
    }

    /// RFC 4271 §6.8 connection collision detection / RFC 4724 §4.2 GR
    /// override — entry point.
    ///
    /// Called when the daemon's listener accepts an inbound TCP connection
    /// from this peer. When there's no existing connection to protect
    /// (`Idle`/`Connect`/`Active`), adopts it immediately. When there IS one
    /// (`OpenSent`/`OpenConfirm`, or `Established` with Graceful Restart
    /// negotiated), the incoming connection is *staged*, not decided on the
    /// spot: RFC 4271 §6.8's own procedure operates on "the BGP Identifier
    /// of the remote system as specified in the [new] OPEN message," which
    /// isn't known yet at TCP-accept time. See `resolve_collision_candidate`
    /// for the actual decision, made once that OPEN is read.
    ///
    /// Returns `Some(FsmInput)` only for the immediate-adopt case; the
    /// staged case always returns `None` here (the eventual decision surfaces
    /// asynchronously through `wait_for_input`'s `pending_collision_candidate`
    /// arm).
    fn handle_incoming_connection(&mut self, stream: TcpStream) -> Option<FsmInput> {
        use crate::fsm::State;

        // Only one staged candidate at a time. A further incoming connection
        // arriving while one is already being validated is rejected outright
        // rather than juggling multiple unconfirmed candidates.
        if self.pending_collision_candidate.is_some() {
            tracing::debug!(
                peer = %self.config.peer_addr,
                "rejecting incoming connection: a collision candidate is already staged"
            );
            drop(stream);
            return None;
        }

        match self.fsm.state() {
            // No active outbound attempt — accept the incoming connection directly.
            State::Idle | State::Connect | State::Active => {
                self.local_addr = stream.local_addr().ok().map(|a| a.ip());
                self.transport_identity = connection_identity(&stream, ConnectionOrigin::Inbound);
                if let Some(factory) = &self.connect_factory {
                    self.transport = Some(factory(stream));
                }
                Some(FsmInput::TcpConnected)
            }

            // A connection already exists that this candidate might collide
            // with (OpenSent/OpenConfirm) or might be a GR reconnect for
            // (Established). Stage it — wrap it via the same connect_factory
            // used for a direct accept, but hold it separately from
            // `self.transport` until its OPEN is read and validated.
            State::OpenSent | State::OpenConfirm => {
                self.stage_collision_candidate(stream);
                None
            }
            State::Established if self.fsm.peer_has_graceful_restart() => {
                self.stage_collision_candidate(stream);
                None
            }

            // Already established, no Graceful Restart — reject the incoming
            // connection outright. RFC 4271 §6.8: "a connection collision
            // with an existing BGP connection that is in the Established
            // state causes closing of the newly created connection" — no
            // BGP-Identifier comparison applies here at all, so there's
            // nothing to stage or read.
            State::Established => {
                tracing::warn!(
                    peer = %self.config.peer_addr,
                    "BGP collision: already established, rejecting duplicate incoming connection"
                );
                drop(stream);
                None
            }
        }
    }

    /// Wraps `stream` via `connect_factory` and stores it as
    /// `pending_collision_candidate`, starting the OPEN-wait deadline. A
    /// no-op (drops `stream`) if no `connect_factory` is configured
    /// (injected-transport/test mode without one set up), or if the
    /// identity can't be determined (conservatively refuse to stage
    /// something we can't ever prove is a genuine reversed pair). Always
    /// `Inbound` — every candidate arrives via `SessionCommand::IncomingConnection`.
    fn stage_collision_candidate(&mut self, stream: TcpStream) {
        let Some(identity) = connection_identity(&stream, ConnectionOrigin::Inbound) else {
            return;
        };
        let Some(factory) = &self.connect_factory else {
            return;
        };
        self.pending_collision_candidate = Some(CollisionCandidate {
            transport: factory(stream),
            identity,
            open: None,
        });
        self.pending_collision_deadline =
            Some(Instant::now() + self.collision_candidate_open_timeout);
    }

    /// Handles the first message read from a staged collision candidate
    /// (called from `wait_for_input`'s select loop once
    /// `pending_collision_candidate` produces one — only fires while
    /// `open` is still `None`, i.e. before the candidate has proven itself;
    /// see `recv_candidate_message`).
    ///
    /// Validates the OPEN (RFC 4271 §6.2 — version, BGP Identifier, peer
    /// AS, hold time; RFC 5492 §3 required capabilities; RFC 9234 §5.1 Role
    /// compatibility) and the reversed-pair endpoint check (RFC 4271 §6.8)
    /// immediately — both are already fully knowable and don't depend on
    /// anything the primary connection might still be waiting on. Anything
    /// other than a valid OPEN from a genuine reversed pair means the
    /// candidate is dropped here and now; the existing connection (if any)
    /// is never touched.
    ///
    /// A candidate that clears both checks isn't necessarily *decided* yet
    /// — seeing `try_resolve_pending_candidate`.
    async fn handle_collision_candidate_message(
        &mut self,
        msg: Option<Result<BgpMessage, FramingError>>,
    ) {
        use crate::fsm::State;

        let Some(mut candidate) = self.pending_collision_candidate.take() else {
            return;
        };
        self.pending_collision_deadline = None;

        let open = match msg {
            Some(Ok(BgpMessage::Open(open))) => open,
            Some(Ok(other)) => {
                tracing::debug!(
                    peer = %self.config.peer_addr,
                    message = ?other,
                    "collision candidate's first message was not an OPEN; dropping it"
                );
                drop(candidate);
                return;
            }
            Some(Err(e)) => {
                tracing::debug!(
                    peer = %self.config.peer_addr,
                    error = %e,
                    "codec error reading collision candidate's OPEN; dropping it"
                );
                drop(candidate);
                return;
            }
            None => {
                tracing::debug!(
                    peer = %self.config.peer_addr,
                    "collision candidate closed before sending an OPEN; dropping it"
                );
                drop(candidate);
                return;
            }
        };

        if let Err((error, data)) = self.fsm.validate_open(&open) {
            tracing::warn!(
                peer = %self.config.peer_addr,
                candidate_bgp_id = %open.bgp_id,
                error = ?error,
                "rejecting collision candidate: OPEN failed validation; \
                 existing connection (if any) left undisturbed"
            );
            let _ = candidate
                .transport
                .send(BgpMessage::Notification(NotificationMessage {
                    error,
                    data,
                }))
                .await;
            drop(candidate);
            return;
        }

        // RFC 4271 §6.8's own collision definition only applies to a
        // genuine reversed pair. This check doesn't depend on any
        // FSM-state-specific logic — it's already fully known — so it's
        // resolved here immediately rather than deferred, unlike the
        // BGP-Identifier tiebreak below (which needs `try_resolve_pending_candidate`
        // for the `OpenSent` case). Skipped entirely for `Idle`/`Connect`/
        // `Active` (existing already gone, nothing to reverse-pair against)
        // and `Established`+GR (not a simultaneous-dial scenario at all —
        // see `try_resolve_pending_candidate`'s doc comment).
        let needs_reversed_pair = matches!(self.fsm.state(), State::OpenSent | State::OpenConfirm);
        if needs_reversed_pair
            && !self
                .transport_identity
                .is_some_and(|e| e.is_reversed_pair_with(candidate.identity))
        {
            tracing::warn!(
                peer = %self.config.peer_addr,
                candidate_bgp_id = %open.bgp_id,
                candidate_identity = ?candidate.identity,
                existing_identity = ?self.transport_identity,
                "rejecting collision candidate: not a reversed-direction TCP \
                 pair per RFC 4271 §6.8"
            );
            drop(candidate);
            return;
        }

        candidate.open = Some(open);
        self.pending_collision_candidate = Some(candidate);
        self.try_resolve_pending_candidate().await;
    }

    /// Attempts to resolve a staged, already-validated collision candidate
    /// (`pending_collision_candidate.open.is_some()`) against the *current*
    /// primary-connection state. Called right after a candidate clears
    /// validation, and unconditionally after every `FsmInput` `run()`
    /// processes — covering both events that might newly permit a decision
    /// that couldn't be made when the candidate first validated: the
    /// primary reaching `OpenConfirm` from `OpenSent` (learning its peer's
    /// real BGP Identifier for the first time) or dying entirely. A cheap
    /// no-op whenever there's no candidate, or it hasn't validated an OPEN
    /// yet, or the primary's own state still doesn't permit a decision.
    ///
    /// RFC 4271 §6.8's collision-resolution procedure only triggers when an
    /// existing connection's peer BGP Identifier equals the *new*
    /// connection's, as carried in its own OPEN message. The pre-fix
    /// version of this code ignored that in `OpenSent` — it just always
    /// adopted, since the existing connection's ID isn't known yet — but
    /// RFC 4271 §6.8 doesn't sanction examining an `OpenSent` connection at
    /// all except "if [the implementation] knows the BGP Identifier of the
    /// peer by means outside of the protocol," which this implementation
    /// has no way to do. So rather than guessing, an `OpenSent` primary
    /// defers the decision until its own OPEN arrives (or it dies).
    ///
    /// Also applies the identical identity gap fix to the RFC 4724 §4.2 GR
    /// override, which previously had no identity check at all — any second
    /// incoming connection while Established-with-GR unconditionally
    /// displaced the live session.
    async fn try_resolve_pending_candidate(&mut self) {
        use crate::fsm::State;

        let Some(candidate) = &self.pending_collision_candidate else {
            return;
        };
        let Some(open) = candidate.open.clone() else {
            return;
        };

        let adopt = match self.fsm.state() {
            // Primary's own identity still unknown — wait for its own OPEN
            // (or for it to die, landing in Idle/Connect/Active below) to
            // resolve this later. The reversed-pair check already ran (see
            // `handle_collision_candidate_message`); only identity remains
            // pending.
            State::OpenSent => return,

            // The existing connection's peer ID IS known — RFC 4271 §6.8
            // only applies when it equals the candidate's. If it doesn't,
            // this isn't a genuine collision with the existing connection;
            // reject the candidate rather than letting an unexpected
            // identity influence it.
            State::OpenConfirm => match self.fsm.peer_bgp_id() {
                Some(existing_id) if existing_id == open.bgp_id => {
                    self.config.local_bgp_id < open.bgp_id
                }
                Some(_) => false,
                None => return, // Shouldn't happen in OpenConfirm; wait rather than guess.
            },

            // RFC 4724 §4.2 override: only a reconnection *by the same peer*
            // may silently displace the live session. Not gated on the
            // reversed-pair check — GR reconnection ("old TCP died, same
            // peer dialed in again") isn't RFC 4271 §6.8's simultaneous-dial
            // scenario and has no such requirement.
            State::Established if self.fsm.peer_has_graceful_restart() => {
                self.fsm.peer_bgp_id() == Some(open.bgp_id)
            }

            // The connection this candidate was staged against (or was
            // waiting on, if deferred from OpenSent) is already gone —
            // nothing left to protect. Adopt it directly, same as a fresh
            // accepted connection.
            State::Idle | State::Connect | State::Active => true,

            // A fresh session cycle started (and possibly re-established,
            // this time without GR) since this candidate was staged. It's
            // stale context from a session that no longer exists; drop it
            // rather than risk disrupting an unrelated, healthy connection.
            State::Established => false,
        };

        let candidate = self
            .pending_collision_candidate
            .take()
            .expect("checked Some above; state() calls above don't touch this field");

        if !adopt {
            tracing::warn!(
                peer = %self.config.peer_addr,
                candidate_bgp_id = %open.bgp_id,
                fsm_state = ?self.fsm.state(),
                "rejecting collision candidate: BGP Identifier does not match \
                 the existing connection's peer (or the existing connection \
                 has moved on)"
            );
            drop(candidate);
            return;
        }

        match self.fsm.state() {
            State::OpenSent | State::OpenConfirm => {
                tracing::info!(
                    peer = %self.config.peer_addr,
                    local_bgp_id = %self.config.local_bgp_id,
                    candidate_bgp_id = %open.bgp_id,
                    "BGP collision: adopting validated incoming connection, closing existing"
                );
                let outputs = self.fsm.process(FsmInput::CollisionDetected);
                self.execute(outputs).await;
            }
            State::Established => {
                tracing::info!(
                    peer = %self.config.peer_addr,
                    "BGP collision: peer has Graceful Restart, adopting validated incoming \
                     connection over presumed-dead Established session"
                );
                // execute() reads self.termination_reason when it forwards
                // FsmOutput::SessionTerminated — set it explicitly rather than
                // relying on whatever the field last held, since this call
                // bypasses run()'s normal set-before-process step. RFC 4724
                // §4.2 treats an undetected old-connection death as the same
                // "unclean" case the daemon's GR helper-mode entry already
                // keys on (TerminationReason::Unclean).
                self.termination_reason = TerminationReason::Unclean;
                let outputs = self.fsm.process(FsmInput::CollisionDetected);
                self.execute(outputs).await;
            }
            State::Idle | State::Connect | State::Active => {
                // Nothing to tear down.
            }
        }

        self.transport = Some(candidate.transport);
        self.transport_identity = Some(candidate.identity);
        self.local_addr = Some(candidate.identity.local);
        // Drive both follow-up transitions synchronously here rather than
        // via the wait_for_input()/pending_input bypass (which only holds
        // one queued input): TcpConnected (Active/whatever-state -> OpenSent,
        // sends our OPEN), then the candidate's already-validated OPEN
        // (OpenSent -> OpenConfirm, sends our KEEPALIVE) — it was already
        // consumed reading it off the wire, so it can't be read again.
        let outputs = self.fsm.process(FsmInput::TcpConnected);
        self.execute(outputs).await;
        let outputs = self
            .fsm
            .process(FsmInput::MessageReceived(BgpMessage::Open(open)));
        self.execute(outputs).await;
    }

    /// Execute a batch of FSM outputs. Returns `false` if a TCP send failed;
    /// the caller is responsible for feeding [`FsmInput::TcpFailed`] back to
    /// the FSM.
    async fn execute(&mut self, outputs: Vec<FsmOutput>) -> bool {
        for output in outputs {
            match output {
                FsmOutput::InitiateTcpConnect => {
                    if let Some(t) = self.pending_transport.take() {
                        // Injected-transport path: activate immediately and queue
                        // TcpConnected so the FSM advances on the next loop tick.
                        // No real TcpStream here, so no endpoints to capture —
                        // harmless, since this test/mock-only path never stages
                        // a real collision candidate to compare against.
                        self.transport = Some(t);
                        self.pending_input = Some(FsmInput::TcpConnected);
                    } else if self.connect_factory.is_some() {
                        let addr = self.config.peer_addr;
                        let password = self.config.md5_password.clone();
                        self.connect_task = Some(tokio::spawn(async move {
                            tcp_connect(addr, password.as_deref()).await
                        }));
                    } else {
                        // Injected-transport mode with no transport remaining — signal
                        // failure so the FSM can back off rather than hanging forever.
                        self.pending_input = Some(FsmInput::TcpFailed);
                    }
                }
                FsmOutput::CloseTcpConnection => {
                    self.drop_connection();
                }
                FsmOutput::SendMessage(msg) => {
                    if let Some(t) = &mut self.transport
                        && t.send(msg).await.is_err()
                    {
                        self.drop_connection();
                        return false;
                    }
                }
                FsmOutput::StartHoldTimer(d) => {
                    self.hold_deadline = Some(Instant::now() + d);
                }
                FsmOutput::StopHoldTimer => {
                    self.hold_deadline = None;
                }
                FsmOutput::StartKeepaliveTimer(d) => {
                    self.keepalive_deadline = Some(Instant::now() + d);
                }
                FsmOutput::StopKeepaliveTimer => {
                    self.keepalive_deadline = None;
                }
                FsmOutput::StartConnectRetryTimer(_) => {
                    self.retry_deadline = Some(Instant::now() + self.config.connect_retry_time);
                }
                FsmOutput::StopConnectRetryTimer => {
                    self.retry_deadline = None;
                }
                FsmOutput::SessionEstablished(mut info) => {
                    // RFC 8654: raise the codec limit if both sides negotiated
                    // Extended Message capability.
                    let extended = info
                        .peer_capabilities
                        .contains(&Capability::ExtendedMessage)
                        && self
                            .config
                            .capabilities
                            .contains(&Capability::ExtendedMessage);
                    if let Some(t) = &mut self.transport {
                        t.set_extended_message(extended);
                    }
                    info.local_addr = self.local_addr;
                    let _ = self.event_tx.send(SessionEvent::Established(info)).await;
                }
                FsmOutput::SessionTerminated => {
                    let _ = self
                        .event_tx
                        .send(SessionEvent::Terminated(self.termination_reason.clone()))
                        .await;
                }
                FsmOutput::RouteUpdate(update) => {
                    let _ = self.event_tx.send(SessionEvent::RouteUpdate(update)).await;
                }
            }
        }
        true
    }

    /// Handles one decoded (or failed-to-decode) message from the primary
    /// transport, called from `wait_for_input`'s select loop.
    async fn handle_primary_message(
        &mut self,
        msg: Option<Result<BgpMessage, FramingError>>,
    ) -> Option<FsmInput> {
        match msg {
            Some(Ok(BgpMessage::MalformedUpdate(m))) => self.handle_malformed_update(m).await,
            Some(Ok(m)) => Some(FsmInput::MessageReceived(m)),
            Some(Err(e)) => {
                tracing::warn!(peer = %self.config.peer_addr, error = %e, "codec error on received message");
                if let Some(notif) = header_error_notification(&e)
                    && let Some(t) = &mut self.transport
                {
                    let _ = t.send(BgpMessage::Notification(notif)).await;
                }
                self.drop_connection();
                Some(FsmInput::TcpFailed)
            }
            None => {
                self.drop_connection();
                Some(FsmInput::TcpFailed)
            }
        }
    }

    /// Apply RFC 7606 error policy for a malformed UPDATE.
    ///
    /// - `SessionReset` (RFC 7606 §3(g): a duplicated `MP_REACH_NLRI` or
    ///   `MP_UNREACH_NLRI`): tear down the session with a Malformed Attribute
    ///   List NOTIFICATION. Per §3(h) this is the strongest of the four
    ///   error-handling approaches and takes priority over `treat_as_withdraw`
    ///   when both are set in the same UPDATE. Returns `Some(FsmInput)` for
    ///   the caller to return from the event loop in this case — specifically
    ///   `ProtocolErrorNotificationToSend` (RFC 4271 §8.2.2 Event 28), not a
    ///   manually-sent NOTIFICATION plus `TcpFailed` and not the plain
    ///   `NotificationToSend`: this is a locally *detected* protocol error on
    ///   an ongoing, still-configured peer, so it must (a) record
    ///   `TerminationReason::OperatorStop` (immediate route flush, not
    ///   `Unclean`'s GR-retention path — we know exactly why the session
    ///   ended) and (b) still schedule an automatic reconnect, unlike a
    ///   genuine administrative/operator-initiated teardown.
    /// - `TreatAsWithdraw`: synthesise a withdrawal UPDATE for all NLRIs that
    ///   were announced in this message, then forward it as a `RouteUpdate`.
    ///   Session stays up; returns `None`.
    /// - `AttributeDiscard` (all remaining errors): forward the cleaned
    ///   UPDATE (bad attributes already removed by the decoder). Session
    ///   stays up; returns `None`.
    async fn handle_malformed_update(&mut self, m: MalformedUpdate) -> Option<FsmInput> {
        for e in &m.errors {
            tracing::warn!(
                peer = %self.config.peer_addr,
                type_code = e.type_code,
                detail = e.detail,
                policy = ?e.policy,
                "RFC 7606: malformed path attribute"
            );
        }

        if m.session_reset {
            let notif = NotificationMessage {
                error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAttributeList),
                data: vec![],
            };
            return Some(FsmInput::ProtocolErrorNotificationToSend(notif));
        }

        let update = if m.treat_as_withdraw {
            make_treat_as_withdraw(m.update)
        } else {
            m.update
        };

        let _ = self.event_tx.send(SessionEvent::RouteUpdate(update)).await;
        None
    }

    fn drop_connection(&mut self) {
        self.transport = None;
        self.transport_identity = None;
        if let Some(t) = self.connect_task.take() {
            t.abort();
        }
    }
}

/// Map an RFC 4271 §6.1 message-header framing error to the NOTIFICATION that
/// must be sent before the connection is torn down.
///
/// Returns `None` for `CodecError` variants below the header layer (malformed
/// OPEN/NOTIFICATION message bodies) — those aren't RFC 7606-eligible (that
/// policy only applies to UPDATE attribute errors) and mapping each to its
/// RFC-precise `NotificationError`/subcode is a separate follow-up (see
/// TODO.md).
fn header_error_notification(e: &FramingError) -> Option<NotificationMessage> {
    let FramingError::Codec(codec_err) = e else {
        return None;
    };
    let (error, data) = match codec_err {
        CodecError::InvalidMarker => (
            NotificationError::MessageHeader(MsgHeaderError::ConnectionNotSynchronized),
            vec![],
        ),
        CodecError::InvalidLength(len) => (
            NotificationError::MessageHeader(MsgHeaderError::BadMessageLength),
            len.to_be_bytes().to_vec(),
        ),
        CodecError::UnknownMessageType(t) => (
            NotificationError::MessageHeader(MsgHeaderError::BadMessageType),
            vec![*t],
        ),
        _ => return None,
    };
    Some(NotificationMessage { error, data })
}

/// Convert an UPDATE with treat-as-withdraw errors into a withdrawal-only UPDATE.
///
/// All announced IPv4 NLRIs are moved into `withdrawn`. Any `MP_REACH_NLRI`
/// attributes are converted to `MP_UNREACH_NLRI` so that non-IPv4 prefixes are
/// also withdrawn. All other attributes are dropped.
pub(crate) fn make_treat_as_withdraw(update: UpdateMessage) -> UpdateMessage {
    let mut withdrawn = update.withdrawn;
    withdrawn.extend(update.announced);

    // Convert any decoded MP_REACH_NLRI → MP_UNREACH_NLRI.
    let mp_unreaches: Vec<PathAttribute> = update
        .attributes
        .into_iter()
        .filter_map(|attr| {
            if let PathAttribute::MpReachNlri(mp) = attr {
                Some(PathAttribute::MpUnreachNlri(MpUnreachNlri {
                    afi_safi: mp.afi_safi,
                    prefixes: mp.prefixes,
                }))
            } else {
                None
            }
        })
        .collect();

    UpdateMessage {
        withdrawn,
        attributes: mp_unreaches,
        announced: vec![],
    }
}

// ── TCP connect helper ────────────────────────────────────────────────────────

/// Connect to `addr`, optionally setting `TCP_MD5SIG` before the handshake.
///
/// When `password` is `None` this is equivalent to `TcpStream::connect(addr)`.
/// When `password` is `Some(key)`, a raw socket is created first, the MD5 key
/// is installed via [`apply_tcp_md5sig`], and then the socket is connected.
async fn tcp_connect(addr: SocketAddr, password: Option<&str>) -> io::Result<TcpStream> {
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpSocket;

    let Some(key) = password else {
        return TcpStream::connect(addr).await;
    };

    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    apply_tcp_md5sig(socket.as_raw_fd(), addr.ip(), key).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("TCP MD5SIG setup failed for {}: {e}", addr.ip()),
        )
    })?;

    socket.connect(addr).await
}

// ── Free async helpers ────────────────────────────────────────────────────────

/// Resolves at `deadline`, or never if `None`.
async fn deadline_fut(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Resolves when the pending connect task completes, or never if `None`.
async fn recv_connect(
    task: &mut Option<JoinHandle<io::Result<TcpStream>>>,
) -> io::Result<TcpStream> {
    match task {
        Some(h) => h.await.unwrap_or_else(|e| Err(io::Error::other(e))),
        None => std::future::pending().await,
    }
}

/// Resolves with the next decoded message from the transport, or never if
/// not connected.
async fn recv_message<T: BgpTransport>(
    transport: &mut Option<T>,
) -> Option<Result<BgpMessage, FramingError>> {
    match transport {
        Some(t) => t.recv().await,
        None => std::future::pending::<Option<Result<BgpMessage, FramingError>>>().await,
    }
}

/// Resolves with the next decoded message from a staged collision
/// candidate, or never if none is currently staged.
async fn recv_candidate_message<T: BgpTransport>(
    candidate: &mut Option<CollisionCandidate<T>>,
) -> Option<Result<BgpMessage, FramingError>> {
    match candidate {
        // Only poll a candidate that hasn't validated an OPEN yet — one
        // that has is held pending a decision (see
        // `try_resolve_pending_candidate`), not read from further.
        Some(c) if c.open.is_none() => c.transport.recv().await,
        _ => std::future::pending::<Option<Result<BgpMessage, FramingError>>>().await,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use std::net::Ipv4Addr as StdIpv4Addr;

    use super::{
        BgpTransport, COLLISION_CANDIDATE_OPEN_TIMEOUT, ConnectionIdentity, ConnectionOrigin,
        DEFAULT_CONNECT_RETRY_TIME, FramedBgpTransport, SessionCommand, SessionConfig,
        SessionEvent, SessionHandle, SpawnedSessionHandle, TerminationReason, spawn, spawn_with,
        spawn_with_collision_timeout,
    };
    use crate::framing::FramingError;
    use pathvector_types::Nlri;

    use crate::message::{
        AttributeDecodeError, AttributeErrorPolicy, BgpMessage, Capability, CeaseError, CodecError,
        MalformedUpdate, MsgHeaderError, NotificationError, NotificationMessage, OpenMessage,
        OpenMsgError, PathAttribute, UpdateMessage, UpdateMsgError,
    };

    // ── MockTransport ─────────────────────────────────────────────────────────

    struct MockTransport {
        recv_rx: mpsc::UnboundedReceiver<Result<BgpMessage, FramingError>>,
        send_tx: mpsc::UnboundedSender<BgpMessage>,
        fail_send: Arc<AtomicBool>,
    }

    struct MockPeer {
        recv_tx: mpsc::UnboundedSender<Result<BgpMessage, FramingError>>,
        send_rx: mpsc::UnboundedReceiver<BgpMessage>,
        fail_send: Arc<AtomicBool>,
    }

    impl MockTransport {
        fn pair() -> (Self, MockPeer) {
            let (recv_tx, recv_rx) = mpsc::unbounded_channel();
            let (send_tx, send_rx) = mpsc::unbounded_channel();
            let fail_send = Arc::new(AtomicBool::new(false));
            (
                MockTransport {
                    recv_rx,
                    send_tx,
                    fail_send: Arc::clone(&fail_send),
                },
                MockPeer {
                    recv_tx,
                    send_rx,
                    fail_send,
                },
            )
        }
    }

    impl BgpTransport for MockTransport {
        async fn send(&mut self, msg: BgpMessage) -> io::Result<()> {
            if self.fail_send.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mock: send failed",
                ));
            }
            let _ = self.send_tx.send(msg);
            Ok(())
        }

        async fn recv(&mut self) -> Option<Result<BgpMessage, FramingError>> {
            self.recv_rx.recv().await
        }
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn test_config() -> SessionConfig {
        SessionConfig {
            local_as: 65001,
            local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            capabilities: vec![Capability::FourByteAsn(65001)],
            required_capabilities: vec![],
            peer_as: Some(65002),
            // peer_addr is unused when a transport is injected via spawn_with.
            peer_addr: "127.0.0.1:0".parse().unwrap(),
            md5_password: None,
            connect_retry_time: DEFAULT_CONNECT_RETRY_TIME,
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

    /// Drive the session through a full OPEN/KEEPALIVE handshake and wait for
    /// the `Established` event. The caller must have already called
    /// `spawn_with` and NOT yet called `start`.
    async fn drive_to_established(handle: &mut SpawnedSessionHandle, peer: &mut MockPeer) {
        handle.start().await;

        let msg = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for OPEN from session")
            .expect("mock channel closed before OPEN");
        assert!(
            matches!(msg, BgpMessage::Open(_)),
            "expected OPEN from session, got {msg:?}"
        );

        peer.recv_tx.send(Ok(peer_open())).unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for KEEPALIVE from session")
            .expect("mock channel closed before KEEPALIVE");
        assert!(
            matches!(msg, BgpMessage::Keepalive),
            "expected KEEPALIVE from session, got {msg:?}"
        );

        peer.recv_tx.send(Ok(BgpMessage::Keepalive)).unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session exited before Established");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "expected Established, got {event:?}"
        );
    }

    // ── Collision-candidate test helpers ────────────────────────────────────
    //
    // Unlike the rest of this module, the collision tests below use the
    // production `spawn()` entry point (`Session<FramedBgpTransport>`) with
    // real TCP loopback sockets on *both* the existing and candidate sides,
    // rather than `MockTransport`. This is required, not just preferred:
    // `spawn_with`'s `MockTransport` harness never sets `connect_factory`
    // (see `spawn_with`), so `stage_collision_candidate` — which needs a
    // `connect_factory` to wrap an incoming `TcpStream` into `T` — is
    // structurally unable to stage anything under it. A real socket pair is
    // the only way to exercise the staged-candidate code path at all.

    /// Spawns a real (`spawn()`-based) session whose outbound dial lands on
    /// a test-controlled `TcpListener`, drives it to `OpenConfirm` with the
    /// peer's OPEN carrying `peer_bgp_id`, and returns the handle plus a
    /// `FramedBgpTransport` for driving that "existing" peer side further.
    /// The peer's own KEEPALIVE is deliberately withheld so the session
    /// stays in `OpenConfirm`.
    async fn spawn_to_open_confirm(
        peer_bgp_id: Ipv4Addr,
    ) -> (SpawnedSessionHandle, FramedBgpTransport) {
        spawn_to_open_confirm_with_timeout(peer_bgp_id, COLLISION_CANDIDATE_OPEN_TIMEOUT).await
    }

    /// Same as `spawn_to_open_confirm`, but overrides the candidate
    /// OPEN-wait deadline — see `spawn_with_collision_timeout`.
    async fn spawn_to_open_confirm_with_timeout(
        peer_bgp_id: Ipv4Addr,
        collision_candidate_open_timeout: Duration,
    ) -> (SpawnedSessionHandle, FramedBgpTransport) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = test_config();
        config.peer_addr = listener.local_addr().unwrap();

        let handle = spawn_with_collision_timeout(config, collision_candidate_open_timeout);
        handle.start().await;

        let (stream, _) = listener.accept().await.unwrap();
        let mut peer = FramedBgpTransport::from_stream(stream);

        let sent_open = tokio::time::timeout(Duration::from_secs(1), peer.recv())
            .await
            .expect("timed out waiting for OPEN")
            .expect("closed before OPEN")
            .expect("decode error on session's OPEN");
        assert!(
            matches!(sent_open, BgpMessage::Open(_)),
            "expected OPEN from session, got {sent_open:?}"
        );

        let mut open = peer_open();
        if let BgpMessage::Open(ref mut o) = open {
            o.bgp_id = peer_bgp_id;
        }
        peer.send(open).await.unwrap();

        let ka = tokio::time::timeout(Duration::from_secs(1), peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE")
            .expect("closed before KEEPALIVE")
            .expect("decode error on session's KEEPALIVE");
        assert!(
            matches!(ka, BgpMessage::Keepalive),
            "expected KEEPALIVE (OpenConfirm entry) from session, got {ka:?}"
        );

        (handle, peer)
    }

    /// Real TCP loopback pair for injecting a "candidate" incoming
    /// connection: the first element is handed to
    /// `SessionCommand::IncomingConnection`; the second is a
    /// `FramedBgpTransport` the test uses to act as the candidate's remote
    /// peer (send its OPEN, read what the session sends back, etc).
    async fn candidate_pair() -> (TcpStream, FramedBgpTransport) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (incoming, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let (accepted_stream, _) = accepted.unwrap();
        (
            incoming.unwrap(),
            FramedBgpTransport::from_stream(accepted_stream),
        )
    }

    /// Extract the inner `UpdateMessage` from a `RouteUpdate` event.
    /// Panics with a clear message if the event is a different variant.
    fn expect_route_update(event: SessionEvent) -> UpdateMessage {
        let SessionEvent::RouteUpdate(u) = event else {
            panic!("expected RouteUpdate, got {event:?}")
        };
        u
    }

    #[test]
    #[should_panic(expected = "expected RouteUpdate")]
    fn test_expect_route_update_panics_on_wrong_variant() {
        expect_route_update(SessionEvent::Terminated(TerminationReason::Unclean));
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// When the transport rejects the very first send (the OPEN message),
    /// `execute` returns `false` and `run` feeds `TcpFailed` back to the FSM.
    /// The session transitions to Active and starts its retry timer — no events
    /// are emitted because the session was never Established.
    #[tokio::test]
    async fn test_send_failure_in_execute_triggers_tcp_failed_recovery() {
        let (mock, peer) = MockTransport::pair();
        peer.fail_send.store(true, Ordering::SeqCst);

        let mut handle = spawn_with(test_config(), mock);
        handle.start().await;

        // Let the session process: ManualStart → InitiateTcpConnect (injection)
        // → pending_input(TcpConnected) → SendMessage(OPEN) → send fails
        // → execute returns false → run feeds TcpFailed → FSM recovers.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // The session silently retries; it was never Established so no events.
        let result = tokio::time::timeout(Duration::from_millis(50), handle.next_event()).await;
        assert!(
            result.is_err(),
            "expected no events from a session that failed before Established"
        );
    }

    /// When a queued outbound UPDATE fails to write after the session is
    /// Established, the write failure in `wait_for_input`'s UPDATE arm feeds
    /// `TcpFailed` to the FSM, which tears down the session and emits
    /// `Terminated`.
    #[tokio::test]
    async fn test_outbound_update_write_failure_emits_terminated() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        // Make all subsequent sends fail and queue an outbound UPDATE.
        peer.fail_send.store(true, Ordering::SeqCst);
        let update_tx = handle.update_sender();
        update_tx
            .send(UpdateMessage {
                withdrawn: vec![],
                attributes: vec![],
                announced: vec![],
            })
            .await
            .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Terminated")
            .expect("session exited unexpectedly");
        assert!(
            matches!(event, SessionEvent::Terminated(_)),
            "expected Terminated after UPDATE write failure, got {event:?}"
        );
    }

    /// `stop_sender` returns a live `Sender` that can enqueue a `Stop` command.
    ///
    /// The clone must share the underlying channel with `handle.cmd_tx` so that
    /// a `Stop` sent through it is received by the session task.
    #[tokio::test]
    async fn test_stop_sender_can_stop_session() {
        use crate::transport::SessionCommand;

        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        // Obtain a stop sender and use it to send a Stop command.
        let stop_tx = handle.stop_sender();
        stop_tx.send(SessionCommand::Stop).await.unwrap();

        // The session should emit Terminated in response to Stop.
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for event after Stop")
            .expect("session exited without emitting an event");
        assert!(
            matches!(event, SessionEvent::Terminated(_)),
            "expected Terminated after Stop command, got {event:?}"
        );
    }

    /// RFC 7606 treat-as-withdraw: a [`MalformedUpdate`] with `treat_as_withdraw=true`
    /// must keep the session alive and emit a [`SessionEvent::RouteUpdate`] whose
    /// withdrawn set contains every announced NLRI from the original message.
    #[tokio::test]
    async fn test_rfc7606_treat_as_withdraw_keeps_session_up_and_withdraws_nlri() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        // Build a MalformedUpdate: ORIGIN was bad (treat-as-withdraw), two
        // announced prefixes.  The decoder would produce this when it encounters
        // a malformed ORIGIN attribute alongside valid NLRI in an UPDATE.
        let prefix_a: Nlri<StdIpv4Addr> = Nlri::new(StdIpv4Addr::new(10, 1, 0, 0), 24).unwrap();
        let prefix_b: Nlri<StdIpv4Addr> = Nlri::new(StdIpv4Addr::new(10, 2, 0, 0), 24).unwrap();

        let malformed = BgpMessage::MalformedUpdate(MalformedUpdate {
            update: UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::Med(100)],
                announced: vec![prefix_a, prefix_b],
            },
            errors: vec![AttributeDecodeError {
                type_code: 1, // ORIGIN
                policy: AttributeErrorPolicy::TreatAsWithdraw,
                detail: "invalid origin value",
            }],
            treat_as_withdraw: true,
            session_reset: false,
        });
        peer.recv_tx.send(Ok(malformed)).unwrap();

        // Session must not emit Terminated — it must stay up.
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for RouteUpdate after malformed UPDATE")
            .expect("session exited unexpectedly");

        let u = expect_route_update(event);
        // treat-as-withdraw: announced list must be empty.
        assert!(
            u.announced.is_empty(),
            "treat-as-withdraw must clear announced, got {:?}",
            u.announced
        );
        // Both prefixes must appear in withdrawn.
        assert!(
            u.withdrawn.contains(&prefix_a),
            "withdrawn must contain {prefix_a:?}"
        );
        assert!(
            u.withdrawn.contains(&prefix_b),
            "withdrawn must contain {prefix_b:?}"
        );

        // Confirm the session is still alive: send a KEEPALIVE and verify the
        // session does NOT emit Terminated within a short window.
        peer.recv_tx.send(Ok(BgpMessage::Keepalive)).unwrap();
        let result = tokio::time::timeout(Duration::from_millis(100), handle.next_event()).await;
        assert!(
            result.is_err() || !matches!(result.unwrap(), Some(SessionEvent::Terminated(_))),
            "session must not terminate after a treat-as-withdraw malformed UPDATE"
        );
    }

    /// RFC 7606 §3(g)/(h): a [`MalformedUpdate`] with `session_reset=true`
    /// (a duplicated `MP_REACH_NLRI`/`MP_UNREACH_NLRI`) is the one per-attribute
    /// error that must actually reset the session — a Malformed Attribute
    /// List NOTIFICATION MUST be sent and the connection torn down, unlike
    /// every other RFC 7606 outcome which keeps the session up.
    ///
    /// Also asserts the specific `TerminationReason`, not just that some
    /// `Terminated` event fires: this is a locally-initiated protocol-error
    /// teardown, so it must be `OperatorStop` (immediate route flush), not
    /// `Unclean` — the daemon's `on_terminated` treats `Unclean` as grounds
    /// to enter RFC 4724 GR helper mode and retain the peer's routes as
    /// stale, which is wrong when we ourselves decided to close the session
    /// over a clear protocol violation.
    #[tokio::test]
    async fn test_rfc7606_session_reset_sends_notification_and_terminates() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        let malformed = BgpMessage::MalformedUpdate(MalformedUpdate {
            update: UpdateMessage {
                withdrawn: vec![],
                attributes: vec![],
                announced: vec![],
            },
            errors: vec![AttributeDecodeError {
                type_code: 14, // MP_REACH_NLRI
                policy: AttributeErrorPolicy::SessionReset,
                detail: "duplicate attribute type code",
            }],
            treat_as_withdraw: false,
            session_reset: true,
        });
        peer.recv_tx.send(Ok(malformed)).unwrap();

        let notification = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for the Malformed Attribute List NOTIFICATION")
            .expect("channel closed before the NOTIFICATION was sent");
        assert!(
            matches!(
                notification,
                BgpMessage::Notification(NotificationMessage {
                    error: NotificationError::UpdateMessage(UpdateMsgError::MalformedAttributeList),
                    ..
                })
            ),
            "expected UpdateMessage/MalformedAttributeList NOTIFICATION (RFC 7606 §3(g)), got {notification:?}"
        );

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Terminated")
            .expect("session exited without emitting an event");
        assert!(
            matches!(
                event,
                SessionEvent::Terminated(TerminationReason::OperatorStop)
            ),
            "expected Terminated(OperatorStop) — a locally-initiated protocol-error \
             teardown must not be recorded as Unclean, which would make the daemon \
             wrongly enter RFC 4724 GR helper mode for this peer — got {event:?}"
        );
    }

    // ── RFC 4271 §6.1 Message Header Error NOTIFICATION ───────────────────────

    #[tokio::test]
    async fn test_invalid_marker_sends_message_header_notification() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        peer.recv_tx
            .send(Err(FramingError::Codec(CodecError::InvalidMarker)))
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for NOTIFICATION")
            .expect("mock channel closed before NOTIFICATION");
        assert_eq!(
            msg,
            BgpMessage::Notification(NotificationMessage {
                error: NotificationError::MessageHeader(MsgHeaderError::ConnectionNotSynchronized),
                data: vec![],
            }),
            "expected a Message Header Error / Connection Not Synchronized NOTIFICATION, got {msg:?}"
        );
    }

    #[tokio::test]
    async fn test_invalid_length_sends_message_header_notification_with_length_in_data() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        peer.recv_tx
            .send(Err(FramingError::Codec(CodecError::InvalidLength(5000))))
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for NOTIFICATION")
            .expect("mock channel closed before NOTIFICATION");
        assert_eq!(
            msg,
            BgpMessage::Notification(NotificationMessage {
                error: NotificationError::MessageHeader(MsgHeaderError::BadMessageLength),
                data: 5000u16.to_be_bytes().to_vec(),
            }),
            "expected a Message Header Error / Bad Message Length NOTIFICATION carrying the \
             erroneous length in data, got {msg:?}"
        );
    }

    #[tokio::test]
    async fn test_unknown_message_type_sends_message_header_notification_with_type_in_data() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        peer.recv_tx
            .send(Err(FramingError::Codec(CodecError::UnknownMessageType(99))))
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for NOTIFICATION")
            .expect("mock channel closed before NOTIFICATION");
        assert_eq!(
            msg,
            BgpMessage::Notification(NotificationMessage {
                error: NotificationError::MessageHeader(MsgHeaderError::BadMessageType),
                data: vec![99],
            }),
            "expected a Message Header Error / Bad Message Type NOTIFICATION carrying the \
             erroneous type byte in data, got {msg:?}"
        );
    }

    /// Documents the explicit scope boundary: a `CodecError` below the header
    /// layer (e.g. a malformed OPEN/NOTIFICATION body) is not yet mapped to a
    /// NOTIFICATION — the connection is dropped silently, matching
    /// pre-existing behavior. See `header_error_notification`'s doc comment.
    #[tokio::test]
    async fn test_other_codec_errors_drop_connection_without_notification() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        peer.recv_tx
            .send(Err(FramingError::Codec(CodecError::Truncated {
                needed: 4,
                available: 1,
            })))
            .unwrap();

        // The connection is dropped without sending anything, which closes
        // the mock's send channel — `recv()` therefore returns `Ok(None)`
        // rather than timing out. Either that or a timeout is acceptable;
        // only an actual sent message (`Ok(Some(_))`) is a failure.
        let result = tokio::time::timeout(Duration::from_millis(100), peer.send_rx.recv()).await;
        assert!(
            !matches!(result, Ok(Some(_))),
            "no message should be sent for a non-header CodecError, got {result:?}"
        );

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Terminated")
            .expect("session channel closed before Terminated");
        assert!(
            matches!(event, SessionEvent::Terminated(_)),
            "expected Terminated after a non-header CodecError, got {event:?}"
        );
    }

    /// RFC 7606 attribute-discard: a [`MalformedUpdate`] with `treat_as_withdraw=false`
    /// must keep the session alive and forward the cleaned UPDATE (bad attributes
    /// already stripped by the decoder) as a [`SessionEvent::RouteUpdate`].
    #[tokio::test]
    async fn test_rfc7606_attribute_discard_keeps_session_up_and_forwards_update() {
        use pathvector_types::Origin;

        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        // MED was malformed (attribute-discard).  The decoder strips it and
        // keeps ORIGIN.  The cleaned update still announces a prefix.
        let prefix: Nlri<StdIpv4Addr> = Nlri::new(StdIpv4Addr::new(192, 168, 1, 0), 24).unwrap();

        let malformed = BgpMessage::MalformedUpdate(MalformedUpdate {
            update: UpdateMessage {
                withdrawn: vec![],
                // MED was bad and has been dropped; only ORIGIN and NEXT_HOP survive.
                attributes: vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::NextHop(StdIpv4Addr::new(10, 0, 0, 1)),
                ],
                announced: vec![prefix],
            },
            errors: vec![AttributeDecodeError {
                type_code: 4, // MED
                policy: AttributeErrorPolicy::AttributeDiscard,
                detail: "wrong length for MED",
            }],
            treat_as_withdraw: false,
            session_reset: false,
        });
        peer.recv_tx.send(Ok(malformed)).unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for RouteUpdate after attribute-discard UPDATE")
            .expect("session exited unexpectedly");

        let u = expect_route_update(event);
        // attribute-discard: announcement must be preserved.
        assert!(
            u.announced.contains(&prefix),
            "announced must contain {prefix:?} after attribute-discard"
        );
        // No spurious withdrawals.
        assert!(
            u.withdrawn.is_empty(),
            "withdrawn must be empty after attribute-discard, got {:?}",
            u.withdrawn
        );

        // Confirm session is still alive.
        peer.recv_tx.send(Ok(BgpMessage::Keepalive)).unwrap();
        let result = tokio::time::timeout(Duration::from_millis(100), handle.next_event()).await;
        assert!(
            result.is_err() || !matches!(result.unwrap(), Some(SessionEvent::Terminated(_))),
            "session must not terminate after an attribute-discard malformed UPDATE"
        );
    }

    /// When `spawn_with` injects a transport that immediately fails (send error on OPEN),
    /// the FSM receives `TcpFailed` and queues a 120 s `ConnectRetryTimer`.  After advancing
    /// mock time past that deadline the timer fires, the FSM emits a second
    /// `InitiateTcpConnect`, and since there is no pending transport AND no connect
    /// factory (injected-transport mode), `pending_input` is set to `TcpFailed`,
    /// keeping the session in its retry backoff loop.
    #[tokio::test]
    async fn test_no_pending_transport_on_retry_sets_tcp_failed_input() {
        tokio::time::pause();

        let (mock, peer) = MockTransport::pair();
        // Fail the very first send so the FSM never establishes.
        peer.fail_send.store(true, Ordering::SeqCst);

        let mut handle = spawn_with(test_config(), mock);
        handle.start().await;

        // Let the session task run: ManualStart → InitiateTcpConnect (consumes the
        // injected transport) → TcpConnected → SendMessage(OPEN) fails →
        // execute returns false → TcpFailed → FSM schedules ConnectRetryTimer(120 s).
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Advance past the 120 s retry deadline so ConnectRetryTimerExpired fires,
        // which triggers a second InitiateTcpConnect — now with no pending transport
        // and no connect factory (lines 455-459: pending_input = TcpFailed).
        tokio::time::advance(Duration::from_secs(121)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Session silently retries; it was never Established so no events.
        let result = tokio::time::timeout(Duration::from_millis(10), handle.next_event()).await;
        assert!(
            result.is_err(),
            "session should not emit events while retrying without a transport"
        );
    }

    /// When the peer OPEN advertises `ExtendedMessage` but the local config does
    /// not include it, `extended` evaluates to `false` via short-circuit on the
    /// second operand (lines 496-499), and `set_extended_message(false)` is
    /// called on the transport.
    #[tokio::test]
    async fn test_extended_message_not_negotiated_when_local_lacks_capability() {
        let (mock, mut peer) = MockTransport::pair();

        // Local config has only FourByteAsn — no ExtendedMessage.
        let config = test_config(); // capabilities: [FourByteAsn(65001)]
        let mut handle = spawn_with(config, mock);
        handle.start().await;

        // Peer OPEN includes ExtendedMessage; local does not → extended = false.
        let open_with_ext = BgpMessage::Open(OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::FourByteAsn(65002), Capability::ExtendedMessage],
        });

        // Drain the outbound OPEN.
        let _ = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for OPEN");

        peer.recv_tx.send(Ok(open_with_ext)).unwrap();

        // Drain the KEEPALIVE.
        let _ = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for KEEPALIVE");

        peer.recv_tx.send(Ok(BgpMessage::Keepalive)).unwrap();

        // Session reaches Established with extended_message = false.
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("no event");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "expected Established, got {event:?}"
        );
    }

    /// `make_treat_as_withdraw` must convert `MpReachNlri` attributes into
    /// `MpUnreachNlri` (lines 567-570) so that IPv6 prefixes are also withdrawn.
    #[tokio::test]
    async fn test_treat_as_withdraw_converts_mp_reach_to_mp_unreach() {
        use crate::message::{MpReachNlri, Prefix};
        use pathvector_types::{AfiSafi, NextHop, Nlri};
        use std::net::Ipv6Addr;

        let prefix_v6: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();

        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);
        drive_to_established(&mut handle, &mut peer).await;

        let malformed = BgpMessage::MalformedUpdate(MalformedUpdate {
            update: UpdateMessage {
                withdrawn: vec![],
                attributes: vec![PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(prefix_v6)],
                })],
                announced: vec![],
            },
            errors: vec![AttributeDecodeError {
                type_code: 14, // MP_REACH_NLRI
                policy: AttributeErrorPolicy::TreatAsWithdraw,
                detail: "malformed mp_reach",
            }],
            treat_as_withdraw: true,
            session_reset: false,
        });
        peer.recv_tx.send(Ok(malformed)).unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for RouteUpdate")
            .expect("session exited");

        let u = expect_route_update(event);
        let has_unreach = u.attributes.iter().any(
            |a| matches!(a, PathAttribute::MpUnreachNlri(m) if m.afi_safi == AfiSafi::IPV6_UNICAST),
        );
        assert!(
            has_unreach,
            "expected MpUnreachNlri in treat-as-withdraw result"
        );
    }

    /// `FramedBgpTransport::send` maps `FramingError::Io` to the underlying
    /// `io::Error` when the TCP write half has been closed.
    #[tokio::test]
    async fn test_framed_transport_send_io_error_is_forwarded() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client_stream, server_accept) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let client_stream = client_stream.unwrap();
        let (server_stream, _addr) = server_accept.unwrap();

        // Close the server side so that writing to the client eventually fails.
        drop(server_stream);

        let mut transport = FramedBgpTransport::from_stream(client_stream);

        // Keep sending until we get an io::Error (a closed peer may buffer briefly).
        let mut result = Ok(());
        for _ in 0..20 {
            result = transport.send(BgpMessage::Keepalive).await;
            if result.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            result.is_err(),
            "expected FramedBgpTransport::send to fail after peer closed"
        );
    }

    /// RFC 4271 §6.8, collision resolution rule 2 (quoted verbatim from
    /// rfc-editor.org/rfc/rfc4271):
    ///
    /// > If the value of the local BGP Identifier is less than the remote
    /// > one, the local system closes the BGP connection that already
    /// > exists (the one that is already in the OpenConfirm state), and
    /// > accepts the BGP connection initiated by the remote system.
    ///
    /// `local_bgp_id` = 10.0.0.1 (`test_config()`), candidate's BGP ID
    /// (from its OPEN) = 10.0.0.2, matching the existing connection's
    /// already-known peer ID — a genuine same-peer collision. local < peer,
    /// so the existing connection must be closed and the candidate adopted.
    ///
    /// Unlike the pre-fix version of this test, this one completes a real
    /// second handshake over the adopted connection and confirms
    /// `Established` — possible now because `spawn()` gives the candidate a
    /// real `connect_factory`-wrapped transport, not a mock with nowhere to
    /// bridge a raw `TcpStream` into.
    #[tokio::test]
    async fn test_collision_candidate_matching_id_lower_local_adopts_incoming_end_to_end() {
        let candidate_bgp_id = Ipv4Addr::new(10, 0, 0, 2);
        let (mut handle, mut existing_peer) = spawn_to_open_confirm(candidate_bgp_id).await;

        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();

        // Candidate's OPEN carries the SAME BGP ID as the existing
        // connection's already-known peer — this is what makes it a
        // genuine RFC 4271 §6.8 collision rather than an unrelated
        // connection that happens to share the peer's address.
        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = candidate_bgp_id;
        }
        candidate_peer.send(candidate_open).await.unwrap();

        // The existing connection must see the Cease/ConnectionCollisionResolution
        // NOTIFICATION (RFC 4271 §8.2.2), then close.
        let notification = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for the collision NOTIFICATION")
            .expect("existing connection closed before the NOTIFICATION")
            .expect("decode error on the collision NOTIFICATION");
        assert!(
            matches!(
                notification,
                BgpMessage::Notification(NotificationMessage {
                    error: NotificationError::Cease(CeaseError::ConnectionCollisionResolution),
                    ..
                })
            ),
            "expected Cease/ConnectionCollisionResolution NOTIFICATION (RFC 4271 §8.2.2), got {notification:?}"
        );
        let closed = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for the old connection to close");
        assert!(
            closed.is_none(),
            "existing connection must be closed when adopting a validated \
             higher-ID candidate (RFC 4271 §6.8 rule 2), got {closed:?}"
        );

        // Complete the handshake over the newly-adopted candidate connection
        // and confirm the session actually re-establishes over it.
        let sent_open = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for OPEN on the adopted connection")
            .expect("adopted connection closed before OPEN")
            .expect("decode error");
        assert!(matches!(sent_open, BgpMessage::Open(_)));
        let ka = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE on the adopted connection")
            .expect("adopted connection closed before KEEPALIVE")
            .expect("decode error");
        assert!(matches!(ka, BgpMessage::Keepalive));
        candidate_peer.send(BgpMessage::Keepalive).await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "expected Established over the adopted connection, got {event:?}"
        );
    }

    /// RFC 4271 §6.8, collision resolution rule 3 (same source as above):
    ///
    /// > Otherwise, the local system closes the newly created BGP
    /// > connection (the one associated with the newly received OPEN
    /// > message), and continues to use the existing one (the one that is
    /// > already in the OpenConfirm state).
    ///
    /// `local_bgp_id` = 10.0.0.1, candidate's BGP ID = 10.0.0.0 (lower than
    /// local), matching the existing connection's already-known peer ID —
    /// local > peer, so the existing connection must be kept (reaching
    /// `Established` over it) and the candidate's socket must actually
    /// close, not linger.
    #[tokio::test]
    async fn test_collision_candidate_matching_id_higher_local_keeps_existing_rejects_candidate() {
        let candidate_bgp_id = Ipv4Addr::new(10, 0, 0, 0);
        let (mut handle, mut existing_peer) = spawn_to_open_confirm(candidate_bgp_id).await;

        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();

        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = candidate_bgp_id;
        }
        candidate_peer.send(candidate_open).await.unwrap();

        // Existing connection must be entirely undisturbed: completing its
        // handshake still reaches Established.
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "expected Established over the kept existing connection \
             (RFC 4271 §6.8 rule 3), got {event:?}"
        );

        // The rejected candidate's socket must actually close.
        let closed = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for the rejected candidate to close");
        assert!(
            closed.is_none(),
            "rejected candidate connection must be closed, not held open, got {closed:?}"
        );
    }

    /// The actual regression test for the gap Codex's review of this PR
    /// found: RFC 4271 §6.8's collision-resolution procedure only applies
    /// "when...there is a connection to a remote BGP speaker whose BGP
    /// Identifier equals the one in the [new] OPEN message." The pre-fix
    /// code skipped that precondition — it compared the local BGP ID
    /// against whatever the *existing* connection's peer ID already was,
    /// without ever confirming the candidate actually belonged to that same
    /// peer, so a second connection from the peer's configured address
    /// carrying a *different* BGP Identifier could still run the tiebreak
    /// and tear down a healthy connection.
    ///
    /// Existing connection's known peer ID is 10.0.0.2 (> local 10.0.0.1).
    /// The candidate sends an OPEN with a *different* ID, 10.0.0.9 — also >
    /// local, so the naive (pre-fix) tiebreak math would have said "adopt."
    /// The fix must reject the candidate anyway, since its identity doesn't
    /// match the connection it's supposedly colliding with, and leave the
    /// existing connection to reach `Established` untouched.
    #[tokio::test]
    async fn test_collision_candidate_mismatched_bgp_id_rejected_existing_survives() {
        let existing_peer_id = Ipv4Addr::new(10, 0, 0, 2);
        let mismatched_candidate_id = Ipv4Addr::new(10, 0, 0, 9);
        let (mut handle, mut existing_peer) = spawn_to_open_confirm(existing_peer_id).await;

        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();

        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = mismatched_candidate_id;
        }
        candidate_peer.send(candidate_open).await.unwrap();

        // The existing connection must survive completely undisturbed.
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "a candidate with a mismatched BGP Identifier must never influence \
             the existing connection, got {event:?}"
        );

        // The mismatched-identity candidate must be rejected (socket closes).
        let closed = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for the mismatched candidate to close");
        assert!(
            closed.is_none(),
            "candidate with a BGP Identifier that doesn't match the existing \
             connection's peer must be rejected, got {closed:?}"
        );
    }

    /// Codex's review of this PR's first version found a second gap: RFC
    /// 4271 §6.8 defines a collision only for a *reversed-direction* pair
    /// (our own outbound dial versus an inbound candidate). Two connections
    /// accepted in the *same* direction — here, a second inbound connection
    /// arriving while an earlier *inbound* connection is still
    /// mid-handshake — must not be treated as a collision, even when their
    /// BGP Identifiers match and would otherwise trigger the tiebreak in
    /// the candidate's favor.
    #[tokio::test]
    async fn test_collision_candidate_rejected_when_existing_connection_is_also_inbound() {
        // Point the session at a port nothing is listening on so the
        // outbound dial is refused and the FSM lands in Active (mirrors the
        // technique `pathvector-session/tests/transport.rs`'s
        // `test_incoming_connection_in_active_accepted` uses).
        let refused_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_addr = refused_listener.local_addr().unwrap();
        drop(refused_listener);

        let mut config = test_config();
        config.peer_addr = refused_addr;
        let mut handle = spawn(config);
        handle.start().await;
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        // First inbound connection: accepted directly (Active state — no
        // existing connection to protect). This is genuinely inbound.
        let existing_peer_id = Ipv4Addr::new(10, 0, 0, 2);
        let (first_incoming, mut existing_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(first_incoming))
            .await
            .unwrap();

        // Immediate-accept path is unchanged: the session sends its OPEN first.
        let sent_open = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for OPEN")
            .expect("closed before OPEN")
            .expect("decode error");
        assert!(matches!(sent_open, BgpMessage::Open(_)));

        let mut open = peer_open();
        if let BgpMessage::Open(ref mut o) = open {
            o.bgp_id = existing_peer_id;
        }
        existing_peer.send(open).await.unwrap();

        let ka = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE")
            .expect("closed before KEEPALIVE")
            .expect("decode error");
        assert!(matches!(ka, BgpMessage::Keepalive));
        // Withhold our own KEEPALIVE — session stays in OpenConfirm.

        // Second inbound connection: a genuine same-direction extra
        // connection, with a MATCHING BGP ID chosen so the naive tiebreak
        // (ignoring direction) would say "adopt" (local 10.0.0.1 < 10.0.0.2).
        let (second_incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(second_incoming))
            .await
            .unwrap();
        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = existing_peer_id;
        }
        candidate_peer.send(candidate_open).await.unwrap();

        // The first (existing, inbound) connection must survive completely
        // undisturbed.
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "a second inbound connection must never collide with an existing \
             inbound connection (not a reversed pair per RFC 4271 §6.8), got {event:?}"
        );

        // The second (same-direction) connection must be rejected.
        let closed = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for the same-direction candidate to close");
        assert!(
            closed.is_none(),
            "a same-direction second connection must be rejected, got {closed:?}"
        );
    }

    /// Pure, socket-free unit test of `ConnectionIdentity::is_reversed_pair_with`
    /// covering all three cases Codex's second review flagged: a genuine
    /// collision (matching endpoints, opposite direction) must pass; two
    /// connections in the *same* direction (a second inbound arriving while
    /// an existing inbound connection is still mid-handshake) must fail
    /// even though their endpoints match; and Codex's specific multihomed
    /// counter-example — outbound dialed from local address A, an unrelated
    /// inbound connection landing on a *different* local address C — must
    /// fail even though direction is opposite, since the endpoints
    /// themselves don't actually reverse.
    #[test]
    fn test_connection_identity_reversed_pair() {
        let addr_a: IpAddr = "10.0.0.1".parse().unwrap();
        let addr_c: IpAddr = "10.0.0.3".parse().unwrap();
        let peer: IpAddr = "192.0.2.1".parse().unwrap();

        // Genuine collision: existing dialed out from A to peer; candidate
        // is peer dialing in, landing on that same local address A.
        let existing = ConnectionIdentity {
            local: addr_a,
            peer,
            origin: ConnectionOrigin::Outbound,
        };
        let candidate = ConnectionIdentity {
            local: addr_a,
            peer,
            origin: ConnectionOrigin::Inbound,
        };
        assert!(
            existing.is_reversed_pair_with(candidate),
            "matching endpoints with opposite direction must be a genuine \
             reversed pair"
        );

        // Same direction, matching endpoints: not a collision under RFC
        // 4271 §6.8's definition — no connection we dialed is involved.
        let existing_inbound = ConnectionIdentity {
            origin: ConnectionOrigin::Inbound,
            ..existing
        };
        assert!(
            !existing_inbound.is_reversed_pair_with(candidate),
            "two inbound connections from the same peer must not be treated \
             as a reversed pair, even with identical endpoints"
        );

        // Multihomed: outbound dialed from A, but the "candidate" landed on
        // a different local address C — opposite direction, but not
        // actually a reversed pair.
        let candidate_wrong_local = ConnectionIdentity {
            local: addr_c,
            ..candidate
        };
        assert!(
            !existing.is_reversed_pair_with(candidate_wrong_local),
            "opposite direction alone is not sufficient — endpoints must \
             also actually reverse (Codex's multihomed counter-example)"
        );
    }

    /// Codex's review of this PR's second version: RFC 4271 §6.8 doesn't
    /// sanction resolving a collision against an `OpenSent` connection
    /// unless the peer's BGP Identifier is already known "by means outside
    /// of the protocol" — which this implementation doesn't have. A
    /// candidate arriving while the primary is `OpenSent` must not be
    /// decided on the spot; it must wait until the primary's own OPEN
    /// supplies a real identity to compare against. Here, the candidate's
    /// BGP ID (10.0.0.9) does *not* match what the primary's own peer turns
    /// out to be (10.0.0.2, lower than local — would lose the tiebreak
    /// anyway, but that's not even reachable since identity doesn't match):
    /// the candidate must be rejected once the primary resolves, and the
    /// primary itself must never have been disturbed in the meantime.
    #[tokio::test]
    async fn test_collision_candidate_deferred_in_open_sent_rejected_once_primary_id_known() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = test_config();
        config.peer_addr = listener.local_addr().unwrap();
        let mut handle = spawn(config);
        handle.start().await;

        let (stream, _) = listener.accept().await.unwrap();
        let mut existing_peer = FramedBgpTransport::from_stream(stream);

        // Confirm the session is in OpenSent: it has sent its own OPEN, but
        // we haven't replied yet.
        let sent_open = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for OPEN")
            .expect("closed before OPEN")
            .expect("decode error");
        assert!(matches!(sent_open, BgpMessage::Open(_)));

        // Candidate arrives and validates while the primary is still
        // OpenSent — its identity (10.0.0.9) is unrelated to what the
        // primary will end up reporting.
        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();
        let mismatched_candidate_id = Ipv4Addr::new(10, 0, 0, 9);
        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = mismatched_candidate_id;
        }
        candidate_peer.send(candidate_open).await.unwrap();

        // Give the deferred-resolution path a chance to (incorrectly, if
        // the fix regressed) act before the primary's own OPEN arrives.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Now complete the primary's own handshake with its real identity
        // (10.0.0.2) — unrelated to the candidate's remembered 10.0.0.9.
        let primary_peer_id = Ipv4Addr::new(10, 0, 0, 2);
        let mut primary_open = peer_open();
        if let BgpMessage::Open(ref mut o) = primary_open {
            o.bgp_id = primary_peer_id;
        }
        existing_peer.send(primary_open).await.unwrap();

        let ka = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE")
            .expect("closed before KEEPALIVE")
            .expect("decode error");
        assert!(matches!(ka, BgpMessage::Keepalive));
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "the primary connection must reach Established undisturbed — a \
             deferred OpenSent candidate must never preempt it before the \
             primary's own identity is known, got {event:?}"
        );

        // The candidate, now resolved against the primary's real (mismatched)
        // identity, must be rejected.
        let closed = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for the deferred candidate to close");
        assert!(
            closed.is_none(),
            "candidate with an identity that doesn't match the primary's \
             now-known peer must be rejected once deferral resolves, got {closed:?}"
        );
    }

    /// Companion to the test above: if the primary dies (here: the peer
    /// simply closes the TCP connection) while a validated candidate is
    /// still deferred in `OpenSent`, the candidate must be adopted directly
    /// once `run()`'s post-input `try_resolve_pending_candidate` hook sees
    /// the primary has moved to `Active` — same as a fresh accepted
    /// connection.
    #[tokio::test]
    async fn test_collision_candidate_deferred_in_open_sent_adopted_when_primary_dies() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = test_config();
        config.peer_addr = listener.local_addr().unwrap();
        let mut handle = spawn(config);
        handle.start().await;

        let (stream, _) = listener.accept().await.unwrap();
        let mut existing_peer = FramedBgpTransport::from_stream(stream);

        let sent_open = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for OPEN")
            .expect("closed before OPEN")
            .expect("decode error");
        assert!(matches!(sent_open, BgpMessage::Open(_)));

        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();
        let candidate_id = Ipv4Addr::new(10, 0, 0, 9);
        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = candidate_id;
        }
        candidate_peer.send(candidate_open).await.unwrap();

        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Kill the primary connection outright — the session should observe
        // EOF, feed TcpFailed to the FSM, and land in Active.
        drop(existing_peer);

        // The deferred candidate must now be adopted directly: it completes
        // a fresh handshake and the session reaches Established over it.
        let sent_open = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for OPEN on the adopted candidate")
            .expect("candidate closed before OPEN")
            .expect("decode error");
        assert!(matches!(sent_open, BgpMessage::Open(_)));
        let ka = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE on the adopted candidate")
            .expect("candidate closed before KEEPALIVE")
            .expect("decode error");
        assert!(matches!(ka, BgpMessage::Keepalive));
        candidate_peer.send(BgpMessage::Keepalive).await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "a deferred candidate must be adopted once the primary it was \
             waiting on dies, got {event:?}"
        );
    }

    /// Codex's review of this PR's first version found a third gap: the
    /// candidate's OPEN must pass the same validation any OPEN would (RFC
    /// 4271 §6.2 — version, BGP Identifier, peer AS, hold time; RFC 5492
    /// §3 required capabilities; RFC 9234 §5.1 Role compatibility) *before*
    /// the existing connection is torn down — not just the BGP-Identifier
    /// match/tiebreak. A same-identity candidate with an invalid field
    /// (here: a peer AS that doesn't match the configured `peer_as`) must
    /// be rejected without ever disturbing the existing connection.
    #[tokio::test]
    async fn test_collision_candidate_with_invalid_open_rejected_existing_survives() {
        let existing_peer_id = Ipv4Addr::new(10, 0, 0, 2);
        let (mut handle, mut existing_peer) = spawn_to_open_confirm(existing_peer_id).await;

        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();

        // Same BGP ID as the existing connection's known peer (so identity
        // matching and the tiebreak alone would say "adopt"), but a peer AS
        // that doesn't match test_config()'s configured peer_as (65002) —
        // this must fail Fsm::validate_open's RFC 4271 §6.2 check.
        let mut invalid_open = peer_open();
        if let BgpMessage::Open(ref mut o) = invalid_open {
            o.bgp_id = existing_peer_id;
            o.my_as = 23456; // AS_TRANS placeholder; real ASN carried below.
            o.capabilities = vec![Capability::FourByteAsn(99999)];
        }
        candidate_peer.send(invalid_open).await.unwrap();

        // The candidate must receive a NOTIFICATION citing the actual
        // validation failure, then close — not silently dropped, and
        // critically, sent on the *candidate's* connection, never the
        // existing one.
        let notification = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for the validation-failure NOTIFICATION")
            .expect("candidate closed before the NOTIFICATION")
            .expect("decode error");
        assert!(
            matches!(
                notification,
                BgpMessage::Notification(NotificationMessage {
                    error: NotificationError::OpenMessage(OpenMsgError::BadPeerAs),
                    ..
                })
            ),
            "expected OPEN Message Error/Bad Peer AS NOTIFICATION, got {notification:?}"
        );

        // The existing connection must be completely undisturbed — proof
        // that the identity/tiebreak match alone did *not* trigger teardown.
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "a same-identity candidate with an invalid OPEN must never tear \
             down the existing connection, got {event:?}"
        );
    }

    /// The candidate-staging deadline mechanism actually fires and drops a
    /// candidate that never sends anything, without disturbing the existing
    /// connection. Uses `spawn_with_collision_timeout` to shorten the
    /// deadline for a fast, real (unpaused) wall-clock wait rather than
    /// `tokio::time::pause` + `advance` — that combination, used elsewhere
    /// in this module for purely mock/channel-based tests (e.g.
    /// `test_no_pending_transport_on_retry_sets_tcp_failed_input`), races
    /// tokio's paused-clock auto-advance-when-idle against this module's
    /// real-TCP collision tests badly enough to deadlock outright, not just
    /// flake — confirmed while developing this test.
    #[tokio::test]
    async fn test_collision_candidate_times_out_if_it_never_sends_open() {
        // Uses a short, real (unpaused) deadline via
        // `spawn_with_collision_timeout` rather than `tokio::time::pause` +
        // `advance`: combining paused time with this module's real-TCP
        // collision tests raced tokio's auto-advance-when-idle behavior
        // against genuine socket I/O badly enough to deadlock outright (not
        // just flake) while developing this test. A short real timeout
        // sidesteps the interaction entirely.
        let short_timeout = Duration::from_millis(200);
        let existing_peer_id = Ipv4Addr::new(10, 0, 0, 2);
        let (mut handle, mut existing_peer) =
            spawn_to_open_confirm_with_timeout(existing_peer_id, short_timeout).await;

        // Keep the candidate peer side alive but never write anything to it.
        let (incoming, mut silent_candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();

        // The dropped candidate's socket must actually close once the
        // (real) deadline elapses.
        let closed = tokio::time::timeout(short_timeout * 10, silent_candidate_peer.recv())
            .await
            .expect("timed out waiting for the candidate to be dropped on deadline");
        assert!(
            closed.is_none(),
            "candidate must be dropped once its OPEN-wait deadline elapses, got {closed:?}"
        );

        // The existing connection must be unaffected by the timed-out candidate.
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "a timed-out candidate must not disturb the existing connection, got {event:?}"
        );
    }

    /// RFC 4724 §4.2: "the previous TCP session MUST be closed, and the new
    /// one retained... Since the previous connection is considered to be
    /// terminated, no NOTIFICATION message should be sent -- the previous
    /// TCP session is simply closed."
    ///
    /// Establishes a session where the peer advertised Graceful Restart,
    /// then injects a second incoming connection — with the SAME BGP
    /// Identifier as the Established peer — while the FSM still thinks it's
    /// Established (simulating an undetected TCP failure). The old
    /// connection must close with no NOTIFICATION, a `Terminated(Unclean)`
    /// event must fire, and — unlike the pre-fix mock-based version of this
    /// test — the candidate must actually complete a fresh handshake and
    /// reach `Established` again, proven end to end over real sockets.
    #[tokio::test]
    async fn test_incoming_connection_while_established_with_gr_matching_id_closes_old_no_notification()
     {
        let peer_bgp_id = Ipv4Addr::new(10, 0, 0, 2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = test_config();
        config.peer_addr = listener.local_addr().unwrap();
        let mut handle = spawn(config);
        handle.start().await;

        let (stream, _) = listener.accept().await.unwrap();
        let mut existing_peer = FramedBgpTransport::from_stream(stream);

        let _sent_open = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for OPEN")
            .expect("closed before OPEN")
            .expect("decode error");

        let mut gr_open = peer_open();
        if let BgpMessage::Open(ref mut open) = gr_open {
            open.bgp_id = peer_bgp_id;
            open.capabilities.push(Capability::GracefulRestart {
                restart_flags: 0,
                restart_time: 120,
                families: vec![],
            });
        }
        existing_peer.send(gr_open).await.unwrap();

        let _ka = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE")
            .expect("closed before KEEPALIVE")
            .expect("decode error");
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for initial Established")
            .expect("session channel closed before Established");
        assert!(matches!(event, SessionEvent::Established(_)));

        // Simulate the peer's old TCP connection dying without us noticing:
        // inject a brand-new incoming connection, with the same BGP
        // Identifier, while still Established.
        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();
        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = peer_bgp_id;
            o.capabilities.push(Capability::GracefulRestart {
                restart_flags: 0,
                restart_time: 120,
                families: vec![],
            });
        }
        candidate_peer.send(candidate_open).await.unwrap();

        // The old connection must be torn down with NO NOTIFICATION — just
        // the socket closing (RFC 4724 §4.2, distinct from RFC 4271 §6.8's
        // default Cease-NOTIFICATION collision behavior).
        let closed = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for the old connection to close");
        assert!(
            closed.is_none(),
            "RFC 4724 §4.2 requires the old connection to simply close with \
             no NOTIFICATION, got {closed:?}"
        );

        let terminated_event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Terminated event")
            .expect("session channel closed");
        assert!(
            matches!(
                terminated_event,
                SessionEvent::Terminated(TerminationReason::Unclean)
            ),
            "expected Terminated(Unclean) for the presumed-dead old connection, \
             got {terminated_event:?}"
        );

        // The candidate must complete a fresh handshake and reach
        // Established again, proving real end-to-end adoption.
        let sent_open = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for OPEN on the adopted connection")
            .expect("adopted connection closed before OPEN")
            .expect("decode error");
        assert!(matches!(sent_open, BgpMessage::Open(_)));
        let ka = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE on the adopted connection")
            .expect("adopted connection closed before KEEPALIVE")
            .expect("decode error");
        assert!(matches!(ka, BgpMessage::Keepalive));
        candidate_peer.send(BgpMessage::Keepalive).await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for re-Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "expected Established over the adopted GR-reconnect connection, got {event:?}"
        );
    }

    /// The same identity-validation gap as
    /// `test_collision_candidate_mismatched_bgp_id_rejected_existing_survives`,
    /// but for the RFC 4724 §4.2 Established/GR override — which, pre-fix,
    /// had NO identity check at all (it unconditionally adopted any second
    /// incoming connection while Established with GR negotiated). A
    /// candidate with a BGP Identifier that doesn't match the live,
    /// Established peer's must not be allowed to displace it.
    #[tokio::test]
    async fn test_incoming_connection_while_established_with_gr_mismatched_id_rejected() {
        let peer_bgp_id = Ipv4Addr::new(10, 0, 0, 2);
        let mismatched_candidate_id = Ipv4Addr::new(10, 0, 0, 9);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = test_config();
        config.peer_addr = listener.local_addr().unwrap();
        let mut handle = spawn(config);
        handle.start().await;

        let (stream, _) = listener.accept().await.unwrap();
        let mut existing_peer = FramedBgpTransport::from_stream(stream);

        let _sent_open = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for OPEN")
            .expect("closed before OPEN")
            .expect("decode error");

        let mut gr_open = peer_open();
        if let BgpMessage::Open(ref mut open) = gr_open {
            open.bgp_id = peer_bgp_id;
            open.capabilities.push(Capability::GracefulRestart {
                restart_flags: 0,
                restart_time: 120,
                families: vec![],
            });
        }
        existing_peer.send(gr_open).await.unwrap();

        let _ka = tokio::time::timeout(Duration::from_secs(1), existing_peer.recv())
            .await
            .expect("timed out waiting for KEEPALIVE")
            .expect("closed before KEEPALIVE")
            .expect("decode error");
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for initial Established")
            .expect("session channel closed before Established");
        assert!(matches!(event, SessionEvent::Established(_)));

        // A second incoming connection arrives with a DIFFERENT BGP
        // Identifier than the live Established peer's.
        let (incoming, mut candidate_peer) = candidate_pair().await;
        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();
        let mut candidate_open = peer_open();
        if let BgpMessage::Open(ref mut o) = candidate_open {
            o.bgp_id = mismatched_candidate_id;
            o.capabilities.push(Capability::GracefulRestart {
                restart_flags: 0,
                restart_time: 120,
                families: vec![],
            });
        }
        candidate_peer.send(candidate_open).await.unwrap();

        // The mismatched candidate must be rejected outright (socket closes).
        let closed = tokio::time::timeout(Duration::from_secs(1), candidate_peer.recv())
            .await
            .expect("timed out waiting for the mismatched candidate to close");
        assert!(
            closed.is_none(),
            "a candidate with a BGP Identifier that doesn't match the live \
             Established peer must be rejected, got {closed:?}"
        );

        // The live Established session must remain completely undisturbed:
        // no Terminated event, and it still responds to a normal KEEPALIVE.
        existing_peer.send(BgpMessage::Keepalive).await.unwrap();
        let result = tokio::time::timeout(Duration::from_millis(200), handle.next_event()).await;
        assert!(
            result.is_err(),
            "a mismatched-identity candidate must not produce any session \
             event on the live Established peer, got {result:?}"
        );
    }

    // ── make_treat_as_withdraw unit tests ─────────────────────────────────────

    #[test]
    fn test_make_treat_as_withdraw_moves_announced_to_withdrawn() {
        use pathvector_types::Nlri;

        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![nlri],
        };
        let result = super::make_treat_as_withdraw(update);
        assert_eq!(result.withdrawn, vec![nlri]);
        assert!(result.announced.is_empty());
        assert!(result.attributes.is_empty());
    }

    #[test]
    fn test_make_treat_as_withdraw_strips_non_mp_reach_attributes() {
        use pathvector_types::Origin;

        let update = UpdateMessage {
            withdrawn: vec![],
            // LOCAL_PREF and ORIGIN are not MpReachNlri — they must be stripped.
            attributes: vec![
                PathAttribute::LocalPref(100),
                PathAttribute::Origin(Origin::Igp),
            ],
            announced: vec![],
        };
        let result = super::make_treat_as_withdraw(update);
        assert!(
            result.attributes.is_empty(),
            "non-MpReach attrs must be stripped"
        );
        assert!(result.withdrawn.is_empty());
        assert!(result.announced.is_empty());
    }

    #[test]
    fn test_make_treat_as_withdraw_mixed_attrs_keeps_only_mp_unreach() {
        use std::net::Ipv6Addr;

        use crate::message::{MpReachNlri, Prefix};
        use pathvector_types::{AfiSafi, NextHop, Nlri, Origin};

        let prefix: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![
                PathAttribute::LocalPref(200),
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi: AfiSafi::IPV6_UNICAST,
                    next_hop: NextHop::V6("2001:db8::1".parse().unwrap()),
                    prefixes: vec![Prefix::V6(prefix)],
                }),
                PathAttribute::Origin(Origin::Egp),
            ],
            announced: vec![],
        };
        let result = super::make_treat_as_withdraw(update);
        // Only the converted MpUnreachNlri should remain.
        assert_eq!(result.attributes.len(), 1);
        assert!(
            matches!(&result.attributes[0], PathAttribute::MpUnreachNlri(m) if m.afi_safi == AfiSafi::IPV6_UNICAST),
            "expected MpUnreachNlri after conversion"
        );
        assert!(result.announced.is_empty());
    }

    #[test]
    fn test_make_treat_as_withdraw_empty_update_is_noop() {
        let update = UpdateMessage {
            withdrawn: vec![],
            attributes: vec![],
            announced: vec![],
        };
        let result = super::make_treat_as_withdraw(update);
        assert!(result.withdrawn.is_empty());
        assert!(result.attributes.is_empty());
        assert!(result.announced.is_empty());
    }

    /// `SetCapabilities` while not Established updates the FSM's capability set.
    /// We test through `Fsm::set_capabilities` / `Fsm::capabilities_for_test`
    /// since `make_open` is private and the mock transport cannot reconnect.
    #[test]
    fn test_set_capabilities_updates_fsm_config() {
        use crate::fsm::{Fsm, FsmConfig};
        use crate::message::Capability;

        let initial = vec![Capability::FourByteAsn(65001)];
        let mut fsm = Fsm::new(FsmConfig {
            local_as: 65001,
            local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time: 90,
            capabilities: initial.clone(),
            required_capabilities: vec![],
            peer_as: Some(65002),
        });

        assert!(!fsm.is_established(), "FSM must start non-Established");
        assert_eq!(
            fsm.local_capabilities(),
            &initial,
            "initial caps must match config"
        );

        let updated = vec![Capability::FourByteAsn(65001), Capability::ExtendedMessage];
        fsm.set_capabilities(updated.clone());

        assert_eq!(
            fsm.local_capabilities(),
            &updated,
            "set_capabilities must update the FSM's local capability set"
        );
    }

    /// `SpawnedSessionHandle::stop` sends `SessionCommand::Stop` and the session
    /// terminates, emitting `Terminated`.
    #[tokio::test]
    async fn test_spawned_handle_stop_terminates_session() {
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);

        drive_to_established(&mut handle, &mut peer).await;

        handle.stop().await;

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Terminated after stop()")
            .expect("session exited without emitting Terminated");
        assert!(
            matches!(event, SessionEvent::Terminated(_)),
            "expected Terminated after stop(), got {event:?}"
        );
    }
}
