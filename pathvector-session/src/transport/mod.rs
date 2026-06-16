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
use std::net::{Ipv4Addr, SocketAddr};

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
    BgpMessage, Capability, MalformedUpdate, MpUnreachNlri, PathAttribute, UpdateMessage,
};

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
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Configuration for a BGP session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub local_as: u32,
    pub local_bgp_id: Ipv4Addr,
    /// Proposed hold time in seconds (`0` to disable; otherwise ≥ 3).
    pub hold_time: u16,
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
}

/// Events emitted by a session to its caller.
#[derive(Debug)]
pub enum SessionEvent {
    /// The session reached Established. Contains negotiated parameters.
    Established(SessionInfo),
    /// The session was torn down (after previously being Established).
    Terminated,
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
        update_rx,
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
        update_rx,
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
    // so the daemon can use it as the eBGP NEXT_HOP (RFC 4271 §5.1.3).
    local_addr: Option<Ipv4Addr>,
    // Outbound UPDATE messages queued by the daemon.
    update_rx: mpsc::Receiver<UpdateMessage>,
}

impl<T: BgpTransport> Session<T> {
    async fn run(mut self) {
        loop {
            let input = self.wait_for_input().await;
            let outputs = self.fsm.process(input);
            if !self.execute(outputs).await {
                // A TCP send failed; feed TcpFailed back into the FSM.
                let recovery = self.fsm.process(FsmInput::TcpFailed);
                self.execute(recovery).await;
            }
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
                        if let Some(input) = self.handle_incoming_connection(stream).await {
                            return input;
                        }
                        // Won the collision: incoming rejected, outbound continues.
                    }
                },

                result = recv_connect(&mut self.connect_task) => {
                    self.connect_task = None;
                    return match result {
                        Ok(stream) => {
                            self.local_addr = stream.local_addr().ok().and_then(|a| {
                                if let std::net::IpAddr::V4(ip) = a.ip() { Some(ip) } else { None }
                            });
                            // connect_task is only spawned when connect_factory is Some.
                            self.transport = Some(self.connect_factory.as_ref().unwrap()(stream));
                            FsmInput::TcpConnected
                        }
                        Err(_) => FsmInput::TcpFailed,
                    };
                }

                msg = recv_message(&mut self.transport) => {
                    match msg {
                        Some(Ok(BgpMessage::MalformedUpdate(m))) => {
                            self.handle_malformed_update(m).await;
                            // Session stays up — continue the select! loop.
                        }
                        Some(Ok(m)) => return FsmInput::MessageReceived(m),
                        Some(Err(e)) => {
                            tracing::warn!(peer = %self.config.peer_addr, error = %e, "codec error on received message");
                            self.drop_connection();
                            return FsmInput::TcpFailed;
                        }
                        None => {
                            self.drop_connection();
                            return FsmInput::TcpFailed;
                        }
                    }
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

    /// RFC 4271 §6.8 connection collision detection.
    ///
    /// Called when the daemon's listener accepts an inbound TCP connection from
    /// this peer.  Returns `Some(FsmInput)` when the session should adopt the
    /// incoming connection (the FSM will process the input normally), or `None`
    /// when the incoming connection was rejected and the outbound connection
    /// should continue undisturbed.
    async fn handle_incoming_connection(&mut self, stream: TcpStream) -> Option<FsmInput> {
        use crate::fsm::State;
        match self.fsm.state() {
            // No active outbound attempt — accept the incoming connection directly.
            State::Idle | State::Connect | State::Active => {
                self.local_addr = stream.local_addr().ok().and_then(|a| {
                    if let std::net::IpAddr::V4(ip) = a.ip() {
                        Some(ip)
                    } else {
                        None
                    }
                });
                if let Some(factory) = &self.connect_factory {
                    self.transport = Some(factory(stream));
                }
                Some(FsmInput::TcpConnected)
            }

            // Collision: compare BGP identifiers (RFC 4271 §6.8).
            // local > peer  →  close outbound, adopt incoming (CollisionDetected)
            // local < peer  →  keep outbound, discard incoming (return None)
            // unknown peer  →  conservative: adopt incoming
            State::OpenSent | State::OpenConfirm => {
                let should_close_outbound = self
                    .fsm
                    .peer_bgp_id()
                    .is_none_or(|peer_id| self.config.local_bgp_id > peer_id);

                if should_close_outbound {
                    tracing::info!(
                        peer = %self.config.peer_addr,
                        local_bgp_id = %self.config.local_bgp_id,
                        "BGP collision: local BGP ID higher, closing outbound and adopting incoming"
                    );
                    let outputs = self.fsm.process(FsmInput::CollisionDetected);
                    self.execute(outputs).await;
                    self.local_addr = stream.local_addr().ok().and_then(|a| {
                        if let std::net::IpAddr::V4(ip) = a.ip() {
                            Some(ip)
                        } else {
                            None
                        }
                    });
                    if let Some(factory) = &self.connect_factory {
                        self.transport = Some(factory(stream));
                    }
                    Some(FsmInput::TcpConnected)
                } else {
                    let peer_bgp_id = self.fsm.peer_bgp_id().unwrap();
                    tracing::info!(
                        peer = %self.config.peer_addr,
                        local_bgp_id = %self.config.local_bgp_id,
                        peer_bgp_id = %peer_bgp_id,
                        "BGP collision: peer BGP ID higher, keeping outbound and rejecting incoming"
                    );
                    drop(stream);
                    None
                }
            }

            // Already established — reject the incoming connection.
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
                FsmOutput::StartConnectRetryTimer(d) => {
                    self.retry_deadline = Some(Instant::now() + d);
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
                    let _ = self.event_tx.send(SessionEvent::Terminated).await;
                }
                FsmOutput::RouteUpdate(update) => {
                    let _ = self.event_tx.send(SessionEvent::RouteUpdate(update)).await;
                }
            }
        }
        true
    }

    /// Apply RFC 7606 error policy for a malformed UPDATE.
    ///
    /// - `TreatAsWithdraw`: synthesise a withdrawal UPDATE for all NLRIs that
    ///   were announced in this message, then forward it as a `RouteUpdate`.
    /// - `AttributeDiscard` (all errors): forward the cleaned UPDATE (bad
    ///   attributes already removed by the decoder).
    ///
    /// The session is not reset in either case.
    async fn handle_malformed_update(&mut self, m: MalformedUpdate) {
        for e in &m.errors {
            tracing::warn!(
                peer = %self.config.peer_addr,
                type_code = e.type_code,
                detail = e.detail,
                policy = ?e.policy,
                "RFC 7606: malformed path attribute"
            );
        }

        let update = if m.treat_as_withdraw {
            make_treat_as_withdraw(m.update)
        } else {
            m.update
        };

        let _ = self.event_tx.send(SessionEvent::RouteUpdate(update)).await;
    }

    fn drop_connection(&mut self) {
        self.transport = None;
        if let Some(t) = self.connect_task.take() {
            t.abort();
        }
    }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::sync::mpsc;

    use std::net::Ipv4Addr as StdIpv4Addr;

    use super::{
        BgpTransport, FramedBgpTransport, SessionCommand, SessionConfig, SessionEvent,
        SessionHandle, SpawnedSessionHandle, spawn_with,
    };
    use crate::framing::FramingError;
    use pathvector_types::Nlri;

    use crate::message::{
        AttributeDecodeError, AttributeErrorPolicy, BgpMessage, Capability, MalformedUpdate,
        OpenMessage, PathAttribute, UpdateMessage,
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
        expect_route_update(SessionEvent::Terminated);
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
            matches!(event, SessionEvent::Terminated),
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
            matches!(event, SessionEvent::Terminated),
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
            result.is_err() || !matches!(result.unwrap(), Some(SessionEvent::Terminated)),
            "session must not terminate after a treat-as-withdraw malformed UPDATE"
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
            result.is_err() || !matches!(result.unwrap(), Some(SessionEvent::Terminated)),
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

    /// When an incoming connection arrives while the session is in `OpenConfirm`
    /// AND the peer's BGP ID (from the received OPEN) is higher than the local
    /// BGP ID, the session must keep the outbound connection and silently drop
    /// the incoming one (RFC 4271 §6.8, "peer wins" case — exercises L498-505).
    #[tokio::test]
    async fn test_collision_in_open_confirm_peer_bgp_id_higher_rejects_incoming() {
        use tokio::net::TcpListener;

        // local_bgp_id = 10.0.0.1, peer_open uses bgp_id = 10.0.0.2 (higher).
        let (mock, mut peer) = MockTransport::pair();
        let mut handle = spawn_with(test_config(), mock);
        handle.start().await;

        // Receive the OPEN the session sent.
        let _sent_open = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for OPEN")
            .expect("channel closed before OPEN");

        // Inject peer OPEN with higher BGP ID (10.0.0.2 > 10.0.0.1).
        peer.recv_tx.send(Ok(peer_open())).unwrap();

        // Wait for the session's KEEPALIVE — confirms it is now in OpenConfirm
        // and has recorded the peer's BGP ID.
        let _ka = tokio::time::timeout(Duration::from_secs(1), peer.send_rx.recv())
            .await
            .expect("timed out waiting for KEEPALIVE")
            .expect("channel closed before KEEPALIVE");

        // Create a real TcpStream to inject as an incoming connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (incoming, _) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let incoming = incoming.unwrap();

        handle
            .incoming_sender()
            .send(SessionCommand::IncomingConnection(incoming))
            .await
            .unwrap();

        // Complete the handshake — session keeps the outbound and reaches Established.
        peer.recv_tx.send(Ok(BgpMessage::Keepalive)).unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), handle.next_event())
            .await
            .expect("timed out waiting for Established")
            .expect("session channel closed");
        assert!(
            matches!(event, SessionEvent::Established(_)),
            "expected Established after peer-wins collision, got {event:?}"
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
        assert!(result.attributes.is_empty(), "non-MpReach attrs must be stripped");
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
            matches!(event, SessionEvent::Terminated),
            "expected Terminated after stop(), got {event:?}"
        );
    }
}
