//! BGP TCP transport.
//!
//! Wires the [`crate::framing::BgpCodec`] and [`crate::fsm::Fsm`] together
//! over a real TCP connection. Call [`spawn`] to start a session task and
//! interact with it via the returned [`SessionHandle`].

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
use crate::message::{BgpMessage, Capability, UpdateMessage};

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
            reader: FramedRead::new(r, BgpCodec),
            writer: FramedWrite::new(w, BgpCodec),
        }
    }
}

impl BgpTransport for FramedBgpTransport {
    async fn send(&mut self, msg: BgpMessage) -> io::Result<()> {
        self.writer.send(msg).await.map_err(|e| match e {
            FramingError::Io(io_err) => io_err,
            FramingError::Codec(_) => {
                io::Error::new(io::ErrorKind::InvalidData, "BGP encode error")
            }
        })
    }

    async fn recv(&mut self) -> Option<Result<BgpMessage, FramingError>> {
        self.reader.next().await
    }
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
    /// Expected peer AS. `None` accepts any AS.
    pub peer_as: Option<u32>,
    /// Address (IP + port) of the remote BGP peer.
    pub peer_addr: SocketAddr,
}

/// Commands sent to a running session via [`SessionHandle`].
#[derive(Debug)]
pub enum SessionCommand {
    /// Begin the TCP connect / FSM start sequence.
    Start,
    /// Send CEASE NOTIFICATION and drop the connection.
    Stop,
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
pub struct SessionHandle {
    cmd_tx: mpsc::Sender<SessionCommand>,
    event_rx: mpsc::Receiver<SessionEvent>,
    update_tx: mpsc::Sender<UpdateMessage>,
}

impl SessionHandle {
    /// Send a [`SessionCommand::Start`] to the session.
    pub async fn start(&self) {
        let _ = self.cmd_tx.send(SessionCommand::Start).await;
    }

    /// Send a [`SessionCommand::Stop`] to the session.
    pub async fn stop(&self) {
        let _ = self.cmd_tx.send(SessionCommand::Stop).await;
    }

    /// Receive the next [`SessionEvent`]. Returns `None` when the session task
    /// has exited.
    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        self.event_rx.recv().await
    }

    /// Returns a cloneable sender for queuing outbound UPDATE messages to this
    /// session.
    ///
    /// Messages sent here are written to the TCP connection when the session is
    /// in the Established state. If the session is not connected, the messages
    /// are discarded. The channel has capacity 256; senders should treat a full
    /// channel as a backpressure signal and log a warning.
    #[must_use]
    pub fn update_sender(&self) -> mpsc::Sender<UpdateMessage> {
        self.update_tx.clone()
    }
}

/// Spawn a BGP session task and return a handle to control it.
///
/// The session starts in `Idle`. Call [`SessionHandle::start`] to initiate the
/// TCP connection.
#[must_use]
pub fn spawn(config: SessionConfig) -> SessionHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(64);
    let (update_tx, update_rx) = mpsc::channel(256);

    let fsm_config = FsmConfig {
        local_as: config.local_as,
        local_bgp_id: config.local_bgp_id,
        hold_time: config.hold_time,
        capabilities: config.capabilities.clone(),
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
        update_rx,
    };

    tokio::spawn(session.run());
    SessionHandle {
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
/// Intended exclusively for tests that need a controllable transport without
/// binding real TCP sockets.
#[cfg(test)]
pub fn spawn_with<T: BgpTransport>(config: SessionConfig, transport: T) -> SessionHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(64);
    let (update_tx, update_rx) = mpsc::channel(256);

    let fsm_config = FsmConfig {
        local_as: config.local_as,
        local_bgp_id: config.local_bgp_id,
        hold_time: config.hold_time,
        capabilities: config.capabilities.clone(),
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
        update_rx,
    };

    tokio::spawn(session.run());
    SessionHandle {
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

                cmd = self.cmd_rx.recv() => return match cmd {
                    Some(SessionCommand::Start) => FsmInput::ManualStart,
                    // None = handle dropped → treat as operator stop.
                    Some(SessionCommand::Stop) | None => FsmInput::ManualStop,
                },

                result = recv_connect(&mut self.connect_task) => {
                    self.connect_task = None;
                    return match result {
                        Ok(stream) => {
                            // connect_task is only spawned when connect_factory is Some.
                            self.transport = Some(self.connect_factory.as_ref().unwrap()(stream));
                            FsmInput::TcpConnected
                        }
                        Err(_) => FsmInput::TcpFailed,
                    };
                }

                msg = recv_message(&mut self.transport) => {
                    match msg {
                        Some(Ok(m)) => return FsmInput::MessageReceived(m),
                        Some(Err(e)) => {
                            tracing::warn!(peer = %self.config.peer_addr, error = %e, "codec error on received message");
                        }
                        None => {}
                    }
                    self.drop_connection();
                    return FsmInput::TcpFailed;
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
                    if let Some(t) = &mut self.transport {
                        if t.send(BgpMessage::Update(update)).await.is_err() {
                            self.drop_connection();
                            return FsmInput::TcpFailed;
                        }
                    }
                    // Not yet Established, or send succeeded — loop.
                }
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
                        self.connect_task =
                            Some(tokio::spawn(async move { TcpStream::connect(addr).await }));
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
                    if let Some(t) = &mut self.transport {
                        if t.send(msg).await.is_err() {
                            self.drop_connection();
                            return false;
                        }
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
                FsmOutput::SessionEstablished(info) => {
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

    fn drop_connection(&mut self) {
        self.transport = None;
        if let Some(t) = self.connect_task.take() {
            t.abort();
        }
    }
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

    use super::{BgpTransport, SessionConfig, SessionEvent, spawn_with};
    use crate::framing::FramingError;
    use crate::message::{BgpMessage, Capability, OpenMessage, UpdateMessage};

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
            peer_as: Some(65002),
            // peer_addr is unused when a transport is injected via spawn_with.
            peer_addr: "127.0.0.1:0".parse().unwrap(),
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
    async fn drive_to_established(handle: &mut super::SessionHandle, peer: &mut MockPeer) {
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
}
