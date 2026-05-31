//! BGP TCP transport.
//!
//! Wires the [`crate::framing::BgpCodec`] and [`crate::fsm::Fsm`] together
//! over a real TCP connection. Call [`spawn`] to start a session task and
//! interact with it via the returned [`SessionHandle`].

#[cfg(test)]
mod prop_tests;

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
}

/// Spawn a BGP session task and return a handle to control it.
///
/// The session starts in `Idle`. Call [`SessionHandle::start`] to initiate the
/// TCP connection.
#[must_use]
pub fn spawn(config: SessionConfig) -> SessionHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (event_tx, event_rx) = mpsc::channel(64);

    let fsm_config = FsmConfig {
        local_as: config.local_as,
        local_bgp_id: config.local_bgp_id,
        hold_time: config.hold_time,
        capabilities: config.capabilities.clone(),
        peer_as: config.peer_as,
    };

    let session = Session {
        config,
        fsm: Fsm::new(fsm_config),
        cmd_rx,
        event_tx,
        hold_deadline: None,
        keepalive_deadline: None,
        retry_deadline: None,
        reader: None,
        writer: None,
        connect_task: None,
    };

    tokio::spawn(session.run());
    SessionHandle { cmd_tx, event_rx }
}

// ── Internal session worker ───────────────────────────────────────────────────

struct Session {
    config: SessionConfig,
    fsm: Fsm,
    cmd_rx: mpsc::Receiver<SessionCommand>,
    event_tx: mpsc::Sender<SessionEvent>,

    // Timer deadlines — None means the timer is not running.
    hold_deadline: Option<Instant>,
    keepalive_deadline: Option<Instant>,
    retry_deadline: Option<Instant>,

    // TCP halves — both present when Connected, both None otherwise.
    reader: Option<FramedRead<OwnedReadHalf, BgpCodec>>,
    writer: Option<FramedWrite<OwnedWriteHalf, BgpCodec>>,
    // Pending outbound TCP connect (Connecting state only).
    connect_task: Option<JoinHandle<io::Result<TcpStream>>>,
}

impl Session {
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
    async fn wait_for_input(&mut self) -> FsmInput {
        let hold = deadline_fut(self.hold_deadline);
        let keepalive = deadline_fut(self.keepalive_deadline);
        let retry = deadline_fut(self.retry_deadline);

        tokio::select! {
            biased;

            cmd = self.cmd_rx.recv() => match cmd {
                Some(SessionCommand::Start) => FsmInput::ManualStart,
                // None = handle dropped → treat as operator stop.
                Some(SessionCommand::Stop) | None => FsmInput::ManualStop,
            },

            result = recv_connect(&mut self.connect_task) => {
                self.connect_task = None;
                match result {
                    Ok(stream) => {
                        let (r, w) = stream.into_split();
                        self.reader = Some(FramedRead::new(r, BgpCodec));
                        self.writer = Some(FramedWrite::new(w, BgpCodec));
                        FsmInput::TcpConnected
                    }
                    Err(_) => FsmInput::TcpFailed,
                }
            }

            msg = recv_message(&mut self.reader) => {
                if let Some(Ok(m)) = msg {
                    return FsmInput::MessageReceived(m);
                }
                self.drop_connection();
                FsmInput::TcpFailed
            }

            () = hold => {
                self.hold_deadline = None;
                FsmInput::HoldTimerExpired
            }

            () = keepalive => {
                self.keepalive_deadline = None;
                FsmInput::KeepaliveTimerExpired
            }

            () = retry => {
                self.retry_deadline = None;
                FsmInput::ConnectRetryTimerExpired
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
                    let addr = self.config.peer_addr;
                    self.connect_task =
                        Some(tokio::spawn(async move { TcpStream::connect(addr).await }));
                }
                FsmOutput::CloseTcpConnection => {
                    self.drop_connection();
                }
                FsmOutput::SendMessage(msg) => {
                    if let Some(w) = &mut self.writer {
                        if w.send(msg).await.is_err() {
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
        self.reader = None;
        self.writer = None;
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

/// Resolves with the next decoded message, or never if not connected.
async fn recv_message(
    reader: &mut Option<FramedRead<OwnedReadHalf, BgpCodec>>,
) -> Option<Result<BgpMessage, FramingError>> {
    match reader {
        Some(r) => r.next().await,
        None => std::future::pending().await,
    }
}
