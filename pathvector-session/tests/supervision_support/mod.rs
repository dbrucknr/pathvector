//! Mock transport and helpers for the deadline-supervision tests.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use pathvector_session::framing::FramingError;
use pathvector_session::message::{
    BgpMessage, Capability, OpenMessage, PathAttribute, UpdateMessage,
};
use pathvector_session::transport::{
    BgpReader, BgpTransport, BgpWriter, DEFAULT_CONNECT_RETRY_TIME, SessionConfig, SessionEvent,
    SessionHandle, SpawnedSessionHandle, spawn_with,
};
use pathvector_types::{Nlri, Origin};

/// One message the session wrote, with when it was written and how many
/// inbound messages the session had read by then.
#[derive(Debug, Clone)]
pub struct Sent {
    pub msg: BgpMessage,
    pub at: Instant,
    pub consumed: usize,
}

pub struct MockTransport {
    reader: MockReader,
    writer: MockWriter,
}

pub struct MockReader {
    inbound: mpsc::UnboundedReceiver<Result<BgpMessage, FramingError>>,
    consumed: Arc<AtomicUsize>,
    _alive: Arc<()>,
}

pub struct MockWriter {
    queued: VecDeque<BgpMessage>,
    sent: mpsc::UnboundedSender<Sent>,
    consumed: Arc<AtomicUsize>,
    writable: watch::Receiver<bool>,
    broken: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
    _alive: Arc<()>,
}

/// The remote end of a [`MockTransport`].
pub struct MockPeer {
    inbound: mpsc::UnboundedSender<Result<BgpMessage, FramingError>>,
    sent: mpsc::UnboundedReceiver<Sent>,
    consumed: Arc<AtomicUsize>,
    writable: watch::Sender<bool>,
    broken: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
    alive: std::sync::Weak<()>,
    log: Mutex<Vec<Sent>>,
}

pub fn mock() -> (MockTransport, MockPeer) {
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    let (writable_tx, writable_rx) = watch::channel(true);
    let consumed = Arc::new(AtomicUsize::new(0));
    let alive = Arc::new(());
    let broken = Arc::new(AtomicBool::new(false));
    let aborted = Arc::new(AtomicBool::new(false));
    let weak = Arc::downgrade(&alive);
    (
        MockTransport {
            reader: MockReader {
                inbound: in_rx,
                consumed: Arc::clone(&consumed),
                _alive: Arc::clone(&alive),
            },
            writer: MockWriter {
                queued: VecDeque::new(),
                sent: sent_tx,
                consumed: Arc::clone(&consumed),
                writable: writable_rx,
                broken: Arc::clone(&broken),
                aborted: Arc::clone(&aborted),
                _alive: alive,
            },
        },
        MockPeer {
            inbound: in_tx,
            sent: sent_rx,
            consumed,
            writable: writable_tx,
            broken,
            aborted,
            alive: weak,
            log: Mutex::new(Vec::new()),
        },
    )
}

impl BgpTransport for MockTransport {
    type Reader = MockReader;
    type Writer = MockWriter;

    fn into_split(self) -> (MockReader, MockWriter) {
        (self.reader, self.writer)
    }
}

impl BgpReader for MockReader {
    async fn recv(&mut self) -> Option<Result<BgpMessage, FramingError>> {
        let msg = self.inbound.recv().await;
        if msg.is_some() {
            self.consumed.fetch_add(1, Ordering::SeqCst);
        }
        msg
    }
}

impl BgpWriter for MockWriter {
    fn queue(&mut self, msg: BgpMessage) -> io::Result<usize> {
        if self.broken.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        // The size a real encoder would produce, so batching is exercised.
        let len = msg.encode().len();
        self.queued.push_back(msg);
        Ok(len)
    }

    async fn flush(&mut self) -> io::Result<()> {
        while !*self.writable.borrow_and_update() {
            if self.writable.changed().await.is_err() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        while let Some(msg) = self.queued.pop_front() {
            let _ = self.sent.send(Sent {
                msg,
                at: Instant::now(),
                consumed: self.consumed.load(Ordering::SeqCst),
            });
        }
        Ok(())
    }

    fn abort(&mut self) {
        self.aborted.store(true, Ordering::SeqCst);
    }
}

impl MockPeer {
    pub fn push(&self, msg: BgpMessage) {
        let _ = self.inbound.send(Ok(msg));
    }

    /// Inbound messages the session has read so far.
    pub fn consumed(&self) -> usize {
        self.consumed.load(Ordering::SeqCst)
    }

    /// `false`: the peer stops reading, so the session's writes block.
    pub fn set_reading(&self, reading: bool) {
        let _ = self.writable.send(reading);
    }

    /// Every further write fails.
    pub fn break_writes(&self) {
        self.broken.store(true, Ordering::SeqCst);
    }

    /// Whether the session discarded unwritten data when it closed.
    pub fn aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }

    /// Whether the session still holds this connection.
    pub fn connection_open(&self) -> bool {
        self.alive.upgrade().is_some()
    }

    /// Forget what the session has written so far.
    pub fn clear_sent(&mut self) {
        self.sent();
        self.log.get_mut().unwrap().clear();
    }

    /// Everything the session has written since the last `clear_sent`.
    pub fn sent(&mut self) -> Vec<Sent> {
        let log = self.log.get_mut().unwrap();
        while let Ok(s) = self.sent.try_recv() {
            log.push(s);
        }
        log.clone()
    }

    pub fn keepalive_times(&mut self) -> Vec<Instant> {
        self.sent()
            .into_iter()
            .filter(|s| matches!(s.msg, BgpMessage::Keepalive))
            .map(|s| s.at)
            .collect()
    }

    pub async fn next_sent(&mut self) -> Sent {
        let s = tokio::time::timeout(Duration::from_secs(5), self.sent.recv())
            .await
            .expect("timed out waiting for the session to write")
            .expect("session dropped the connection");
        self.log.get_mut().unwrap().push(s.clone());
        s
    }
}

pub fn config(hold_time: u16) -> SessionConfig {
    SessionConfig {
        local_as: 65001,
        local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time,
        capabilities: vec![Capability::FourByteAsn(65001), Capability::RouteRefresh],
        required_capabilities: vec![],
        peer_as: Some(65002),
        confederation_member: false,
        public_as: 65001,
        peer_addr: "127.0.0.1:0".parse().unwrap(),
        tcp_md5: None,
        connect_retry_time: DEFAULT_CONNECT_RETRY_TIME,
        send_hold_time: pathvector_session::fsm::SendHoldTime::default(),
    }
}

pub fn peer_open(hold_time: u16) -> BgpMessage {
    BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time,
        bgp_id: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![Capability::FourByteAsn(65002), Capability::RouteRefresh],
    })
}

/// An UPDATE announcing one distinct /32, so order and loss are observable.
pub fn update(n: u32) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        announced: vec![Nlri::new(Ipv4Addr::from(0x0b00_0000 + n), 32).expect("valid /32")],
    }
}

pub fn update_msg(n: u32) -> BgpMessage {
    BgpMessage::Update(update(n))
}

/// Spawn a session with a mock transport and drive it to Established.
pub async fn established(config: SessionConfig) -> (SpawnedSessionHandle, MockPeer) {
    let hold = config.hold_time;
    let (transport, mut peer) = mock();
    let mut handle = spawn_with(config, transport);
    handle.start().await;
    assert!(matches!(peer.next_sent().await.msg, BgpMessage::Open(_)));
    peer.push(peer_open(hold));
    assert!(matches!(peer.next_sent().await.msg, BgpMessage::Keepalive));
    peer.push(BgpMessage::Keepalive);
    let event = next_event(&mut handle).await;
    assert!(matches!(event, SessionEvent::Established(_)), "{event:?}");
    (handle, peer)
}

pub async fn next_event(handle: &mut SpawnedSessionHandle) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(5), handle.next_event())
        .await
        .expect("timed out waiting for a session event")
        .expect("session exited")
}

/// Let every ready task run without moving the paused clock.
pub async fn settle() {
    for _ in 0..2_000 {
        tokio::task::yield_now().await;
    }
}
