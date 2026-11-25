//! Simulated BGP peers.
//!
//! Each peer owns one TCP session to `pathvectord`, bound to a specific
//! source address (the daemon identifies peers by source IP). A background
//! reader drains everything the daemon sends — so a slow reader never
//! becomes a confound — while a writer task owns the socket's write half and
//! multiplexes timer-driven KEEPALIVEs with bulk sends, the way a real
//! single-threaded BGP implementation would.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use pathvector_session::message::{BgpMessage, Capability, OpenMessage};
use pathvector_types::AfiSafi;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{sleep_until, timeout},
};

const HEADER_LEN: usize = 19;
const MSG_UPDATE: u8 = 2;
const MSG_NOTIFICATION: u8 = 3;
const MSG_KEEPALIVE: u8 = 4;
const AS_TRANS: u16 = 23456;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Observations about one session, shared between the peer's tasks and the
/// scenario code reading them.
pub struct PeerStats {
    pub updates_rx: AtomicU64,
    pub keepalives_rx: AtomicU64,
    pub bytes_rx: AtomicU64,
    /// When the session ended (EOF, error, or NOTIFICATION), if it has.
    closed_at: Mutex<Option<Instant>>,
    /// `(error code, subcode)` of a NOTIFICATION the daemon sent us.
    notification: Mutex<Option<(u8, u8)>>,
    /// Arrival time of every message after the handshake, when
    /// `record_arrivals` is on.
    arrivals: Mutex<Vec<Instant>>,
    record_arrivals: bool,
    /// When the handshake completed.
    established_at: Instant,
}

impl PeerStats {
    /// Created as the handshake completes, which fixes
    /// [`established_at`](Self::established_at).
    fn new(record_arrivals: bool) -> Self {
        Self {
            updates_rx: AtomicU64::new(0),
            keepalives_rx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            closed_at: Mutex::new(None),
            notification: Mutex::new(None),
            arrivals: Mutex::new(Vec::new()),
            record_arrivals,
            established_at: Instant::now(),
        }
    }

    /// When the KEEPALIVE that completed the handshake arrived: the point from
    /// which the daemon's silence is measured.
    #[must_use]
    pub fn established_at(&self) -> Instant {
        self.established_at
    }

    /// Whether the session has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed_at.lock().unwrap().is_some()
    }

    /// When the session ended, if it has.
    #[must_use]
    pub fn closed_at(&self) -> Option<Instant> {
        *self.closed_at.lock().unwrap()
    }

    /// `(code, subcode)` of a NOTIFICATION received from the daemon.
    #[must_use]
    pub fn notification(&self) -> Option<(u8, u8)> {
        *self.notification.lock().unwrap()
    }

    /// Arrival times recorded so far (empty unless recording is enabled).
    #[must_use]
    pub fn arrivals(&self) -> Vec<Instant> {
        self.arrivals.lock().unwrap().clone()
    }

    fn mark_closed(&self) {
        let mut c = self.closed_at.lock().unwrap();
        if c.is_none() {
            *c = Some(Instant::now());
        }
    }
}

/// A bulk send queued for the writer task.
struct SendJob {
    msgs: Arc<Vec<Vec<u8>>>,
    done: oneshot::Sender<io::Result<Duration>>,
}

/// A live simulated peer session.
pub struct PeerHandle {
    pub name: String,
    pub stats: Arc<PeerStats>,
    tx: mpsc::Sender<SendJob>,
    writer: JoinHandle<()>,
    reader: JoinHandle<()>,
}

impl PeerHandle {
    /// Connects from `src` to `dst`, completes the OPEN/KEEPALIVE handshake,
    /// and starts the reader and keepalive-aware writer tasks.
    ///
    /// `hold` is offered in our OPEN; KEEPALIVEs go out every `hold / 3`
    /// regardless of what the bulk sender is doing. With `record_arrivals`,
    /// every received message's arrival time is kept (used by the control
    /// peer to measure the daemon's keepalive spacing).
    ///
    /// # Errors
    ///
    /// Fails on bind/connect error, handshake timeout, or a NOTIFICATION
    /// during the handshake.
    pub async fn connect(
        name: &str,
        src: Ipv4Addr,
        dst: SocketAddr,
        my_as: u32,
        hold: u16,
        record_arrivals: bool,
    ) -> io::Result<Self> {
        let sock = TcpSocket::new_v4()?;
        sock.bind(SocketAddr::from((src, 0)))?;
        let stream = sock.connect(dst).await?;
        stream.set_nodelay(true)?;
        let (mut rd, mut wr) = stream.into_split();

        timeout(
            HANDSHAKE_TIMEOUT,
            handshake(&mut rd, &mut wr, src, my_as, hold),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "BGP handshake timed out"))??;

        let stats = Arc::new(PeerStats::new(record_arrivals));
        let (tx, rx) = mpsc::channel(4);
        let ka_interval = Duration::from_secs(u64::from((hold / 3).max(1)));

        let reader = tokio::spawn(reader_task(rd, Arc::clone(&stats)));
        let writer = tokio::spawn(writer_task(wr, rx, ka_interval, Arc::clone(&stats)));

        Ok(Self {
            name: name.to_string(),
            stats,
            tx,
            writer,
            reader,
        })
    }

    /// Writes every message in `msgs` in order (interleaving KEEPALIVEs on
    /// schedule) and returns how long the whole send took. Resolves when the
    /// last byte has been handed to the kernel — i.e. once the daemon has
    /// *read* it, since TCP backpressure stalls the write otherwise.
    ///
    /// # Errors
    ///
    /// Returns the write error if the session died mid-send, or `TimedOut` if
    /// the send is not finished within `deadline` — a daemon that has stopped
    /// reading would otherwise park the write forever. The session is unusable
    /// after a timeout.
    pub async fn send_all(
        &self,
        msgs: Arc<Vec<Vec<u8>>>,
        deadline: Duration,
    ) -> io::Result<Duration> {
        let send = async {
            let ended = || io::Error::new(io::ErrorKind::BrokenPipe, "peer writer task ended");
            let (done, rx) = oneshot::channel();
            self.tx
                .send(SendJob { msgs, done })
                .await
                .map_err(|_| ended())?;
            rx.await.map_err(|_| ended())?
        };
        if let Ok(result) = timeout(deadline, send).await {
            return result;
        }
        // The writer is stuck inside `write_all` and may have sent part of a
        // message, so nothing more can be written on this session.
        self.writer.abort();
        self.stats.mark_closed();
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("send timed out after {deadline:?}: the daemon stopped reading this session"),
        ))
    }

    /// Drops the TCP connection without any NOTIFICATION — the abrupt
    /// teardown a crashed peer or severed link produces.
    pub async fn close_abruptly(self) {
        // Abort rather than ask: a writer blocked on a daemon that is not
        // reading would never see a request to close.
        self.writer.abort();
        let _ = self.writer.await;
        self.reader.abort();
        self.stats.mark_closed();
    }
}

async fn handshake(
    rd: &mut OwnedReadHalf,
    wr: &mut OwnedWriteHalf,
    router_id: Ipv4Addr,
    my_as: u32,
    hold: u16,
) -> io::Result<()> {
    let my_as_wire = u16::try_from(my_as).unwrap_or(AS_TRANS);
    let open = BgpMessage::Open(OpenMessage {
        version: 4,
        my_as: my_as_wire,
        hold_time: hold,
        bgp_id: router_id,
        capabilities: vec![
            Capability::FourByteAsn(my_as),
            Capability::MultiProtocol(AfiSafi::IPV4_UNICAST),
        ],
    });
    wr.write_all(&open.encode()).await?;

    let (ty, _) = read_msg(rd).await?;
    if ty != 1 {
        return Err(io::Error::other(format!(
            "expected OPEN, got message type {ty}"
        )));
    }
    wr.write_all(&BgpMessage::Keepalive.encode()).await?;

    loop {
        let (ty, body) = read_msg(rd).await?;
        match ty {
            MSG_KEEPALIVE => return Ok(()),
            MSG_NOTIFICATION => {
                return Err(io::Error::other(format!(
                    "daemon sent NOTIFICATION during handshake: code/subcode {:?}",
                    body.get(..2)
                )));
            }
            _ => {}
        }
    }
}

/// Reads one BGP message, returning `(type, body)`.
async fn read_msg(rd: &mut OwnedReadHalf) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; HEADER_LEN];
    rd.read_exact(&mut header).await?;
    let total = usize::from(u16::from_be_bytes([header[16], header[17]]));
    if total < HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("BGP length {total} < {HEADER_LEN}"),
        ));
    }
    let mut body = vec![0u8; total - HEADER_LEN];
    rd.read_exact(&mut body).await?;
    Ok((header[18], body))
}

async fn reader_task(mut rd: OwnedReadHalf, stats: Arc<PeerStats>) {
    loop {
        let Ok((ty, body)) = read_msg(&mut rd).await else {
            stats.mark_closed();
            return;
        };
        if stats.record_arrivals {
            stats.arrivals.lock().unwrap().push(Instant::now());
        }
        stats
            .bytes_rx
            .fetch_add((HEADER_LEN + body.len()) as u64, Ordering::Relaxed);
        match ty {
            MSG_UPDATE => {
                stats.updates_rx.fetch_add(1, Ordering::Relaxed);
            }
            MSG_KEEPALIVE => {
                stats.keepalives_rx.fetch_add(1, Ordering::Relaxed);
            }
            MSG_NOTIFICATION => {
                if let [code, sub, ..] = body[..] {
                    *stats.notification.lock().unwrap() = Some((code, sub));
                }
                stats.mark_closed();
                return;
            }
            _ => {}
        }
    }
}

/// Owns the write half. Sends KEEPALIVEs every `ka_interval` — measured from
/// the last write of any kind — and executes bulk-send commands, checking the
/// keepalive deadline between every message so a long blast cannot starve it
/// (unless the socket itself is back-pressured, which is the daemon's doing).
async fn writer_task(
    mut wr: OwnedWriteHalf,
    mut rx: mpsc::Receiver<SendJob>,
    ka_interval: Duration,
    stats: Arc<PeerStats>,
) {
    let keepalive = BgpMessage::Keepalive.encode();
    let mut last_write = tokio::time::Instant::now();

    loop {
        tokio::select! {
            job = rx.recv() => {
                let Some(SendJob { msgs, done }) = job else {
                    return;
                };
                let started = Instant::now();
                let mut result = Ok(());
                for m in msgs.iter() {
                    if last_write.elapsed() >= ka_interval {
                        if let Err(e) = wr.write_all(&keepalive).await {
                            result = Err(e);
                            break;
                        }
                        last_write = tokio::time::Instant::now();
                    }
                    if let Err(e) = wr.write_all(m).await {
                        result = Err(e);
                        break;
                    }
                    last_write = tokio::time::Instant::now();
                }
                let failed = result.is_err();
                let _ = done.send(result.map(|()| started.elapsed()));
                if failed {
                    stats.mark_closed();
                    return;
                }
            }
            () = sleep_until(last_write + ka_interval) => {
                if wr.write_all(&keepalive).await.is_err() {
                    stats.mark_closed();
                    return;
                }
                last_write = tokio::time::Instant::now();
            }
        }
    }
}
