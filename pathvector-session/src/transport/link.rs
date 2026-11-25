//! The BGP message I/O port and one connection's write state.
//!
//! The session never waits for a write. A [`BgpWriter`] buffers a message
//! without blocking and is flushed concurrently with everything else the
//! session loop is waiting for, so a peer that stops reading cannot stop the
//! session reading, serving commands or running its timers.

use std::future::Future;
use std::io;

use bytes::{Buf, BytesMut};
use futures::{FutureExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{Encoder, FramedRead};

use crate::framing::{BgpCodec, FramingError};
use crate::message::{AsnWidth, BgpMessage, RouteRefreshMessage};

// ── Port traits ──────────────────────────────────────────────────────────────

/// A connected BGP message channel, split into the two directions the session
/// drives independently.
pub trait BgpTransport: Send + 'static {
    /// The receiving direction.
    type Reader: BgpReader;
    /// The sending direction.
    type Writer: BgpWriter;

    /// Split into the two directions.
    fn into_split(self) -> (Self::Reader, Self::Writer);
}

/// The receiving direction of a [`BgpTransport`].
pub trait BgpReader: Send + 'static {
    /// Read the next decoded BGP message from the peer. Returns `None` when
    /// the connection has closed cleanly.
    ///
    /// Must be cancel safe: the session drops this future whenever something
    /// else needs it first, and no message may be lost when it does.
    fn recv(
        &mut self,
    ) -> impl Future<Output = Option<Result<BgpMessage, FramingError>>> + Send + '_;

    /// Raise (or lower) the message size limit after Extended Message capability
    /// (RFC 8654) is negotiated. Default implementation is a no-op.
    fn set_extended_message(&mut self, _enabled: bool) {}

    /// Set the width of AS numbers on this session (RFC 6793 §4) for decoding
    /// received UPDATEs. Default implementation is a no-op.
    fn set_asn_width(&mut self, _width: AsnWidth) {}
}

/// The sending direction of a [`BgpTransport`].
pub trait BgpWriter: Send + 'static {
    /// Encode and buffer one message without waiting, and return how many
    /// bytes it added. The session limits how much it queues before it waits
    /// for [`Self::flush`].
    ///
    /// # Errors
    ///
    /// If the connection is already known to be broken or the message cannot be
    /// encoded.
    fn queue(&mut self, msg: BgpMessage) -> io::Result<usize>;

    /// Write everything queued.
    ///
    /// Must be cancel safe: when this future is dropped, unwritten bytes stay
    /// queued and the next call carries on from them.
    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + Send + '_;

    /// Set the width of AS numbers for encoding queued UPDATEs (RFC 6793 §4).
    /// Default implementation is a no-op.
    fn set_asn_width(&mut self, _width: AsnWidth) {}

    /// The connection is about to be dropped with data still unwritten:
    /// discard it rather than leave the kernel trying to deliver it to a peer
    /// that is not reading. Default implementation is a no-op.
    fn abort(&mut self) {}
}

// ── Production transport ─────────────────────────────────────────────────────

pub(super) struct FramedBgpTransport {
    reader: SocketReader,
    writer: SocketWriter,
}

impl FramedBgpTransport {
    pub(super) fn from_stream(stream: TcpStream) -> Self {
        let (r, w) = stream.into_split();
        Self {
            reader: SocketReader(FramedRead::new(r, BgpCodec::new())),
            writer: SocketWriter {
                half: w,
                codec: BgpCodec::new(),
                buf: BytesMut::new(),
            },
        }
    }
}

impl BgpTransport for FramedBgpTransport {
    type Reader = SocketReader;
    type Writer = SocketWriter;

    fn into_split(self) -> (SocketReader, SocketWriter) {
        (self.reader, self.writer)
    }
}

/// Lets tests use a `FramedBgpTransport` as the remote end of a connection.
#[cfg(test)]
impl FramedBgpTransport {
    pub(super) async fn send(&mut self, msg: BgpMessage) -> io::Result<()> {
        self.writer.queue(msg)?;
        self.writer.flush().await
    }

    pub(super) async fn recv(&mut self) -> Option<Result<BgpMessage, FramingError>> {
        self.reader.recv().await
    }

    /// Shut down the local write half, so that the next write fails.
    pub(super) async fn shutdown_write(&mut self) -> io::Result<()> {
        self.writer.half.shutdown().await
    }
}

pub(super) struct SocketReader(FramedRead<OwnedReadHalf, BgpCodec>);

impl BgpReader for SocketReader {
    async fn recv(&mut self) -> Option<Result<BgpMessage, FramingError>> {
        self.0.next().await
    }

    fn set_extended_message(&mut self, enabled: bool) {
        self.0.decoder_mut().set_extended_message(enabled);
    }

    fn set_asn_width(&mut self, width: AsnWidth) {
        self.0.decoder_mut().set_asn_width(width);
    }
}

pub(super) struct SocketWriter {
    half: OwnedWriteHalf,
    // A separate codec instance from the reader's: it must be told the ASN
    // width too, or the outbound side would keep encoding four-octet ASNs to an
    // OLD peer.
    codec: BgpCodec,
    buf: BytesMut,
}

impl BgpWriter for SocketWriter {
    fn queue(&mut self, msg: BgpMessage) -> io::Result<usize> {
        let before = self.buf.len();
        self.codec.encode(msg, &mut self.buf)?;
        Ok(self.buf.len() - before)
    }

    async fn flush(&mut self) -> io::Result<()> {
        while self.buf.has_remaining() {
            // `write_buf` is cancel safe: it has either written and advanced
            // `buf`, or written nothing.
            if self.half.write_buf(&mut self.buf).await? == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
        }
        Ok(())
    }

    fn set_asn_width(&mut self, width: AsnWidth) {
        self.codec.set_asn_width(width);
    }

    fn abort(&mut self) {
        // A zero linger makes close() reset the connection and free the send
        // buffer, instead of retrying it against a closed window.
        let stream: &TcpStream = self.half.as_ref();
        if let Err(e) = socket2::SockRef::from(stream).set_linger(Some(std::time::Duration::ZERO)) {
            tracing::debug!(error = %e, "could not set zero linger on a stalled connection");
        }
    }
}

// ── Connection state ─────────────────────────────────────────────────────────

/// Poll `future` once and return its output if it is already ready.
///
/// Runs outside tokio's cooperative budget: an exhausted budget would report a
/// ready socket as pending.
pub(super) fn ready_now<F: Future>(future: F) -> Option<F::Output> {
    tokio::task::unconstrained(future).now_or_never()
}

/// A writer plus what it still has to write.
pub(super) struct Outbound<W> {
    writer: W,
    flushing: bool,
    // Set when queued messages have been written out.
    sent: bool,
    // Idempotent messages already waiting in the buffer. Queuing another copy
    // behind them would grow the buffer without telling the peer anything.
    keepalive_waiting: bool,
    refresh_waiting: Vec<RouteRefreshMessage>,
}

impl<W: BgpWriter> Outbound<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            flushing: false,
            sent: false,
            keepalive_waiting: false,
            refresh_waiting: Vec::new(),
        }
    }

    /// Whether queued bytes are still waiting to be written.
    pub(super) fn is_flushing(&self) -> bool {
        self.flushing
    }

    /// Buffer `msg`, returning the bytes added. A KEEPALIVE or ROUTE-REFRESH
    /// identical to one still waiting to be written adds nothing.
    pub(super) fn queue(&mut self, msg: BgpMessage) -> io::Result<usize> {
        match &msg {
            BgpMessage::Keepalive => {
                if std::mem::replace(&mut self.keepalive_waiting, true) {
                    return Ok(0);
                }
            }
            BgpMessage::RouteRefresh(rr) => {
                if self.refresh_waiting.contains(rr) {
                    return Ok(0);
                }
                self.refresh_waiting.push(rr.clone());
            }
            _ => {}
        }
        let added = self.writer.queue(msg)?;
        self.flushing = true;
        Ok(added)
    }

    /// Write everything queued. Cancel safe.
    pub(super) async fn flush(&mut self) -> io::Result<()> {
        self.writer.flush().await?;
        self.sent |= self.flushing;
        self.flushing = false;
        self.keepalive_waiting = false;
        self.refresh_waiting.clear();
        Ok(())
    }

    /// Whether messages were written out since the last call.
    pub(super) fn take_sent(&mut self) -> bool {
        std::mem::take(&mut self.sent)
    }

    /// Write as much as can be written without waiting. `None` if some is left.
    pub(super) fn try_flush(&mut self) -> Option<io::Result<()>> {
        ready_now(self.flush())
    }

    pub(super) fn set_asn_width(&mut self, width: AsnWidth) {
        self.writer.set_asn_width(width);
    }

    pub(super) fn abort(&mut self) {
        self.writer.abort();
    }
}

/// One connection.
pub(super) struct Link<T: BgpTransport> {
    pub(super) reader: T::Reader,
    pub(super) out: Outbound<T::Writer>,
}

impl<T: BgpTransport> Link<T> {
    pub(super) fn new(transport: T) -> Self {
        let (reader, writer) = transport.into_split();
        Self {
            reader,
            out: Outbound::new(writer),
        }
    }
}
