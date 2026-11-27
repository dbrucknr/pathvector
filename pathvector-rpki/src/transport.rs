//! The byte-stream adapter: one RTR connection, PDUs in and out.
//!
//! All framing state lives in the [`Connection`] (in its [`FrameDecoder`]),
//! never in a read future, so [`Connection::read_frame`] can be abandoned at
//! any await point and called again without losing a byte. That matters
//! because the session loop races it against the RFC 8210 §6 Refresh Interval
//! timer.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    error::RtrError,
    frame::{Frame, FrameDecoder, FrameError},
    pdu::{self, Pdu, RtrVersion},
};

/// Most one `read` takes from the socket. A full load is hundreds of
/// thousands of 20- and 32-byte PDUs, so reading in bulk replaces two system
/// calls per record with one per several hundred.
const READ_CHUNK: usize = 16 * 1024;

/// Why no PDU could be read.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// The connection failed or closed; there is nobody to report to.
    Transport(RtrError),
    /// The peer sent bytes that cannot be decoded.
    Malformed(FrameError),
}

/// One RTR connection over any byte stream.
pub(crate) struct Connection<S> {
    stream: S,
    decoder: FrameDecoder,
    chunk: Box<[u8]>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::new(),
            chunk: vec![0; READ_CHUNK].into_boxed_slice(),
        }
    }

    /// The next PDU from the peer.
    ///
    /// **Cancellation safe**: if this future is dropped, every byte already
    /// received stays buffered in the connection and the next call resumes
    /// where this one stopped. Both await points preserve that —
    /// `consume_budget` runs before anything is taken from the decoder, and
    /// `read` either completes with data (pushed before the next await) or
    /// reads nothing.
    ///
    /// # Errors
    ///
    /// [`ReadError::Transport`] with [`RtrError::Closed`] at end of stream
    /// (including mid-PDU) or [`RtrError::Io`]; [`ReadError::Malformed`] for
    /// bytes that are not a PDU.
    pub(crate) async fn read_frame(&mut self) -> Result<Frame, ReadError> {
        loop {
            // Frames already buffered are returned without touching the
            // socket; stay a cooperative task while working through them.
            tokio::task::consume_budget().await;
            if let Some(frame) = self.decoder.next_frame().map_err(ReadError::Malformed)? {
                return Ok(frame);
            }
            let n = self
                .stream
                .read(&mut self.chunk)
                .await
                .map_err(|e| ReadError::Transport(RtrError::Io(e)))?;
            if n == 0 {
                return Err(ReadError::Transport(RtrError::Closed));
            }
            self.decoder.push(&self.chunk[..n]);
        }
    }

    /// Steps over a PDU [`read_frame`](Self::read_frame) rejected that the
    /// protocol says to ignore.
    pub(crate) fn skip(&mut self, rejected: &FrameError) {
        self.decoder.skip(rejected);
    }

    /// Sends one PDU.
    ///
    /// # Errors
    ///
    /// [`RtrError::Io`] if the stream cannot be written.
    pub(crate) async fn write_pdu(
        &mut self,
        version: RtrVersion,
        pdu: &Pdu,
    ) -> Result<(), RtrError> {
        write_pdu(&mut self.stream, version, pdu).await
    }
}

/// Encodes and writes one PDU.
///
/// # Errors
///
/// [`RtrError::Io`] if the stream cannot be written.
pub(crate) async fn write_pdu<W: AsyncWrite + Unpin>(
    stream: &mut W,
    version: RtrVersion,
    pdu: &Pdu,
) -> Result<(), RtrError> {
    stream.write_all(&pdu::encode(version, pdu)).await?;
    Ok(())
}

/// Reads exactly one PDU and not a byte more, for the scripted servers in
/// tests, which hold a bare stream rather than a [`Connection`].
#[cfg(test)]
pub(crate) async fn read_pdu<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(RtrVersion, Pdu), RtrError> {
    let mut decoder = FrameDecoder::new();
    loop {
        if let Some(frame) = decoder.next_frame().map_err(|e| RtrError::Pdu(e.error))? {
            return Ok((frame.version, frame.pdu));
        }
        let mut chunk = vec![0; decoder.needed()];
        match stream.read(&mut chunk).await? {
            0 => return Err(RtrError::Closed),
            n => decoder.push(&chunk[..n]),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::pin, task::Context, task::Poll, task::Waker};

    use proptest::prelude::*;
    use tokio::io::{DuplexStream, duplex};

    use super::*;
    use crate::pdu::EndOfDataIntervals;

    /// Several consecutive PDUs of one version.
    fn pdus(version: RtrVersion) -> Vec<Pdu> {
        let intervals = (version == RtrVersion::V1).then_some(EndOfDataIntervals {
            refresh: 3600,
            retry: 600,
            expire: 7200,
        });
        vec![
            Pdu::SerialNotify {
                session_id: 7,
                serial: 2,
            },
            Pdu::CacheResponse { session_id: 7 },
            Pdu::announce_v4("192.0.2.0".parse().unwrap(), 24, 24, 65001),
            Pdu::EndOfData {
                session_id: 7,
                serial: 2,
                intervals,
            },
        ]
    }

    /// Starts a `read_frame`, polls it once, then drops it — what `select!`
    /// does to the read when the timer wins. Returns the frame if the poll
    /// completed one.
    fn poll_once_and_cancel(connection: &mut Connection<DuplexStream>) -> Option<Frame> {
        // `unconstrained`: this helper polls far more often than the
        // cooperative budget of one task turn allows, and here `Pending` must
        // mean "waiting for bytes". Cancellation at the budget's own await
        // point is covered separately below.
        let mut read = pin!(tokio::task::unconstrained(connection.read_frame()));
        match read.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => Some(result.unwrap()),
            Poll::Pending => None,
        }
    }

    /// Delivers `bytes` in pieces cut at `cuts`, cancelling a read after
    /// every piece (and again with nothing new), and returns what came out.
    async fn read_with_cancellations(bytes: &[u8], cuts: &[usize]) -> Vec<(RtrVersion, Pdu)> {
        let (mut server, client) = duplex(64 * 1024);
        let mut connection = Connection::new(client);
        let mut got = Vec::new();
        let mut sent = 0;
        for &cut in cuts.iter().chain([&bytes.len()]) {
            server.write_all(&bytes[sent..cut]).await.unwrap();
            sent = cut;
            while let Some(frame) = poll_once_and_cancel(&mut connection) {
                got.push((frame.version, frame.pdu));
            }
        }
        got
    }

    fn encoded(version: RtrVersion) -> (Vec<(RtrVersion, Pdu)>, Vec<u8>) {
        let expected: Vec<_> = pdus(version).into_iter().map(|p| (version, p)).collect();
        let bytes = expected
            .iter()
            .flat_map(|(v, p)| pdu::encode(*v, p))
            .collect();
        (expected, bytes)
    }

    /// Every offset of every header and body, both protocol versions.
    #[tokio::test]
    async fn cancelling_at_every_byte_offset_loses_nothing() {
        for version in [RtrVersion::V0, RtrVersion::V1] {
            let (expected, bytes) = encoded(version);
            for split in 0..=bytes.len() {
                assert_eq!(
                    read_with_cancellations(&bytes, &[split]).await,
                    expected,
                    "{version:?}, cancelled after {split} bytes"
                );
            }
        }
    }

    #[tokio::test]
    async fn cancelling_after_every_single_byte_loses_nothing() {
        let (expected, bytes) = encoded(RtrVersion::V1);
        let every: Vec<usize> = (1..bytes.len()).collect();
        assert_eq!(read_with_cancellations(&bytes, &every).await, expected);
    }

    /// The other await point: with the task's cooperative budget exhausted,
    /// `read_frame` suspends before touching the decoder. Cancelling there
    /// must not skip or repeat a PDU either.
    #[tokio::test]
    async fn cancelling_while_out_of_budget_loses_nothing() {
        let (mut server, client) = duplex(READ_CHUNK);
        let mut connection = Connection::new(client);
        let count: u32 = 600; // several budgets' worth
        let bytes: Vec<u8> = (0..count)
            .flat_map(|serial| {
                pdu::encode(
                    RtrVersion::V1,
                    &Pdu::SerialNotify {
                        session_id: 1,
                        serial,
                    },
                )
            })
            .collect();
        server.write_all(&bytes).await.unwrap();

        let mut serials = Vec::new();
        let mut cancelled = 0;
        while serials.len() < count as usize {
            let polled = {
                let mut read = pin!(connection.read_frame());
                std::future::poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await
            };
            match polled {
                Poll::Ready(result) => match result.unwrap().pdu {
                    Pdu::SerialNotify { serial, .. } => serials.push(serial),
                    other => panic!("unexpected {other:?}"),
                },
                Poll::Pending => {
                    cancelled += 1;
                    tokio::task::yield_now().await;
                }
            }
        }
        assert!(cancelled > 0, "the budget await point was never exercised");
        assert_eq!(serials, (0..count).collect::<Vec<_>>());
    }

    proptest! {
        #[test]
        fn cancellation_points_are_not_observable(
            version in prop_oneof![Just(RtrVersion::V0), Just(RtrVersion::V1)],
            mut cuts in prop::collection::vec(0usize..64, 0..12),
        ) {
            let (expected, bytes) = encoded(version);
            for cut in &mut cuts {
                *cut = (*cut).min(bytes.len());
            }
            cuts.sort_unstable();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let got = runtime.block_on(read_with_cancellations(&bytes, &cuts));
            prop_assert_eq!(got, expected);
        }
    }

    #[tokio::test]
    async fn end_of_stream_is_closed_whether_or_not_a_pdu_was_in_progress() {
        for partial in [0, 3, HEADER_AND_SOME] {
            let (mut server, client) = duplex(64);
            let (_, bytes) = encoded(RtrVersion::V1);
            server.write_all(&bytes[..partial]).await.unwrap();
            drop(server);
            let result = Connection::new(client).read_frame().await;
            assert!(
                matches!(result, Err(ReadError::Transport(RtrError::Closed))),
                "{partial} bytes then EOF: {result:?}"
            );
        }
    }

    /// 8 bytes of header plus part of a Serial Notify's body.
    const HEADER_AND_SOME: usize = 10;

    /// Cancellation safety must not come at the price of hogging the thread:
    /// a long run of already-buffered PDUs still yields to other tasks.
    #[tokio::test]
    async fn a_buffered_run_of_pdus_yields_to_other_tasks() {
        let (mut server, client) = duplex(READ_CHUNK);
        let one = pdu::encode(RtrVersion::V1, &Pdu::CacheReset);
        let count = READ_CHUNK / one.len();
        server.write_all(&one.repeat(count)).await.unwrap();
        let reader = tokio::spawn(async move {
            let mut connection = Connection::new(client);
            for _ in 0..count {
                connection.read_frame().await.unwrap();
            }
        });
        let mut turns = 0;
        while !reader.is_finished() {
            turns += 1;
            tokio::task::yield_now().await;
        }
        reader.await.unwrap();
        assert!(turns > 2, "{count} frames were read in {turns} turn(s)");
    }
}
