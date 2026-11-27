//! Encoded messages on their way into a byte stream, and where each one ends.
//!
//! RFC 9687 §4.3 restarts the `SendHoldTimer` "[e]ach time the local system
//! sends a BGP message". A stream takes bytes, in pieces of any size, so the
//! boundaries have to be kept here: a message is sent when its last byte has
//! been written, and bytes of an unfinished one are not.

use std::collections::VecDeque;
use std::io;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::codec::Encoder;

use super::link::MessagesWritten;
use crate::framing::BgpCodec;
use crate::message::{AsnWidth, BgpMessage};

/// The write buffer of one byte stream.
pub(super) struct MessageSink<W> {
    io: W,
    // A separate codec instance from the reader's: it must be told the ASN
    // width too, or the outbound side would keep encoding four-octet ASNs to an
    // OLD peer.
    codec: BgpCodec,
    buf: BytesMut,
    // Bytes of each queued message still in `buf`, oldest first.
    unwritten: VecDeque<usize>,
}

impl<W: AsyncWrite + Unpin + Send> MessageSink<W> {
    pub(super) fn new(io: W) -> Self {
        Self {
            io,
            codec: BgpCodec::new(),
            buf: BytesMut::new(),
            unwritten: VecDeque::new(),
        }
    }

    pub(super) fn io(&self) -> &W {
        &self.io
    }

    #[cfg(test)]
    pub(super) fn io_mut(&mut self) -> &mut W {
        &mut self.io
    }

    pub(super) fn set_asn_width(&mut self, width: AsnWidth) {
        self.codec.set_asn_width(width);
    }

    /// See [`super::BgpWriter::queue`].
    pub(super) fn queue(&mut self, msg: BgpMessage) -> io::Result<usize> {
        let before = self.buf.len();
        self.codec.encode(msg, &mut self.buf)?;
        let added = self.buf.len() - before;
        self.unwritten.push_back(added);
        Ok(added)
    }

    /// See [`super::BgpWriter::flush`].
    pub(super) async fn flush(&mut self) -> io::Result<MessagesWritten> {
        while self.buf.has_remaining() {
            // `write_buf` is cancel safe: it has either written and advanced
            // `buf`, or written nothing. Nothing is awaited between its return
            // and the accounting, so that cannot be skipped either.
            let written = self.io.write_buf(&mut self.buf).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            let whole = self.complete(written);
            if whole > 0 {
                return Ok(MessagesWritten(whole));
            }
        }
        Ok(MessagesWritten(0))
    }

    /// Account for `written` bytes: how many messages they finished.
    fn complete(&mut self, mut written: usize) -> usize {
        let mut whole = 0;
        while let Some(left) = self.unwritten.front_mut() {
            if written < *left {
                *left -= written;
                break;
            }
            written -= *left;
            self.unwritten.pop_front();
            whole += 1;
        }
        whole
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures::FutureExt;
    use proptest::prelude::*;

    use super::*;
    use crate::message::{CeaseError, NotificationError, NotificationMessage, RouteRefreshMessage};
    use pathvector_types::AfiSafi;

    /// A stream that takes `room` more bytes and then blocks. Nothing wakes a
    /// blocked write, so tests poll the sink once and look.
    #[derive(Default)]
    struct Window {
        taken: Vec<u8>,
        room: usize,
    }

    impl AsyncWrite for Window {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = data.len().min(self.room);
            if n == 0 {
                return Poll::Pending;
            }
            self.room -= n;
            self.taken.extend_from_slice(&data[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Open the window by `bytes` and write what fits: how many messages that
    /// finished, over as many calls as the sink takes to report them.
    fn open(sink: &mut MessageSink<Window>, bytes: usize) -> usize {
        sink.io_mut().room += bytes;
        let mut whole = 0;
        loop {
            match sink.flush().now_or_never() {
                Some(Ok(MessagesWritten(0))) | None => return whole,
                Some(Ok(MessagesWritten(n))) => whole += n,
                Some(Err(e)) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn a_message_is_reported_when_its_last_byte_is_written() {
        let mut sink = MessageSink::new(Window::default());
        let first = sink.queue(BgpMessage::Keepalive).unwrap();
        let second = sink.queue(BgpMessage::Keepalive).unwrap();

        assert_eq!(open(&mut sink, first - 1), 0);
        assert_eq!(open(&mut sink, 1), 1);
        assert_eq!(open(&mut sink, second - 1), 0);
        assert_eq!(open(&mut sink, 1), 1);
    }

    #[test]
    fn a_message_queued_behind_a_partly_written_one_keeps_both_boundaries() {
        let mut sink = MessageSink::new(Window::default());
        let first = sink.queue(BgpMessage::Keepalive).unwrap();
        assert_eq!(open(&mut sink, first / 2), 0);

        let refresh = RouteRefreshMessage::new(AfiSafi::IPV4_UNICAST);
        let second = sink.queue(BgpMessage::RouteRefresh(refresh)).unwrap();
        assert_eq!(open(&mut sink, first - first / 2 + second - 1), 1);
        assert_eq!(open(&mut sink, 1), 1);
    }

    /// The report must not wait for the rest of the buffer.
    #[test]
    fn flush_resolves_once_a_message_is_out_with_more_still_blocked() {
        let mut sink = MessageSink::new(Window::default());
        let first = sink.queue(BgpMessage::Keepalive).unwrap();
        sink.queue(BgpMessage::Keepalive).unwrap();
        sink.io_mut().room = first + 1;

        let report = sink.flush().now_or_never().map(Result::unwrap);
        assert_eq!(report, Some(MessagesWritten(1)));
        assert!(sink.flush().now_or_never().is_none());
    }

    fn arbitrary_message() -> impl Strategy<Value = BgpMessage> {
        prop_oneof![
            Just(BgpMessage::Keepalive),
            Just(BgpMessage::RouteRefresh(RouteRefreshMessage::new(
                AfiSafi::IPV4_UNICAST
            ))),
            proptest::collection::vec(any::<u8>(), 0..200).prop_map(|data| {
                BgpMessage::Notification(NotificationMessage {
                    error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                    data,
                })
            }),
        ]
    }

    /// Queue a message, or let the stream take some bytes.
    #[derive(Debug, Clone)]
    enum Step {
        Queue(BgpMessage),
        Open(usize),
    }

    fn arbitrary_step() -> impl Strategy<Value = Step> {
        prop_oneof![
            arbitrary_message().prop_map(Step::Queue),
            (1usize..300).prop_map(Step::Open),
        ]
    }

    proptest! {
        /// Whatever the sizes of the messages and of the writes, and however
        /// queuing interleaves with writing: the stream receives the messages'
        /// bytes in order, and the number reported so far is always the number
        /// whose last byte it has.
        #[test]
        fn prop_reported_messages_are_exactly_those_fully_written(
            steps in proptest::collection::vec(arbitrary_step(), 1..60),
        ) {
            let mut sink = MessageSink::new(Window::default());
            let mut expected = Vec::new();
            let mut ends = Vec::new();
            let mut reported = 0;
            for step in steps.into_iter().chain([Step::Open(usize::MAX / 2)]) {
                match step {
                    Step::Queue(msg) => {
                        expected.extend_from_slice(&msg.encode());
                        ends.push(expected.len());
                        sink.queue(msg).unwrap();
                    }
                    Step::Open(bytes) => {
                        // Room left over from before is replaced, not added to.
                        sink.io_mut().room = 0;
                        reported += open(&mut sink, bytes);
                    }
                }
                let taken = &sink.io().taken;
                prop_assert_eq!(taken.as_slice(), &expected[..taken.len()]);
                let whole = ends.iter().filter(|&&end| end <= taken.len()).count();
                prop_assert_eq!(reported, whole);
            }
            prop_assert_eq!(reported, ends.len());
        }
    }
}
