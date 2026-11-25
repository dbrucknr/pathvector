//! Incremental RTR framing — bytes in, PDUs out. No sockets, no clocks.
//!
//! RTR runs over a byte stream, and a PDU is delimited only by its own Length
//! field ("the count of the bytes in the entire PDU, including the 8 bytes of
//! header", RFC 8210 §5.1). How the transport segments those bytes means
//! nothing, so every byte received must be kept until the PDU it belongs to is
//! complete.
//!
//! [`FrameDecoder`] owns that state. Because it is an ordinary value rather
//! than the local variables of a read future, abandoning a read (a `select!`
//! branch losing to the refresh timer) cannot lose bytes. The socket side
//! lives in `transport.rs`.
//!
//! # Memory bound
//!
//! A header declaring more than [`MAX_PDU_LEN`] is rejected as soon as its 8
//! bytes arrive. Provided the caller pushes more input only after
//! [`FrameDecoder::next_frame`] has returned `Ok(None)` — which is what
//! "read more" means — the decoder never holds more than `MAX_PDU_LEN - 1`
//! bytes of an incomplete PDU plus one push.

use crate::{
    error::PduError,
    pdu::{self, Pdu, RtrVersion},
};

/// Size of the fixed header every PDU starts with.
pub(crate) const HEADER_LEN: usize = 8;

/// Upper bound on a single PDU's declared length. The largest legitimate
/// PDU in practice is an `ErrorReport` carrying a copy of the offending PDU
/// plus UTF-8 text, or a `RouterKey` carrying an SPKI — neither approaches
/// this. Rejecting anything larger before buffering it closes off a trivial
/// memory-exhaustion vector: without this cap, a misbehaving or compromised
/// RTR server could declare a length near `u32::MAX` and have the client
/// accumulate that much.
pub(crate) const MAX_PDU_LEN: u32 = 64 * 1024;

/// One PDU off the wire: decoded, plus the exact bytes it arrived as (so an
/// Error Report can echo an offending PDU back — RFC 8210 §5.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    /// The Protocol Version byte the PDU actually carried.
    pub(crate) version: RtrVersion,
    pub(crate) pdu: Pdu,
    pub(crate) raw: Vec<u8>,
}

/// The stream does not contain a well-formed PDU at this point.
///
/// There is no way to resynchronise a length-delimited stream after this, so
/// the session has to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrameError {
    pub(crate) error: PduError,
    /// The offending bytes: the whole PDU if its length was usable, otherwise
    /// just the header.
    pub(crate) raw: Vec<u8>,
}

/// Reassembles PDUs from arbitrarily segmented input.
#[derive(Debug, Default)]
pub(crate) struct FrameDecoder {
    buf: Vec<u8>,
    /// Bytes at the front of `buf` already returned as frames. Reclaimed in
    /// one move at the next [`push`](Self::push) rather than per frame.
    consumed: usize,
}

impl FrameDecoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Appends bytes received from the stream.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buf.drain(..self.consumed);
        self.consumed = 0;
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes received but not yet returned as part of a frame.
    fn pending(&self) -> &[u8] {
        &self.buf[self.consumed..]
    }

    /// How many bytes are held back waiting to be returned.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.pending().len()
    }

    /// The smallest number of further bytes that could let
    /// [`next_frame`](Self::next_frame) make progress; 0 if it already can.
    /// Lets a reader that must not over-read (the scripted servers in tests)
    /// take exactly one PDU off a socket.
    #[cfg(test)]
    pub(crate) fn needed(&self) -> usize {
        let pending = self.pending();
        let Some(header) = pending.get(..HEADER_LEN) else {
            return HEADER_LEN - pending.len();
        };
        match check_header(header) {
            Ok(header) => header.len.saturating_sub(pending.len()),
            Err(_) => 0,
        }
    }

    /// Takes the next complete PDU, or `Ok(None)` if more bytes are needed.
    ///
    /// # Errors
    ///
    /// [`FrameError`] as soon as the bytes received so far cannot be a legal
    /// PDU — for a bad header, without waiting for the body. Nothing is
    /// consumed, so every later call reports the same error.
    pub(crate) fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        let pending = self.pending();
        let Some(header) = pending.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let Header {
            version,
            pdu_type,
            field,
            len,
        } = check_header(header).map_err(|error| FrameError {
            error,
            raw: header.to_vec(),
        })?;
        let Some(raw) = pending.get(..len) else {
            return Ok(None);
        };
        let raw = raw.to_vec();
        #[allow(clippy::cast_possible_truncation)] // len <= MAX_PDU_LEN
        match pdu::decode_payload(version, pdu_type, field, len as u32, &raw) {
            Ok(pdu) => {
                self.consumed += len;
                Ok(Some(Frame { version, pdu, raw }))
            }
            Err(error) => Err(FrameError { error, raw }),
        }
    }
}

struct Header {
    version: RtrVersion,
    pdu_type: pdu::PduType,
    field: u16,
    /// Within `HEADER_LEN..=MAX_PDU_LEN`.
    len: usize,
}

/// Decodes a header and rejects a Length no PDU can have.
fn check_header(header: &[u8]) -> Result<Header, PduError> {
    let (version, pdu_type, field, len) = pdu::decode_header(header)?;
    if len > MAX_PDU_LEN || (len as usize) < HEADER_LEN {
        return Err(PduError::InvalidLength {
            pdu_type: pdu_type as u8,
            len,
        });
    }
    Ok(Header {
        version,
        pdu_type,
        field,
        len: len as usize,
    })
}

/// Runs adversarial input through the decoder twice — delivered at once, and
/// cut into pieces whose sizes come from the input itself — and asserts the
/// two agree. Panics only on a bug.
///
/// Exposed only for fuzzing (`pathvector-fuzz`'s `rtr_pdu` target); not part
/// of the crate's normal public API.
///
/// # Panics
///
/// If decoding depends on how the input was segmented.
#[cfg(any(test, feature = "test-util"))]
pub fn decode_for_fuzzing(data: &[u8]) {
    fn run<'a>(chunks: impl Iterator<Item = &'a [u8]>) -> (Vec<Frame>, Option<FrameError>) {
        let mut decoder = FrameDecoder::new();
        let mut frames = Vec::new();
        for chunk in chunks {
            decoder.push(chunk);
            loop {
                match decoder.next_frame() {
                    Ok(Some(frame)) => frames.push(frame),
                    Ok(None) => break,
                    Err(error) => return (frames, Some(error)),
                }
            }
        }
        (frames, None)
    }

    let size = data.first().map_or(1, |b| usize::from(*b % 33) + 1);
    assert_eq!(
        run(std::iter::once(data)),
        run(data.chunks(size)),
        "decoding depends on segmentation (chunk size {size})"
    );
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::pdu::{EndOfDataIntervals, PrefixFlags};

    fn notify(serial: u32) -> Vec<u8> {
        pdu::encode(
            RtrVersion::V1,
            &Pdu::SerialNotify {
                session_id: 7,
                serial,
            },
        )
    }

    /// Every frame obtainable now, and the error that stopped decoding.
    fn drain(decoder: &mut FrameDecoder, out: &mut Vec<Frame>) -> Option<FrameError> {
        loop {
            match decoder.next_frame() {
                Ok(Some(frame)) => out.push(frame),
                Ok(None) => return None,
                Err(error) => return Some(error),
            }
        }
    }

    /// Feeds `chunks` in order, draining after each, stopping at an error.
    fn decode_chunks<'a>(
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> (Vec<Frame>, Option<FrameError>) {
        let mut decoder = FrameDecoder::new();
        let mut frames = Vec::new();
        for chunk in chunks {
            decoder.push(chunk);
            if let Some(error) = drain(&mut decoder, &mut frames) {
                return (frames, Some(error));
            }
        }
        (frames, None)
    }

    /// One of each shape a cache sends, v0 and v1.
    fn sample_stream() -> (Vec<(RtrVersion, Pdu)>, Vec<u8>) {
        let pdus = vec![
            (RtrVersion::V1, Pdu::CacheResponse { session_id: 1 }),
            (
                RtrVersion::V1,
                Pdu::Ipv4Prefix {
                    flags: PrefixFlags { announce: true },
                    prefix_len: 24,
                    max_len: 24,
                    prefix: "192.0.2.0".parse().unwrap(),
                    asn: 65001,
                },
            ),
            (
                RtrVersion::V1,
                Pdu::Ipv6Prefix {
                    flags: PrefixFlags { announce: false },
                    prefix_len: 32,
                    max_len: 48,
                    prefix: "2001:db8::".parse().unwrap(),
                    asn: 65002,
                },
            ),
            (RtrVersion::V1, Pdu::RouterKey),
            (
                RtrVersion::V1,
                Pdu::EndOfData {
                    session_id: 1,
                    serial: 2,
                    intervals: Some(EndOfDataIntervals {
                        refresh: 3600,
                        retry: 600,
                        expire: 7200,
                    }),
                },
            ),
            (
                RtrVersion::V0,
                Pdu::EndOfData {
                    session_id: 1,
                    serial: 3,
                    intervals: None,
                },
            ),
            (
                RtrVersion::V0,
                Pdu::ErrorReport {
                    error_code: 2,
                    pdu_copy: vec![9; 40],
                    text: "no data".to_string(),
                },
            ),
        ];
        let bytes = pdus.iter().flat_map(|(v, p)| pdu::encode(*v, p)).collect();
        (pdus, bytes)
    }

    #[test]
    fn a_stream_delivered_at_once_yields_every_pdu_in_order() {
        let (pdus, bytes) = sample_stream();
        let (frames, error) = decode_chunks([bytes.as_slice()]);
        assert_eq!(error, None);
        let got: Vec<_> = frames.iter().map(|f| (f.version, f.pdu.clone())).collect();
        assert_eq!(got, pdus);
        let raw: Vec<u8> = frames.into_iter().flat_map(|f| f.raw).collect();
        assert_eq!(raw, bytes, "raw bytes are exactly what arrived");
    }

    /// Exhaustive: every way of cutting the sample stream in two.
    #[test]
    fn every_two_way_split_decodes_identically() {
        let (_, bytes) = sample_stream();
        let whole = decode_chunks([bytes.as_slice()]);
        for split in 0..=bytes.len() {
            let (head, tail) = bytes.split_at(split);
            assert_eq!(decode_chunks([head, tail]), whole, "split at {split}");
        }
    }

    #[test]
    fn one_byte_at_a_time_decodes_identically() {
        let (_, bytes) = sample_stream();
        assert_eq!(
            decode_chunks(bytes.chunks(1)),
            decode_chunks([bytes.as_slice()])
        );
    }

    #[test]
    fn needed_counts_down_to_exactly_one_pdu() {
        let bytes = notify(1);
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.needed(), HEADER_LEN);
        decoder.push(&bytes[..3]);
        assert_eq!(decoder.needed(), HEADER_LEN - 3);
        decoder.push(&bytes[3..HEADER_LEN]);
        assert_eq!(decoder.needed(), bytes.len() - HEADER_LEN);
        decoder.push(&bytes[HEADER_LEN..]);
        assert_eq!(decoder.needed(), 0);
    }

    /// The header alone is enough to refuse an impossible Length: nothing of
    /// the declared body is waited for or buffered.
    #[test]
    fn impossible_lengths_are_refused_from_the_header_alone() {
        for len in [0, 7, MAX_PDU_LEN + 1, u32::MAX] {
            let mut header = vec![1, 8, 0, 0]; // v1 Cache Reset
            header.extend_from_slice(&len.to_be_bytes());
            let mut decoder = FrameDecoder::new();
            decoder.push(&header);
            let error = decoder.next_frame().unwrap_err();
            assert_eq!(
                error,
                FrameError {
                    error: PduError::InvalidLength { pdu_type: 8, len },
                    raw: header,
                }
            );
        }
    }

    #[test]
    fn the_largest_permitted_pdu_is_reassembled() {
        let pdu = Pdu::ErrorReport {
            error_code: 0,
            pdu_copy: vec![0xab; MAX_PDU_LEN as usize - HEADER_LEN - 8],
            text: String::new(),
        };
        let bytes = pdu::encode(RtrVersion::V1, &pdu);
        assert_eq!(bytes.len(), MAX_PDU_LEN as usize);
        let (frames, error) = decode_chunks(bytes.chunks(1000));
        assert_eq!(error, None);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].pdu, pdu);
    }

    /// An error is sticky: the stream cannot be resynchronised, so the
    /// decoder must never skip ahead to something that happens to parse.
    #[test]
    fn nothing_is_decoded_past_a_bad_pdu() {
        let mut stream = notify(1);
        stream.extend_from_slice(&[1, 5, 0, 0, 0, 0, 0, 8]); // type 5: unused
        stream.extend(notify(2));
        let mut decoder = FrameDecoder::new();
        decoder.push(&stream);
        let mut frames = Vec::new();
        let first = drain(&mut decoder, &mut frames).unwrap();
        assert_eq!(first.error, PduError::UnknownPduType(5));
        assert_eq!(frames.len(), 1);
        assert_eq!(decoder.next_frame(), Err(first));
    }

    /// Chunk boundaries as sizes to cut off the front of the stream.
    fn cut<'a>(mut bytes: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
        let mut chunks = Vec::new();
        for &size in sizes.iter().cycle() {
            if bytes.is_empty() {
                break;
            }
            let (head, tail) = bytes.split_at(size.min(bytes.len()));
            chunks.push(head);
            bytes = tail;
        }
        chunks
    }

    /// Mostly well-formed PDUs, with some arbitrary bytes mixed in so the
    /// error paths are exercised under segmentation too.
    fn arb_stream() -> impl Strategy<Value = Vec<u8>> {
        let valid = (any::<u16>(), any::<u32>())
            .prop_map(|(session_id, serial)| {
                pdu::encode(RtrVersion::V1, &Pdu::SerialNotify { session_id, serial })
            })
            .boxed();
        let report = (prop::collection::vec(any::<u8>(), 0..300), ".{0,40}")
            .prop_map(|(pdu_copy, text)| {
                pdu::encode(
                    RtrVersion::V0,
                    &Pdu::ErrorReport {
                        error_code: 1,
                        pdu_copy,
                        text,
                    },
                )
            })
            .boxed();
        let junk = prop::collection::vec(any::<u8>(), 0..24).boxed();
        prop::collection::vec(prop_oneof![4 => valid, 2 => report, 1 => junk], 0..24)
            .prop_map(|parts| parts.concat())
    }

    proptest! {
        /// Segmentation is not observable: same frames, same raw bytes, same
        /// error (if any) however the stream is cut.
        #[test]
        fn segmentation_does_not_change_the_result(
            stream in arb_stream(),
            sizes in prop::collection::vec(1usize..40, 1..16),
        ) {
            prop_assert_eq!(
                decode_chunks(cut(&stream, &sizes)),
                decode_chunks([stream.as_slice()])
            );
        }

        /// The memory bound stated in the module docs.
        #[test]
        fn a_drained_decoder_holds_less_than_one_maximal_pdu(
            stream in arb_stream(),
            sizes in prop::collection::vec(1usize..40, 1..16),
        ) {
            let mut decoder = FrameDecoder::new();
            let mut frames = Vec::new();
            for chunk in cut(&stream, &sizes) {
                decoder.push(chunk);
                if drain(&mut decoder, &mut frames).is_some() {
                    break;
                }
                prop_assert!(decoder.buffered() < MAX_PDU_LEN as usize);
            }
        }
    }
}
