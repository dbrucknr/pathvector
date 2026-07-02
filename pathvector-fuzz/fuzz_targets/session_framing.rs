#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use pathvector_session::framing::BgpCodec;
use pathvector_session::message::BgpMessage;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    let mut codec = BgpCodec::default();
    if let Ok(Some(msg)) = codec.decode(&mut buf) {
        // MalformedUpdate is a decode-only variant — BgpMessage::encode()
        // deliberately panics on it (see
        // pathvector-session's test_malformed_update_encode_panics), since
        // production code (transport/mod.rs) only ever pattern-matches it
        // into handle_malformed_update and never re-encodes it. A generic
        // round-trip isn't a meaningful check for this one variant.
        if matches!(msg, BgpMessage::MalformedUpdate(_)) {
            return;
        }
        // If the framing layer accepted a frame, a round-trip must not panic.
        let encoded = msg.encode();
        let _ = BgpMessage::decode(&encoded);
    }
});
