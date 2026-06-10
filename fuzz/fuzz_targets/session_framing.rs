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
        // If the framing layer accepted a frame, a round-trip must not panic.
        let encoded = msg.encode();
        let _ = BgpMessage::decode(&encoded);
    }
});
