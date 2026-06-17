#![no_main]

use libfuzzer_sys::fuzz_target;
use pathvector_session::message::BgpMessage;

// BGP header constants.
const HEADER_LEN: usize = 19;
const MAX_MSG_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_LEN || data.len() > MAX_MSG_LEN {
        return;
    }

    // Patch the 2-byte length field so BgpMessage::decode sees a consistent
    // total_len and exercises body parsing rather than bailing on a length
    // mismatch.  The marker and type bytes are left as-is, so the decoder may
    // still reject on InvalidMarker or UnknownType — both are fine.
    let mut buf = data.to_vec();
    let len = data.len() as u16;
    buf[16] = (len >> 8) as u8;
    buf[17] = (len & 0xFF) as u8;

    let _ = BgpMessage::decode(&buf);
});
