#![no_main]

use libfuzzer_sys::fuzz_target;
use pathvector_rpki::decode_for_fuzzing;

fuzz_target!(|data: &[u8]| {
    decode_for_fuzzing(data);
});
