#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = citadel_envelope::wire::decode_wire(data);
});
