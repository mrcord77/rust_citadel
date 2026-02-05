#![no_main]

use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;

static KEYPAIR: Lazy<(citadel_envelope::PublicKey, citadel_envelope::SecretKey)> = Lazy::new(|| {
    let citadel = citadel_envelope::CitadelMlKem768::new();
    citadel.keygen()
});

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let a = (data[0] as usize) % (data.len() + 1);
    let b = if data.len() > 1 { (data[1] as usize) % (data.len() + 1) } else { 0 };
    let (i, j) = if a <= b { (a, b) } else { (b, a) };

    let ct = &data[..i];
    let aad = &data[i..j];
    let ctx = &data[j..];

    let citadel = citadel_envelope::CitadelMlKem768::new();
    let (_pk, sk) = &*KEYPAIR;

    let _ = citadel.decrypt(sk, ct, aad, ctx);
});
