use std::hint::black_box;
use std::time::Instant;

use citadel_envelope::CitadelMlKem768;

fn time_it<F: FnMut()>(label: &str, iters: usize, mut f: F) {
    for _ in 0..(iters / 10).max(10) {
        f();
    }

    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let per_iter = elapsed / (iters as u32);

    println!("{:<16} total={:?}  per_iter={:?}", label, elapsed, per_iter);
}

fn main() {
    let cit = CitadelMlKem768::new();
    let (pk, sk) = cit.keygen();

    let plaintext = vec![0x42u8; 1024];
    let aad_good = b"aad-good";
    let aad_bad = b"aad-bad";
    let ctx_good = b"ctx-good";
    let ctx_bad = b"ctx-bad";

    let ct = match cit.encrypt(&pk, &plaintext, aad_good, ctx_good) {
        Ok(ct) => ct,
        Err(e) => {
            eprintln!("timing setup failed: encrypt error: {e}");
            return;
        }
    };

    let mut ct_tampered = ct.clone();
    if !ct_tampered.is_empty() {
        let last = ct_tampered.len() - 1;
        ct_tampered[last] ^= 0x01;
    }

    let iters = 5_000;

    time_it("valid", iters, || {
        let r = cit.decrypt(&sk, black_box(&ct), black_box(aad_good), black_box(ctx_good));
        black_box(r.ok());
    });

    time_it("wrong_aad", iters, || {
        let r = cit.decrypt(&sk, black_box(&ct), black_box(aad_bad), black_box(ctx_good));
        black_box(r.err());
    });

    time_it("wrong_ctx", iters, || {
        let r = cit.decrypt(&sk, black_box(&ct), black_box(aad_good), black_box(ctx_bad));
        black_box(r.err());
    });

    time_it("tampered", iters, || {
        let r = cit.decrypt(
            &sk,
            black_box(&ct_tampered),
            black_box(aad_good),
            black_box(ctx_good),
        );
        black_box(r.err());
    });

    time_it("short", iters, || {
        let r = cit.decrypt(&sk, black_box(b"short"), black_box(aad_good), black_box(ctx_good));
        black_box(r.err());
    });

    println!("\nDone.");
}
