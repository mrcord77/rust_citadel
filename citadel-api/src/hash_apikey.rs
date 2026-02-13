//! Hash an API key for use with CITADEL_API_KEY_HASH.
//!
//! Usage:
//!   cargo run --bin hash-apikey -- "your-secret-api-key"
//!
//! Or generate a random key and hash it:
//!   cargo run --bin hash-apikey -- --generate

use sha2::{Digest, Sha256};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: hash-apikey <api-key>");
        eprintln!("       hash-apikey --generate");
        std::process::exit(1);
    }

    let key = if args[1] == "--generate" {
        // Generate a cryptographically random 32-byte key, hex-encoded
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("failed to generate random bytes");
        let key = hex::encode(buf);
        eprintln!("Generated API key (save this — it cannot be recovered):");
        eprintln!("  {}", key);
        eprintln!();
        key
    } else {
        args[1].clone()
    };

    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();
    let hex_hash = hex::encode(hash);

    eprintln!("SHA-256 hash (set as CITADEL_API_KEY_HASH):");
    println!("{}", hex_hash);
}
