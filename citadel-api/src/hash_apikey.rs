// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hash an API key for use with CITADEL_API_KEY_HASH.
//!
//! Uses HMAC-SHA256 with CITADEL_MASTER_KEY as the server-side secret,
//! matching the algorithm used by the API server at runtime.
//!
//! Usage:
//!   CITADEL_MASTER_KEY=<64-char-hex> cargo run --bin hash-apikey -- "your-secret-api-key"
//!
//! Or generate a random key and hash it:
//!   CITADEL_MASTER_KEY=<64-char-hex> cargo run --bin hash-apikey -- --generate
//!
//! IMPORTANT: CITADEL_MASTER_KEY must be set here AND on the server.
//! Both must use the same key or authentication will fail.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: CITADEL_MASTER_KEY=<64-char-hex> hash-apikey <api-key>");
        eprintln!("       CITADEL_MASTER_KEY=<64-char-hex> hash-apikey --generate");
        std::process::exit(1);
    }

    // Load CITADEL_MASTER_KEY — required for the hash to match the server
    let master_key = match std::env::var("CITADEL_MASTER_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!("ERROR: CITADEL_MASTER_KEY is not set.");
            eprintln!("  The API server uses this key as the HMAC secret when hashing API keys.");
            eprintln!("  Without it, the hash produced here will NOT match the server.");
            eprintln!();
            eprintln!("  Generate a master key: openssl rand -hex 32");
            eprintln!("  Then: CITADEL_MASTER_KEY=<key> hash-apikey <api-key>");
            std::process::exit(1);
        }
    };

    let key = if args[1] == "--generate" {
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

    // Decode the hex-encoded master key to actual bytes before use as HMAC key
    let hmac_key = match hex::decode(master_key.trim()) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!(
                "WARNING: CITADEL_MASTER_KEY is not valid hex; using raw bytes as fallback"
            );
            master_key.into_bytes()
        }
    };

    let mut mac = HmacSha256::new_from_slice(&hmac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(key.as_bytes());
    let hash = mac.finalize().into_bytes();
    let hex_hash = hex::encode(hash);

    eprintln!("HMAC-SHA256 hash (set as CITADEL_API_KEY_HASH):");
    println!("{}", hex_hash);
}
